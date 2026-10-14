import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const script = path.join(path.dirname(fileURLToPath(import.meta.url)), 'test-registry-postgres.ps1');
const quote = value => `'${value.replaceAll("'", "''")}'`;

// Execute the real orchestration with process-local command doubles. No Docker,
// database, network, source-text snapshots or real environment credentials.
async function run(mode = 'success', testExit = 0, selection = 'filtered') {
  const fixture = await mkdtemp(path.join(os.tmpdir(), 'deep-s00-pg-contract-'));
  try {
    const registry = path.join(fixture, 'registry');
    const scripts = path.join(fixture, 'scripts');
    await mkdir(registry);
    await mkdir(scripts);
    await writeFile(path.join(registry, 'Deep.Registry.Api.slnx'), '<Solution />');
    await writeFile(path.join(scripts, 'TestGate.psm1'), `
function Assert-TestGateInterpreter {
  param([string]$Interpreter)
  if ($Interpreter -ne 'WindowsPowerShell51') { throw 'Wrong full interpreter selection.' }
}
Export-ModuleMember -Function Assert-TestGateInterpreter
`);
    await writeFile(path.join(scripts, 'Invoke-RepositoryTestGate.ps1'), `
param([string]$Repository, [string]$RunDirectory, [string[]]$ReferencePaths, [string[]]$AllowedSkippedCases)
if ($Repository -ne 'deep-registry-api' -or
    $RunDirectory -ne ${quote(path.join(registry, 'artifacts', 'contract'))} -or
    $ReferencePaths.Count -ne 2 -or $ReferencePaths[0] -ne 'prior.trx' -or
    $ReferencePaths[1] -ne 'focused.trx' -or $AllowedSkippedCases.Count -ne 2 -or
    $AllowedSkippedCases[0] -ne 'Example.SkipOne' -or $AllowedSkippedCases[1] -ne 'Example.SkipTwo') {
  throw 'Canonical gate arguments or arrays were lost.'
}
Assert-IsolatedInputs
Write-Host 'EVENT:GATE'
exit ${testExit}
`);
    const argumentsBySelection = {
      filtered: "-Filter 'FullyQualifiedName~FocusedCase'",
      profile: "-Filter 'FullyQualifiedName~FocusedCase' -NativePhaseTrace",
      'full-profile': "-GateReferencePaths @('prior.trx') -NativePhaseTrace",
      'missing-references': '',
      'mixed-references': "-Filter 'FullyQualifiedName~FocusedCase' -GateReferencePaths @('prior.trx')",
      full: `-GateReferencePaths @('prior.trx', 'focused.trx') -GateRunDirectory ${quote(path.join(registry, 'artifacts', 'contract'))} -GateAllowedSkippedCases @('Example.SkipOne', 'Example.SkipTwo')`
    };
    const wrapper = `
$global:mode = ${quote(mode)}
$global:owner = ''
function global:docker {
  $global:LASTEXITCODE = 0
  switch ($args[0]) {
    'context' {
      $endpoint = 'unix:///var/run/docker.sock'
      if ($global:mode -eq 'remote-context') { $endpoint = 'ssh://not-local.invalid' }
      if ($global:mode -eq 'remote-pipe') { $endpoint = 'npipe:////not-local.invalid/pipe/docker_engine' }
      return (ConvertTo-Json -InputObject @(@{ Endpoints = @{ docker = @{ Host = $endpoint } } }) -Depth 4 -Compress)
    }
    'run' {
      if ($args -contains '--volume' -or $args -contains '-v' -or $args -contains '--mount') {
        throw 'Persistent mount reached Docker.'
      }
      if ($args[$args.IndexOf('--publish') + 1] -ne '127.0.0.1::5432' -or
          $args[$args.IndexOf('--tmpfs') + 1] -ne '/var/lib/postgresql/data:rw' -or
          $args -notcontains '--rm' -or
          $args[-1] -ne 'postgres@sha256:dc17045ccfd343b49600570ea734b9c4991cf1c3f3302e67df51e3b402dd55c4') {
        throw 'Disposable scope or pinned image violated.'
      }
      $label = $args | Where-Object { $_ -like 'deep.test.invocation=*' }
      $global:owner = $label.Substring('deep.test.invocation='.Length)
      if ($global:owner -notmatch '^[a-f0-9]{32}$') { throw 'Missing invocation ownership.' }
      Write-Host 'EVENT:RUN'
      return ('a' * 64)
    }
    'inspect' {
      if ($args[-1] -ne ('a' * 64)) { throw 'Wrong inspected container.' }
      $health = 'healthy'; $port = '12345'; $owner = $global:owner
      if ($global:mode -eq 'unhealthy') { $health = 'unhealthy' }
      if ($global:mode -eq 'invalid-port') { $port = 'hostile-port' }
      if ($global:mode -eq 'wrong-owner') { $owner = 'another-invocation' }
      return (ConvertTo-Json -InputObject @(@{
        State = @{ Health = @{ Status = $health } }
        NetworkSettings = @{ Ports = @{ '5432/tcp' = @(@{ HostPort = $port }) } }
        Config = @{ Labels = @{ 'deep.test.invocation' = $owner } }
      }) -Depth 6 -Compress)
    }
    'stop' {
      if ($args[-1] -ne ('a' * 64)) { throw 'Wrong cleanup target.' }
      Write-Host 'EVENT:STOP'
      return ('a' * 64)
    }
    default { throw 'Unexpected Docker command.' }
  }
}
function global:Assert-IsolatedInputs {
  if ([string]$env:DEEP_TEST_NATIVE_PHASE_TRACE -ne ${quote(selection === 'profile' ? '1' : '')}) {
    throw 'Native phase tracing escaped its explicit diagnostic selection.'
  }
  foreach ($name in @('DEEP_TEST_DID2_FLOOR_POSTGRES', 'DEEP_TEST_DID2_ROUTE_POSTGRES', 'DEEP_TEST_DID2_GRANT_POSTGRES')) {
    if ([Environment]::GetEnvironmentVariable($name) -ne
        'Host=127.0.0.1;Port=12345;Database=deep_s00;Username=deep_s00;Pooling=false;Timeout=5') {
      throw 'Test did not receive the isolated DSN.'
    }
  }
  if ($env:DEEP_TEST_DID2_EXTERNAL_ORIGIN -or $env:ConnectionStrings__External -or $env:POSTGRES_PASSWORD) {
    throw 'Ambient external inputs leaked into tests.'
  }
}
function global:dotnet {
  Assert-IsolatedInputs
  if ($args[0] -ne 'test' -or $args -notcontains '-p:DeepProtocolLocalCutover=true' -or
      $args -notcontains '-p:DeepProtocolSourceCutover=true' -or $args -notcontains '--filter' -or
      $args[-1] -ne 'FullyQualifiedName~FocusedCase') { throw 'Wrong test command.' }
  Write-Host 'EVENT:TEST'
  $global:LASTEXITCODE = ${testExit}
}
& ${quote(script)} -RegistryRoot ${quote(registry)} -Lane contract ${argumentsBySelection[selection]}
$laneExit = $LASTEXITCODE
if ($global:mode -eq 'success') {
  foreach ($name in @('DEEP_TEST_DID2_EXTERNAL_ORIGIN', 'DEEP_TEST_DID2_FLOOR_POSTGRES',
      'ConnectionStrings__External', 'POSTGRES_PASSWORD', 'DEEP_TEST_NATIVE_PHASE_TRACE')) {
    if ([Environment]::GetEnvironmentVariable($name) -ne 'synthetic-do-not-log') {
      throw 'Ambient input was not restored after tests.'
    }
  }
}
exit $laneExit
`;
    const result = spawnSync(process.env.DEEP_PWSH ?? (process.platform === 'win32' ? 'powershell.exe' : 'pwsh'), ['-NoProfile', '-Command', wrapper], {
      windowsHide: true, encoding: 'utf8', timeout: 15000,
      env: {
        ...process.env,
        DOCKER_HOST: mode === 'remote-override' ? 'tcp://not-local.invalid:2375' : '',
        DEEP_TEST_DID2_EXTERNAL_ORIGIN: 'synthetic-do-not-log',
        DEEP_TEST_DID2_FLOOR_POSTGRES: 'synthetic-do-not-log',
        DEEP_TEST_NATIVE_PHASE_TRACE: 'synthetic-do-not-log',
        ConnectionStrings__External: 'synthetic-do-not-log',
        POSTGRES_PASSWORD: 'synthetic-do-not-log'
      }
    });
    assert.ifError(result.error);
    assert.doesNotMatch(result.stdout + result.stderr, /synthetic-do-not-log/);
    return result;
  } finally { await rm(fixture, { recursive: true, force: true }); }
}

for (const mode of ['remote-context', 'remote-override', 'remote-pipe']) {
  test(`${mode} rejects before starting a container`, async () => {
    const result = await run(mode);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /remote/);
    assert.doesNotMatch(result.stdout, /EVENT:/);
  });
}

for (const exit of [0, 7]) {
  test(`isolated inputs, pinned tmpfs and owned cleanup preserve test exit ${exit}`, async () => {
    const result = await run('success', exit);
    assert.equal(result.status, exit, result.stderr);
    assert.match(result.stdout, /EVENT:RUN[\s\S]*EVENT:TEST[\s\S]*EVENT:STOP/);
  });
}

test('explicit filtered profiling enables only its process-local phase listener and restores the environment', async () => {
  const result = await run('success', 0, 'profile');
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /EVENT:RUN[\s\S]*EVENT:TEST[\s\S]*EVENT:STOP/);
});

test('full qualification rejects phase profiling before any provider operation', async () => {
  const result = await run('success', 0, 'full-profile');
  assert.equal(result.status, 1);
  assert.match(result.stderr, /forbidden in full qualification/);
  assert.doesNotMatch(result.stdout, /EVENT:/);
});

for (const mode of ['unhealthy', 'invalid-port']) {
  test(`${mode} skips tests and cleans only the invocation's container`, async () => {
    const result = await run(mode);
    assert.equal(result.status, 1);
    assert.match(result.stdout, /EVENT:RUN[\s\S]*EVENT:STOP/);
    assert.doesNotMatch(result.stdout, /EVENT:TEST/);
  });
}

test('mismatched ownership refuses cleanup instead of stopping another container', async () => {
  const result = await run('wrong-owner');
  assert.equal(result.status, 1);
  assert.match(result.stderr, /ownership could not be verified/);
  assert.doesNotMatch(result.stdout, /EVENT:STOP/);
});

for (const selection of ['missing-references', 'mixed-references']) {
  test(`${selection} rejects before any provider operation`, async () => {
    const result = await run('success', 0, selection);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /predeclared references|filtered diagnostic/);
    assert.doesNotMatch(result.stdout, /EVENT:/);
  });
}

for (const exit of [0, 7]) {
  test(`full delegation preserves reference/skip arrays, cleanup and native exit ${exit}`, async () => {
    const result = await run('success', exit, 'full');
    assert.equal(result.status, exit, result.stderr);
    assert.match(result.stdout, /EVENT:RUN[\s\S]*EVENT:GATE[\s\S]*EVENT:STOP/);
    assert.doesNotMatch(result.stdout, /EVENT:TEST/);
  });
}
