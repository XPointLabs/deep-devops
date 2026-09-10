import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const digestPinnedNode = /^node:24-bookworm-slim@sha256:[0-9a-f]{64}$/;
const composeSurvivalPath = path.join(repositoryRoot, 'docker-compose.survival.dev.yml');
const expectedSurvivalDotnetSdk = 'mcr.microsoft.com/dotnet/sdk:10.0.301@sha256:ea8bde36c11b6e7eec2656d0e59101d4462f6bd630730f2c8201ed0572b295d5';
const expectedSurvivalRuntime = 'mcr.microsoft.com/dotnet/aspnet:10.0.9@sha256:7644f992230d35cf230017189d4038c0ae0f7388b13f4f7ae1900a155bafb597';
const expectedSurvivalNode = 'node@sha256:242549cd46785b480c832479a730f4f2a20865d61ea2e404fdb2a5c3d3b73ecf';
const scopedSurvivalInlineBuilds = [
  { name: 'x-xnode-build', args: ['SDK_IMAGE', 'RUNTIME_IMAGE'] },
  { name: 'x-mailbox-driver-build', args: ['SDK_IMAGE', 'RUNTIME_IMAGE'] },
  { name: 'x-membership-fixture-build', args: ['SDK_IMAGE', 'RUNTIME_IMAGE'] },
  { name: 'x-compat-build', args: ['NODE_IMAGE'] },
  { name: 'contracts-devnet', args: ['NODE_IMAGE'] },
  { name: 'registry', args: ['SDK_IMAGE', 'RUNTIME_IMAGE'] },
  { name: 'staking-backend', args: ['SDK_IMAGE', 'RUNTIME_IMAGE'] },
];

function topLevelComposeBlock(source, name) {
  const lines = source.split(/\r?\n/);
  const escapedName = name.replace(/[.*+?^${}()|[\]\\]/g, '\\\\$&');
  const headerPattern = new RegExp(`^([ \\t]*)${escapedName}:(?:\\s+&[^\\s]+)?`);
  let headerIndex = -1;
  let indent = 0;
  for (let index = 0; index < lines.length; index += 1) {
    const match = lines[index].match(headerPattern);
    if (!match) {
      continue;
    }
    headerIndex = index;
    indent = match[1].length;
    break;
  }
  assert.ok(headerIndex !== -1, `missing ${name} block`);
  const bodyLines = [];
  for (let index = headerIndex + 1; index < lines.length; index += 1) {
    const line = lines[index];
    if (line.trim() === '') {
      bodyLines.push(line);
      continue;
    }
    const headerLike = line.match(/^([ \t]*)([A-Za-z][A-Za-z0-9_-]*:|services:|volumes:|networks:|secrets:)/);
    if (headerLike !== null && headerLike[1].length <= indent) {
      break;
    }
    bodyLines.push(line);
  }
  return bodyLines.join('\n');
}

function extractInlineDockerfileFromCompose(source, name) {
  const block = topLevelComposeBlock(source, name);
  const lines = block.split(/\r?\n/);
  const marker = lines.findIndex(line => /^\s*dockerfile_inline:\s*\|$/.test(line));
  assert.notEqual(marker, -1, `${name} must include dockerfile_inline`);
  const markerIndent = lines[marker].match(/^[ \t]*/)?.[0] ?? '';
  const bodyIndent = `${markerIndent}  `;
  const bodyLines = [];
  for (let index = marker + 1; index < lines.length; index += 1) {
    const line = lines[index];
    if (line.length === 0) {
      bodyLines.push('');
      continue;
    }
    if (!line.startsWith(bodyIndent)) break;
    bodyLines.push(line.slice(bodyIndent.length));
  }
  const body = bodyLines.join('\n');
  assert.match(body, /^# /m, `${name} inline dockerfile must keep a directive comment`);
  return body;
}

function assertScopedInvalidDefaultArgInFromPolicy(source, label, expectedArgs, fromInline = false) {
  const checks = [...source.matchAll(/^\s*#\s*check=skip=([^\r\n]+)\s*$/gm)];
  assert.equal(checks.length, 1, `${label} must declare exactly one check policy`);
  assert.equal(checks[0][1].trim(), 'InvalidDefaultArgInFrom', `${label} must only skip InvalidDefaultArgInFrom`);
  for (const arg of expectedArgs) {
    assert.match(source, new RegExp(`^\\s*ARG ${arg}\\s*$`, 'm'), `${label} must declare ${arg} without default`);
    const fromPattern = fromInline
      ? new RegExp(`^\\s*FROM .*\\$\\$\\{${arg}\\}`, 'm')
      : new RegExp(`^\\s*FROM .*\\$\\{${arg}\\}`, 'm');
    assert.match(source, fromPattern, `${label} must consume ${arg}`);
  }
}

function assertNoGlobalCheckPolicy(source, label) {
  const checkAll = [...source.matchAll(/^\s*#\s*check=([^\r\n]+)\s*$/gm)];
  for (const match of checkAll) {
    assert.equal(match[1].trim(), 'skip=InvalidDefaultArgInFrom', `${label} declares a non-targeted check directive`);
  }
}

test('all Node compatibility-service builds pass one immutable digest-pinned NODE_IMAGE', async () => {
  const compose = await readFile(path.join(repositoryRoot, 'docker-compose.yml'), 'utf8');
  const pin = compose.match(/^\s{2}NODE_IMAGE: (node:24-bookworm-slim@sha256:[0-9a-f]{64})\s*$/m)?.[1];
  assert.match(pin ?? '', digestPinnedNode);
  const expectedServices = [
    'storage', 'storage-service', 'file', 'file-service', 'calls', 'push-service'
  ];
  for (const name of expectedServices) {
    const block = compose.match(new RegExp(`^  ${name}:\\r?\\n([\\s\\S]*?)(?=^  [a-zA-Z0-9-]+:|(?![\\s\\S]))`, 'm'))?.[1] ?? '';
    assert.match(block, /^\s{6}args: \*node-runtime-build-args\s*$/m, `${name} must consume the reviewed pin`);
  }
});

test('mandatory NODE_IMAGE Dockerfiles and production storage build use the reviewed pin', async () => {
  const dockerfiles = ['storage-service', 'file-service', 'push-service'];
  for (const name of dockerfiles) {
    const source = await readFile(path.join(repositoryRoot, 'docker', `${name}.Dockerfile`), 'utf8');
    assert.match(source, /^ARG NODE_IMAGE\s*$/m, `${name} must not define a mutable Dockerfile default`);
    assert.match(source, /^FROM \$\{NODE_IMAGE\}\s*$/m, `${name} must consume the required build arg`);
  }
  const dotnetService = await readFile(path.join(repositoryRoot, 'docker', 'dotnet-service.Dockerfile'), 'utf8');
  assert.match(dotnetService, /^ARG SDK_IMAGE\s*$/m, 'dotnet-service must not define a mutable SDK image default');
  assert.match(dotnetService, /^ARG RUNTIME_IMAGE\s*$/m, 'dotnet-service must not define a mutable runtime image default');
  assert.match(dotnetService, /^FROM \$\{SDK_IMAGE\} AS build$/m, 'dotnet-service must consume required SDK image arg');
  assert.match(dotnetService, /^FROM \$\{RUNTIME_IMAGE\} AS runtime$/m, 'dotnet-service must consume required runtime image arg');

  const workflow = await readFile(
    path.join(repositoryRoot, '.github', 'workflows', 'publish-production-images.yml'),
    'utf8'
  );
  assert.match(workflow, /NODE_IMAGE=node:24-bookworm-slim@sha256:[0-9a-f]{64}/);
  assert.match(
    workflow,
    /build-contexts:\s*\|\s*\r?\n\s+deep_protocol=\.\/deep-protocol/,
    'production xnode publication must bind the checked-out protocol source as a named build context'
  );
});

test('multi-node compose startup is isolated, bounded, observable, and always cleaned', async () => {
  const source = await readFile(path.join(repositoryRoot, 'scripts', 'multi-node-rehearsal.ps1'), 'utf8');
  const rehearsal = await readFile(path.join(repositoryRoot, 'scripts', 'multi-node-rehearsal.mjs'), 'utf8');
  assert.match(source, /\$ComposeProjectName = "deep-multi-node-rehearsal"/);
  assert.match(source, /DEEP_MULTI_NODE_COMPOSE_TIMEOUT_SECONDS/);
  assert.match(source, /Invoke-DockerBounded -TimeoutSeconds \$ComposeTimeoutSeconds/);
  assert.match(source, /"multi-node-build",\s*\r?\n\s*"build",\s*\r?\n\s*"xnode-multi-node-image",\s*\r?\n\s*"registry"/);
  assert.match(source, /Invoke-DockerBounded -TimeoutSeconds 300/);
  assert.match(source, /"up",\s*\r?\n\s*"--no-build"/);
  assert.doesNotMatch(source, /"up",\s*\r?\n\s*"--build"/);
  assert.match(source, /XNODE_ASPNETCORE_ENVIRONMENT = "Development"/);
  assert.match(source, /artifacts["']?\)?[\s\S]*rehearsals\\multi-node/);
  assert.match(source, /\$env:DEEP_REHEARSAL_RUN_DIR = \$ArtifactDir/);
  assert.match(source, /ComposeProjectName \$ComposeProjectName/);
  assert.match(source, /\$startProcessParameters\.WindowStyle = 'Hidden'/);
  assert.match(source, /\[Environment\]::OSVersion\.Platform -eq \[PlatformID\]::Win32NT/);
  assert.match(source, /\[void\]\$process\.Handle/);
  assert.match(source, /completed without an observable integer exit code/);
  assert.match(source, /function Invoke-DockerCleanupBounded/);
  assert.match(source, /foreach \(\$attempt in 1\.\.\$Attempts\)/);
  assert.match(source, /taskkill\.exe \/PID \$process\.Id \/T \/F/);
  assert.match(source, /\$process\.Refresh\(\)/);
  assert.match(source, /docker compose is still running/);
  assert.match(source, /"down",\s*\r?\n\s*"--volumes",\s*\r?\n\s*"--remove-orphans"/);
  assert.match(rehearsal, /stakeAtomic: 25_000n \* 1_000_000_000n/);
  assert.match(rehearsal, /amountAtomic: 25_000n \* 1_000_000_000n/);
  assert.match(rehearsal, /signingEndpoint: `http:\/\/xnode-\$\{index \+ 1\}:8080\/api\/staking\/quorum\/sign`/);
  assert.match(rehearsal, /const transportStatus = node\.xray \?\? property\(payload, 'transport', 'Transport'\)/);
  assert.match(rehearsal, /running: Boolean\(property\(transportStatus, 'running', 'Running'\)\)/);
  assert.match(rehearsal, /mocked: Boolean\(property\(transportStatus, 'mocked', 'Mocked'\)\)/);
});

test('no-mock compose pins both supported Xray platform assets and Dockerfile selects fail closed', async () => {
  const compose = await readFile(path.join(repositoryRoot, 'docker-compose.yml'), 'utf8');
  const dockerfile = await readFile(path.join(repositoryRoot, 'docker', 'xnode-xray.Dockerfile'), 'utf8');
  const services = ['xnode', 'xnode-multi-node-image'];
  for (const name of services) {
    const block = compose.match(new RegExp(`^  ${name}:\\r?\\n([\\s\\S]*?)(?=^  [a-zA-Z0-9-]+:|(?![\\s\\S]))`, 'm'))?.[1] ?? '';
    assert.match(block, /^\s{8}XRAY_SHA256_AMD64: [0-9a-f]{64}\s*$/m, `${name} amd64 Xray digest`);
    assert.match(block, /^\s{8}XRAY_SHA256_ARM64: [0-9a-f]{64}\s*$/m, `${name} arm64 Xray digest`);
  }
  for (const name of ['xnode-1', 'xnode-2', 'xnode-3']) {
    const block = compose.match(new RegExp(`^  ${name}:\\r?\\n([\\s\\S]*?)(?=^  [a-zA-Z0-9-]+:|(?![\\s\\S]))`, 'm'))?.[1] ?? '';
    assert.match(block, /^\s{4}image: deep-multi-node-rehearsal\/xnode-xray:dev\s*$/m);
    assert.match(block, /^\s{4}pull_policy: never\s*$/m);
    assert.doesNotMatch(block, /^\s{4}build:/m, `${name} must consume the one shared build`);
  }
  assert.match(dockerfile, /amd64\) XRAY_ASSET=.*XRAY_EXPECTED_SHA256="\$\{XRAY_SHA256_AMD64:-\$XRAY_SHA256\}"/);
  assert.match(dockerfile, /arm64\) XRAY_ASSET=.*XRAY_EXPECTED_SHA256="\$\{XRAY_SHA256_ARM64:-\$XRAY_SHA256\}"/);
  assert.match(dockerfile, /test "\$\{#XRAY_EXPECTED_SHA256\}" -eq 64/);
  assert.match(dockerfile, /echo "\$XRAY_EXPECTED_SHA256  \/tmp\/xray-download\/xray\.zip" \| sha256sum -c -/);
  assert.match(dockerfile, /dotnet restore "\$PROJECT" --locked-mode/);
  assert.match(dockerfile, /for attempt in 1 2 3/);
  assert.match(dockerfile, /ResponseEnded\|unexpected EOF/);
  assert.match(dockerfile, /--retry 5 --retry-all-errors/);
  assert.doesNotMatch(dockerfile, /dotnet restore[^\r\n]*--(?:arch|runtime|-r)\b/);
  assert.match(dockerfile, /dotnet publish[^\r\n]*--runtime "linux-\$DOTNET_ARCH"[^\r\n]*--no-restore/);

  for (const [service, index] of [['xnode', 1], ['xnode-1', 2], ['xnode-2', 3], ['xnode-3', 4]]) {
    const block = compose.match(new RegExp(`^  ${service}:\\r?\\n([\\s\\S]*?)(?=^  [a-zA-Z0-9-]+:|(?![\\s\\S]))`, 'm'))?.[1] ?? '';
    assert.match(block, new RegExp(`Vless__ClientIdFile: /run/secrets/xnode-${index}-vless-client-id`));
    assert.match(block, new RegExp(`Vless__Reality__PrivateKeyFile: /run/secrets/xnode-${index}-reality-private-key`));
    assert.doesNotMatch(block, /Vless__ClientId:/);
    assert.doesNotMatch(block, /Vless__Reality__PrivateKey:/);
  }
});

test('no-mock integration uses real Xray without impersonating production authority readiness', async () => {
  const source = await readFile(path.join(repositoryRoot, 'scripts', 'test-env.ps1'), 'utf8');
  assert.match(source, /XNODE_ASPNETCORE_ENVIRONMENT" -Value "Development"/);
  assert.match(source, /XNODE_VLESS_MOCK_PROCESS" -Value "false"/);
  assert.match(source, /XNODE_XRAY_EXECUTABLE_PATH" -Value "\/usr\/local\/bin\/xray"/);
});

test('mandatory whole-image ARGs stay explicit and checks are scoped to InvalidDefaultArgInFrom', async () => {
  const composeSurvival = await readFile(composeSurvivalPath, 'utf8');
  const dotnetDockerfile = await readFile(path.join(repositoryRoot, 'docker', 'dotnet-service.Dockerfile'), 'utf8');
  const xnodeDockerfile = await readFile(path.join(repositoryRoot, 'docker', 'xnode-xray.Dockerfile'), 'utf8');

  assertScopedInvalidDefaultArgInFromPolicy(dotnetDockerfile, 'dotnet-service.Dockerfile', ['SDK_IMAGE', 'RUNTIME_IMAGE']);
  assertScopedInvalidDefaultArgInFromPolicy(xnodeDockerfile, 'xnode-xray.Dockerfile', ['SDK_IMAGE', 'RUNTIME_IMAGE']);
  for (const { name, args } of scopedSurvivalInlineBuilds) {
    assertScopedInvalidDefaultArgInFromPolicy(
      extractInlineDockerfileFromCompose(composeSurvival, name),
      `${name} inline dockerfile`,
      args,
      true
    );
  }
});

test('survival compose keeps immutable digest pins for SDK/RUNTIME/NODE image args', async () => {
  const composeSurvival = await readFile(composeSurvivalPath, 'utf8');
  const pinnedSdk = [...composeSurvival.matchAll(/^[ \t]*SDK_IMAGE:\s*\$\{SURVIVAL_DOTNET_SDK_IMAGE:-([^}]+)\}/gm)].map(match => match[1]);
  const pinnedRuntime = [...composeSurvival.matchAll(/^[ \t]*RUNTIME_IMAGE:\s*\$\{SURVIVAL_DOTNET_RUNTIME_IMAGE:-([^}]+)\}/gm)].map(match => match[1]);
  const pinnedNode = [...composeSurvival.matchAll(/^[ \t]*NODE_IMAGE:\s*\$\{SURVIVAL_NODE_IMAGE:-([^}]+)\}/gm)].map(match => match[1]);
  assert.ok(pinnedSdk.every(value => value === expectedSurvivalDotnetSdk));
  assert.ok(pinnedRuntime.every(value => value === expectedSurvivalRuntime));
  assert.ok(pinnedNode.every(value => value === expectedSurvivalNode));
  assert.equal(new Set(pinnedSdk).size, 1);
  assert.equal(new Set(pinnedRuntime).size, 1);
  assert.equal(new Set(pinnedNode).size, 1);
  assert.equal(pinnedSdk.length, 5);
  assert.equal(pinnedRuntime.length, 5);
  assert.equal(pinnedNode.length, 2);
});

test('InvalidDefaultArgInFrom skip is intentionally local, not global', async () => {
  const composeSurvival = await readFile(composeSurvivalPath, 'utf8');
  const composeScopedPolicies = [...composeSurvival.matchAll(/^\s*#\s*check=skip=InvalidDefaultArgInFrom\s*$/gm)];
  assert.equal(composeScopedPolicies.length, scopedSurvivalInlineBuilds.length);
  for (const { name, args } of scopedSurvivalInlineBuilds) {
    assertScopedInvalidDefaultArgInFromPolicy(
      extractInlineDockerfileFromCompose(composeSurvival, name),
      `${name} inline dockerfile`,
      args,
      true
    );
  }
  const dotnetDockerfile = await readFile(path.join(repositoryRoot, 'docker', 'dotnet-service.Dockerfile'), 'utf8');
  const xnodeDockerfile = await readFile(path.join(repositoryRoot, 'docker', 'xnode-xray.Dockerfile'), 'utf8');
  assertNoGlobalCheckPolicy(dotnetDockerfile, 'dotnet-service.Dockerfile');
  assertNoGlobalCheckPolicy(xnodeDockerfile, 'xnode-xray.Dockerfile');
  assertNoGlobalCheckPolicy(composeSurvival, 'docker-compose.survival.dev.yml');
});
