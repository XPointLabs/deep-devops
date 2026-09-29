import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const read = p => readFile(new URL(p, import.meta.url), 'utf8');

test('deep-dev keeps exactly six scoped native ARM64 services and durable custody', async () => {
  const compose = await read('../docker-compose.deep-dev.yml');
  const services = compose.split('services:\n')[1].split('\nnetworks:')[0];
  assert.deepEqual([...services.matchAll(/^  ([\w-]+):/gm)].map(m => m[1]),
    ['publisher', 'floor', 'registry', 'node-1', 'node-2', 'node-3']);
  assert.match(compose, /platform: linux\/arm64/);
  assert.equal([...compose.matchAll(/restart: always/g)].length, 2);
  assert.doesNotMatch(compose, /restart: unless-stopped/);
  assert.match(compose, /privacyRouting/);
  assert.match(compose, /registry-state:\/var\/lib\/registry/);
  for (const n of [1, 2, 3]) {
    assert.match(compose, new RegExp(`node-${n}-secrets:/run/secrets:ro`));
    assert.match(compose, new RegExp(`node-${n}-state:/var/lib/xnode`));
  }
  assert.doesNotMatch(compose, /offline-root|privileged:|docker\.sock/);
});

test('recovery scripts do not reset custody and historical probe receives public inputs only', async () => {
  const script = await read('./deep-dev.ps1');
  assert.match(script, /--project-name','deep-dev'/);
  assert.match(script, /secrets\\dev/);
  assert.doesNotMatch(script, /'down'.*'--volumes'|'volume','rm'|'system','prune'|Remove-Item/);
  const fault = script.split("if ($Action -eq 'HistoryFault')")[1].split("if ($Action -in")[0];
  assert.match(fault, /finally.*start','node-1','node-2','node-3'/s);
  assert.match(fault, /target=\/run\/deep-public,readonly/);
  assert.doesNotMatch(fault, /target=\/run\/(secrets|deep-operator)|target=\/var\/lib/);
  assert.match(fault, /messageDeliveryEvidence=\$false/);
});

test('local builds use reviewed image digests and a prebuilt native asset, not C++ compilation', async () => {
  const dockerfile = await read('../docker/deep-dev.Dockerfile');
  for (const image of ['golang', 'mcr.microsoft.com/dotnet/sdk', 'mcr.microsoft.com/dotnet/aspnet'])
    assert.ok(dockerfile.includes(`${image}@sha256:`));
  assert.match(dockerfile, /GOARCH=arm64/);
  assert.match(dockerfile, /FROM build AS protocol-tests/);
  assert.doesNotMatch(dockerfile, /cmake|g\+\+|clang|build-essential/);
  const testEnv = await read('./test-env.ps1');
  assert.match(testEnv, /\$BackendMode = .*else \{ "deep-dev" \}/);
});

test('engine fault tests automatic restart with retained custody and refuse a shared engine', async () => {
  const script = await read('./deep-dev.ps1');
  const fault = script.split("if ($Action -in @('StackFault','EngineFault','ExpiryFault'))")[1].split("if ($Action -eq 'Verify')")[0];
  assert.match(script, /\$Action -eq 'EngineFault' -and -not \$ConfirmEngineShutdown/);
  assert.match(fault, /\$wholeEngine = \$Action -eq 'EngineFault'/);
  assert.match(fault, /desktop-linux/);
  assert.match(fault, /\$allRunning.Count -ne 6/);
  assert.match(fault, /\$policy -cne 'always'/);
  assert.match(fault, /Invoke-DesktopOperation 'stop' 60/);
  assert.match(fault, /finally\s*\{\s*if \(\$wholeEngine\) \{[^}]*Invoke-DesktopOperation 'start' 120/s);
  assert.match(fault, /if \(\$wholeEngine\) \{ Invoke-DesktopOperation 'stop' 60 \}\s*else \{ Run-Native docker \(\$compose \+ @\('stop','--timeout','10'\)\) \}/);
  assert.match(fault, /else \{ Run-Native docker \(\$compose \+ @\('start'\)\) \}/);
  assert.match(fault, /post-restart stability window/);
  assert.match(fault, /Online custody changed/);
  assert.match(fault, /unchangedStateMounts=\$true/);
  assert.match(fault, /messageDeliveryEvidence=\$false/);
  assert.match(script, /WaitForExit\(\(\$TimeoutSeconds \+ 10\) \* 1000\)/);
  assert.doesNotMatch(script, /\$process.Kill\(\$true\)/);
  assert.match(fault, /deep-dev-engine-case.v1/);
  assert.match(fault, /deep-dev-stack-case.v1/);
  assert.match(fault, /automaticContainerStart=\$wholeEngine;wholeEngineShutdown=\$wholeEngine/);
});

test('expiry fault authors shorter real signed views without clock or trust changes', async () => {
  const script = await read('./deep-dev.ps1');
  assert.match(script, /publish-short-view/);
  assert.match(script, /\$OfflineSeconds = 200/);
  const publisher = await read('../tools/deep-dev/DevPublisher.cs');
  assert.match(publisher, /operationalLifetimeSeconds is < 180 or > 3_600/);
  assert.match(publisher, /AuthorDelegatedAsync/);
  assert.match(publisher, /checked\(observed\+operationalLifetimeSeconds-30\)/);
  assert.match(publisher, /if \(singlePublication\) return/);
  assert.doesNotMatch(script, /Set-Date|hwclock|timedatectl/);
});
