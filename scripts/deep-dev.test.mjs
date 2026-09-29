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
  assert.match(compose, /restart: unless-stopped/);
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
