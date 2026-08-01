import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const digestPinnedNode = /^node:24-bookworm-slim@sha256:[0-9a-f]{64}$/;

test('all Node compatibility-service builds pass one immutable digest-pinned NODE_IMAGE', async () => {
  const compose = await readFile(path.join(repositoryRoot, 'docker-compose.yml'), 'utf8');
  const pin = compose.match(/^\s{2}NODE_IMAGE: (node:24-bookworm-slim@sha256:[0-9a-f]{64})\s*$/m)?.[1];
  assert.match(pin ?? '', digestPinnedNode);
  const expectedServices = [
    'storage', 'storage-service', 'file', 'file-service', 'calls', 'calls-service', 'push-service'
  ];
  for (const name of expectedServices) {
    const block = compose.match(new RegExp(`^  ${name}:\\r?\\n([\\s\\S]*?)(?=^  [a-zA-Z0-9-]+:|(?![\\s\\S]))`, 'm'))?.[1] ?? '';
    assert.match(block, /^\s{6}args: \*node-runtime-build-args\s*$/m, `${name} must consume the reviewed pin`);
  }
});

test('mandatory NODE_IMAGE Dockerfiles and production storage build use the reviewed pin', async () => {
  const dockerfiles = ['storage-service', 'file-service', 'calls-service', 'push-service'];
  for (const name of dockerfiles) {
    const source = await readFile(path.join(repositoryRoot, 'docker', `${name}.Dockerfile`), 'utf8');
    assert.match(source, /^ARG NODE_IMAGE\s*$/m, `${name} must not define a mutable Dockerfile default`);
    assert.match(source, /^FROM \$\{NODE_IMAGE\}\s*$/m, `${name} must consume the required build arg`);
  }

  const workflow = await readFile(
    path.join(repositoryRoot, '.github', 'workflows', 'publish-production-images.yml'),
    'utf8'
  );
  assert.match(workflow, /NODE_IMAGE=node:24-bookworm-slim@sha256:[0-9a-f]{64}/);
});

test('multi-node compose startup is isolated, bounded, observable, and always cleaned', async () => {
  const source = await readFile(path.join(repositoryRoot, 'scripts', 'multi-node-rehearsal.ps1'), 'utf8');
  assert.match(source, /\$ComposeProjectName = "deep-multi-node-rehearsal"/);
  assert.match(source, /DEEP_MULTI_NODE_COMPOSE_TIMEOUT_SECONDS/);
  assert.match(source, /Invoke-DockerBounded -TimeoutSeconds \$ComposeTimeoutSeconds/);
  assert.match(source, /\$process\.Kill\(\$true\)/);
  assert.match(source, /\$process\.Refresh\(\)/);
  assert.match(source, /docker compose is still running/);
  assert.match(source, /"down",\s*\r?\n\s*"--volumes",\s*\r?\n\s*"--remove-orphans"/);
});

test('no-mock compose pins both supported Xray platform assets and Dockerfile selects fail closed', async () => {
  const compose = await readFile(path.join(repositoryRoot, 'docker-compose.yml'), 'utf8');
  const dockerfile = await readFile(path.join(repositoryRoot, 'docker', 'xnode-xray.Dockerfile'), 'utf8');
  const services = ['xnode', 'xnode-1', 'xnode-2', 'xnode-3'];
  for (const name of services) {
    const block = compose.match(new RegExp(`^  ${name}:\\r?\\n([\\s\\S]*?)(?=^  [a-zA-Z0-9-]+:|(?![\\s\\S]))`, 'm'))?.[1] ?? '';
    assert.match(block, /^\s{8}XRAY_SHA256_AMD64: [0-9a-f]{64}\s*$/m, `${name} amd64 Xray digest`);
    assert.match(block, /^\s{8}XRAY_SHA256_ARM64: [0-9a-f]{64}\s*$/m, `${name} arm64 Xray digest`);
  }
  assert.match(dockerfile, /amd64\) XRAY_ASSET=.*XRAY_EXPECTED_SHA256="\$\{XRAY_SHA256_AMD64:-\$XRAY_SHA256\}"/);
  assert.match(dockerfile, /arm64\) XRAY_ASSET=.*XRAY_EXPECTED_SHA256="\$\{XRAY_SHA256_ARM64:-\$XRAY_SHA256\}"/);
  assert.match(dockerfile, /test "\$\{#XRAY_EXPECTED_SHA256\}" -eq 64/);
  assert.match(dockerfile, /echo "\$XRAY_EXPECTED_SHA256  \/tmp\/xray-download\/xray\.zip" \| sha256sum -c -/);
  assert.match(dockerfile, /dotnet restore "\$PROJECT" --locked-mode/);
  assert.doesNotMatch(dockerfile, /dotnet restore[^\r\n]*--(?:arch|runtime|-r)\b/);
  assert.match(dockerfile, /dotnet publish[^\r\n]*--runtime "linux-\$DOTNET_ARCH"[^\r\n]*--no-restore/);
});
