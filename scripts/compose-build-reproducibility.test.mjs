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
});
