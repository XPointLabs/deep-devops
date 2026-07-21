import assert from 'node:assert/strict';
import test from 'node:test';

import {
  assertNoForbiddenText,
  assertOwnedResources,
  assertSafeCleanupCommand,
  executeWithGuaranteedCleanup,
  executeReceiptAction,
  executeStagedLifecycle,
  removeValidatedOwnedImages,
  validateBuildPolicy,
  validateCollisionInventory,
  validateCleanupInventory,
  validateComposeModel,
  validateForeignInventoryInvariant,
  validateImageMetadata,
  validateHardhatIsolation,
  validateIdentitySurfaces,
  validateKeepRunningGate,
  validateLifecycleOperationOrder,
  validateOwnershipReceipt,
  validateReceiptResources,
  validateImageSourceBindings,
  validateProjectName
} from './p15c-headless-contracts.mjs';

const sha = 'a'.repeat(40);
const tree = 'b'.repeat(40);
const digest = `sha256:${'c'.repeat(64)}`;
const nonce = 'd'.repeat(32);
const project = 'p15c-0123456789abcdef';

test('project namespace is exact and bounded', () => {
  assert.equal(validateProjectName(project), true);
  for (const invalid of ['p15c-ABCDEF0123456789', 'p15-0123456789abcdef', 'p15c-short', `${project}0`]) {
    assert.throws(() => validateProjectName(invalid));
  }
});

test('cleanup is exact-project compose down only', () => {
  assert.equal(assertSafeCleanupCommand(`docker compose -p ${project} -f docker-compose.p15c-headless.yml down --volumes --remove-orphans`, project), true);
  for (const command of [
    'docker system prune -af',
    'docker container prune',
    'docker rm -f $(docker ps -aq)',
    'docker compose down --volumes',
    `docker compose -p p15c-fedcba9876543210 down --volumes --remove-orphans`
  ]) assert.throws(() => assertSafeCleanupCommand(command, project));
});

test('foreign resources are rejected before mutation', () => {
  assert.equal(assertOwnedResources(project, [{ project, kind: 'container' }]), true);
  assert.throws(() => assertOwnedResources(project, [{ project: 'foreign', kind: 'network' }]));
});

test('forbidden authority, transport and host-integration text is rejected', () => {
  assert.equal(assertNoForbiddenText('Vless__Enabled=false\nproductRuntime=false'), true);
  for (const value of ['mnemonic', 'arbitrum sepolia', 'deep-uat', 'UAT authority', 'old identity', 'legacy compose', 'host-gateway', '/var/run/docker.sock', 'privileged: true', 'mock Xray', 'profile activation', 'profile signer', 'client verifier', 'runtime registration', 'product-runtime: true']) {
    assert.throws(() => assertNoForbiddenText(value));
  }
});

test('compose model is isolated Linux ARM64 headless topology', () => {
  const roles = ['contracts-devnet', 'xnode-1', 'xnode-2', 'xnode-3', 'registry', 'staking-backend', 'storage', 'file', 'push', 'calls', 'test-client'];
  const services = Object.fromEntries(roles.map(role => [role, {
    platform: 'linux/arm64',
    networks: ['runtime'],
    image: role.startsWith('xnode-') ? `p15c-node:${sha}` : `p15c-${role}:${sha}`,
    pull_policy: 'never',
    read_only: true,
    cap_drop: ['ALL'],
    security_opt: ['no-new-privileges:true'],
    healthcheck: role === 'test-client' ? undefined : { test: ['CMD', 'true'] },
    labels: {
      'org.opencontainers.image.revision': sha,
      'org.opencontainers.image.source-tree': tree,
      'com.xpoint.p15c.role': role,
      'com.xpoint.evidence-class': 'headless-harness',
      'com.xpoint.product-runtime': 'false'
    },
    environment: role.startsWith('xnode-') ? { Vless__Enabled: 'false', Node__Ed25519PrivateKeyPath: `/run/secrets/${role}` } : {},
    secrets: role.startsWith('xnode-') ? [{ source: `${role}-identity`, target: role }, { source: `${role}-config`, target: `appsettings.${role}.json` }] : undefined,
    ports: ['127.0.0.1:39001:8080']
  }]));
  services['test-client'].restart = 'no';
  delete services['test-client'].ports;
  delete services.storage.ports;
  delete services.file.ports;
  delete services.push.ports;
  delete services.calls.ports;
  const model = { name: project, services, networks: { runtime: { internal: true } }, volumes: {} };
  assert.equal(validateComposeModel(model, { sha, tree }), true);
  model.networks.runtime.internal = false;
  assert.throws(() => validateComposeModel(model, { sha, tree }));
});

test('compose mutations fail for every isolation and image invariant', () => {
  const make = () => {
    const roles = ['contracts-devnet', 'xnode-1', 'xnode-2', 'xnode-3', 'registry', 'staking-backend', 'storage', 'file', 'push', 'calls', 'test-client'];
    const services = Object.fromEntries(roles.map(role => [role, {
      platform: 'linux/arm64', networks: ['runtime'], image: role.startsWith('xnode-') ? 'p15c-xnode:exact' : `p15c-${role}:exact`, pull_policy: 'never', read_only: true,
      cap_drop: ['ALL'], security_opt: ['no-new-privileges:true'], healthcheck: role === 'test-client' ? undefined : { test: ['CMD', 'true'] },
      labels: { 'org.opencontainers.image.revision': sha, 'org.opencontainers.image.source-tree': tree, 'com.xpoint.p15c.role': role, 'com.xpoint.evidence-class': 'headless-harness', 'com.xpoint.product-runtime': 'false' },
      environment: role.startsWith('xnode-') ? { Vless__Enabled: 'false', Node__Ed25519PrivateKeyPath: `/run/secrets/${role}` } : {},
      secrets: role.startsWith('xnode-') ? [{ source: `${role}-identity`, target: role }, { source: `${role}-config`, target: `appsettings.${role}.json` }] : undefined,
      ports: ['127.0.0.1:39001:8080']
    }]));
    for (const role of ['storage', 'file', 'push', 'calls', 'test-client']) delete services[role].ports;
    return { name: project, services, networks: { runtime: { internal: true } }, volumes: {}, secrets: {} };
  };
  const mutations = [
    m => { m.services.registry.platform = 'linux/amd64'; },
    m => { m.services.registry.pull_policy = 'always'; },
    m => { m.services.registry.read_only = false; },
    m => { m.services.registry.cap_drop = []; },
    m => { m.services.registry.security_opt = []; },
    m => { m.services.registry.healthcheck = undefined; },
    m => { m.services['test-client'].healthcheck = undefined; }, // remains legal one-shot
    m => { m.services.registry.ports = ['0.0.0.0:39001:8080']; },
    m => { m.services.storage.ports = ['127.0.0.1:39002:8080']; },
    m => { m.services.registry.volumes = ['/host/source:/app']; },
    m => { m.services.registry.volumes = ['C:\\host\\source:/app']; },
    m => { m.services.registry.volumes = ['./source:/app']; },
    m => { m.services.registry.network_mode = 'host'; },
    m => { m.services.registry.privileged = true; },
    m => { m.services.registry.devices = ['/dev/net/tun']; },
    m => { m.services.registry.volumes = ['/var/run/docker.sock:/var/run/docker.sock']; },
    m => { m.services.registry.extra_hosts = ['host.docker.internal:host-gateway']; },
    m => { m.services.registry.cap_add = ['NET_ADMIN']; },
    m => { m.services['xnode-2'].image = 'p15c-xnode:different'; },
    m => { m.services['xnode-2'].environment.Vless__Enabled = 'true'; },
    m => { m.services['xnode-2'].environment.Node__Ed25519PrivateKey = 'inline'; },
    m => { delete m.services['xnode-2'].environment.Node__Ed25519PrivateKeyPath; },
    m => { m.services['xnode-2'].secrets = []; },
    m => { m.services.registry.labels['com.xpoint.product-runtime'] = 'true'; },
    m => { m.services.registry.labels['org.opencontainers.image.source-tree'] = 'c'.repeat(40); }
  ];
  for (let index = 0; index < mutations.length; index += 1) {
    const model = make();
    mutations[index](model);
    if (index === 6) assert.equal(validateComposeModel(model, { sha, tree }), true);
    else assert.throws(() => validateComposeModel(model, { sha, tree }), `mutation ${index} must fail`);
  }
});

test('orchestrator order proves collision and foreign snapshot precede build/up', () => {
  const valid = ['source-preflight', 'image-preflight', 'collision-check', 'foreign-snapshot', 'generate-secrets', 'compose-config', 'build', 'up-contracts', 'deploy-contracts', 'up-runtime', 'probe', 'e2e', 'labels', 'evidence', 'cleanup'];
  assert.equal(validateLifecycleOperationOrder(valid), true);
  for (const mutation of [
    valid.filter(value => value !== 'collision-check'),
    valid.filter(value => value !== 'foreign-snapshot'),
    [...valid.slice(0, 6), 'build', 'collision-check', ...valid.slice(7)],
    [...valid.slice(0, 7), 'up-contracts', 'foreign-snapshot', ...valid.slice(8)]
  ]) assert.throws(() => validateLifecycleOperationOrder(mutation));
});

test('Hardhat is ephemeral chain 31337 without chain volume or external authority env', () => {
  const valid = { chainId: 31337, volumes: [], environment: {}, command: ['pnpm', 'exec', 'hardhat', 'node'], stakingAddressSource: 'validated-local-manifest' };
  assert.equal(validateHardhatIsolation(valid), true);
  for (const patch of [{ chainId: 421614 }, { volumes: ['chain-state:/data'] }, { environment: { ETH_RPC_URL: 'https://outside' } }, { environment: { PRIVATE_KEY: 'x' } }, { stakingAddressSource: 'environment-default' }]) {
    assert.throws(() => validateHardhatIsolation({ ...valid, ...patch }));
  }
});

test('build definitions require exact operator digest, pull never and distinct SDK/runtime', () => {
  const sdk = `mcr.microsoft.com/dotnet/sdk@${digest}`;
  const runtime = `mcr.microsoft.com/dotnet/aspnet@sha256:${'d'.repeat(64)}`;
  const node = `node@sha256:${'e'.repeat(64)}`;
  const valid = { operatorSupplied: { sdk, runtime, node }, usedBases: [sdk, runtime, node], pullPolicy: 'never', buildPull: false, sdk, runtime };
  assert.equal(validateBuildPolicy(valid), true);
  for (const patch of [{ pullPolicy: 'missing' }, { buildPull: true }, { usedBases: ['node:latest'] }, { runtime: sdk }, { operatorSupplied: { sdk, runtime } }]) {
    assert.throws(() => validateBuildPolicy({ ...valid, ...patch }));
  }
});

test('generated identities are absent from command, env, logs, evidence and receipt', () => {
  const identity = 'f'.repeat(64);
  const surfaces = { commands: ['dotnet XNode.dll'], environments: { Vless__Enabled: 'false' }, logs: ['gate passed'], evidence: { result: 'pass' }, receipt: { schema: 'owned' } };
  assert.equal(validateIdentitySurfaces([identity], surfaces), true);
  for (const name of Object.keys(surfaces)) assert.throws(() => validateIdentitySurfaces([identity], { ...surfaces, [name]: `${identity}` }));
});

test('built image metadata is exact and non-product', () => {
  const labels = {
    'org.opencontainers.image.revision': sha,
    'org.opencontainers.image.source-tree': tree,
    'org.opencontainers.image.source': 'xnode',
    'com.xpoint.p15c.role': 'xnode',
    'com.xpoint.evidence-class': 'headless-harness',
    'com.xpoint.product-runtime': 'false',
    'com.xpoint.p15c.ownership-nonce': nonce
  };
  assert.equal(validateImageMetadata({ id: digest, os: 'linux', architecture: 'arm64', labels }, { sha, tree, role: 'xnode', nonce }), true);
  labels['com.xpoint.product-runtime'] = 'true';
  assert.throws(() => validateImageMetadata({ id: digest, os: 'linux', architecture: 'arm64', labels }, { sha, tree, role: 'xnode', nonce }));
});

test('KeepRunning and receipt validation fail closed', () => {
  assert.equal(validateKeepRunningGate({ allGatesPassed: true, requested: true }), true);
  assert.throws(() => validateKeepRunningGate({ allGatesPassed: false, requested: true }));
  const receipt = { schema: 'deep-p15c-ownership.v1', project, nonce, composeSha256: digest.slice(7), sources: { devops: { sha, tree } }, images: [{ role: 'xnode', id: digest }] };
  assert.equal(validateOwnershipReceipt(receipt, { project, nonce, composeSha256: digest.slice(7), sources: receipt.sources }), true);
  assert.throws(() => validateOwnershipReceipt({ ...receipt, nonce: 'e'.repeat(32) }, { project, nonce, composeSha256: digest.slice(7), sources: receipt.sources }));
});

test('collision gate runs before build and rejects every owned namespace collision', () => {
  assert.equal(validateCollisionInventory(project, { containers: [], networks: [], volumes: [], images: [] }), true);
  for (const kind of ['containers', 'networks', 'volumes', 'images']) {
    const inventory = { containers: [], networks: [], volumes: [], images: [] };
    inventory[kind].push({ project });
    assert.throws(() => validateCollisionInventory(project, inventory));
  }
});

test('foreign inventory comparison is byte-for-byte stable', () => {
  const before = '{"containers":["foreign-a"],"images":["foreign-b"]}\n';
  assert.equal(validateForeignInventoryInvariant(before, before), true);
  assert.throws(() => validateForeignInventoryInvariant(before, before.replace('a', 'c')));
});

test('receipt resources revalidate nonce, sources and exact image labels', () => {
  const expected = { project, nonce, sources: { devops: { sha, tree } } };
  const valid = [{ kind: 'image', project, nonce, role: 'xnode', id: digest, os: 'linux', architecture: 'arm64', labels: { 'org.opencontainers.image.revision': sha, 'org.opencontainers.image.source-tree': tree, 'com.xpoint.p15c.role': 'xnode', 'com.xpoint.p15c.ownership-nonce': nonce, 'com.xpoint.evidence-class': 'headless-harness', 'com.xpoint.product-runtime': 'false', 'org.opencontainers.image.source': 'xnode' } }];
  assert.equal(validateReceiptResources(valid, expected), true);
  assert.throws(() => validateReceiptResources(valid.map(value => ({ ...value, nonce: 'e'.repeat(32) })), expected));
  assert.throws(() => validateReceiptResources(valid.map(value => ({ ...value, labels: { ...value.labels, 'org.opencontainers.image.source-tree': 'e'.repeat(40) } })), expected));
});

test('receipt resources validate containers, networks, volumes and images by kind', () => {
  const labels = { 'com.xpoint.p15c.ownership-nonce': nonce };
  const expected = { project, nonce, sources: { devops: { sha, tree } } };
  const nonImages = ['container', 'network', 'volume'].map(kind => ({ kind, project, nonce, labels }));
  assert.equal(validateReceiptResources(nonImages, expected), true);
  for (const kind of ['container', 'network', 'volume']) {
    assert.throws(() => validateReceiptResources([{ kind, project: 'foreign', nonce, labels }], expected));
    assert.throws(() => validateReceiptResources([{ kind, project, nonce: 'e'.repeat(32), labels }], expected));
  }
});

test('exact owned image removal validates all receipt bindings before first call', async () => {
  const labels = { 'org.opencontainers.image.revision': sha, 'org.opencontainers.image.source-tree': tree, 'com.xpoint.p15c.role': 'xnode', 'com.xpoint.p15c.ownership-nonce': nonce, 'com.xpoint.evidence-class': 'headless-harness', 'com.xpoint.product-runtime': 'false', 'org.opencontainers.image.source': 'xnode' };
  const owned = [{ kind: 'image', project, nonce, role: 'xnode', id: digest, os: 'linux', architecture: 'arm64', labels }];
  const receipt = { schema: 'deep-p15c-ownership.v1', project, nonce, composeSha256: '9'.repeat(64), sources: { xnode: { sha, tree } }, images: [{ role: 'xnode', source: 'xnode', sha, tree, id: digest }] };
  const calls = [];
  await removeValidatedOwnedImages(receipt, owned, async args => calls.push(args));
  assert.deepEqual(calls, [['image', 'rm', digest]]);
  calls.length = 0;
  await assert.rejects(() => removeValidatedOwnedImages({ ...receipt, nonce: 'e'.repeat(32) }, owned, async args => calls.push(args)));
  assert.equal(calls.length, 0);
  await assert.rejects(() => removeValidatedOwnedImages({ project, nonce, images: receipt.images }, owned, async args => calls.push(args)));
  assert.equal(calls.length, 0);
  const foreignId = `sha256:${'f'.repeat(64)}`;
  assert.equal(calls.flat().includes(foreignId), false);
});

test('image roles bind to their own exact source pins', () => {
  const sources = { devops: { sha, tree }, xnode: { sha: '1'.repeat(40), tree: '2'.repeat(40) }, e2e: { sha: '3'.repeat(40), tree: '4'.repeat(40) } };
  assert.equal(validateImageSourceBindings([{ role: 'xnode', source: 'xnode', sha: sources.xnode.sha, tree: sources.xnode.tree }, { role: 'storage', source: 'devops', sha, tree }, { role: 'test-client', source: 'e2e', sha: sources.e2e.sha, tree: sources.e2e.tree }], sources), true);
  assert.throws(() => validateImageSourceBindings([{ role: 'xnode', source: 'devops', sha, tree }], sources));
});

test('cleanup is guaranteed after injected probe or label failure', async () => {
  for (const stage of ['probe', 'labels']) {
    let cleaned = false;
    await assert.rejects(() => executeWithGuaranteedCleanup(async () => { throw new Error(stage); }, async () => { cleaned = true; }));
    assert.equal(cleaned, true);
  }
});

test('operation plus cleanup failure surfaces both errors', async () => {
  await assert.rejects(
    () => executeWithGuaranteedCleanup(async () => { throw new Error('operation failed'); }, async () => { throw new Error('cleanup failed'); }),
    error => error instanceof AggregateError && error.errors.some(value => value.message === 'operation failed') && error.errors.some(value => value.message === 'cleanup failed')
  );
});

test('staged lifecycle cleans normal success and every build/up/probe/label/e2e failure', async () => {
  const stages = ['build', 'up', 'probe', 'label', 'e2e'];
  for (const failure of [undefined, ...stages]) {
    const calls = [];
    const run = stage => async () => { calls.push(stage); if (stage === failure) throw new Error(stage); };
    const operations = Object.fromEntries(stages.map(stage => [stage, run(stage)]));
    if (failure) await assert.rejects(() => executeStagedLifecycle(operations, async () => calls.push('cleanup'), { keepRunning: false }));
    else await executeStagedLifecycle(operations, async () => calls.push('cleanup'), { keepRunning: false });
    assert.equal(calls.at(-1), 'cleanup');
  }
});

test('KeepRunning occurs only after gates and wrong receipt makes zero Docker calls', async () => {
  const calls = [];
  await assert.rejects(() => executeStagedLifecycle({ build: async () => calls.push('build'), gates: async () => { throw new Error('gate'); } }, async () => calls.push('cleanup'), { keepRunning: true }));
  assert.deepEqual(calls, ['build', 'cleanup']);
  let dockerCalls = 0;
  await assert.rejects(() => executeReceiptAction({ bad: true }, () => { throw new Error('receipt'); }, async () => { dockerCalls += 1; }));
  assert.equal(dockerCalls, 0);
});

test('cleanup inventory must be empty', () => {
  assert.equal(validateCleanupInventory({ containers: 0, networks: 0, volumes: 0, images: 0 }), true);
  assert.throws(() => validateCleanupInventory({ containers: 0, networks: 1, volumes: 0, images: 0 }));
});
