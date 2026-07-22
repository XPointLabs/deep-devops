import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import test from 'node:test';

import {
  assertNoForbiddenText,
  assertOwnedResources,
  assertSafeCleanupCommand,
  executeWithGuaranteedCleanup,
  executeReceiptAction,
  executeCleanupPlan,
  executeStagedLifecycle,
  removeValidatedOwnedImages,
  runCallsSignalingE2E,
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
  validateLifecycleOperationPrefix,
  validateOwnedOutputPaths,
  validateRetainedOwnershipState,
  validateFinalEvidenceEligibility,
  validateOwnershipReceipt,
  validateOwnedProjectRuntimeInventory,
  canDeleteOwnedOutput,
  validateReceiptResources,
  validateImageSourceBindings,
  executeExactResourceCleanup,
  loadValidatedReceiptOnce,
  publishOwnedOutput,
  stableForeignInventory,
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

test('cleanup rejects compose down and every broad Docker mutation', () => {
  for (const command of [
    'docker system prune -af',
    'docker container prune',
    'docker rm -f $(docker ps -aq)',
    'docker compose down --volumes',
    `docker compose -p p15c-fedcba9876543210 down --volumes --remove-orphans`,
    `docker compose -p ${project} -f docker-compose.p15c-headless.yml down --volumes --remove-orphans`
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
    m => { m.volumes.state = {}; },
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
    if (index === 7) assert.equal(validateComposeModel(model, { sha, tree }), true);
    else assert.throws(() => validateComposeModel(model, { sha, tree }), `mutation ${index} must fail`);
  }
});

test('orchestrator order proves collision and foreign snapshot precede build/up', () => {
  const valid = ['source-preflight', 'collision-check', 'foreign-snapshot', 'image-preflight', 'generate-secrets', 'source-export', 'compose-config', 'build', 'up-contracts', 'deploy-contracts', 'up-runtime', 'probe', 'e2e', 'labels', 'cleanup', 'evidence'];
  assert.equal(validateLifecycleOperationOrder(valid), true);
  for (const mutation of [
    valid.filter(value => value !== 'collision-check'),
    valid.filter(value => value !== 'foreign-snapshot'),
    [...valid.slice(0, 6), 'build', 'collision-check', ...valid.slice(7)],
    [...valid.slice(0, 7), 'up-contracts', 'foreign-snapshot', ...valid.slice(8)]
  ]) assert.throws(() => validateLifecycleOperationOrder(mutation));
});

test('actual observed normal and retained prefixes cannot fake cleanup/evidence', () => {
  const common = ['source-preflight', 'collision-check', 'foreign-snapshot', 'image-preflight', 'generate-secrets', 'source-export', 'compose-config', 'build', 'up-contracts', 'deploy-contracts', 'up-runtime', 'probe', 'e2e', 'labels'];
  assert.equal(validateLifecycleOperationPrefix([...common, 'cleanup', 'evidence'], { retained: false }), true);
  assert.equal(validateLifecycleOperationPrefix([...common, 'receipt-retained'], { retained: true }), true);
  assert.throws(() => validateLifecycleOperationPrefix([...common, 'cleanup', 'evidence'], { retained: true }));
  assert.throws(() => validateLifecycleOperationPrefix([...common, 'evidence', 'cleanup'], { retained: false }));
});

test('final PASS evidence is legal only after proved cleanup and foreign invariance', () => {
  assert.equal(validateFinalEvidenceEligibility({ retained: false, zeroOwned: true, foreignUnchanged: true }), true);
  for (const value of [{ retained: true, zeroOwned: true, foreignUnchanged: true }, { retained: false, zeroOwned: false, foreignUnchanged: true }, { retained: false, zeroOwned: true, foreignUnchanged: false }]) {
    assert.throws(() => validateFinalEvidenceEligibility(value));
  }
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
  const receipt = { schema: 'deep-p15c-ownership.v1', project, nonce, composeSha256: digest.slice(7), manifestSha256: '1'.repeat(64), foreignSnapshotSha256: '2'.repeat(64), sources: { devops: { sha, tree } }, images: [{ role: 'xnode', source: 'devops', sha, tree, id: digest }] };
  const expected = { project, nonce, composeSha256: digest.slice(7), manifestSha256: receipt.manifestSha256, foreignSnapshotSha256: receipt.foreignSnapshotSha256, sources: receipt.sources, roles: ['xnode'] };
  assert.equal(validateOwnershipReceipt(receipt, expected), true);
  assert.throws(() => validateOwnershipReceipt({ ...receipt, nonce: 'e'.repeat(32) }, expected));
  assert.throws(() => validateOwnershipReceipt({ ...receipt, manifestSha256: '3'.repeat(64) }, expected));
  assert.throws(() => validateOwnershipReceipt({ ...receipt, foreignSnapshotSha256: '4'.repeat(64) }, expected));
  assert.throws(() => validateOwnershipReceipt({ ...receipt, images: [...receipt.images, { ...receipt.images[0], id: `sha256:${'f'.repeat(64)}` }] }, expected));
  assert.throws(() => validateOwnershipReceipt({ ...receipt, images: [...receipt.images, { ...receipt.images[0], role: 'other' }] }, { ...expected, roles: ['xnode', 'other'] }));
});

test('collision gate runs before build and rejects every owned namespace collision', () => {
  assert.equal(validateCollisionInventory(project, { containers: [], networks: [], volumes: [], images: [] }), true);
  for (const kind of ['containers', 'networks', 'volumes', 'images']) {
    const inventory = { containers: [], networks: [], volumes: [], images: [] };
    inventory[kind].push({ project });
    assert.throws(() => validateCollisionInventory(project, inventory));
  }
});

test('foreign inventory ignores runtime state but rejects identity or membership drift', () => {
  const records = {
    containers: [{ id: 'a'.repeat(64), name: '/foreign', image: 'sha256:' + 'b'.repeat(64), project: 'other', status: 'running', health: 'healthy', restartCount: 0 }],
    images: [{ id: 'sha256:' + 'c'.repeat(64), repository: 'foreign', tag: 'one', digest: 'sha256:' + 'd'.repeat(64) }],
    networks: [{ id: 'e'.repeat(64), name: 'foreign', driver: 'bridge', scope: 'local', project: 'other' }],
    volumes: [{ name: 'foreign', driver: 'local', project: 'other' }]
  };
  const before = stableForeignInventory(records);
  const afterRestart = stableForeignInventory({ ...records, containers: [{ ...records.containers[0], status: 'restarting', health: 'starting', restartCount: 9 }] });
  assert.equal(validateForeignInventoryInvariant(before, afterRestart), true);
  assert.equal(validateForeignInventoryInvariant(before, before), true);
  assert.throws(() => validateForeignInventoryInvariant(before, stableForeignInventory({ ...records, containers: [] })));
  assert.throws(() => validateForeignInventoryInvariant(before, stableForeignInventory({ ...records, containers: [{ ...records.containers[0], id: 'f'.repeat(64) }] })));
});

test('exact cleanup captures evidence and revalidates every resource immediately before exact removal', async () => {
  const label = { 'com.xpoint.p15c.ownership-nonce': nonce };
  const resources = [
    { kind: 'container', id: '1'.repeat(64), name: `${project}-storage-1`, project, nonce, role: 'storage', labels: label },
    { kind: 'network', id: '2'.repeat(64), name: `${project}_runtime`, project, nonce, role: 'runtime', labels: label },
    { kind: 'image', id: `sha256:${'3'.repeat(64)}`, name: `${project}-calls`, project, nonce, role: 'calls', labels: label }
  ];
  const live = new Map(resources.map(resource => [`${resource.kind}:${resource.id}`, structuredClone(resource)]));
  const calls = [];
  await executeExactResourceCleanup({
    project,
    nonce,
    captured: resources,
    list: async () => [...live.values()],
    inspect: async resource => live.get(`${resource.kind}:${resource.id}`),
    remove: async (resource, command) => {
      calls.push(command);
      live.delete(`${resource.kind}:${resource.id}`);
    }
  });
  assert.deepEqual(calls, [
    ['container', 'rm', '--force', '1'.repeat(64)],
    ['network', 'rm', '2'.repeat(64)],
    ['image', 'rm', `sha256:${'3'.repeat(64)}`]
  ]);
});

test('post-capture same-project orphan injection is never removed', async () => {
  const label = { 'com.xpoint.p15c.ownership-nonce': nonce };
  const owned = { kind: 'container', id: '1'.repeat(64), name: `${project}-storage-1`, project, nonce, role: 'storage', labels: label };
  const injected = { kind: 'container', id: '9'.repeat(64), name: `${project}-injected`, project, nonce, role: 'injected', labels: label };
  const calls = [];
  await assert.rejects(() => executeExactResourceCleanup({
    project,
    nonce,
    captured: [owned],
    list: async () => [owned, injected],
    inspect: async () => owned,
    remove: async (_resource, command) => calls.push(command)
  }));
  assert.deepEqual(calls, []);
});

test('stranded labelled preflight container is removable but zero-owned evidence fails closed', async () => {
  const label = { 'com.xpoint.p15c.ownership-nonce': nonce };
  const preflight = { kind: 'container', id: '4'.repeat(64), name: `${project}-preflight`, project, nonce, role: 'p15c-preflight-node', labels: label };
  const live = new Map([[`container:${preflight.id}`, preflight]]);
  const calls = [];
  await executeExactResourceCleanup({ project, nonce, captured: [preflight], list: async () => [...live.values()], inspect: async () => preflight, remove: async (resource, command) => { calls.push(command); live.delete(`${resource.kind}:${resource.id}`); } });
  assert.deepEqual(calls, [['container', 'rm', '--force', preflight.id]]);
  await assert.rejects(() => executeExactResourceCleanup({ project, nonce, captured: [], list: async () => [], inspect: async () => null, remove: async () => assert.fail('must not remove') }));
});

test('retained receipt bytes are read once and validated summary is the only authority', async () => {
  let reads = 0;
  let bytes = Buffer.from('{"project":"first"}');
  const summary = await loadValidatedReceiptOnce({
    read: async () => { reads += 1; const result = bytes; bytes = Buffer.from('{"project":"substituted"}'); return result; },
    validate: raw => ({ project: JSON.parse(raw).project, receiptSha256: 'a'.repeat(64) })
  });
  assert.equal(reads, 1);
  assert.deepEqual(summary, { project: 'first', receiptSha256: 'a'.repeat(64) });
  assert.throws(() => { summary.project = 'mutated'; });
});

test('output publication stages in owned tree and revalidates parents immediately before atomic no-overwrite move', async () => {
  const calls = [];
  await publishOwnedOutput({
    staged: 'C:\\owned\\run\\evidence.stage',
    destination: 'C:\\evidence\\result.json',
    ownedRoot: 'C:\\owned\\run',
    destinationExists: async () => false,
    validateParents: async () => { calls.push('parents'); return true; },
    moveNoReplace: async () => calls.push('move')
  });
  assert.deepEqual(calls, ['parents', 'parents', 'move']);

  calls.length = 0;
  await assert.rejects(() => publishOwnedOutput({
    staged: 'C:\\owned\\run\\evidence.stage',
    destination: 'C:\\evidence\\result.json',
    ownedRoot: 'C:\\owned\\run',
    destinationExists: async () => false,
    validateParents: async () => { calls.push('parents'); return calls.length === 1; },
    moveNoReplace: async () => calls.push('move')
  }));
  assert.deepEqual(calls, ['parents', 'parents']);
});

test('receipt resources revalidate nonce, sources and exact image labels', () => {
  const expected = { project, nonce, sources: { devops: { sha, tree } } };
  const valid = [{ kind: 'image', project, nonce, role: 'xnode', id: digest, os: 'linux', architecture: 'arm64', labels: { 'org.opencontainers.image.revision': sha, 'org.opencontainers.image.source-tree': tree, 'com.xpoint.p15c.role': 'xnode', 'com.xpoint.p15c.ownership-nonce': nonce, 'com.xpoint.evidence-class': 'headless-harness', 'com.xpoint.product-runtime': 'false', 'org.opencontainers.image.source': 'xnode' } }];
  assert.equal(validateReceiptResources(valid, expected), true);
  assert.throws(() => validateReceiptResources(valid.map(value => ({ ...value, nonce: 'e'.repeat(32) })), expected));
  assert.throws(() => validateReceiptResources(valid.map(value => ({ ...value, labels: { ...value.labels, 'org.opencontainers.image.source-tree': 'e'.repeat(40) } })), expected));
});

test('receipt resources validate only immutable-ID cleanup kinds', () => {
  const labels = { 'com.xpoint.p15c.ownership-nonce': nonce };
  const expected = { project, nonce, sources: { devops: { sha, tree } } };
  const nonImages = ['container', 'network'].map(kind => ({ kind, project, nonce, labels }));
  assert.equal(validateReceiptResources(nonImages, expected), true);
  for (const kind of ['container', 'network']) {
    assert.throws(() => validateReceiptResources([{ kind, project: 'foreign', nonce, labels }], expected));
    assert.throws(() => validateReceiptResources([{ kind, project, nonce: 'e'.repeat(32), labels }], expected));
  }
  assert.throws(() => validateReceiptResources([{ kind: 'volume', project, nonce, labels }], expected));
});

test('project runtime inventory rejects injected same-project resources before compose down', () => {
  const services = ['contracts-devnet', 'xnode-1'];
  const volumes = [];
  const label = { 'com.xpoint.p15c.ownership-nonce': nonce };
  const valid = {
    containers: services.map(service => ({ project, nonce, service, labels: label })),
    networks: [{ project, nonce, network: 'runtime', labels: label }],
    volumes: []
  };
  assert.equal(validateOwnedProjectRuntimeInventory(valid, { project, nonce, services, networks: ['runtime'], volumes, allowPartial: false }), true);
  assert.throws(() => validateOwnedProjectRuntimeInventory({ ...valid, containers: [...valid.containers, { project, nonce, service: 'injected-orphan', labels: label }] }, { project, nonce, services, networks: ['runtime'], volumes, allowPartial: false }));
  assert.throws(() => validateOwnedProjectRuntimeInventory({ ...valid, volumes: [{ project, nonce, volume: 'substituted', labels: label }] }, { project, nonce, services, networks: ['runtime'], volumes, allowPartial: false }));
  assert.equal(validateOwnedProjectRuntimeInventory({ containers: valid.containers.slice(0, 1), networks: [], volumes: [] }, { project, nonce, services, networks: ['runtime'], volumes, allowPartial: true }), true);
});

test('failure cleanup deletes only exclusively created and still-bound output files', () => {
  const record = { created: true, path: 'C:\\evidence\\owned.json', expectedSha256: '1'.repeat(64) };
  assert.equal(canDeleteOwnedOutput(record, { path: record.path, kind: 'file', sha256: record.expectedSha256 }), true);
  for (const candidate of [
    { ...record, created: false },
    { ...record, path: 'C:\\evidence\\raced.json' },
    { ...record, expectedSha256: '2'.repeat(64) }
  ]) assert.equal(canDeleteOwnedOutput(candidate, { path: record.path, kind: 'file', sha256: record.expectedSha256 }), false);
  assert.equal(canDeleteOwnedOutput(record, { path: record.path, kind: 'directory', sha256: record.expectedSha256 }), false);
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

test('cleanup plan runs every step, aggregates failures and preserves ownership state', async () => {
  const calls = [];
  await assert.rejects(
    () => executeCleanupPlan({
      resources: [async () => { calls.push('down'); throw new Error('down failed'); }, async () => { calls.push('images'); throw new Error('images failed'); }],
      state: [async () => { calls.push('secrets'); }, async () => { calls.push('run-state'); }]
    }),
    error => error instanceof AggregateError && error.errors.length === 2 && error.preserveOwnershipState === true
  );
  assert.deepEqual(calls, ['down', 'images']);

  calls.length = 0;
  await assert.rejects(
    () => executeCleanupPlan({
      resources: [async () => calls.push('resources-clean')],
      state: [async () => { calls.push('secret-state'); throw new Error('secret cleanup failed'); }, async () => calls.push('run-and-receipt-erased')]
    }),
    error => error instanceof AggregateError && error.errors.length === 1 && error.preserveOwnershipState === true
  );
  assert.deepEqual(calls, ['resources-clean', 'secret-state']);
});

test('retained state validates exact markers, children, manifest, sources and receipt before Docker', () => {
  const base = 'C:\\Users\\test\\AppData\\Local\\Deep\\P15C';
  const runPath = `${base}\\${project}-${nonce}`;
  const receipt = { schema: 'deep-p15c-ownership.v1', project, nonce, composeSha256: '9'.repeat(64), sources: { devops: { sha, tree } }, images: [{ role: 'storage', source: 'devops', sha, tree, id: digest }] };
  const valid = { base, runPath, runMarker: 'deep-p15c-run.v1', secretMarker: 'deep-p15c-ephemeral-secrets.v1', secretChildren: ['.p15c-secret-owner', 'node-1.seed', 'node-2.seed', 'node-3.seed', 'node-1.config.json', 'node-2.config.json', 'node-3.config.json'], receipt, expectedSources: receipt.sources, expectedRoles: ['storage'], manifestValid: true, sourcePreflightPassed: true };
  assert.equal(validateRetainedOwnershipState(valid), true);
  for (const patch of [{ runMarker: 'bad' }, { secretMarker: 'bad' }, { secretChildren: [...valid.secretChildren, 'extra'] }, { runPath: 'C:\\repo\\owned' }, { manifestValid: false }, { sourcePreflightPassed: false }, { receipt: { ...receipt, images: [...receipt.images, receipt.images[0]] } }]) {
    assert.throws(() => validateRetainedOwnershipState({ ...valid, ...patch }));
  }
});

test('evidence and receipt paths are canonical outside repos and owned run tree', () => {
  const repos = ['C:\\Work\\repo'];
  const runTree = 'C:\\Users\\test\\AppData\\Local\\Deep\\P15C\\run';
  assert.equal(validateOwnedOutputPaths({ evidence: 'C:\\evidence\\result.json', receipt: 'C:\\evidence\\receipt.json', repos, runTree }), true);
  for (const patch of [{ evidence: 'C:\\Work\\repo\\e.json' }, { receipt: `${runTree}\\receipt.json` }, { evidence: 'C:\\evidence\\..\\Work\\repo\\e.json' }]) assert.throws(() => validateOwnedOutputPaths({ evidence: 'C:\\evidence\\result.json', receipt: 'C:\\evidence\\receipt.json', repos, runTree, ...patch }));
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

test('owned test-client runs semantic calls signaling queue, drain, rejection and pending behavior', async () => {
  const pending = [];
  const server = createServer(async (request, response) => {
    const url = new URL(request.url, 'http://127.0.0.1');
    const json = (status, value) => { response.writeHead(status, { 'content-type': 'application/json' }); response.end(JSON.stringify(value)); };
    if (request.method === 'POST' && url.pathname === '/api/calls/signal') {
      const chunks = [];
      for await (const chunk of request) chunks.push(chunk);
      const body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      if (!body.callId || !body.conversationId || !/^05[0-9a-f]{64}$/.test(body.sender?.value) || !/^05[0-9a-f]{64}$/.test(body.recipient?.value)) return json(400, { error: 'invalid-request' });
      pending.push(body);
      return json(202, { accepted: true, callId: body.callId });
    }
    if (request.method === 'GET' && url.pathname.startsWith('/api/calls/inbox/')) {
      const recipient = decodeURIComponent(url.pathname.slice('/api/calls/inbox/'.length));
      if (!/^05[0-9a-f]{64}$/.test(recipient)) return json(400, { error: 'invalid-request' });
      const selected = pending.filter(value => value.recipient.value === recipient);
      pending.splice(0, pending.length, ...pending.filter(value => value.recipient.value !== recipient));
      return json(200, selected);
    }
    if (request.method === 'GET' && url.pathname === '/stats') return json(200, { inventory: { callSignals: pending.length } });
    return json(404, { error: 'not-found' });
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const address = server.address();
    const result = await runCallsSignalingE2E(`http://127.0.0.1:${address.port}`);
    assert.deepEqual(result, { malformedRejected: true, firstDrained: true, unrelatedPending: true, finalPending: 0 });
  } finally {
    await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  }
});

test('release contract and documentation keep GO outcomes conditional until real lifecycle', () => {
  const contract = JSON.parse(readFileSync(new URL('../release/contracts/p15c-headless-v1.json', import.meta.url), 'utf8'));
  assert.equal(Object.hasOwn(contract, 'acceptance'), false);
  assert.deepEqual(contract.currentStatus, ['IMPLEMENTED', 'REAL-LIFECYCLE-PENDING', 'NO-GO']);
  assert.ok(Array.isArray(contract.acceptanceTarget) && contract.acceptanceTarget.includes('P15C1-HEADLESS-HARNESS-GO'));
  const docs = readFileSync(new URL('../docs/P15C_HEADLESS_HARNESS.md', import.meta.url), 'utf8');
  assert.doesNotMatch(docs, /Passing P15C means only:/);
  assert.match(docs, /acceptance target/i);
  assert.match(docs, /real lifecycle pending/i);
  const compose = readFileSync(new URL('../docker-compose.p15c-headless.yml', import.meta.url), 'utf8');
  assert.match(compose, /COPY --chown=node:node scripts\/p15c-headless-contracts\.mjs \/p15c\//);
  assert.match(compose, /command:\s*\[node, \/p15c\/p15c-headless-contracts\.mjs, test-client, http:\/\/calls:8080\]/);
});
