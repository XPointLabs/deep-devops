import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';

const expectedSourceSha = '1c01e24e24647a46b4f37622f3934dc2cc1284ef';
const expectedSourceTree = 'f608ecf9a53d1ce2c99d9c71bdebe4e95b2ebea2';
const expectedBaseDigest = 'sha256:242549cd46785b480c832479a730f4f2a20865d61ea2e404fdb2a5c3d3b73ecf';
const expectedBaseImageId = expectedBaseDigest;

async function contracts() {
  return import('./p15-compat-contracts.mjs');
}

test('wrong or dirty source identity fails before Docker', async () => {
  const { validateSourceIdentity } = await contracts();
  assert.throws(() => validateSourceIdentity({
    actualSha: '0'.repeat(40),
    actualTree: expectedSourceTree,
    expectedSha: expectedSourceSha,
    expectedTree: expectedSourceTree,
    dirty: false
  }), /source SHA/i);
  assert.throws(() => validateSourceIdentity({
    actualSha: expectedSourceSha,
    actualTree: '0'.repeat(40),
    expectedSha: expectedSourceSha,
    expectedTree: expectedSourceTree,
    dirty: false
  }), /source tree/i);
  assert.throws(() => validateSourceIdentity({
    actualSha: expectedSourceSha,
    actualTree: expectedSourceTree,
    expectedSha: expectedSourceSha,
    expectedTree: expectedSourceTree,
    dirty: true
  }), /dirty/i);
});

test('floating, missing, wrong-architecture and emulated base images fail', async () => {
  const { validateImageLock } = await contracts();
  const valid = {
    reference: `node@${expectedBaseDigest}`,
    expectedDigest: expectedBaseDigest,
    expectedImageId: expectedBaseImageId,
    observedImageId: expectedBaseImageId,
    repoDigests: [`node@${expectedBaseDigest}`],
    architecture: 'arm64',
    os: 'linux',
    engineArchitecture: 'aarch64'
  };
  assert.doesNotThrow(() => validateImageLock(valid));
  assert.throws(() => validateImageLock({ ...valid, reference: 'node:24-bookworm-slim' }), /digest/i);
  assert.throws(() => validateImageLock({ ...valid, observedImageId: '' }), /missing/i);
  assert.throws(() => validateImageLock({ ...valid, architecture: 'amd64' }), /architecture/i);
  assert.throws(() => validateImageLock({ ...valid, engineArchitecture: 'x86_64' }), /emulation/i);
});

test('project namespace and compose topology reject fixed names and host ports', async () => {
  const { validateProjectName, validateComposeConfig } = await contracts();
  for (const value of ['', 'p15a', 'deep-uat', 'p15a-fixed', 'P15A-1234567890abcdef']) {
    assert.throws(() => validateProjectName(value), /project/i);
  }
  assert.doesNotThrow(() => validateProjectName('p15a-a1b2c3d4e5f60708'));
  assert.throws(() => validateComposeConfig({
    name: 'p15a-a1b2c3d4e5f60708',
    services: {
      storage: { ports: ['8080:8080'] }
    }
  }), /host port/i);
});

test('compose contract requires four compat services, one internal probe and exact profiles', async () => {
  const { validateComposeConfig } = await contracts();
  const valid = composeFixture();
  assert.doesNotThrow(() => validateComposeConfig(valid));
  assert.throws(() => validateComposeConfig({
    ...valid,
    services: { ...valid.services, xnode: serviceFixture('xnode', 'p15-compat-core') }
  }), /service set/i);
  assert.throws(() => validateComposeConfig({
    ...valid,
    services: {
      ...valid.services,
      probe: { ...valid.services.probe, profiles: ['p15-product'] }
    }
  }), /profile/i);
});

test('OCI source, evidence class and product-runtime labels are mandatory', async () => {
  const { validateImageMetadata } = await contracts();
  const valid = imageFixture();
  assert.doesNotThrow(() => validateImageMetadata(valid));
  for (const label of [
    'org.opencontainers.image.revision',
    'org.opencontainers.image.source',
    'com.xpoint.evidence-class',
    'com.xpoint.product-runtime'
  ]) {
    const labels = { ...valid.labels };
    delete labels[label];
    assert.throws(() => validateImageMetadata({ ...valid, labels }), /label/i);
  }
  assert.throws(() => validateImageMetadata({
    ...valid,
    labels: { ...valid.labels, 'com.xpoint.product-runtime': 'true' }
  }), /product runtime/i);
});

test('health and service identity mismatch or timeout are hard failures', async () => {
  const { validateHealthObservation } = await contracts();
  assert.doesNotThrow(() => validateHealthObservation({
    expectedService: 'p15-storage-compat',
    containerHealth: 'healthy',
    response: { ok: true, service: 'p15-storage-compat' },
    elapsedMs: 200,
    timeoutMs: 5_000
  }));
  assert.throws(() => validateHealthObservation({
    expectedService: 'p15-storage-compat',
    containerHealth: 'starting',
    response: { ok: true, service: 'p15-storage-compat' },
    elapsedMs: 5_001,
    timeoutMs: 5_000
  }), /timeout|health/i);
  assert.throws(() => validateHealthObservation({
    expectedService: 'p15-storage-compat',
    containerHealth: 'healthy',
    response: { ok: true, service: 'wrong' },
    elapsedMs: 200,
    timeoutMs: 5_000
  }), /identity/i);
});

test('probe proves its intended container and target service identities', async () => {
  const { validateProbeIdentity } = await contracts();
  assert.doesNotThrow(() => validateProbeIdentity({
    probeRole: 'p15-internal-black-box-probe',
    expectedTarget: 'p15-file-compat',
    observedTarget: 'p15-file-compat',
    networkClass: 'internal-only'
  }));
  assert.throws(() => validateProbeIdentity({
    probeRole: 'unknown',
    expectedTarget: 'p15-file-compat',
    observedTarget: 'p15-file-compat',
    networkClass: 'internal-only'
  }), /probe identity/i);
  assert.throws(() => validateProbeIdentity({
    probeRole: 'p15-internal-black-box-probe',
    expectedTarget: 'p15-file-compat',
    observedTarget: 'p15-storage-compat',
    networkClass: 'internal-only'
  }), /target identity/i);
});

test('restart persistence is required independently for all four services', async () => {
  const { validateRestartPersistence } = await contracts();
  const valid = Object.fromEntries(
    ['storage', 'file', 'push', 'calls'].map(service => [
      service,
      { before: 1, after: 1, operationPassed: true }
    ])
  );
  assert.doesNotThrow(() => validateRestartPersistence(valid));
  assert.throws(() => validateRestartPersistence({
    ...valid,
    push: { before: 1, after: 0, operationPassed: true }
  }), /push.*persistence/i);
});

test('network disconnect must fail boundedly and reconnect must restore service', async () => {
  const { validateNetworkFault } = await contracts();
  assert.doesNotThrow(() => validateNetworkFault({
    disconnectedFailureObserved: true,
    failureBoundMs: 2_000,
    observedFailureMs: 100,
    reconnectedHealthy: true,
    operationRestored: true
  }));
  assert.throws(() => validateNetworkFault({
    disconnectedFailureObserved: false,
    failureBoundMs: 2_000,
    observedFailureMs: 100,
    reconnectedHealthy: true,
    operationRestored: true
  }), /disconnect/i);
  assert.throws(() => validateNetworkFault({
    disconnectedFailureObserved: true,
    failureBoundMs: 2_000,
    observedFailureMs: 100,
    reconnectedHealthy: false,
    operationRestored: false
  }), /reconnect/i);
});

test('cleanup and second-run inventory must be exactly empty', async () => {
  const { validateCleanupInventory, validateEmptyInventory } = await contracts();
  assert.doesNotThrow(() => validateCleanupInventory({ containers: 0, networks: 0, volumes: 0, images: 0 }));
  assert.throws(() => validateCleanupInventory({ containers: 0, networks: 1, volumes: 0, images: 0 }), /residual/i);
  assert.doesNotThrow(() => validateEmptyInventory({
    storageMessages: 0,
    files: 0,
    subscriptions: 0,
    callSignals: 0
  }));
  assert.throws(() => validateEmptyInventory({
    storageMessages: 1,
    files: 0,
    subscriptions: 0,
    callSignals: 0
  }), /empty inventory/i);
});

test('cleanup refuses foreign labels and source prohibits global prune', async () => {
  const { assertOwnedResources, assertNoGlobalPrune } = await contracts();
  assert.doesNotThrow(() => assertOwnedResources(
    'p15a-a1b2c3d4e5f60708',
    [{ project: 'p15a-a1b2c3d4e5f60708', resourceType: 'volume' }]
  ));
  assert.throws(() => assertOwnedResources(
    'p15a-a1b2c3d4e5f60708',
    [{ project: 'deep-uat', resourceType: 'volume' }]
  ), /foreign/i);
  assert.throws(() => assertNoGlobalPrune('docker system prune --all'), /global prune/i);
});

test('driver uses finally-scoped cleanup and injected post-up failure', async () => {
  const source = await readFile(new URL('./p15-compat-lab.ps1', import.meta.url), 'utf8');
  assert.match(source, /finally\s*\{/i);
  assert.match(source, /down.+--volumes.+--remove-orphans/is);
  assert.match(source, /InjectFailureAfterUp/i);
  assert.match(source, /network.+connect.+--alias.+file/is);
  assert.doesNotMatch(source, /\$input\s*=/i);
  assert.match(source, /\$contextSha256\s*=/i);
  assert.doesNotMatch(source, /--eval/i);
  assert.doesNotMatch(source, /docker\s+(?:system|container|network|volume|image)\s+prune/i);
});

test('missing scenarios and evidence are strict failures', async () => {
  const { validateScenarioResults, validateEvidenceCompleteness } = await contracts();
  const scenarios = Object.fromEntries(requiredScenarios().map(value => [value, 'pass']));
  assert.doesNotThrow(() => validateScenarioResults(scenarios));
  const missing = { ...scenarios };
  delete missing.cleanup;
  assert.throws(() => validateScenarioResults(missing), /missing scenario/i);
  assert.throws(() => validateEvidenceCompleteness({ schema: 'wrong' }), /evidence/i);
});

test('fixed clock and scenario input produce byte-identical canonical JSON', async () => {
  const { buildEvidence, canonicalJson } = await contracts();
  const input = evidenceFixture();
  assert.equal(canonicalJson(buildEvidence(input)), canonicalJson(buildEvidence(structuredClone(input))));
});

test('compose renders without host ports and with the exact internal network', async () => {
  const composePath = new URL('../docker-compose.p15-compat.yml', import.meta.url);
  await readFile(composePath);
  const stdout = execFileSync(
    'docker',
    ['compose', '-f', composePath.pathname.slice(1), '--profile', 'p15-compat-probe', 'config', '--format', 'json'],
    {
      encoding: 'utf8',
      env: {
        ...process.env,
        P15_PROJECT_NAME: 'p15a-a1b2c3d4e5f60708',
        P15_SOURCE_SHA: expectedSourceSha,
        P15_SOURCE_TREE: expectedSourceTree,
        P15_BASE_IMAGE: `node@${expectedBaseDigest}`,
        P15_IMAGE_NAME: 'local/p15-compat:test',
        P15_CONTEXT_SHA256: `sha256:${'6'.repeat(64)}`
      }
    }
  );
  const { validateComposeConfig } = await contracts();
  validateComposeConfig(JSON.parse(stdout));
});

test('run image reference is unique and a preexisting or foreign tag fails closed', async () => {
  const { createRunImageReference, validateImageReferencePreflight } = await contracts();
  const first = createRunImageReference('p15a-a1b2c3d4e5f60708');
  const second = createRunImageReference('p15a-a1b2c3d4e5f60709');
  assert.notEqual(first, second);
  assert.match(first, /^local\/p15-compat:p15a-[0-9a-f]{16}$/);
  assert.doesNotThrow(() => validateImageReferencePreflight({ reference: first, existing: null }));
  assert.throws(() => validateImageReferencePreflight({
    reference: first,
    existing: { imageId: `sha256:${'1'.repeat(64)}`, project: 'deep-uat' }
  }), /preexisting|foreign|image reference/i);
});

test('built image ownership and each started container image ID are exact', async () => {
  const { validateRunImageOwnership, validateContainerImageIdentity } = await contracts();
  const imageId = `sha256:${'2'.repeat(64)}`;
  const project = 'p15a-a1b2c3d4e5f60708';
  assert.doesNotThrow(() => validateRunImageOwnership({
    imageId,
    referenceImageId: imageId,
    project,
    labels: { 'com.docker.compose.project': project }
  }));
  assert.throws(() => validateRunImageOwnership({
    imageId,
    referenceImageId: `sha256:${'3'.repeat(64)}`,
    project,
    labels: { 'com.docker.compose.project': 'deep-uat' }
  }), /ownership|reference/i);
  assert.doesNotThrow(() => validateContainerImageIdentity({
    expectedImageId: imageId,
    observedImageId: imageId
  }));
  assert.throws(() => validateContainerImageIdentity({
    expectedImageId: imageId,
    observedImageId: `sha256:${'4'.repeat(64)}`
  }), /container image/i);
});

test('cleanup inventory includes images and injected failures after build/up are covered', async () => {
  const { validateCleanupInventory } = await contracts();
  assert.doesNotThrow(() => validateCleanupInventory({
    containers: 0, networks: 0, volumes: 0, images: 0
  }));
  assert.throws(() => validateCleanupInventory({
    containers: 0, networks: 0, volumes: 0, images: 1
  }), /image|residual/i);
  const source = await readFile(new URL('./p15-compat-lab.ps1', import.meta.url), 'utf8');
  assert.match(source, /InjectFailureAfterBuild/i);
  assert.match(source, /Remove-OwnedRunImage/i);
  assert.match(source, /Assert-ZeroResidualResources/is);
  assert.match(source, /\.Image.+RunImageId|RunImageId.+\.Image/is);
});

test('deny-by-default context manifest ignores untracked and ignored fixture bytes', async () => {
  const { computeContextManifestHash } = await contracts();
  const root = await mkdtemp(path.join(tmpdir(), 'p15-context-'));
  try {
    await mkdir(path.join(root, 'tools'), { recursive: true });
    await writeFile(path.join(root, 'tools', 'allowed.mjs'), 'allowed\n');
    const files = ['tools/allowed.mjs'];
    const first = await computeContextManifestHash(root, files);
    await writeFile(path.join(root, 'ignored-secret.fixture'), 'must-not-enter-context\n');
    const second = await computeContextManifestHash(root, files);
    assert.equal(first, second);
    assert.notEqual(first, await computeContextManifestHash(root, [
      ...files,
      'ignored-secret.fixture'
    ]));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('.dockerignore is deny-by-default and allows only the tracked context manifest', async () => {
  const source = await readFile(new URL('../.dockerignore', import.meta.url), 'utf8');
  assert.match(source, /^\*\*\s*$/m);
  assert.doesNotMatch(source, /^!\*\*/m);
  assert.doesNotMatch(source, /test|fixture|artifact|\.git/i);
  const contract = JSON.parse(await readFile(
    new URL('../release/contracts/p15-compat-lab-v1.json', import.meta.url),
    'utf8'
  ));
  assert.ok(Array.isArray(contract.buildContext?.files));
  assert.ok(contract.buildContext.files.length > 0);
  assert.equal(new Set(contract.buildContext.files).size, contract.buildContext.files.length);
});

function serviceFixture(identity, profile) {
  return {
    profiles: [profile, 'p15-compat-faults'],
    labels: {
      'com.xpoint.p15.service-identity': identity,
      'com.xpoint.evidence-class': 'compatibility-lab',
      'com.xpoint.product-runtime': 'false'
    },
    healthcheck: { test: ['CMD', 'node', '--eval', 'health'] },
    networks: ['lab'],
    volumes: [`${identity}-state:/state`]
  };
}

function composeFixture() {
  return {
    name: 'p15a-a1b2c3d4e5f60708',
    services: {
      storage: serviceFixture('p15-storage-compat', 'p15-compat-core'),
      file: serviceFixture('p15-file-compat', 'p15-compat-core'),
      push: serviceFixture('p15-push-compat', 'p15-compat-core'),
      calls: serviceFixture('p15-calls-compat', 'p15-compat-core'),
      probe: serviceFixture('p15-internal-black-box-probe', 'p15-compat-probe')
    },
    networks: { lab: { internal: true } },
    volumes: {
      'storage-state': {},
      'file-state': {},
      'push-state': {},
      'calls-state': {}
    }
  };
}

function imageFixture() {
  return {
    imageId: expectedBaseImageId,
    architecture: 'arm64',
    os: 'linux',
    labels: {
      'org.opencontainers.image.revision': expectedSourceSha,
      'org.opencontainers.image.source': 'deep-devops',
      'com.xpoint.evidence-class': 'compatibility-lab',
      'com.xpoint.product-runtime': 'false'
    }
  };
}

function requiredScenarios() {
  return [
    'source-lock',
    'image-lock',
    'empty-start',
    'health-identity',
    'operations',
    'restart-persistence',
    'network-fault-recovery',
    'privacy-scan',
    'cleanup'
  ];
}

function evidenceFixture() {
  return {
    clock: '2026-07-20T00:00:00.000Z',
    sourceSha: expectedSourceSha,
    sourceTree: expectedSourceTree,
    baseImageDigest: expectedBaseDigest,
    baseImageId: expectedBaseImageId,
    contextSha256: `sha256:${'6'.repeat(64)}`,
    architecture: 'arm64',
    scenarios: Object.fromEntries(requiredScenarios().map(value => [value, 'pass'])),
    counts: {
      services: 4,
      probes: 4,
      restarts: 4,
      networkFaults: 1,
      residualResources: 0,
      residualImages: 0
    },
    durationBoundsMs: {
      health: 30_000,
      operation: 5_000,
      networkFailure: 5_000
    }
  };
}
