import { pathToFileURL } from 'node:url';
import { readFile, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import path from 'node:path';
import {
  createTestStorageSigningIdentity,
  pushSignatureVersion
} from '../tools/compat-services/storage-signatures.mjs';
import { canonicalJson, sanitizeEvidence } from './p15-evidence-sanitizer.mjs';

export { canonicalJson };

export const P15_SOURCE_BASE_SHA = '1c01e24e24647a46b4f37622f3934dc2cc1284ef';
export const P15_SOURCE_BASE_TREE = 'f608ecf9a53d1ce2c99d9c71bdebe4e95b2ebea2';
export const P15_E2E_SHA = 'da24f530f187dbd81258905bc28feedce0eb23eb';
export const P15_E2E_TREE = '566ee86cd01ec5a32d3ad60d1c9eac9183328c1f';
export const P15_BASE_IMAGE_DIGEST = 'sha256:242549cd46785b480c832479a730f4f2a20865d61ea2e404fdb2a5c3d3b73ecf';
export const P15_BASE_IMAGE_ID = P15_BASE_IMAGE_DIGEST;

export function createRunImageReference(project) {
  validateProjectName(project);
  return `local/p15-compat:${project}`;
}

export function validateImageReferencePreflight({ reference, existing }) {
  if (!/^local\/p15-compat:p15a-[0-9a-f]{16}$/.test(String(reference))) {
    fail('run image reference is invalid');
  }
  if (existing !== null && existing !== undefined) {
    fail('preexisting or foreign run image reference is prohibited');
  }
  return true;
}

export function validateRunImageOwnership({
  imageId, referenceImageId, project, labels
}) {
  if (!/^sha256:[0-9a-f]{64}$/.test(String(imageId)) ||
      referenceImageId !== imageId) {
    fail('run image reference does not resolve to the built image');
  }
  if (labels?.['com.docker.compose.project'] !== project) {
    fail('run image ownership label does not match');
  }
  return true;
}

export function validateContainerImageIdentity({ expectedImageId, observedImageId }) {
  if (expectedImageId !== observedImageId) {
    fail('container image does not match the exact built image ID');
  }
  return true;
}

export async function computeContextManifestHash(root, files) {
  if (!Array.isArray(files) || files.length === 0 ||
      new Set(files).size !== files.length) {
    fail('build context manifest is invalid');
  }
  const hash = createHash('sha256');
  for (const relative of [...files].sort()) {
    if (typeof relative !== 'string' || path.isAbsolute(relative) ||
        relative.includes('..') || relative.includes('\\')) {
      fail('build context manifest path is invalid');
    }
    hash.update(relative);
    hash.update('\0');
    hash.update(await readFile(path.join(root, ...relative.split('/'))));
    hash.update('\0');
  }
  return `sha256:${hash.digest('hex')}`;
}

const serviceNames = Object.freeze(['storage', 'file', 'push', 'calls', 'probe']);
const requiredScenarios = Object.freeze([
  'source-lock',
  'image-lock',
  'empty-start',
  'health-identity',
  'operations',
  'restart-persistence',
  'network-fault-recovery',
  'privacy-scan',
  'cleanup'
]);
const serviceIdentities = Object.freeze({
  storage: 'p15-storage-compat',
  file: 'p15-file-compat',
  push: 'p15-push-compat',
  calls: 'p15-calls-compat',
  probe: 'p15-internal-black-box-probe'
});
const allowedProfiles = new Set([
  'p15-compat-core',
  'p15-compat-probe',
  'p15-compat-faults'
]);

export function validateSourceIdentity({
  actualSha,
  actualTree,
  expectedSha,
  expectedTree,
  dirty
}) {
  if (actualSha !== expectedSha) {
    fail('source SHA does not match the exact requested source');
  }
  if (actualTree !== expectedTree) {
    fail('source tree does not match the exact requested source');
  }
  if (dirty) {
    fail('source worktree is dirty');
  }
  return true;
}

export function validateImageLock({
  reference,
  expectedDigest,
  expectedImageId,
  observedImageId,
  repoDigests,
  architecture,
  os,
  engineArchitecture
}) {
  if (reference !== `node@${expectedDigest}` || !/^sha256:[0-9a-f]{64}$/.test(expectedDigest)) {
    fail('base image reference must use the exact digest');
  }
  if (!observedImageId) {
    fail('base image is missing');
  }
  if (observedImageId !== expectedImageId ||
      !Array.isArray(repoDigests) ||
      !repoDigests.includes(reference)) {
    fail('base image ID or digest does not match the local lock');
  }
  if (os !== 'linux' || architecture !== 'arm64') {
    fail('base image architecture must be Linux ARM64');
  }
  if (!['arm64', 'aarch64'].includes(engineArchitecture)) {
    fail('emulation is prohibited; Docker Engine must be ARM64');
  }
  return true;
}

export function validateProjectName(value) {
  if (typeof value !== 'string' || !/^p15a-[0-9a-f]{16}$/.test(value)) {
    fail('project name must be a bounded unique p15a namespace');
  }
  return true;
}

export function validateComposeConfig(model) {
  if (!model || typeof model !== 'object') {
    fail('Compose model is missing');
  }
  if (model.name !== undefined) {
    validateProjectName(model.name);
  }
  for (const [name, service] of Object.entries(model.services ?? {})) {
    if (Array.isArray(service.ports) && service.ports.length > 0) {
      fail(`host port publication is prohibited for ${name}`);
    }
  }
  const actualServices = Object.keys(model.services ?? {}).sort();
  if (!sameValues(actualServices, [...serviceNames].sort())) {
    fail('Compose service set must contain only four compatibility services and the probe');
  }
  const networks = Object.keys(model.networks ?? {});
  if (networks.length !== 1 || networks[0] !== 'lab' || model.networks.lab?.internal !== true) {
    fail('Compose must contain exactly one internal lab network');
  }
  const volumes = Object.keys(model.volumes ?? {}).sort();
  if (!sameValues(volumes, ['calls-state', 'file-state', 'push-state', 'storage-state'])) {
    fail('Compose must contain exactly four isolated service state volumes');
  }

  for (const name of serviceNames) {
    const service = model.services[name];
    if (service.network_mode || service.pid || service.ipc ||
        service.privileged === true || service.devices || service.extra_hosts) {
      fail(`unsafe host integration is prohibited for ${name}`);
    }
    const profiles = Array.isArray(service.profiles) ? service.profiles : [];
    if (profiles.length === 0 || profiles.some(profile => !allowedProfiles.has(profile))) {
      fail(`profile set is invalid for ${name}`);
    }
    const requiredProfile = name === 'probe' ? 'p15-compat-probe' : 'p15-compat-core';
    if (!profiles.includes(requiredProfile)) {
      fail(`required profile is missing for ${name}`);
    }
    if (!profiles.includes('p15-compat-faults')) {
      fail(`fault profile is missing for ${name}`);
    }
    if (!service.healthcheck || service.healthcheck.disable === true ||
        !Array.isArray(service.healthcheck.test) ||
        service.healthcheck.test.length < 2) {
      fail(`strict healthcheck is missing for ${name}`);
    }
    const attachedNetworks = Array.isArray(service.networks)
      ? service.networks
      : Object.keys(service.networks ?? {});
    if (!sameValues(attachedNetworks, ['lab'])) {
      fail(`service ${name} must use only the internal lab network`);
    }
    const labels = service.labels ?? {};
    if (labels['com.xpoint.p15.service-identity'] !== serviceIdentities[name] ||
        labels['com.xpoint.evidence-class'] !== 'compatibility-lab' ||
        String(labels['com.xpoint.product-runtime']) !== 'false') {
      fail(`service identity labels are invalid for ${name}`);
    }
  }
  return true;
}

export function validateImageMetadata({ imageId, architecture, os, labels }) {
  if (!/^sha256:[0-9a-f]{64}$/.test(String(imageId ?? ''))) {
    fail('built image ID is missing');
  }
  if (architecture !== 'arm64' || os !== 'linux') {
    fail('built image architecture is invalid');
  }
  const required = {
    'org.opencontainers.image.revision': undefined,
    'org.opencontainers.image.source': 'deep-devops',
    'com.xpoint.evidence-class': 'compatibility-lab',
    'com.xpoint.product-runtime': 'false'
  };
  for (const [name, expected] of Object.entries(required)) {
    if (!(name in (labels ?? {})) || labels[name] === '') {
      fail(`required OCI or evidence label ${name} is missing`);
    }
    if (expected !== undefined && String(labels[name]) !== expected) {
      if (name === 'com.xpoint.product-runtime') {
        fail('built image must not be a product runtime');
      }
      fail(`required image label ${name} is invalid`);
    }
  }
  return true;
}

export function validateHealthObservation({
  expectedService,
  containerHealth,
  response,
  elapsedMs,
  timeoutMs
}) {
  if (elapsedMs > timeoutMs) {
    fail('health timeout exceeded');
  }
  if (containerHealth !== 'healthy' || response?.ok !== true) {
    fail('service health is not healthy');
  }
  if (response.service !== expectedService) {
    fail('service identity response does not match');
  }
  return true;
}

export function validateProbeIdentity({
  probeRole,
  expectedTarget,
  observedTarget,
  networkClass
}) {
  if (probeRole !== serviceIdentities.probe || networkClass !== 'internal-only') {
    fail('probe identity is invalid');
  }
  if (expectedTarget !== observedTarget) {
    fail('target identity does not match');
  }
  return true;
}

export function validateRestartPersistence(observations) {
  for (const name of ['storage', 'file', 'push', 'calls']) {
    const value = observations?.[name];
    if (!value || value.before !== value.after || value.after < 1 || value.operationPassed !== true) {
      fail(`${name} persistence was not proved after restart`);
    }
  }
  return true;
}

export function validateNetworkFault({
  disconnectedFailureObserved,
  failureBoundMs,
  observedFailureMs,
  reconnectedHealthy,
  operationRestored
}) {
  if (disconnectedFailureObserved !== true ||
      !Number.isFinite(observedFailureMs) ||
      observedFailureMs > failureBoundMs) {
    fail('network disconnect did not produce the expected bounded failure');
  }
  if (reconnectedHealthy !== true || operationRestored !== true) {
    fail('network reconnect did not restore health and operation');
  }
  return true;
}

export function validateCleanupInventory(value) {
  if (!value || value.containers !== 0 || value.networks !== 0 ||
      value.volumes !== 0 || value.images !== 0) {
    fail('residual P15A resources remain after cleanup');
  }
  return true;
}

export function validateEmptyInventory(value) {
  const expected = {
    storageMessages: 0,
    files: 0,
    subscriptions: 0,
    callSignals: 0
  };
  if (!value || Object.entries(expected).some(([name, count]) => value[name] !== count)) {
    fail('empty inventory was not proved');
  }
  return true;
}

export function assertOwnedResources(project, resources) {
  validateProjectName(project);
  for (const resource of resources ?? []) {
    if (resource?.project !== project) {
      fail(`foreign ${resource?.resourceType ?? 'Docker'} resource must not be touched`);
    }
  }
  return true;
}

export function assertNoGlobalPrune(command) {
  if (/\bdocker\s+(?:system|container|network|volume|image)\s+prune\b/i.test(String(command))) {
    fail('global prune is prohibited');
  }
  return true;
}

export function validateScenarioResults(scenarios) {
  for (const scenario of requiredScenarios) {
    if (scenarios?.[scenario] !== 'pass') {
      fail(`missing scenario or non-pass result: ${scenario}`);
    }
  }
  if (Object.keys(scenarios ?? {}).length !== requiredScenarios.length) {
    fail('unexpected scenario is present');
  }
  return true;
}

export function buildEvidence({
  clock,
  sourceSha,
  sourceTree,
  baseImageDigest,
  baseImageId,
  contextSha256,
  architecture,
  scenarios,
  counts,
  durationBoundsMs
}) {
  validateScenarioResults(scenarios);
  return sanitizeEvidence({
    schema: 'deep-p15-compat-lab-evidence.v1',
    evidenceClass: 'compatibility-lab',
    productRuntime: false,
    clock,
    source: {
      sha: sourceSha,
      tree: sourceTree
    },
    image: {
      baseDigest: baseImageDigest,
      baseImageId,
      contextSha256,
      architecture
    },
    scenarios,
    counts,
    durationBoundsMs,
    result: 'pass'
  });
}

export function validateEvidenceCompleteness(value) {
  sanitizeEvidence(value);
  return true;
}

function fail(message) {
  throw new Error(`P15A contract failure: ${message}`);
}

function sameValues(left, right) {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

const probeTargets = Object.freeze({
  storage: { origin: 'http://storage:8080', identity: serviceIdentities.storage },
  file: { origin: 'http://file:8080', identity: serviceIdentities.file },
  push: { origin: 'http://push:8080', identity: serviceIdentities.push },
  calls: { origin: 'http://calls:8080', identity: serviceIdentities.calls }
});

async function fetchBounded(target, pathname, options = {}, timeoutMs = 3_000) {
  const response = await fetch(`${target.origin}${pathname}`, {
    ...options,
    signal: AbortSignal.timeout(timeoutMs)
  });
  const contentType = response.headers.get('content-type') ?? '';
  const body = contentType.includes('application/json')
    ? await response.json()
    : Buffer.from(await response.arrayBuffer());
  if (!response.ok) {
    throw new Error(`probe request failed with status class ${Math.floor(response.status / 100)}xx`);
  }
  return body;
}

async function fetchRejected(target, pathname, options = {}, expectedStatus = 400) {
  const response = await fetch(`${target.origin}${pathname}`, {
    ...options,
    signal: AbortSignal.timeout(3_000)
  });
  const body = await response.json();
  if (response.status !== expectedStatus || body?.error !== 'invalid-request') {
    fail('malformed calls party did not fail with the exact rejection contract');
  }
  return body;
}

async function observeHealth(name) {
  const target = probeTargets[name];
  if (!target) {
    fail('probe target is invalid');
  }
  const started = Date.now();
  const response = await fetchBounded(target, '/health/ready');
  validateProbeIdentity({
    probeRole: process.env.P15_PROBE_ROLE,
    expectedTarget: target.identity,
    observedTarget: response.service,
    networkClass: process.env.P15_NETWORK_CLASS
  });
  validateHealthObservation({
    expectedService: target.identity,
    containerHealth: 'healthy',
    response,
    elapsedMs: Date.now() - started,
    timeoutMs: 3_000
  });
}

async function stats(name) {
  const value = await fetchBounded(probeTargets[name], '/stats');
  if (value.service !== probeTargets[name].identity) {
    fail(`${name} stats identity does not match`);
  }
  return value;
}

async function assertInitialEmpty() {
  const [storage, file, push, calls] = await Promise.all(
    ['storage', 'file', 'push', 'calls'].map(stats)
  );
  validateEmptyInventory({
    storageMessages: storage.inventory.storageMessages,
    files: file.inventory.files,
    subscriptions: push.inventory.subscriptions,
    callSignals: calls.inventory.callSignals
  });
}

async function probeOperations() {
  const publicInbox = {
    pubkey: `03${'11'.repeat(32)}`,
    namespace: -10,
    timestamp: Date.now(),
    ttl: 600_000,
    data: Buffer.from('p15-storage-record-v1').toString('base64'),
    idempotency_key: 'p15-storage-idempotency-v1'
  };
  const storageFirst = await fetchBounded(probeTargets.storage, '/storage/store', jsonPost(publicInbox));
  const storageSecond = await fetchBounded(probeTargets.storage, '/storage/store', jsonPost(publicInbox));
  if (storageSecond.idempotent !== true || storageSecond.hash !== storageFirst.hash) {
    fail('storage idempotency probe failed');
  }
  const retrieved = await fetchBounded(
    probeTargets.storage,
    '/storage/retrieve',
    jsonPost({ pubkey: publicInbox.pubkey, namespace: publicInbox.namespace })
  );
  if (!Array.isArray(retrieved.messages) || retrieved.messages.length !== 1) {
    fail('storage retrieve probe failed');
  }

  const fileBody = Buffer.from('p15-file-record-v1');
  const fileFirst = await fetchBounded(probeTargets.file, '/file', {
    method: 'POST',
    headers: { 'content-type': 'application/octet-stream', 'x-file-ttl': '600' },
    body: fileBody
  });
  const fileSecond = await fetchBounded(probeTargets.file, '/file', {
    method: 'POST',
    headers: { 'content-type': 'application/octet-stream', 'x-file-ttl': '600' },
    body: fileBody
  });
  if (!fileFirst.id || fileFirst.id !== fileSecond.id) {
    fail('file idempotency probe failed');
  }
  const fileRead = await fetchBounded(probeTargets.file, `/file/${encodeURIComponent(fileFirst.id)}`);
  if (!Buffer.isBuffer(fileRead) || !fileRead.equals(fileBody)) {
    fail('file read probe failed');
  }

  const identity = createTestStorageSigningIdentity();
  const timestamp = Math.floor(Date.now() / 1000);
  const pushRequest = {
    pubkey: identity.sessionPubkey,
    session_ed25519: identity.pubkeyEd25519,
    namespaces: [-10],
    data: false,
    service: 'firebase',
    sig_ts: timestamp,
    signature: '',
    service_info: { token: 'p15-internal-device-v1' },
    enc_key: '22'.repeat(32),
    app_id: 'p15.compat.lab',
    app_version: '1',
    idempotency_key: 'p15-push-idempotency-v1',
    sig_v: pushSignatureVersion
  };
  pushRequest.signature = identity.signPushSubscribeV2({
    pubkey: pushRequest.pubkey,
    timestamp,
    wantData: pushRequest.data,
    namespaces: pushRequest.namespaces,
    service: pushRequest.service,
    deviceToken: pushRequest.service_info.token,
    encryptionKey: pushRequest.enc_key,
    appId: pushRequest.app_id,
    appVersion: pushRequest.app_version
  });
  const pushFirst = await fetchBounded(probeTargets.push, '/subscribe', jsonPost(pushRequest));
  const pushSecond = await fetchBounded(probeTargets.push, '/subscribe', jsonPost(pushRequest));
  if (pushFirst.success !== true || pushSecond.idempotent !== true) {
    fail('push idempotency probe failed');
  }

  const callRequest = {
    callId: 'p15-call-v1',
    conversationId: 'p15-conversation-v1',
    sender: { value: `05${'1'.repeat(64)}` },
    recipient: { value: `05${'2'.repeat(64)}` }
  };
  for (const malformed of [
    { ...callRequest, sender: { value: `04${'1'.repeat(64)}` } },
    { ...callRequest, recipient: { value: `05${'A'.repeat(64)}` } }
  ]) {
    await fetchRejected(
      probeTargets.calls,
      '/api/calls/signal',
      jsonPost(malformed)
    );
  }
  await fetchRejected(
    probeTargets.calls,
    `/api/calls/inbox/${encodeURIComponent(`05${'g'.repeat(64)}`)}`
  );
  const callsBeforeValid = await fetchBounded(probeTargets.calls, '/stats');
  if (callsBeforeValid.inventory?.callSignals !== 0) {
    fail('malformed calls parties mutated the pending queue');
  }
  const callResult = await fetchBounded(
    probeTargets.calls,
    '/api/calls/signal',
    jsonPost(callRequest)
  );
  if (callResult.accepted !== true) {
    fail('calls store probe failed');
  }

  const current = await observePersistence();
  validateRestartPersistence(current);
}

async function observePersistence() {
  const [storage, file, push, calls] = await Promise.all(
    ['storage', 'file', 'push', 'calls'].map(stats)
  );
  const counts = {
    storage: storage.inventory.storageMessages,
    file: file.inventory.files,
    push: push.inventory.subscriptions,
    calls: calls.inventory.callSignals
  };
  return Object.fromEntries(
    Object.entries(counts).map(([name, count]) => [
      name,
      { before: 1, after: count, operationPassed: count === 1 }
    ])
  );
}

async function verifyPersistenceOperations() {
  const observations = await observePersistence();
  validateRestartPersistence(observations);

  const publicInbox = {
    pubkey: `03${'11'.repeat(32)}`,
    namespace: -10
  };
  const retrieved = await fetchBounded(
    probeTargets.storage,
    '/storage/retrieve',
    jsonPost(publicInbox)
  );
  if (!Array.isArray(retrieved.messages) || retrieved.messages.length !== 1) {
    fail('storage persistence read failed');
  }

  const fileBody = Buffer.from('p15-file-record-v1');
  const fileResult = await fetchBounded(probeTargets.file, '/file', {
    method: 'POST',
    headers: { 'content-type': 'application/octet-stream', 'x-file-ttl': '600' },
    body: fileBody
  });
  const fileRead = await fetchBounded(probeTargets.file, `/file/${encodeURIComponent(fileResult.id)}`);
  if (!Buffer.isBuffer(fileRead) || !fileRead.equals(fileBody)) {
    fail('file persistence read failed');
  }

  const inbox = await fetchBounded(
    probeTargets.calls,
    `/api/calls/inbox/${encodeURIComponent(`05${'2'.repeat(64)}`)}`
  );
  if (!Array.isArray(inbox) || inbox.length !== 1) {
    fail('calls persistence read failed');
  }
}

function jsonPost(value) {
  return {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(value)
  };
}

async function runProbe(action, targetName) {
  if (process.env.P15_PROBE_ROLE !== serviceIdentities.probe ||
      process.env.P15_NETWORK_CLASS !== 'internal-only') {
    fail('probe process identity is invalid');
  }
  if (action === 'health') {
    await Promise.all(Object.keys(probeTargets).map(observeHealth));
    return;
  }
  if (action === 'health-target') {
    await observeHealth(targetName);
    return;
  }
  if (action === 'initial') {
    await Promise.all(Object.keys(probeTargets).map(observeHealth));
    await assertInitialEmpty();
    await probeOperations();
    return;
  }
  if (action === 'persistence') {
    await Promise.all(Object.keys(probeTargets).map(observeHealth));
    await verifyPersistenceOperations();
    return;
  }
  fail('probe action is invalid');
}

async function main() {
  const [command, ...args] = process.argv.slice(2);
  if (command === 'validate-compose' && args.length === 1) {
    validateComposeConfig(JSON.parse(await readFile(args[0], 'utf8')));
    return;
  }
  if (command === 'write-evidence' && args.length === 2) {
    const input = JSON.parse(await readFile(args[0], 'utf8'));
    await writeFile(
      args[1],
      canonicalJson(buildEvidence(input)),
      { encoding: 'utf8', flag: 'wx' }
    );
    return;
  }
  if (command === 'context-hash' && args.length === 2) {
    const contract = JSON.parse(await readFile(args[1], 'utf8'));
    process.stdout.write(await computeContextManifestHash(args[0], contract.buildContext.files));
    return;
  }
  if (command === 'probe') {
    await runProbe(args[0], args[1]);
    return;
  }
  throw new Error('P15A contract command is invalid');
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  main().catch(error => {
    console.error(error instanceof Error ? error.message : 'P15A contract failure');
    process.exitCode = 1;
  });
}
