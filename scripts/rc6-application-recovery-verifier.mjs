import { spawnSync } from 'node:child_process';
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  randomBytes,
  sign as cryptoSign
} from 'node:crypto';
import { chmod, readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';

const schemaVersion = 1;
const maxJsonBytes = 4 * 1024 * 1024;
const requestTimeoutMs = 5_000;
const readyTimeoutMs = 45_000;
const pollDelayMs = 250;
const commandTimeoutMs = 120_000;
const restartCommandTimeoutMs = 60_000;
const immutableImagePattern = /(?:@sha256:|^sha256:)[0-9a-f]{64}$/;
const sha256Pattern = /^[0-9a-f]{64}$/;
const ed25519Pattern = /^[0-9a-f]{64}$/;
const sessionIdPattern = /^05[0-9a-f]{64}$/;
const directIdPattern = /^03[0-9a-f]{64}$/;
const supportedComposeFile = resolve(
  import.meta.dirname,
  '..',
  'docker-compose.rc6-application-recovery.yml');
const volumeVariables = Object.freeze([
  'RC6_RECOVERY_MEMBERSHIP_VOLUME',
  'RC6_RECOVERY_REGISTRY_VOLUME',
  'RC6_RECOVERY_STORAGE_VOLUME',
  'RC6_RECOVERY_FILE_VOLUME',
  'RC6_RECOVERY_PUSH_VOLUME',
  'RC6_RECOVERY_XNODE_1_VOLUME',
  'RC6_RECOVERY_XNODE_2_VOLUME',
  'RC6_RECOVERY_XNODE_3_VOLUME',
  'RC6_RECOVERY_XNODE_4_VOLUME',
  'RC6_RECOVERY_XNODE_5_VOLUME',
  'RC6_RECOVERY_XNODE_6_VOLUME',
  'RC6_RECOVERY_VERIFIER_STATE_VOLUME'
]);
const restartServices = Object.freeze([
  'registry', 'storage', 'file', 'push',
  'xnode-1', 'xnode-2', 'xnode-3', 'xnode-4', 'xnode-5', 'xnode-6'
]);
const serviceUrls = Object.freeze({
  registry: 'http://registry:8080',
  storage: 'http://storage:8080',
  file: 'http://file:8080',
  push: 'http://push:8080',
  'xnode-1': 'http://xnode-1:8080',
  'xnode-2': 'http://xnode-2:8080',
  'xnode-3': 'http://xnode-3:8080',
  'xnode-4': 'http://xnode-4:8080',
  'xnode-5': 'http://xnode-5:8080',
  'xnode-6': 'http://xnode-6:8080'
});

class RecoveryFailure extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}

function fail(code) {
  throw new RecoveryFailure(code);
}

function argValue(name) {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

function hasArg(name) {
  return process.argv.includes(name);
}

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function isCount(value) {
  return Number.isSafeInteger(value) && value >= 0;
}

function exactKeys(value, keys) {
  return isObject(value) &&
    Object.keys(value).sort().join('\n') === [...keys].sort().join('\n');
}

function requireHash(value, code) {
  if (typeof value !== 'string' || !sha256Pattern.test(value)) fail(code);
}

function requireCount(value, code) {
  if (!isCount(value)) fail(code);
}

function validateExpectations(document) {
  if (!exactKeys(document, ['schemaVersion', 'images', 'storage', 'file', 'push', 'registry'])) {
    fail('expectations-shape-invalid');
  }
  if (document.schemaVersion !== schemaVersion) fail('expectations-version-invalid');

  if (!exactKeys(document.images, ['xnode', 'registry', 'compat', 'verifier'])) {
    fail('expectations-images-shape-invalid');
  }
  for (const value of Object.values(document.images)) {
    if (typeof value !== 'string' || !immutableImagePattern.test(value)) {
      fail('expectations-image-not-immutable');
    }
  }

  if (!exactKeys(document.storage, [
    'messageCount', 'ownerEd25519PublicKey', 'ownerPublicKey',
    'ownerPublicFingerprintSha256', 'namespaces'
  ])) fail('expectations-storage-shape-invalid');
  requireCount(document.storage.messageCount, 'expectations-storage-count-invalid');
  if (!ed25519Pattern.test(document.storage.ownerEd25519PublicKey ?? '')) {
    fail('expectations-storage-public-key-invalid');
  }
  if (!sessionIdPattern.test(document.storage.ownerPublicKey ?? '') &&
      !directIdPattern.test(document.storage.ownerPublicKey ?? '')) {
    fail('expectations-storage-owner-public-key-invalid');
  }
  requireHash(document.storage.ownerPublicFingerprintSha256, 'expectations-storage-fingerprint-invalid');
  if (!Array.isArray(document.storage.namespaces) || document.storage.namespaces.length === 0 ||
      document.storage.namespaces.length > 64) fail('expectations-storage-namespaces-invalid');
  let expectedStorageHashes = 0;
  const namespaceSet = new Set();
  for (const namespace of document.storage.namespaces) {
    if (!exactKeys(namespace, ['namespace', 'messageHashes']) ||
        !Number.isSafeInteger(namespace.namespace) || namespaceSet.has(namespace.namespace) ||
        !Array.isArray(namespace.messageHashes) || namespace.messageHashes.length === 0 ||
        namespace.messageHashes.length > 10_000) fail('expectations-storage-namespace-invalid');
    namespaceSet.add(namespace.namespace);
    const hashes = new Set();
    for (const hash of namespace.messageHashes) {
      requireHash(hash, 'expectations-storage-message-hash-invalid');
      if (hashes.has(hash)) fail('expectations-storage-message-hash-duplicate');
      hashes.add(hash);
    }
    expectedStorageHashes += hashes.size;
  }
  if (expectedStorageHashes > document.storage.messageCount) {
    fail('expectations-storage-canary-count-invalid');
  }

  if (!exactKeys(document.file, ['fileCount', 'avatarCount', 'objects'])) {
    fail('expectations-file-shape-invalid');
  }
  requireCount(document.file.fileCount, 'expectations-file-count-invalid');
  requireCount(document.file.avatarCount, 'expectations-avatar-count-invalid');
  if (!Array.isArray(document.file.objects) || document.file.objects.length === 0 ||
      document.file.objects.length > 1_000) fail('expectations-file-objects-invalid');
  for (const object of document.file.objects) {
    if (!exactKeys(object, ['kind', 'publicId', 'sha256', 'size', 'metadataSha256']) ||
        !['file', 'avatar'].includes(object.kind) ||
        typeof object.publicId !== 'string' || object.publicId.length < 1 || object.publicId.length > 512 ||
        !Number.isSafeInteger(object.size) || object.size < 0) fail('expectations-file-object-invalid');
    requireHash(object.sha256, 'expectations-file-object-hash-invalid');
    requireHash(object.metadataSha256, 'expectations-file-metadata-hash-invalid');
  }

  if (!exactKeys(document.push, ['subscriptionCount', 'deliveryCount', 'canaries'])) {
    fail('expectations-push-shape-invalid');
  }
  requireCount(document.push.subscriptionCount, 'expectations-push-subscription-count-invalid');
  requireCount(document.push.deliveryCount, 'expectations-push-delivery-count-invalid');
  if (!Array.isArray(document.push.canaries) || document.push.canaries.length === 0 ||
      document.push.canaries.length > 1_000) fail('expectations-push-canaries-invalid');
  for (const canary of document.push.canaries) {
    if (!exactKeys(canary, ['publicKey', 'snapshotSha256']) ||
        typeof canary.publicKey !== 'string' || canary.publicKey.length < 2 || canary.publicKey.length > 128) {
      fail('expectations-push-canary-invalid');
    }
    requireHash(canary.snapshotSha256, 'expectations-push-canary-hash-invalid');
  }

  if (!exactKeys(document.registry, ['membershipCatalogSha256'])) {
    fail('expectations-registry-shape-invalid');
  }
  requireHash(document.registry.membershipCatalogSha256, 'expectations-membership-hash-invalid');
  return document;
}

async function readBoundedJson(fileName, missingCode, invalidCode) {
  let bytes;
  try {
    bytes = await readFile(fileName);
  } catch {
    fail(missingCode);
  }
  if (bytes.length === 0 || bytes.length > maxJsonBytes) fail(invalidCode);
  try {
    return JSON.parse(bytes.toString('utf8'));
  } catch {
    fail(invalidCode);
  }
}

function canonicalJson(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

const curve25519Prime = (1n << 255n) - 19n;

function curveMod(value) {
  const result = value % curve25519Prime;
  return result >= 0n ? result : result + curve25519Prime;
}

function curvePow(base, exponent) {
  let result = 1n;
  let factor = curveMod(base);
  let power = exponent;
  while (power > 0n) {
    if ((power & 1n) === 1n) result = curveMod(result * factor);
    factor = curveMod(factor * factor);
    power >>= 1n;
  }
  return result;
}

function ed25519PublicKeyToX25519(ed25519) {
  if (!Buffer.isBuffer(ed25519) || ed25519.length !== 32) fail('ed25519-public-key-invalid');
  const yBytes = Buffer.from(ed25519);
  yBytes[31] &= 0x7f;
  let y = 0n;
  for (let index = yBytes.length - 1; index >= 0; index -= 1) {
    y = (y << 8n) + BigInt(yBytes[index]);
  }
  let value = curveMod((1n + y) * curvePow(1n - y, curve25519Prime - 2n));
  const output = Buffer.alloc(32);
  for (let index = 0; index < output.length; index += 1) {
    output[index] = Number(value & 0xffn);
    value >>= 8n;
  }
  return output;
}

function publicIdentity(privateKey) {
  const publicDer = createPublicKey(privateKey).export({ type: 'spki', format: 'der' });
  const ed25519 = Buffer.from(publicDer.subarray(-32));
  return {
    ed25519: ed25519.toString('hex'),
    directId: `03${ed25519.toString('hex')}`,
    sessionId: `05${ed25519PublicKeyToX25519(ed25519).toString('hex')}`,
    fingerprint: sha256(ed25519)
  };
}

function imageExpectationsFromEnvironment() {
  const values = {
    xnode: process.env.RC6_RECOVERY_XNODE_IMAGE,
    registry: process.env.RC6_RECOVERY_REGISTRY_IMAGE,
    compat: process.env.RC6_RECOVERY_COMPAT_IMAGE,
    verifier: process.env.RC6_RECOVERY_VERIFIER_IMAGE
  };
  for (const value of Object.values(values)) {
    if (typeof value !== 'string' || !immutableImagePattern.test(value)) fail('runtime-image-not-immutable');
  }
  return values;
}

function assertExpectedImages(expectations) {
  const runtime = imageExpectationsFromEnvironment();
  for (const key of Object.keys(runtime)) {
    if (runtime[key] !== expectations.images[key]) fail('runtime-image-fingerprint-mismatch');
  }
}

async function fetchBounded(url, options = {}, expectedStatus = 200) {
  const signal = AbortSignal.timeout(requestTimeoutMs);
  let response;
  try {
    response = await fetch(url, { ...options, signal });
  } catch {
    fail('service-request-failed');
  }
  if (response.status !== expectedStatus) fail('service-response-status-invalid');
  const length = Number(response.headers.get('content-length') ?? 0);
  if (Number.isFinite(length) && length > maxJsonBytes) fail('service-response-too-large');
  const bytes = Buffer.from(await response.arrayBuffer());
  if (bytes.length > maxJsonBytes) fail('service-response-too-large');
  return bytes;
}

async function fetchJson(url, options = {}, expectedStatus = 200) {
  const bytes = await fetchBounded(url, options, expectedStatus);
  try {
    return JSON.parse(bytes.toString('utf8'));
  } catch {
    fail('service-response-json-invalid');
  }
}

async function waitForReadiness() {
  const deadline = Date.now() + readyTimeoutMs;
  const pending = new Set(Object.keys(serviceUrls));
  while (pending.size > 0 && Date.now() < deadline) {
    for (const service of [...pending]) {
      const healthPath = service === 'registry' ? '/health/ready' : '/health/ready';
      try {
        const response = await fetch(`${serviceUrls[service]}${healthPath}`, {
          signal: AbortSignal.timeout(requestTimeoutMs)
        });
        if (response.status === 200) pending.delete(service);
      } catch {
        // Bounded retry; details are intentionally not logged.
      }
    }
    if (pending.size > 0) await new Promise(resolve => setTimeout(resolve, pollDelayMs));
  }
  if (pending.size > 0) fail('readiness-timeout');
}

async function validateServiceCounts(expectations) {
  const [storage, file, push] = await Promise.all([
    fetchJson(`${serviceUrls.storage}/stats`),
    fetchJson(`${serviceUrls.file}/stats`),
    fetchJson(`${serviceUrls.push}/stats`)
  ]);
  if (storage?.inventory?.storageMessages !== expectations.storage.messageCount) {
    fail('storage-count-mismatch');
  }
  if (file?.inventory?.files !== expectations.file.fileCount ||
      file?.inventory?.avatars !== expectations.file.avatarCount) fail('file-count-mismatch');
  if (push?.inventory?.subscriptions !== expectations.push.subscriptionCount ||
      push?.inventory?.pushDeliveries !== expectations.push.deliveryCount) fail('push-count-mismatch');
}

async function loadCanarySigner(expectations) {
  const signerPath = process.env.RC6_RECOVERY_CANARY_SIGNER_FILE;
  if (!signerPath) fail('protected-canary-signer-file-not-supplied');
  let signerBytes;
  try {
    signerBytes = await readFile(signerPath);
  } catch {
    fail('protected-canary-signer-unreadable');
  }
  if (signerBytes.length < 48 || signerBytes.length > 16_384) fail('protected-canary-signer-invalid');
  let privateKey;
  try {
    privateKey = createPrivateKey(signerBytes);
  } catch {
    fail('protected-canary-signer-invalid');
  }
  const identity = publicIdentity(privateKey);
  if (identity.ed25519 !== expectations.storage.ownerEd25519PublicKey ||
      ![identity.directId, identity.sessionId].includes(expectations.storage.ownerPublicKey) ||
      identity.fingerprint !== expectations.storage.ownerPublicFingerprintSha256) {
    fail('protected-canary-signer-public-fingerprint-mismatch');
  }
  return { privateKey, identity };
}

async function validateStorageCanaries(expectations, signer) {
  for (const namespace of expectations.storage.namespaces) {
    const observed = [];
    let lastHash;
    for (let page = 0; page < 100; page += 1) {
      const timestamp = Date.now();
      const signature = cryptoSign(
        null,
        Buffer.from(`retrieve${namespace.namespace === 0 ? '' : namespace.namespace}${timestamp}`),
        signer.privateKey).toString('base64');
      const payload = {
        pubkey: expectations.storage.ownerPublicKey,
        pubkey_ed25519: signer.identity.ed25519,
        namespace: namespace.namespace,
        timestamp,
        signature,
        max_results: 100
      };
      if (lastHash) payload.last_hash = lastHash;
      const result = await fetchJson(`${serviceUrls.storage}/storage/retrieve`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(payload)
      });
      if (!Array.isArray(result?.messages) || typeof result.more !== 'boolean') {
        fail('storage-canary-response-invalid');
      }
      for (const message of result.messages) {
        if (!isObject(message) || typeof message.hash !== 'string') fail('storage-canary-response-invalid');
        observed.push(message.hash);
      }
      if (!result.more) break;
      if (result.messages.length === 0) fail('storage-canary-pagination-invalid');
      lastHash = result.messages.at(-1).hash;
      if (page === 99) fail('storage-canary-pagination-limit');
    }
    const expected = [...namespace.messageHashes].sort();
    if (observed.sort().join('\n') !== expected.join('\n')) fail('storage-canary-hash-mismatch');
  }
}

async function validateFileCanaries(expectations) {
  for (const object of expectations.file.objects) {
    const encoded = encodeURIComponent(object.publicId);
    const route = object.kind === 'file' ? `/file/${encoded}` : `/avatar/${encoded}`;
    const [bytes, metadata] = await Promise.all([
      fetchBounded(`${serviceUrls.file}${route}`),
      fetchJson(`${serviceUrls.file}${route}/info`)
    ]);
    if (bytes.length !== object.size || sha256(bytes) !== object.sha256 ||
        sha256(canonicalJson(metadata)) !== object.metadataSha256) fail('file-canary-hash-mismatch');
  }
}

async function validatePushCanaries(expectations) {
  for (const canary of expectations.push.canaries) {
    const snapshot = await fetchJson(
      `${serviceUrls.push}/subscriptions/${encodeURIComponent(canary.publicKey)}`);
    if (sha256(canonicalJson(snapshot)) !== canary.snapshotSha256) fail('push-canary-hash-mismatch');
  }
}

async function validateMembershipCanary(expectations) {
  const catalog = await fetchBounded(`${serviceUrls.registry}/api/network/membership-route-catalog`);
  if (sha256(catalog) !== expectations.registry.membershipCatalogSha256) {
    fail('membership-catalog-hash-mismatch');
  }
}

function generateCallIdentity() {
  const pair = generateKeyPairSync('ed25519');
  const identity = publicIdentity(pair.privateKey);
  return { privateKey: pair.privateKey, ...identity };
}

function signCallSignal(sender, recipient, values = {}) {
  const createdAtUnixMs = values.createdAtUnixMs ?? Date.now();
  const nonce = values.nonce ?? randomBytes(16).toString('hex');
  const request = {
    callId: values.callId ?? `recovery-${randomBytes(16).toString('hex')}`,
    conversationId: recipient.sessionId,
    sender: { value: sender.sessionId },
    recipient: { value: recipient.sessionId },
    type: 0,
    payload: values.payload ?? `sealed-v1:${randomBytes(32).toString('base64')}`,
    createdAt: new Date(createdAtUnixMs).toISOString(),
    senderEd25519: sender.ed25519,
    signature: null,
    nonce
  };
  request.signature = cryptoSign(null, Buffer.from(JSON.stringify({
    version: 'deep-call-signal-v2',
    callId: request.callId,
    conversationId: request.conversationId,
    sender: request.sender.value,
    recipient: request.recipient.value,
    type: 'Offer',
    payload: request.payload,
    createdAtUnixMs,
    senderEd25519: request.senderEd25519,
    nonce
  })), sender.privateKey).toString('base64');
  return request;
}

function signedCallGet(identity, nonce = randomBytes(16).toString('hex')) {
  const timestamp = Math.floor(Date.now() / 1000);
  const path = `/api/calls/inbox/${identity.sessionId}`;
  const message = `deep-call-inbox-v2\nGET\n${path}\n${identity.sessionId}\n${timestamp}\n${nonce}`;
  return {
    path,
    headers: {
      'X-Deep-Ed25519': identity.ed25519,
      'X-Deep-Timestamp': String(timestamp),
      'X-Deep-Nonce': nonce,
      'X-Deep-Signature': cryptoSign(null, Buffer.from(message), identity.privateKey).toString('base64')
    }
  };
}

async function assertNegativeCallAuth() {
  const response = await fetch(`${serviceUrls.registry}/api/calls/inbox/${'05'.padEnd(66, '0')}`, {
    signal: AbortSignal.timeout(requestTimeoutMs)
  });
  if (response.status !== 401) fail('calls-v2-negative-auth-not-rejected');
}

async function postCallSignal(signal, expectedStatus) {
  await fetchBounded(`${serviceUrls.registry}/api/calls/signal`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(signal)
  }, expectedStatus);
}

async function drainCallExactlyOnce(recipient, expectedCallId) {
  const inbox = signedCallGet(recipient);
  const signals = await fetchJson(`${serviceUrls.registry}${inbox.path}`, { headers: inbox.headers });
  if (!Array.isArray(signals) || signals.length !== 1 ||
      signals[0]?.callId !== expectedCallId) fail('calls-v2-exactly-once-failed');
  await fetchBounded(`${serviceUrls.registry}${inbox.path}`, { headers: inbox.headers }, 409);
  const freshInbox = signedCallGet(recipient);
  const empty = await fetchJson(`${serviceUrls.registry}${freshInbox.path}`, {
    headers: freshInbox.headers
  });
  if (!Array.isArray(empty) || empty.length !== 0) fail('calls-v2-drain-replay-failed');
}

async function exerciseImmediateCallsProbe() {
  const sender = generateCallIdentity();
  const recipient = generateCallIdentity();
  const signal = signCallSignal(sender, recipient);
  await postCallSignal(signal, 202);
  await postCallSignal(signal, 202);
  const fork = signCallSignal(sender, recipient, {
    nonce: signal.nonce,
    createdAtUnixMs: Date.parse(signal.createdAt),
    payload: signal.payload
  });
  await postCallSignal(fork, 409);
  await drainCallExactlyOnce(recipient, signal.callId);
}

async function beforeCallsProbe() {
  await assertNegativeCallAuth();
  await exerciseImmediateCallsProbe();
  const sender = generateCallIdentity();
  const recipient = generateCallIdentity();
  const signal = signCallSignal(sender, recipient);
  await postCallSignal(signal, 202);
  await postCallSignal(signal, 202);
  const fork = signCallSignal(sender, recipient, {
    nonce: signal.nonce,
    createdAtUnixMs: Date.parse(signal.createdAt),
    payload: signal.payload
  });
  await postCallSignal(fork, 409);

  const checkpointPath = process.env.RC6_RECOVERY_CHECKPOINT_FILE;
  if (!checkpointPath) fail('calls-v2-checkpoint-not-configured');
  const checkpoint = {
    schemaVersion,
    senderPrivateKey: sender.privateKey.export({ type: 'pkcs8', format: 'pem' }),
    recipientPrivateKey: recipient.privateKey.export({ type: 'pkcs8', format: 'pem' }),
    signal
  };
  try {
    await writeFile(checkpointPath, `${JSON.stringify(checkpoint)}\n`, { mode: 0o600 });
    await chmod(checkpointPath, 0o600);
  } catch {
    fail('calls-v2-checkpoint-write-failed');
  }
}

async function afterCallsProbe() {
  await assertNegativeCallAuth();
  const checkpointPath = process.env.RC6_RECOVERY_CHECKPOINT_FILE;
  if (!checkpointPath) fail('calls-v2-checkpoint-not-configured');
  const checkpoint = await readBoundedJson(
    checkpointPath, 'calls-v2-checkpoint-missing', 'calls-v2-checkpoint-invalid');
  if (!exactKeys(checkpoint, ['schemaVersion', 'senderPrivateKey', 'recipientPrivateKey', 'signal']) ||
      checkpoint.schemaVersion !== schemaVersion || !isObject(checkpoint.signal)) {
    fail('calls-v2-checkpoint-invalid');
  }
  let sender;
  let recipient;
  try {
    const senderKey = createPrivateKey(checkpoint.senderPrivateKey);
    const recipientKey = createPrivateKey(checkpoint.recipientPrivateKey);
    sender = { privateKey: senderKey, ...publicIdentity(senderKey) };
    recipient = { privateKey: recipientKey, ...publicIdentity(recipientKey) };
  } catch {
    fail('calls-v2-checkpoint-invalid');
  }
  if (checkpoint.signal.sender?.value !== sender.sessionId ||
      checkpoint.signal.recipient?.value !== recipient.sessionId) fail('calls-v2-checkpoint-invalid');

  await postCallSignal(checkpoint.signal, 202);
  const fork = signCallSignal(sender, recipient, {
    nonce: checkpoint.signal.nonce,
    createdAtUnixMs: Date.parse(checkpoint.signal.createdAt),
    payload: checkpoint.signal.payload
  });
  await postCallSignal(fork, 409);

  await drainCallExactlyOnce(recipient, checkpoint.signal.callId);
}

async function runProbe() {
  const phase = argValue('--phase');
  if (!['before', 'after'].includes(phase)) fail('probe-phase-invalid');
  const expectationsPath = process.env.RC6_RECOVERY_EXPECTATIONS_FILE;
  if (!expectationsPath) fail('expectations-file-not-supplied');
  const expectations = validateExpectations(await readBoundedJson(
    expectationsPath, 'expectations-file-unreadable', 'expectations-json-invalid'));
  assertExpectedImages(expectations);
  await waitForReadiness();
  const signer = await loadCanarySigner(expectations);
  if (phase === 'after') await afterCallsProbe();
  await validateServiceCounts(expectations);
  await validateStorageCanaries(expectations, signer);
  await validateFileCanaries(expectations);
  await validatePushCanaries(expectations);
  await validateMembershipCanary(expectations);
  if (phase === 'before') await beforeCallsProbe();
  return {
    schemaVersion,
    status: 'ok',
    phase,
    partialApplicationServicesValidated: true,
    applicationContourValidated: false,
    checks: [
      'exact-images', 'readiness', 'restored-counts', 'storage-canary-hashes',
      'file-canary-hashes', 'push-public-fingerprints', 'membership-public-fingerprint',
      'calls-v2-exact-replay', 'calls-v2-exactly-once', 'calls-v2-negative-auth'
    ],
    unvalidated: ['xnode-identity', 'privacy-routing', 'turn'],
    blockers: []
  };
}

function runDocker(args, failureCode, timeoutMs = commandTimeoutMs) {
  const result = spawnSync('docker', args, {
    encoding: 'utf8',
    env: process.env,
    maxBuffer: 1024 * 1024,
    timeout: timeoutMs,
    windowsHide: true
  });
  if (result.error || result.status !== 0) fail(failureCode);
  return String(result.stdout ?? '').trim();
}

function assertRestoredVolumesIsolated(projectName) {
  const observed = new Set();
  for (const variable of volumeVariables) {
    const volumeName = process.env[variable];
    if (typeof volumeName !== 'string' || !/^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$/.test(volumeName)) {
      fail('restored-volume-name-invalid');
    }
    if (observed.has(volumeName)) fail('restored-volume-name-duplicate');
    observed.add(volumeName);
    const containers = runDocker(
      ['ps', '-aq', '--filter', `volume=${volumeName}`],
      'restored-volume-usage-check-failed').split(/\r?\n/).filter(Boolean);
    for (const container of containers) {
      if (!/^[0-9a-f]{12,64}$/.test(container)) fail('restored-volume-usage-check-failed');
      const ownerProject = runDocker([
        'inspect', '--format', '{{ index .Config.Labels "com.docker.compose.project" }}', container
      ], 'restored-volume-usage-check-failed');
      if (ownerProject !== projectName) fail('restored-volume-already-mounted');
    }
  }
}

function parseProbeOutput(output, phase) {
  const lines = output.split(/\r?\n/).filter(Boolean);
  if (lines.length !== 1 || lines[0].length > 32_768) fail(`${phase}-probe-output-invalid`);
  let result;
  try {
    result = JSON.parse(lines[0]);
  } catch {
    fail(`${phase}-probe-output-invalid`);
  }
  if (!isObject(result) || result.status !== 'ok' || result.phase !== phase ||
      !Array.isArray(result.checks) || result.blockers?.length !== 0) {
    fail(`${phase}-probe-failed`);
  }
  return result;
}

async function writeEvidence(fileName, document) {
  if (!fileName) return;
  try {
    await writeFile(fileName, `${JSON.stringify(document, null, 2)}\n`, { flag: 'wx' });
  } catch {
    fail('evidence-write-failed');
  }
}

function safeFailure(code) {
  const allowed = typeof code === 'string' && /^[a-z0-9-]{3,96}$/.test(code)
    ? code
    : 'internal-recovery-verifier-failure';
  return {
    schemaVersion,
    status: 'failed',
    partialApplicationServicesValidated: false,
    applicationContourValidated: false,
    scope: 'isolated-restored-application-contour',
    checks: [],
    blockers: [allowed]
  };
}

async function validateOnly() {
  const expectationsPath = argValue('--expectations');
  if (!expectationsPath) fail('expectations-file-not-supplied');
  validateExpectations(await readBoundedJson(
    expectationsPath, 'expectations-file-unreadable', 'expectations-json-invalid'));
  return {
    schemaVersion,
    status: 'scaffold',
    partialApplicationServicesValidated: false,
    applicationContourValidated: false,
    scope: 'isolated-restored-application-contour',
    checks: ['expectations-schema'],
    blockers: ['runtime-recovery-not-executed']
  };
}

async function runController() {
  const requestedComposeFile = argValue('--compose-file');
  const composeFile = supportedComposeFile;
  const projectName = argValue('--project-name');
  const expectationsPath = argValue('--expectations');
  const evidencePath = argValue('--evidence');
  if (requestedComposeFile && resolve(requestedComposeFile) !== composeFile) {
    fail('compose-file-not-supported');
  }
  if (!projectName || !/^[a-z0-9][a-z0-9_-]{2,62}$/.test(projectName) ||
      ['deep-survival-dev', 'deep-uat'].includes(projectName)) fail('recovery-project-name-invalid');
  if (!expectationsPath) fail('expectations-file-not-supplied');
  const expectations = validateExpectations(await readBoundedJson(
    expectationsPath, 'expectations-file-unreadable', 'expectations-json-invalid'));
  const runtimeImages = imageExpectationsFromEnvironment();
  for (const key of Object.keys(runtimeImages)) {
    if (runtimeImages[key] !== expectations.images[key]) fail('runtime-image-fingerprint-mismatch');
  }
  if (!process.env.RC6_RECOVERY_CANARY_SIGNER_FILE) {
    fail('protected-canary-signer-file-not-supplied');
  }
  assertRestoredVolumesIsolated(projectName);

  const compose = ['compose', '-f', composeFile, '-p', projectName];
  let stackStarted = false;
  let evidence;
  try {
    runDocker([...compose, 'up', '-d', '--no-build', '--pull', 'never', ...restartServices], 'recovery-stack-start-failed');
    stackStarted = true;
    const before = parseProbeOutput(runDocker([
      ...compose, 'run', '--rm', '--no-deps', 'recovery-verifier', '--probe', '--phase', 'before'
    ], 'before-probe-command-failed'), 'before');
    runDocker(
      [...compose, 'restart', '--timeout', '20', ...restartServices],
      'recovery-stack-restart-failed',
      restartCommandTimeoutMs);
    const after = parseProbeOutput(runDocker([
      ...compose, 'run', '--rm', '--no-deps', 'recovery-verifier', '--probe', '--phase', 'after'
    ], 'after-probe-command-failed'), 'after');
    if (after.partialApplicationServicesValidated !== true ||
        after.applicationContourValidated !== false) {
      fail('after-partial-services-probe-not-validated');
    }

    evidence = {
      schemaVersion,
      status: 'ok',
      partialApplicationServicesValidated: true,
      applicationContourValidated: false,
      scope: 'isolated-restored-application-services-partial',
      phases: { before: before.checks, after: after.checks },
      restart: { bounded: true, services: restartServices.length },
      unvalidated: ['xnode-identity', 'privacy-routing', 'turn'],
      blockers: []
    };
  } finally {
    if (stackStarted) {
      runDocker(
        [...compose, 'down', '--remove-orphans'],
        'recovery-stack-cleanup-failed',
        restartCommandTimeoutMs);
    }
  }
  await writeEvidence(evidencePath, evidence);
  return evidence;
}

async function main() {
  let evidencePath;
  try {
    let result;
    if (hasArg('--validate-only')) result = await validateOnly();
    else if (hasArg('--probe')) result = await runProbe();
    else {
      evidencePath = argValue('--evidence');
      result = await runController();
    }
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } catch (error) {
    const failure = safeFailure(error instanceof RecoveryFailure ? error.code : undefined);
    if (evidencePath) {
      try {
        await writeEvidence(evidencePath, failure);
      } catch {
        failure.blockers = ['evidence-write-failed'];
      }
    }
    process.stdout.write(`${JSON.stringify(failure)}\n`);
    process.exitCode = 1;
  }
}

await main();
