import assert from 'node:assert/strict';
import { createHash, createPrivateKey, createPublicKey, sign as cryptoSign } from 'node:crypto';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { spawn } from 'node:child_process';
import {
  createPushSubscribeSignatureMessageV2,
  createPushUnsubscribeSignatureMessageV2,
  createTestStorageSigningIdentity,
  verifySessionSignature
} from './storage-signatures.mjs';

const scriptPath = path.resolve(path.dirname(fileURLToPath(import.meta.url)), 'compat-service.mjs');
const pushV2FixturePath = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '..',
  'fixtures',
  'push-signature-v2.golden.json'
);
const pushV2FixtureSha256 = '4bca6bffffa751d124a322a51af878476522faa9ded8a56bd2c89f93ac1e576a';

async function waitForReady(baseUrl, timeoutMs = 5000) {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    try {
      const response = await fetch(`${baseUrl}/health/ready`);
      if (response.ok) {
        return;
      }
    } catch {
      // Keep retrying until timeout.
    }

    await new Promise(resolve => setTimeout(resolve, 100));
  }

  throw new Error('compat-service did not become ready in time');
}

async function startMockService({ port, stateDir, extraEnv = {} }) {
  const child = spawn(process.execPath, [scriptPath], {
    env: {
      ...process.env,
      SERVICE_MODE: 'all',
      PORT: String(port),
      MOCK_STATE_DIR: stateDir,
      ...extraEnv
    },
    stdio: ['ignore', 'pipe', 'pipe']
  });

  let stderr = '';
  child.stderr.on('data', chunk => {
    stderr += String(chunk);
  });

  const baseUrl = `http://127.0.0.1:${port}`;
  await waitForReady(baseUrl);

  return {
    baseUrl,
    async stop() {
      child.kill('SIGTERM');
      await new Promise(resolve => {
        child.once('exit', () => resolve());
        setTimeout(() => {
          if (!child.killed) {
            child.kill('SIGKILL');
          }
        }, 1000);
      });

      if (stderr.trim()) {
        assert.fail(`compat-service stderr was not empty:\n${stderr}`);
      }
    }
  };
}

function randomPort() {
  return 19000 + Math.floor(Math.random() * 1000);
}

function currentSigTs(offsetSeconds = 0) {
  return Math.floor(Date.now() / 1000) + offsetSeconds;
}

const validSessionEd25519 = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const validPushSignature = 'f8efdd12000700000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000';
const validEncKey = 'abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd';
const compatRelayId = '1111111111111111111111111111111111111111111111111111111111111111';
const expectedSessionFileId = 'G11G5sQmyOccBQIlkx3f_X2Ms8oKfF8bgZ9pyJUzvFGv';
const storageSigningIdentity = createTestStorageSigningIdentity();
const pushSigningIdentity = createTestStorageSigningIdentity();

function invalidateSignature(signature) {
  const bytes = Buffer.from(signature, 'base64');
  bytes[0] ^= 0xff;
  return bytes.toString('base64');
}

function withStorageSubaccount(payload, subaccount) {
  return {
    ...payload,
    subaccount: subaccount.subaccount,
    subaccount_sig: subaccount.subaccountSig
  };
}

function createPushSubscribePayload(overrides = {}) {
  const serviceInfo = overrides.service_info ?? { token: 'token-1' };
  return {
    pubkey: '05push',
    session_ed25519: validSessionEd25519,
    data: true,
    sig_ts: currentSigTs(),
    signature: validPushSignature,
    service: 'apns',
    service_info: serviceInfo,
    enc_key: validEncKey,
    namespaces: [0, 11],
    ...overrides,
    service_info: serviceInfo
  };
}

function createPushUnsubscribePayload(overrides = {}) {
  const serviceInfo = overrides.service_info ?? { token: 'token-1' };
  return {
    pubkey: '05push',
    session_ed25519: validSessionEd25519,
    sig_ts: currentSigTs(),
    signature: validPushSignature,
    service: 'apns',
    service_info: serviceInfo,
    ...overrides,
    service_info: serviceInfo
  };
}

function createSignedPushSubscribePayload(identity, overrides = {}) {
  const {
    service_info: providedServiceInfo,
    namespaces: providedNamespaces,
    signature: providedSignature,
    pubkey: providedPubkey,
    session_ed25519: providedSessionEd25519,
    data: providedData,
    sig_ts: providedSigTs,
    ...rest
  } = overrides;
  const pubkey = String(providedPubkey ?? identity.sessionPubkey ?? identity.directPubkey);
  const sigTs = Number(providedSigTs ?? currentSigTs());
  const data = providedData ?? true;
  const namespaces = Array.isArray(providedNamespaces) ? providedNamespaces.map(value => Number(value)) : [0, 11];
  const serviceInfo = providedServiceInfo ?? { token: 'signed-token-1' };
  const sessionEd25519 = providedSessionEd25519 ?? (pubkey.startsWith('05') ? identity.pubkeyEd25519 : undefined);

  return {
    pubkey,
    ...(sessionEd25519 ? { session_ed25519: sessionEd25519 } : {}),
    data,
    sig_ts: sigTs,
    signature: providedSignature ?? identity.signPushSubscribe(pubkey, sigTs, data, namespaces),
    service: 'apns',
    service_info: serviceInfo,
    enc_key: validEncKey,
    namespaces,
    ...rest
  };
}

function createSignedPushUnsubscribePayload(identity, overrides = {}) {
  const {
    service_info: providedServiceInfo,
    signature: providedSignature,
    pubkey: providedPubkey,
    session_ed25519: providedSessionEd25519,
    sig_ts: providedSigTs,
    ...rest
  } = overrides;
  const pubkey = String(providedPubkey ?? identity.sessionPubkey ?? identity.directPubkey);
  const sigTs = Number(providedSigTs ?? currentSigTs());
  const serviceInfo = providedServiceInfo ?? { token: 'signed-token-1' };
  const sessionEd25519 = providedSessionEd25519 ?? (pubkey.startsWith('05') ? identity.pubkeyEd25519 : undefined);

  return {
    pubkey,
    ...(sessionEd25519 ? { session_ed25519: sessionEd25519 } : {}),
    sig_ts: sigTs,
    signature: providedSignature ?? identity.signPushUnsubscribe(pubkey, sigTs),
    service: 'apns',
    service_info: serviceInfo,
    ...rest
  };
}

function createSignedPushSubscribePayloadV2(identity, overrides = {}) {
  const pubkey = String(overrides.pubkey ?? identity.sessionPubkey);
  const serviceInfo = overrides.service_info ?? { token: 'signed-v2-token-1' };
  const request = {
    pubkey,
    session_ed25519: overrides.session_ed25519 ?? identity.pubkeyEd25519,
    data: true,
    sig_ts: currentSigTs(),
    service: 'apns',
    service_info: serviceInfo,
    enc_key: validEncKey,
    namespaces: [0, 11],
    app_id: 'network.deep.app',
    app_version: '1.0.0',
    sig_v: 2,
    ...overrides,
    service_info: serviceInfo
  };
  request.signature = Object.hasOwn(overrides, 'signature')
    ? overrides.signature
    : identity.signPushSubscribeV2({
        pubkey: request.pubkey,
        timestamp: request.sig_ts,
        wantData: request.data,
        namespaces: request.namespaces,
        service: request.service,
        deviceToken: request.service_info.token,
        encryptionKey: request.enc_key,
        appId: request.app_id,
        appVersion: request.app_version
      });
  return request;
}

function createSignedPushUnsubscribePayloadV2(identity, overrides = {}) {
  const pubkey = String(overrides.pubkey ?? identity.sessionPubkey);
  const serviceInfo = overrides.service_info ?? { token: 'signed-v2-token-1' };
  const request = {
    pubkey,
    session_ed25519: overrides.session_ed25519 ?? identity.pubkeyEd25519,
    sig_ts: currentSigTs(),
    service: 'apns',
    service_info: serviceInfo,
    sig_v: 2,
    ...overrides,
    service_info: serviceInfo
  };
  request.signature = Object.hasOwn(overrides, 'signature')
    ? overrides.signature
    : identity.signPushUnsubscribeV2({
        pubkey: request.pubkey,
        timestamp: request.sig_ts,
        service: request.service,
        deviceToken: request.service_info.token
      });
  return request;
}

function createOldCoercivePushV2Message(operation, fields) {
  let canonical = `deep.push/${operation}/v2\n`;
  for (const [name, rawValue] of fields) {
    const value = String(rawValue ?? '');
    canonical += `${name}=${Buffer.byteLength(value, 'utf8')}:${value}\n`;
  }
  return Buffer.from(canonical, 'utf8');
}

function signOldCoerciveSubscribeV2(identity, request) {
  const namespaces = Array.isArray(request.namespaces)
    ? request.namespaces.map(value => Number(value)).sort((left, right) => left - right).join(',')
    : '';
  return identity.signMessage(createOldCoercivePushV2Message('subscribe', [
    ['pubkey', request.pubkey],
    ['sig_ts', Number(request.sig_ts)],
    ['service', request.service],
    ['device_token', request.service_info?.token],
    ['enc_key', request.enc_key],
    ['want_data', request.data ? '1' : '0'],
    ['namespaces', namespaces],
    ['app_id', request.app_id],
    ['app_version', request.app_version]
  ]));
}

function signOldCoerciveUnsubscribeV2(identity, request) {
  return identity.signMessage(createOldCoercivePushV2Message('unsubscribe', [
    ['pubkey', request.pubkey],
    ['sig_ts', Number(request.sig_ts)],
    ['service', request.service],
    ['device_token', request.service_info?.token]
  ]));
}

function createStorageStorePayload(overrides = {}) {
  const payload = { ...overrides };
  const namespace = Number(payload.namespace ?? 0);
  if (namespace % 10 !== 0 && payload.signature === undefined) {
    payload.signature = validPushSignature;
  }
  return payload;
}

test('push signature v2 golden fixture pins UTF-8 canonical bytes and Ed25519 signatures', async () => {
  const fixtureBytes = await readFile(pushV2FixturePath);
  assert.equal(createHash('sha256').update(fixtureBytes).digest('hex'), pushV2FixtureSha256);
  const fixture = JSON.parse(fixtureBytes.toString('utf8'));
  assert.equal(fixture.signature_version, 2);
  const seed = Buffer.from(fixture.key.private_seed_hex, 'hex');
  const privateKey = createPrivateKey({
    key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]),
    format: 'der',
    type: 'pkcs8'
  });
  const publicKeyDer = createPublicKey(privateKey).export({ format: 'der', type: 'spki' });
  assert.equal(Buffer.from(publicKeyDer.subarray(-32)).toString('hex'), fixture.key.ed25519_public_key_hex);

  for (const goldenCase of fixture.cases) {
    const request = goldenCase.request;
    const message = goldenCase.operation === 'subscribe'
      ? createPushSubscribeSignatureMessageV2({
          pubkey: request.pubkey,
          timestamp: request.sig_ts,
          wantData: request.data,
          namespaces: request.namespaces,
          service: request.service,
          deviceToken: request.service_info.token,
          encryptionKey: request.enc_key,
          appId: request.app_id,
          appVersion: request.app_version
        })
      : createPushUnsubscribeSignatureMessageV2({
          pubkey: request.pubkey,
          timestamp: request.sig_ts,
          service: request.service,
          deviceToken: request.service_info.token
        });

    if (goldenCase.operation === 'subscribe') {
      assert.throws(
        () => createPushSubscribeSignatureMessageV2({
          pubkey: request.pubkey,
          timestamp: request.sig_ts,
          wantData: request.data,
          namespaces: goldenCase.unsorted_namespaces_for_canonicalizer,
          service: request.service,
          deviceToken: request.service_info.token,
          encryptionKey: request.enc_key,
          appId: request.app_id,
          appVersion: request.app_version
        }),
        /sorted numerically/,
        `${goldenCase.id} must reject noncanonical namespace order`
      );
    }

    assert.equal(message.toString('utf8'), goldenCase.canonical, goldenCase.id);
    assert.equal(message.toString('hex'), goldenCase.canonical_hex, goldenCase.id);
    assert.equal(message.length, goldenCase.canonical_utf8_length, goldenCase.id);
    assert.equal(message.includes(13), false, goldenCase.id);
    assert.equal(cryptoSign(null, message, privateKey).toString('base64'), request.signature, goldenCase.id);
    assert.equal(verifySessionSignature({
      pubkey: request.pubkey,
      pubkeyEd25519: request.session_ed25519,
      signature: request.signature,
      message
    }), true, goldenCase.id);
  }
});

test('compat push v2 canonicalizer rejects coercive and noncanonical inputs', () => {
  const validSubscribe = {
    pubkey: pushSigningIdentity.sessionPubkey,
    timestamp: currentSigTs(),
    wantData: true,
    namespaces: [0, 10],
    service: 'apns',
    deviceToken: 'canonicalizer-token',
    encryptionKey: validEncKey,
    appId: 'network.deep.app',
    appVersion: '1.0.0'
  };
  const invalidSubscribe = [
    { ...validSubscribe, timestamp: String(validSubscribe.timestamp) },
    { ...validSubscribe, pubkey: validSubscribe.pubkey.toUpperCase() },
    { ...validSubscribe, wantData: 1 },
    { ...validSubscribe, namespaces: ['0', 10] },
    { ...validSubscribe, namespaces: [null, 10] },
    { ...validSubscribe, namespaces: [0, '0'] },
    { ...validSubscribe, namespaces: [0, 10.5] },
    { ...validSubscribe, namespaces: [0, Number.MAX_SAFE_INTEGER + 1] },
    { ...validSubscribe, namespaces: [-2_147_483_649, 0] },
    { ...validSubscribe, namespaces: [0, 2_147_483_648] },
    { ...validSubscribe, namespaces: [10, 0] },
    { ...validSubscribe, namespaces: [0, 0] },
    { ...validSubscribe, service: 1 },
    { ...validSubscribe, deviceToken: 12345 },
    { ...validSubscribe, encryptionKey: 12345 },
    { ...validSubscribe, appId: 1 },
    { ...validSubscribe, appVersion: 1 }
  ];
  for (const input of invalidSubscribe) {
    assert.throws(() => createPushSubscribeSignatureMessageV2(input), TypeError);
  }
  assert.ok(Buffer.isBuffer(createPushSubscribeSignatureMessageV2({
    ...validSubscribe,
    namespaces: [-2_147_483_648, 0, 2_147_483_647]
  })));

  const validUnsubscribe = {
    pubkey: pushSigningIdentity.sessionPubkey,
    timestamp: currentSigTs(),
    service: 'apns',
    deviceToken: 'canonicalizer-token'
  };
  for (const input of [
    { ...validUnsubscribe, timestamp: String(validUnsubscribe.timestamp) },
    { ...validUnsubscribe, pubkey: validUnsubscribe.pubkey.toUpperCase() },
    { ...validUnsubscribe, service: 1 },
    { ...validUnsubscribe, deviceToken: 12345 }
  ]) {
    assert.throws(() => createPushUnsubscribeSignatureMessageV2(input), TypeError);
  }
});

function isNoAuthRetrieveNamespace(namespace) {
  return namespace === -10 || (namespace < 0 && (-namespace % 20) === 1);
}

function createStorageRetrievePayload(overrides = {}) {
  const payload = { ...overrides };
  const namespace = payload.namespace === undefined ? undefined : Number(payload.namespace);
  if ((namespace === undefined || !isNoAuthRetrieveNamespace(namespace)) && payload.signature === undefined) {
    payload.signature = validPushSignature;
  }
  if (payload.signature !== undefined && payload.timestamp === undefined) {
    payload.timestamp = Date.now();
  }
  return payload;
}

function createSignedStorageStorePayload(identity, overrides = {}) {
  const payload = { ...overrides };
  const namespace = Number(payload.namespace ?? 0);
  const signatureTimestamp = Number(payload.sig_timestamp ?? payload.sigTimestamp ?? payload.timestamp ?? Date.now());

  return {
    pubkey: identity.directPubkey,
    timestamp: signatureTimestamp,
    ttl: 60_000,
    namespace,
    data: Buffer.from('signed-storage-message', 'utf8').toString('base64'),
    signature: identity.signStore(namespace, signatureTimestamp),
    ...payload
  };
}

function createSignedStorageRetrievePayload(identity, overrides = {}) {
  const payload = { ...overrides };
  const namespace = payload.namespace === undefined ? 0 : Number(payload.namespace);
  const timestamp = Number(payload.timestamp ?? Date.now());

  return {
    pubkey: identity.directPubkey,
    namespace,
    timestamp,
    signature: identity.signRetrieve(namespace, timestamp),
    ...payload
  };
}

function createSignedStorageGetExpiriesPayload(identity, overrides = {}) {
  const payload = { ...overrides };
  const timestamp = Number(payload.timestamp ?? Date.now());
  const messages = Array.isArray(payload.messages) ? payload.messages.map(value => String(value)) : [];

  return {
    pubkey: identity.directPubkey,
    timestamp,
    messages,
    signature: identity.signGetExpiries(timestamp, messages),
    ...payload
  };
}

function createSignedStorageExpireAllPayload(identity, overrides = {}) {
  const payload = { ...overrides };
  const namespace = payload.namespace ?? 0;
  const expiry = Number(payload.expiry ?? (Date.now() + 60_000));

  return {
    pubkey: identity.directPubkey,
    expiry,
    signature: identity.signExpireAll(namespace, expiry),
    ...payload
  };
}

function createSignedStorageExpirePayload(identity, overrides = {}) {
  const payload = { ...overrides };
  const messages = Array.isArray(payload.messages) ? payload.messages.map(value => String(value)) : [];
  const expiry = Array.isArray(payload.expiry)
    ? payload.expiry.map(value => Number(value))
    : Number(payload.expiry ?? (Date.now() + 60_000));
  const mode = payload.shorten === true ? 'shorten' : payload.extend === true ? 'extend' : '';

  return {
    pubkey: identity.directPubkey,
    messages,
    expiry,
    signature: identity.signExpire(mode, expiry, messages),
    ...payload
  };
}

function createSignedStorageDeletePayload(identity, overrides = {}) {
  const payload = { ...overrides };
  const messages = Array.isArray(payload.messages) ? payload.messages.map(value => String(value)) : [];

  return {
    pubkey: identity.directPubkey,
    messages,
    signature: identity.signDelete(messages),
    ...payload
  };
}

function createSignedStorageDeleteAllPayload(identity, overrides = {}) {
  const payload = { ...overrides };
  const namespace = payload.namespace ?? 0;
  const timestamp = Number(payload.timestamp ?? Date.now());

  return {
    pubkey: identity.directPubkey,
    timestamp,
    signature: identity.signDeleteAll(namespace, timestamp),
    ...payload
  };
}

function createSignedStorageDeleteBeforePayload(identity, overrides = {}) {
  const payload = { ...overrides };
  const namespace = payload.namespace ?? 0;
  const before = Number(payload.before ?? Date.now());

  return {
    pubkey: identity.directPubkey,
    before,
    signature: identity.signDeleteBefore(namespace, before),
    ...payload
  };
}

function normalizeSubaccountTokenValues(values) {
  const items = Array.isArray(values) ? values : [values];
  return items.map(value => typeof value === 'object' && value !== null && 'subaccount' in value ? value.subaccount : String(value));
}

function createSignedStorageRevokeSubaccountPayload(identity, overrides = {}) {
  const { revoke: providedRevoke, ...rest } = overrides;
  const timestamp = Number(rest.timestamp ?? Date.now());
  const revokeValues = normalizeSubaccountTokenValues(providedRevoke ?? []);
  const revoke = Array.isArray(providedRevoke) ? revokeValues : revokeValues[0];

  return {
    pubkey: identity.directPubkey,
    timestamp,
    revoke,
    signature: identity.signRevokeSubaccount(timestamp, revokeValues),
    ...rest
  };
}

function createSignedStorageUnrevokeSubaccountPayload(identity, overrides = {}) {
  const { unrevoke: providedUnrevoke, ...rest } = overrides;
  const timestamp = Number(rest.timestamp ?? Date.now());
  const unrevokeValues = normalizeSubaccountTokenValues(providedUnrevoke ?? []);
  const unrevoke = Array.isArray(providedUnrevoke) ? unrevokeValues : unrevokeValues[0];

  return {
    pubkey: identity.directPubkey,
    timestamp,
    unrevoke,
    signature: identity.signUnrevokeSubaccount(timestamp, unrevokeValues),
    ...rest
  };
}

function createSignedStorageRevokedSubaccountsPayload(identity, overrides = {}) {
  const payload = { ...overrides };
  const timestamp = Number(payload.timestamp ?? Date.now());

  return {
    pubkey: identity.directPubkey,
    timestamp,
    signature: identity.signRevokedSubaccounts(timestamp),
    ...payload
  };
}

async function storeSignedStorageMessage(mock, identity, overrides = {}) {
  const payload = createSignedStorageStorePayload(identity, overrides);
  const response = await fetch(`${mock.baseUrl}/storage/store`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(payload)
  });
  const body = await response.json();
  assert.equal(response.status, 200);
  return body;
}

test('storage store supports idempotency key replay', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'deep-mock-'));
  const mock = await startMockService({ port: randomPort(), stateDir });

  try {
    const payload = createStorageStorePayload({
      pubkey: '05abc',
      namespace: 11,
      timestamp: Date.now(),
      ttl: 60000,
      data: Buffer.from('hello', 'utf8').toString('base64'),
      idempotency_key: 'idem-1'
    });

    const firstResponse = await fetch(`${mock.baseUrl}/storage/store`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const first = await firstResponse.json();
    assert.equal(firstResponse.status, 200);
    assert.match(first.hash, /^[A-Za-z0-9_-]+$/);

    const secondResponse = await fetch(`${mock.baseUrl}/storage/store`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ ...payload, data: Buffer.from('hello-again', 'utf8').toString('base64') })
    });
    const second = await secondResponse.json();

    assert.equal(secondResponse.status, 200);
    assert.equal(second.hash, first.hash);
    assert.equal(second.idempotent, true);

    const retrieveResponse = await fetch(`${mock.baseUrl}/storage/retrieve`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(createStorageRetrievePayload({ pubkey: payload.pubkey, namespace: payload.namespace }))
    });
    const retrieved = await retrieveResponse.json();

    assert.equal(retrieveResponse.status, 200);
    assert.equal(retrieved.messages.length, 1);
    assert.equal(retrieved.messages[0].hash, first.hash);
  } finally {
    await mock.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('storage store requires signature for private namespaces', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'deep-mock-'));
  const mock = await startMockService({ port: randomPort(), stateDir });

  try {
    const response = await fetch(`${mock.baseUrl}/storage/store`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        pubkey: '05private-store',
        namespace: 42,
        timestamp: Date.now(),
        ttl: 60_000,
        data: Buffer.from('private-message', 'utf8').toString('base64')
      })
    });
    const body = await response.json();

    assert.equal(response.status, 401);
    assert.equal(body.message, 'store: signature required to store to namespace 42');
  } finally {
    await mock.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('storage store rejects namespaces outside the int16 range', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'deep-mock-'));
  const mock = await startMockService({ port: randomPort(), stateDir });

  try {
    const response = await fetch(`${mock.baseUrl}/storage/store`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(createStorageStorePayload({
        pubkey: '05namespace-range',
        namespace: 32768,
        timestamp: Date.now(),
        ttl: 60_000,
        data: Buffer.from('range-message', 'utf8').toString('base64')
      }))
    });
    const body = await response.json();

    assert.equal(response.status, 400);
    assert.equal(body.message, "invalid request: Invalid value given for 'namespace': value out of range");
  } finally {
    await mock.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('storage store rejects signed timestamps outside the tolerance window', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'deep-mock-'));
  const mock = await startMockService({ port: randomPort(), stateDir });

  try {
    const response = await fetch(`${mock.baseUrl}/storage/store`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(createStorageStorePayload({
        pubkey: '05store-old-timestamp',
        namespace: 42,
        timestamp: Date.now() - 61_000,
        ttl: 60_000,
        data: Buffer.from('old-store', 'utf8').toString('base64')
      }))
    });
    const body = await response.json();

    assert.equal(response.status, 406);
    assert.equal(body.message, 'store signature timestamp too far from current time');
  } finally {
    await mock.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('storage store rejects invalid signatures for verifiable identities', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'deep-mock-'));
  const mock = await startMockService({ port: randomPort(), stateDir });

  try {
    const payload = createSignedStorageStorePayload(storageSigningIdentity, {
      namespace: 42,
      timestamp: Date.now()
    });
    payload.signature = invalidateSignature(payload.signature);

    const response = await fetch(`${mock.baseUrl}/storage/store`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const body = await response.json();

    assert.equal(response.status, 401);
    assert.equal(body.message, 'store signature verification failed');
  } finally {
    await mock.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('storage store uses sig_timestamp for signature verification when provided', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'deep-mock-'));
  const mock = await startMockService({ port: randomPort(), stateDir });

  try {
    const timestamp = Date.now() - 100_000;
    const sigTimestamp = Date.now();
    const payload = createSignedStorageStorePayload(storageSigningIdentity, {
      namespace: 42,
      timestamp,
      sig_timestamp: sigTimestamp,
      signature: storageSigningIdentity.signStore(42, sigTimestamp)
    });

    const response = await fetch(`${mock.baseUrl}/storage/store`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const body = await response.json();

    assert.equal(response.status, 200);
    assert.equal(body.t, timestamp);
  } finally {
    await mock.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('storage subaccounts enforce read, write, delete, and any_prefix permissions', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'deep-mock-'));
  const mock = await startMockService({ port: randomPort(), stateDir });

  try {
    const initialStore = await storeSignedStorageMessage(mock, storageSigningIdentity, {
      namespace: 42,
      timestamp: Date.now(),
      data: Buffer.from('subaccount-permissions', 'utf8').toString('base64')
    });
    const hash = initialStore.hash;
    const readOnly = storageSigningIdentity.createSubaccount({ write: false });
    const noPermissions = storageSigningIdentity.createSubaccount({ read: false, write: false });
    const deleteCapable = storageSigningIdentity.createSubaccount({ delete: true });
    const anyPrefix = storageSigningIdentity.createSubaccount({ anyPrefix: true });
    const retrieveTimestamp = Date.now();

    const readOnlyRetrieveResponse = await fetch(`${mock.baseUrl}/storage/retrieve`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(withStorageSubaccount(createSignedStorageRetrievePayload(storageSigningIdentity, {
        namespace: 42,
        timestamp: retrieveTimestamp,
        signature: readOnly.signRetrieve(42, retrieveTimestamp)
      }), readOnly))
    });
    const readOnlyRetrieveBody = await readOnlyRetrieveResponse.json();

    assert.equal(readOnlyRetrieveResponse.status, 200);
    assert.equal(readOnlyRetrieveBody.messages.length, 1);
    assert.equal(readOnlyRetrieveBody.messages[0].hash, hash);

    const noPermissionsRetrieveResponse = await fetch(`${mock.baseUrl}/storage/retrieve`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(withStorageSubaccount(createSignedStorageRetrievePayload(storageSigningIdentity, {
        namespace: 42,
        timestamp: retrieveTimestamp + 1,
        signature: noPermissions.signRetrieve(42, retrieveTimestamp + 1)
      }), noPermissions))
    });
    const noPermissionsRetrieveBody = await noPermissionsRetrieveResponse.json();

    assert.equal(noPermissionsRetrieveResponse.status, 401);
    assert.equal(noPermissionsRetrieveBody.message, 'retrieve signature verification failed');

    const alternatePubkey = `99${storageSigningIdentity.directPubkey.slice(2)}`;
    const readOnlyAlternateResponse = await fetch(`${mock.baseUrl}/storage/retrieve`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(withStorageSubaccount(createSignedStorageRetrievePayload(storageSigningIdentity, {
        pubkey: alternatePubkey,
        namespace: 42,
        timestamp: retrieveTimestamp + 2,
        signature: readOnly.signRetrieve(42, retrieveTimestamp + 2)
      }), readOnly))
    });
    const readOnlyAlternateBody = await readOnlyAlternateResponse.json();

    assert.equal(readOnlyAlternateResponse.status, 401);
    assert.equal(readOnlyAlternateBody.message, 'retrieve signature verification failed');

    const anyPrefixRetrieveResponse = await fetch(`${mock.baseUrl}/storage/retrieve`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(withStorageSubaccount(createSignedStorageRetrievePayload(storageSigningIdentity, {
        pubkey: alternatePubkey,
        namespace: 42,
        timestamp: retrieveTimestamp + 3,
        signature: anyPrefix.signRetrieve(42, retrieveTimestamp + 3)
      }), anyPrefix))
    });
    const anyPrefixRetrieveBody = await anyPrefixRetrieveResponse.json();

    assert.equal(anyPrefixRetrieveResponse.status, 200);
    assert.ok(Array.isArray(anyPrefixRetrieveBody.messages));

    const readOnlyStoreTimestamp = Date.now();
    const readOnlyStoreResponse = await fetch(`${mock.baseUrl}/storage/store`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(withStorageSubaccount(createSignedStorageStorePayload(storageSigningIdentity, {
        namespace: 42,
        timestamp: readOnlyStoreTimestamp,
        signature: readOnly.signStore(42, readOnlyStoreTimestamp)
      }), readOnly))
    });
    const readOnlyStoreBody = await readOnlyStoreResponse.json();

    assert.equal(readOnlyStoreResponse.status, 401);
    assert.equal(readOnlyStoreBody.message, 'store signature verification failed');

    const deleteCapableStoreTimestamp = Date.now() + 1;
    const deleteCapableStoreResponse = await fetch(`${mock.baseUrl}/storage/store`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(withStorageSubaccount(createSignedStorageStorePayload(storageSigningIdentity, {
        namespace: 42,
        timestamp: deleteCapableStoreTimestamp,
        signature: deleteCapable.signStore(42, deleteCapableStoreTimestamp)
      }), deleteCapable))
    });

    assert.equal(deleteCapableStoreResponse.status, 200);

    const readOnlyDeleteResponse = await fetch(`${mock.baseUrl}/storage/delete`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(withStorageSubaccount(createSignedStorageDeletePayload(storageSigningIdentity, {
        messages: [hash],
        signature: readOnly.signDelete([hash])
      }), readOnly))
    });
    const readOnlyDeleteBody = await readOnlyDeleteResponse.json();

    assert.equal(readOnlyDeleteResponse.status, 401);
    assert.equal(readOnlyDeleteBody.message, 'delete_msgs signature verification failed');

    const deleteCapableDeleteResponse = await fetch(`${mock.baseUrl}/storage/delete`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(withStorageSubaccount(createSignedStorageDeletePayload(storageSigningIdentity, {
        messages: [hash],
        signature: deleteCapable.signDelete([hash])
      }), deleteCapable))
    });
    const deleteCapableDeleteBody = await deleteCapableDeleteResponse.json();

    assert.equal(deleteCapableDeleteResponse.status, 200);
    assert.deepEqual(deleteCapableDeleteBody.swarm[compatRelayId].deleted, [hash]);
  } finally {
    await mock.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('storage expire treats write-only subaccounts as extend-only and rejects shorten', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'deep-mock-'));
  const mock = await startMockService({ port: randomPort(), stateDir });

  try {
    const baseTimestamp = Date.now();
    const first = await storeSignedStorageMessage(mock, storageSigningIdentity, {
      namespace: 42,
      timestamp: baseTimestamp,
      ttl: 20_000,
      data: Buffer.from('expire-one', 'utf8').toString('base64')
    });
    const second = await storeSignedStorageMessage(mock, storageSigningIdentity, {
      namespace: 42,
      timestamp: baseTimestamp + 1,
      ttl: 20_000,
      data: Buffer.from('expire-two', 'utf8').toString('base64')
    });
    const third = await storeSignedStorageMessage(mock, storageSigningIdentity, {
      namespace: 42,
      timestamp: baseTimestamp + 2,
      ttl: 20_000,
      data: Buffer.from('expire-three', 'utf8').toString('base64')
    });
    const writeOnly = storageSigningIdentity.createSubaccount();

    const laterExpiry = baseTimestamp + 120_000;
    const laterExpireResponse = await fetch(`${mock.baseUrl}/storage/expire`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(withStorageSubaccount(createSignedStorageExpirePayload(storageSigningIdentity, {
        messages: [first.hash],
        expiry: laterExpiry,
        signature: writeOnly.signExpire('', laterExpiry, [first.hash])
      }), writeOnly))
    });
    const laterExpireBody = await laterExpireResponse.json();

    assert.equal(laterExpireResponse.status, 200);
    assert.equal(laterExpireBody.swarm[compatRelayId].expiry, laterExpiry);
    assert.deepEqual(laterExpireBody.swarm[compatRelayId].updated, [first.hash]);

    const mixedExpiry = baseTimestamp + 60_000;
    const mixedExpireResponse = await fetch(`${mock.baseUrl}/storage/expire`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(withStorageSubaccount(createSignedStorageExpirePayload(storageSigningIdentity, {
        messages: [first.hash, second.hash, third.hash],
        expiry: mixedExpiry,
        signature: writeOnly.signExpire('', mixedExpiry, [first.hash, second.hash, third.hash])
      }), writeOnly))
    });
    const mixedExpireBody = await mixedExpireResponse.json();

    assert.equal(mixedExpireResponse.status, 200);
    assert.equal(mixedExpireBody.swarm[compatRelayId].expiry, mixedExpiry);
    assert.deepEqual(mixedExpireBody.swarm[compatRelayId].updated, [second.hash, third.hash].sort());

    const shortenExpiry = baseTimestamp + 5_000;
    const shortenResponse = await fetch(`${mock.baseUrl}/storage/expire`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(withStorageSubaccount(createSignedStorageExpirePayload(storageSigningIdentity, {
        messages: [first.hash],
        expiry: shortenExpiry,
        shorten: true,
        signature: writeOnly.signExpire('shorten', shortenExpiry, [first.hash])
      }), writeOnly))
    });
    const shortenBody = await shortenResponse.json();

    assert.equal(shortenResponse.status, 400);
    assert.equal(shortenBody.message, 'expire: shorten parameter cannot be used with this subaccount token (missing delete access)');
  } finally {
    await mock.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('storage revoke lifecycle blocks revoked subaccounts except for unrevocable namespaces', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'deep-mock-'));
  const mock = await startMockService({ port: randomPort(), stateDir });

  try {
    const baseTimestamp = Date.now();
    const privateStore = await storeSignedStorageMessage(mock, storageSigningIdentity, {
      namespace: 42,
      timestamp: baseTimestamp,
      data: Buffer.from('revoked-private', 'utf8').toString('base64')
    });
    const unrevocableStore = await storeSignedStorageMessage(mock, storageSigningIdentity, {
      namespace: -11,
      timestamp: baseTimestamp + 1,
      data: Buffer.from('revoked-unrevocable', 'utf8').toString('base64')
    });
    const subaccount = storageSigningIdentity.createSubaccount();

    const initialRetrieveResponse = await fetch(`${mock.baseUrl}/storage/retrieve`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(withStorageSubaccount(createSignedStorageRetrievePayload(storageSigningIdentity, {
        namespace: 42,
        timestamp: baseTimestamp + 2,
        signature: subaccount.signRetrieve(42, baseTimestamp + 2)
      }), subaccount))
    });
    const initialRetrieveBody = await initialRetrieveResponse.json();

    assert.equal(initialRetrieveResponse.status, 200);
    assert.equal(initialRetrieveBody.messages.length, 1);
    assert.equal(initialRetrieveBody.messages[0].hash, privateStore.hash);

    const emptyRevocationListResponse = await fetch(`${mock.baseUrl}/storage/revoked_subaccounts`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(createSignedStorageRevokedSubaccountsPayload(storageSigningIdentity, {
        timestamp: baseTimestamp + 3
      }))
    });
    const emptyRevocationListBody = await emptyRevocationListResponse.json();

    assert.equal(emptyRevocationListResponse.status, 200);
    assert.deepEqual(emptyRevocationListBody.revoked_subaccounts, []);

    const revokeResponse = await fetch(`${mock.baseUrl}/storage/revoke_subaccount`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(createSignedStorageRevokeSubaccountPayload(storageSigningIdentity, {
        timestamp: baseTimestamp + 4,
        revoke: subaccount
      }))
    });
    const revokeBody = await revokeResponse.json();

    assert.equal(revokeResponse.status, 200);
    assert.equal(revokeBody.swarm[compatRelayId].count, 1);

    const revokedRetrieveResponse = await fetch(`${mock.baseUrl}/storage/retrieve`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(withStorageSubaccount(createSignedStorageRetrievePayload(storageSigningIdentity, {
        namespace: 42,
        timestamp: baseTimestamp + 5,
        signature: subaccount.signRetrieve(42, baseTimestamp + 5)
      }), subaccount))
    });
    const revokedRetrieveBody = await revokedRetrieveResponse.json();

    assert.equal(revokedRetrieveResponse.status, 401);
    assert.equal(revokedRetrieveBody.message, 'retrieve signature verification failed');

    const revokedListResponse = await fetch(`${mock.baseUrl}/storage/revoked_subaccounts`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(createSignedStorageRevokedSubaccountsPayload(storageSigningIdentity, {
        timestamp: baseTimestamp + 6
      }))
    });
    const revokedListBody = await revokedListResponse.json();

    assert.equal(revokedListResponse.status, 200);
    assert.deepEqual(revokedListBody.revoked_subaccounts, [subaccount.subaccount]);

    const unrevocableRetrieveResponse = await fetch(`${mock.baseUrl}/storage/retrieve`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(withStorageSubaccount(createSignedStorageRetrievePayload(storageSigningIdentity, {
        namespace: -11,
        timestamp: baseTimestamp + 7,
        signature: subaccount.signRetrieve(-11, baseTimestamp + 7)
      }), subaccount))
    });
    const unrevocableRetrieveBody = await unrevocableRetrieveResponse.json();

    assert.equal(unrevocableRetrieveResponse.status, 200);
    assert.equal(unrevocableRetrieveBody.messages.length, 1);
    assert.equal(unrevocableRetrieveBody.messages[0].hash, unrevocableStore.hash);

    const unrevokeResponse = await fetch(`${mock.baseUrl}/storage/unrevoke_subaccount`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(createSignedStorageUnrevokeSubaccountPayload(storageSigningIdentity, {
        timestamp: baseTimestamp + 8,
        unrevoke: subaccount
      }))
    });
    const unrevokeBody = await unrevokeResponse.json();

    assert.equal(unrevokeResponse.status, 200);
    assert.equal(unrevokeBody.swarm[compatRelayId].count, 1);

    const restoredRetrieveResponse = await fetch(`${mock.baseUrl}/storage/retrieve`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(withStorageSubaccount(createSignedStorageRetrievePayload(storageSigningIdentity, {
        namespace: 42,
        timestamp: baseTimestamp + 9,
        signature: subaccount.signRetrieve(42, baseTimestamp + 9)
      }), subaccount))
    });
    const restoredRetrieveBody = await restoredRetrieveResponse.json();

    assert.equal(restoredRetrieveResponse.status, 200);
    assert.equal(restoredRetrieveBody.messages.length, 1);
    assert.equal(restoredRetrieveBody.messages[0].hash, privateStore.hash);

    const finalRevocationListResponse = await fetch(`${mock.baseUrl}/storage/revoked_subaccounts`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(createSignedStorageRevokedSubaccountsPayload(storageSigningIdentity, {
        timestamp: baseTimestamp + 10
      }))
    });
    const finalRevocationListBody = await finalRevocationListResponse.json();

    assert.equal(finalRevocationListResponse.status, 200);
    assert.deepEqual(finalRevocationListBody.revoked_subaccounts, []);
  } finally {
    await mock.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('storage revoke_subaccount keeps only the most recent 50 revocations', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'deep-mock-'));
  const mock = await startMockService({ port: randomPort(), stateDir });

  try {
    const baseTimestamp = Date.now();
    const stored = await storeSignedStorageMessage(mock, storageSigningIdentity, {
      namespace: 42,
      timestamp: baseTimestamp,
      data: Buffer.from('retention-message', 'utf8').toString('base64')
    });
    const firstSubaccount = storageSigningIdentity.createSubaccount();

    const firstRevokeResponse = await fetch(`${mock.baseUrl}/storage/revoke_subaccount`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(createSignedStorageRevokeSubaccountPayload(storageSigningIdentity, {
        timestamp: baseTimestamp + 1,
        revoke: firstSubaccount
      }))
    });
    const firstRevokeBody = await firstRevokeResponse.json();

    assert.equal(firstRevokeResponse.status, 200);
    assert.equal(firstRevokeBody.swarm[compatRelayId].count, 1);

    const additionalSubaccounts = Array.from({ length: 49 }, () => storageSigningIdentity.createSubaccount());
    const bulkRevokeResponse = await fetch(`${mock.baseUrl}/storage/revoke_subaccount`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(createSignedStorageRevokeSubaccountPayload(storageSigningIdentity, {
        timestamp: baseTimestamp + 1,
        revoke: additionalSubaccounts
      }))
    });
    const bulkRevokeBody = await bulkRevokeResponse.json();

    assert.equal(bulkRevokeResponse.status, 200);
    assert.equal(bulkRevokeBody.swarm[compatRelayId].count, 49);

    const blockedRetrieveResponse = await fetch(`${mock.baseUrl}/storage/retrieve`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(withStorageSubaccount(createSignedStorageRetrievePayload(storageSigningIdentity, {
        namespace: 42,
        timestamp: baseTimestamp + 2,
        signature: firstSubaccount.signRetrieve(42, baseTimestamp + 2)
      }), firstSubaccount))
    });
    const blockedRetrieveBody = await blockedRetrieveResponse.json();

    assert.equal(blockedRetrieveResponse.status, 401);
    assert.equal(blockedRetrieveBody.message, 'retrieve signature verification failed');

    const newestSubaccount = storageSigningIdentity.createSubaccount();
    const overflowRevokeResponse = await fetch(`${mock.baseUrl}/storage/revoke_subaccount`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(createSignedStorageRevokeSubaccountPayload(storageSigningIdentity, {
        timestamp: baseTimestamp + 1,
        revoke: newestSubaccount
      }))
    });
    const overflowRevokeBody = await overflowRevokeResponse.json();

    assert.equal(overflowRevokeResponse.status, 200);
    assert.equal(overflowRevokeBody.swarm[compatRelayId].count, 1);

    const restoredRetrieveResponse = await fetch(`${mock.baseUrl}/storage/retrieve`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(withStorageSubaccount(createSignedStorageRetrievePayload(storageSigningIdentity, {
        namespace: 42,
        timestamp: baseTimestamp + 3,
        signature: firstSubaccount.signRetrieve(42, baseTimestamp + 3)
      }), firstSubaccount))
    });
    const restoredRetrieveBody = await restoredRetrieveResponse.json();

    assert.equal(restoredRetrieveResponse.status, 200);
    assert.equal(restoredRetrieveBody.messages.length, 1);
    assert.equal(restoredRetrieveBody.messages[0].hash, stored.hash);
  } finally {
    await mock.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('storage revoke lifecycle endpoints reject invalid signatures and stale timestamps', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'deep-mock-'));
  const mock = await startMockService({ port: randomPort(), stateDir });

  try {
    const timestamp = Date.now();
    const subaccount = storageSigningIdentity.createSubaccount();

    const revokePayload = createSignedStorageRevokeSubaccountPayload(storageSigningIdentity, {
      timestamp,
      revoke: subaccount
    });
    revokePayload.signature = invalidateSignature(revokePayload.signature);

    const revokeResponse = await fetch(`${mock.baseUrl}/storage/revoke_subaccount`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(revokePayload)
    });
    const revokeBody = await revokeResponse.json();

    assert.equal(revokeResponse.status, 401);
    assert.equal(revokeBody.message, 'revoke_subaccount signature verification failed');

    const unrevokePayload = createSignedStorageUnrevokeSubaccountPayload(storageSigningIdentity, {
      timestamp,
      unrevoke: subaccount
    });
    unrevokePayload.signature = invalidateSignature(unrevokePayload.signature);

    const unrevokeResponse = await fetch(`${mock.baseUrl}/storage/unrevoke_subaccount`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(unrevokePayload)
    });
    const unrevokeBody = await unrevokeResponse.json();

    assert.equal(unrevokeResponse.status, 401);
    assert.equal(unrevokeBody.message, 'unrevoke_subaccount signature verification failed');

    const revokedSubaccountsResponse = await fetch(`${mock.baseUrl}/storage/revoked_subaccounts`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(createSignedStorageRevokedSubaccountsPayload(storageSigningIdentity, {
        timestamp: Date.now() - 61_000,
        signature: storageSigningIdentity.signRevokedSubaccounts(Date.now() - 61_000)
      }))
    });
    const revokedSubaccountsBody = await revokedSubaccountsResponse.json();

    assert.equal(revokedSubaccountsResponse.status, 406);
    assert.equal(revokedSubaccountsBody.message, 'revoked_subaccounts timestamp too far from current time');
  } finally {
    await mock.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('storage retrieve prunes expired messages', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'deep-mock-'));
  const mock = await startMockService({ port: randomPort(), stateDir });

  try {
    const storeResponse = await fetch(`${mock.baseUrl}/storage/store`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(createStorageStorePayload({
        pubkey: '05expired',
        namespace: 22,
        timestamp: Date.now() - 10_000,
        ttl: 1,
        data: Buffer.from('expires-fast', 'utf8').toString('base64')
      }))
    });

    assert.equal(storeResponse.status, 200);

    const retrieveResponse = await fetch(`${mock.baseUrl}/storage/retrieve`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(createStorageRetrievePayload({ pubkey: '05expired', namespace: 22 }))
    });
    const retrieved = await retrieveResponse.json();

    assert.equal(retrieveResponse.status, 200);
    assert.equal(retrieved.messages.length, 0);
  } finally {
    await mock.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('storage retrieve requires signature outside noauth namespaces', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'deep-mock-'));
  const mock = await startMockService({ port: randomPort(), stateDir });

  try {
    const storeResponse = await fetch(`${mock.baseUrl}/storage/store`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        pubkey: '05retrieve-auth',
        namespace: 0,
        timestamp: Date.now(),
        ttl: 60_000,
        data: Buffer.from('retrieve-auth', 'utf8').toString('base64')
      })
    });
    assert.equal(storeResponse.status, 200);

    const retrieveResponse = await fetch(`${mock.baseUrl}/storage/retrieve`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ pubkey: '05retrieve-auth', namespace: 0 })
    });
    const retrieved = await retrieveResponse.json();

    assert.equal(retrieveResponse.status, 401);
    assert.equal(retrieved.message, 'retrieve: request signature required');
  } finally {
    await mock.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('storage retrieve allows public outbox reads without signature', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'deep-mock-'));
  const mock = await startMockService({ port: randomPort(), stateDir });

  try {
    const storeResponse = await fetch(`${mock.baseUrl}/storage/store`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(createStorageStorePayload({
        pubkey: '05retrieve-public-outbox',
        namespace: -1,
        timestamp: Date.now(),
        ttl: 60_000,
        data: Buffer.from('public-outbox', 'utf8').toString('base64')
      }))
    });
    const stored = await storeResponse.json();
    assert.equal(storeResponse.status, 200);

    const retrieveResponse = await fetch(`${mock.baseUrl}/storage/retrieve`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ pubkey: '05retrieve-public-outbox', namespace: -1 })
    });
    const retrieved = await retrieveResponse.json();

    assert.equal(retrieveResponse.status, 200);
    assert.equal(retrieved.messages.length, 1);
    assert.equal(retrieved.messages[0].hash, stored.hash);
  } finally {
    await mock.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('storage retrieve rejects timestamp without signature', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'deep-mock-'));
  const mock = await startMockService({ port: randomPort(), stateDir });

  try {
    const response = await fetch(`${mock.baseUrl}/storage/retrieve`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        pubkey: '05retrieve-missing-signature',
        namespace: -1,
        timestamp: Date.now()
      })
    });
    const body = await response.json();

    assert.equal(response.status, 400);
    assert.equal(body.message, "invalid request: Required field 'signature' missing");
  } finally {
    await mock.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('storage retrieve rejects signed timestamps outside the tolerance window', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'deep-mock-'));
  const mock = await startMockService({ port: randomPort(), stateDir });

  try {
    const response = await fetch(`${mock.baseUrl}/storage/retrieve`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(createStorageRetrievePayload({
        pubkey: '05retrieve-old-timestamp',
        namespace: 0,
        timestamp: Date.now() - 61_000
      }))
    });
    const body = await response.json();

    assert.equal(response.status, 406);
    assert.equal(body.message, 'retrieve timestamp too far from current time');
  } finally {
    await mock.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('storage retrieve rejects invalid signatures for verifiable identities', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'deep-mock-'));
  const mock = await startMockService({ port: randomPort(), stateDir });

  try {
    const storePayload = createSignedStorageStorePayload(storageSigningIdentity, {
      namespace: 42,
      timestamp: Date.now(),
      data: Buffer.from('signed-retrieve-message', 'utf8').toString('base64')
    });
    const storeResponse = await fetch(`${mock.baseUrl}/storage/store`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(storePayload)
    });
    assert.equal(storeResponse.status, 200);

    const retrievePayload = createSignedStorageRetrievePayload(storageSigningIdentity, {
      namespace: 42,
      timestamp: Date.now()
    });
    retrievePayload.signature = invalidateSignature(retrievePayload.signature);

    const response = await fetch(`${mock.baseUrl}/storage/retrieve`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(retrievePayload)
    });
    const body = await response.json();

    assert.equal(response.status, 401);
    assert.equal(body.message, 'retrieve signature verification failed');
  } finally {
    await mock.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('storage get_expiries returns expirations for existing hashes and omits missing ones', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'deep-mock-'));
  const mock = await startMockService({ port: randomPort(), stateDir });

  try {
    const pubkey = '05expiry-check';
    const timestamp = Date.now();
    const ttl = 60_000;
    const storeResponse = await fetch(`${mock.baseUrl}/storage/store`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(createStorageStorePayload({
        pubkey,
        namespace: 9,
        timestamp,
        ttl,
        data: Buffer.from('expiry-message', 'utf8').toString('base64')
      }))
    });
    const stored = await storeResponse.json();
    assert.equal(storeResponse.status, 200);

    const expiriesResponse = await fetch(`${mock.baseUrl}/storage/get_expiries`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        pubkey,
        messages: [stored.hash, 'missing-hash'],
        timestamp: Date.now(),
        signature: validPushSignature
      })
    });
    const expiries = await expiriesResponse.json();

    assert.equal(expiriesResponse.status, 200);
    assert.deepEqual(expiries.expiries, {
      [stored.hash]: timestamp + ttl
    });
  } finally {
    await mock.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('storage get_expiries requires pubkey, messages, timestamp, and signature', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'deep-mock-'));
  const mock = await startMockService({ port: randomPort(), stateDir });

  try {
    const response = await fetch(`${mock.baseUrl}/storage/get_expiries`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ pubkey: '05missing', messages: ['hash-only'] })
    });
    const body = await response.json();

    assert.equal(response.status, 400);
    assert.equal(body.error, 'invalid-request');
  } finally {
    await mock.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('storage get_expiries rejects timestamps outside the Session tolerance window', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'deep-mock-'));
  const mock = await startMockService({ port: randomPort(), stateDir });

  try {
    const response = await fetch(`${mock.baseUrl}/storage/get_expiries`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(createSignedStorageGetExpiriesPayload(storageSigningIdentity, {
        timestamp: Date.now() - 61_000,
        messages: ['hash-1']
      }))
    });
    const body = await response.json();

    assert.equal(response.status, 406);
    assert.equal(body.message, 'get_expiries timestamp too far from current time');
  } finally {
    await mock.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('storage get_expiries rejects invalid signatures for verifiable identities', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'deep-mock-'));
  const mock = await startMockService({ port: randomPort(), stateDir });

  try {
    const stored = await storeSignedStorageMessage(mock, storageSigningIdentity, {
      namespace: 42,
      timestamp: Date.now(),
      data: Buffer.from('expiry-signed-message', 'utf8').toString('base64')
    });

    const payload = createSignedStorageGetExpiriesPayload(storageSigningIdentity, {
      timestamp: Date.now(),
      messages: [stored.hash]
    });
    payload.signature = invalidateSignature(payload.signature);

    const response = await fetch(`${mock.baseUrl}/storage/get_expiries`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const body = await response.json();

    assert.equal(response.status, 401);
    assert.equal(body.message, 'get_expiries signature verification failed');
  } finally {
    await mock.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('storage expire_all shortens only messages with later expirations', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'deep-mock-'));
  const mock = await startMockService({ port: randomPort(), stateDir });

  try {
    const pubkey = '05expire-all';
    const firstTimestamp = Date.now();
    const secondTimestamp = firstTimestamp + 1000;
    const ttl = 60_000;

    const firstStoreResponse = await fetch(`${mock.baseUrl}/storage/store`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(createStorageStorePayload({
        pubkey,
        namespace: 4,
        timestamp: firstTimestamp,
        ttl,
        data: Buffer.from('expire-first', 'utf8').toString('base64')
      }))
    });
    const firstStore = await firstStoreResponse.json();
    assert.equal(firstStoreResponse.status, 200);

    const secondStoreResponse = await fetch(`${mock.baseUrl}/storage/store`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(createStorageStorePayload({
        pubkey,
        namespace: 4,
        timestamp: secondTimestamp,
        ttl,
        data: Buffer.from('expire-second', 'utf8').toString('base64')
      }))
    });
    const secondStore = await secondStoreResponse.json();
    assert.equal(secondStoreResponse.status, 200);

    const targetExpiry = firstTimestamp + ttl;
    const expireResponse = await fetch(`${mock.baseUrl}/storage/expire_all`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        pubkey,
        expiry: targetExpiry,
        signature: validPushSignature
      })
    });
    const expired = await expireResponse.json();

    assert.equal(expireResponse.status, 200);
    assert.equal(expired.swarm[compatRelayId].expiry, targetExpiry);
    assert.deepEqual(expired.swarm[compatRelayId].updated, [secondStore.hash]);

    const expiriesResponse = await fetch(`${mock.baseUrl}/storage/get_expiries`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        pubkey,
        messages: [firstStore.hash, secondStore.hash],
        timestamp: Date.now(),
        signature: validPushSignature
      })
    });
    const expiries = await expiriesResponse.json();

    assert.equal(expiriesResponse.status, 200);
    assert.deepEqual(expiries.expiries, {
      [firstStore.hash]: targetExpiry,
      [secondStore.hash]: targetExpiry
    });
  } finally {
    await mock.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('storage expire_all rejects expiries in the past', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'deep-mock-'));
  const mock = await startMockService({ port: randomPort(), stateDir });

  try {
    const response = await fetch(`${mock.baseUrl}/storage/expire_all`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        pubkey: '05expire-stale',
        expiry: Date.now() - 120_000,
        signature: validPushSignature
      })
    });
    const body = await response.json();

    assert.equal(response.status, 406);
    assert.equal(body.message, 'expire_all timestamp should be >= current time');
  } finally {
    await mock.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('storage expire_all rejects invalid signatures for verifiable identities', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'deep-mock-'));
  const mock = await startMockService({ port: randomPort(), stateDir });

  try {
    await storeSignedStorageMessage(mock, storageSigningIdentity, {
      namespace: 42,
      timestamp: Date.now(),
      data: Buffer.from('expire-all-signed-message', 'utf8').toString('base64')
    });

    const payload = createSignedStorageExpireAllPayload(storageSigningIdentity, {
      expiry: Date.now() + 30_000
    });
    payload.signature = invalidateSignature(payload.signature);

    const response = await fetch(`${mock.baseUrl}/storage/expire_all`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const body = await response.json();

    assert.equal(response.status, 401);
    assert.equal(body.message, 'expire_all signature verification failed');
  } finally {
    await mock.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('storage expire updates requested hashes and ignores missing ones', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'deep-mock-'));
  const mock = await startMockService({ port: randomPort(), stateDir });

  try {
    const pubkey = '05expire-selected';
    const timestamp = Date.now();
    const firstStoreResponse = await fetch(`${mock.baseUrl}/storage/store`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(createStorageStorePayload({
        pubkey,
        namespace: 4,
        timestamp,
        ttl: 60_000,
        data: Buffer.from('expire-a', 'utf8').toString('base64')
      }))
    });
    const firstStore = await firstStoreResponse.json();
    assert.equal(firstStoreResponse.status, 200);

    const secondStoreResponse = await fetch(`${mock.baseUrl}/storage/store`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(createStorageStorePayload({
        pubkey,
        namespace: 4,
        timestamp: timestamp + 1000,
        ttl: 60_000,
        data: Buffer.from('expire-b', 'utf8').toString('base64')
      }))
    });
    const secondStore = await secondStoreResponse.json();
    assert.equal(secondStoreResponse.status, 200);

    const targetExpiry = timestamp + 45_000;
    const response = await fetch(`${mock.baseUrl}/storage/expire`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        pubkey,
        messages: [secondStore.hash, 'missing-hash', firstStore.hash],
        expiry: targetExpiry,
        signature: validPushSignature
      })
    });
    const body = await response.json();

    assert.equal(response.status, 200);
    assert.equal(body.swarm[compatRelayId].expiry, targetExpiry);
    assert.deepEqual(body.swarm[compatRelayId].updated, [firstStore.hash, secondStore.hash]);

    const expiriesResponse = await fetch(`${mock.baseUrl}/storage/get_expiries`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        pubkey,
        messages: [firstStore.hash, secondStore.hash],
        timestamp: Date.now(),
        signature: validPushSignature
      })
    });
    const expiries = await expiriesResponse.json();

    assert.equal(expiriesResponse.status, 200);
    assert.deepEqual(expiries.expiries, {
      [firstStore.hash]: targetExpiry,
      [secondStore.hash]: targetExpiry
    });
  } finally {
    await mock.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('storage expire shorten reports unchanged hashes that are already earlier', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'deep-mock-'));
  const mock = await startMockService({ port: randomPort(), stateDir });

  try {
    const pubkey = '05expire-shorten';
    const timestamp = Date.now();
    const firstTtl = 30_000;
    const secondTtl = 60_000;

    const firstStoreResponse = await fetch(`${mock.baseUrl}/storage/store`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(createStorageStorePayload({
        pubkey,
        namespace: 4,
        timestamp,
        ttl: firstTtl,
        data: Buffer.from('shorten-a', 'utf8').toString('base64')
      }))
    });
    const firstStore = await firstStoreResponse.json();
    assert.equal(firstStoreResponse.status, 200);

    const secondStoreResponse = await fetch(`${mock.baseUrl}/storage/store`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(createStorageStorePayload({
        pubkey,
        namespace: 4,
        timestamp: timestamp + 1000,
        ttl: secondTtl,
        data: Buffer.from('shorten-b', 'utf8').toString('base64')
      }))
    });
    const secondStore = await secondStoreResponse.json();
    assert.equal(secondStoreResponse.status, 200);

    const targetExpiry = timestamp + firstTtl;
    const response = await fetch(`${mock.baseUrl}/storage/expire`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        pubkey,
        messages: [firstStore.hash, secondStore.hash, 'missing-hash'],
        expiry: targetExpiry,
        shorten: true,
        signature: validPushSignature
      })
    });
    const body = await response.json();

    assert.equal(response.status, 200);
    assert.deepEqual(body.swarm[compatRelayId].updated, [secondStore.hash]);
    assert.deepEqual(body.swarm[compatRelayId].unchanged, {
      [firstStore.hash]: targetExpiry
    });
  } finally {
    await mock.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('storage expire extend clamps to the storage max ttl window', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'deep-mock-'));
  const mock = await startMockService({ port: randomPort(), stateDir });

  try {
    const pubkey = '05expire-extend';
    const timestamp = Date.now();
    const storeResponse = await fetch(`${mock.baseUrl}/storage/store`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(createStorageStorePayload({
        pubkey,
        namespace: 4,
        timestamp,
        ttl: 60_000,
        data: Buffer.from('extend-a', 'utf8').toString('base64')
      }))
    });
    const stored = await storeResponse.json();
    assert.equal(storeResponse.status, 200);

    const requestedExpiry = timestamp + 31 * 24 * 60 * 60 * 1000;
    const beforeExpire = Date.now();
    const response = await fetch(`${mock.baseUrl}/storage/expire`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        pubkey,
        messages: [stored.hash],
        expiry: requestedExpiry,
        extend: true,
        signature: validPushSignature
      })
    });
    const afterExpire = Date.now();
    const body = await response.json();

    assert.equal(response.status, 200);
    assert.deepEqual(body.swarm[compatRelayId].updated, [stored.hash]);
    assert.equal(body.swarm[compatRelayId].unchanged && Object.keys(body.swarm[compatRelayId].unchanged).length, 0);

    const minExpectedExpiry = beforeExpire + 30 * 24 * 60 * 60 * 1000;
    const maxExpectedExpiry = afterExpire + 30 * 24 * 60 * 60 * 1000;
    assert.ok(body.swarm[compatRelayId].expiry >= minExpectedExpiry);
    assert.ok(body.swarm[compatRelayId].expiry <= maxExpectedExpiry);

    const expiriesResponse = await fetch(`${mock.baseUrl}/storage/get_expiries`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        pubkey,
        messages: [stored.hash],
        timestamp: Date.now(),
        signature: validPushSignature
      })
    });
    const expiries = await expiriesResponse.json();

    assert.equal(expiriesResponse.status, 200);
    assert.equal(expiries.expiries[stored.hash], body.swarm[compatRelayId].expiry);
  } finally {
    await mock.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('storage expire rejects mutually exclusive extend and shorten flags', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'deep-mock-'));
  const mock = await startMockService({ port: randomPort(), stateDir });

  try {
    const response = await fetch(`${mock.baseUrl}/storage/expire`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        pubkey: '05expire-invalid',
        messages: ['hash'],
        expiry: Date.now() + 60_000,
        extend: true,
        shorten: true,
        signature: validPushSignature
      })
    });
    const body = await response.json();

    assert.equal(response.status, 400);
    assert.equal(body.message, 'extend and shorten are mutually exclusive');
  } finally {
    await mock.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('storage expire accepts per-message expiry arrays and returns sorted updated expiries', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'deep-mock-'));
  const mock = await startMockService({ port: randomPort(), stateDir });

  try {
    const pubkey = '05expire-multi';
    const baseTimestamp = Date.now();
    const storePayloads = [
      { timestamp: baseTimestamp, ttl: 60_000, data: 'multi-a' },
      { timestamp: baseTimestamp + 1_000, ttl: 60_000, data: 'multi-b' },
      { timestamp: baseTimestamp + 2_000, ttl: 60_000, data: 'multi-c' }
    ];

    const stored = [];
    for (const payload of storePayloads) {
      const response = await fetch(`${mock.baseUrl}/storage/store`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(createStorageStorePayload({
          pubkey,
          namespace: 4,
          timestamp: payload.timestamp,
          ttl: payload.ttl,
          data: Buffer.from(payload.data, 'utf8').toString('base64')
        }))
      });
      const body = await response.json();
      assert.equal(response.status, 200);
      stored.push(body);
    }

    const requestedMessages = [stored[2].hash, stored[0].hash, 'missing-hash', stored[1].hash];
    const requestedExpiries = [
      baseTimestamp + 15_000,
      baseTimestamp + 45_000,
      baseTimestamp + 99_000,
      baseTimestamp + 30_000
    ];

    const response = await fetch(`${mock.baseUrl}/storage/expire`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        pubkey,
        messages: requestedMessages,
        expiry: requestedExpiries,
        signature: validPushSignature
      })
    });
    const body = await response.json();

    const expectedPairs = [
      { hash: stored[0].hash, expiry: requestedExpiries[1] },
      { hash: stored[1].hash, expiry: requestedExpiries[3] },
      { hash: stored[2].hash, expiry: requestedExpiries[0] }
    ].sort((left, right) => left.hash.localeCompare(right.hash));

    assert.equal(response.status, 200);
    assert.deepEqual(body.swarm[compatRelayId].updated, expectedPairs.map(item => item.hash));
    assert.deepEqual(body.swarm[compatRelayId].expiry, expectedPairs.map(item => item.expiry));

    const expiriesResponse = await fetch(`${mock.baseUrl}/storage/get_expiries`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        pubkey,
        messages: stored.map(item => item.hash),
        timestamp: Date.now(),
        signature: validPushSignature
      })
    });
    const expiries = await expiriesResponse.json();

    assert.equal(expiriesResponse.status, 200);
    assert.deepEqual(expiries.expiries, Object.fromEntries(expectedPairs.map(item => [item.hash, item.expiry])));
  } finally {
    await mock.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('storage expire rejects invalid signatures for verifiable identities', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'deep-mock-'));
  const mock = await startMockService({ port: randomPort(), stateDir });

  try {
    const stored = await storeSignedStorageMessage(mock, storageSigningIdentity, {
      namespace: 42,
      timestamp: Date.now(),
      data: Buffer.from('expire-signed-message', 'utf8').toString('base64')
    });

    const payload = createSignedStorageExpirePayload(storageSigningIdentity, {
      messages: [stored.hash],
      expiry: Date.now() + 30_000
    });
    payload.signature = invalidateSignature(payload.signature);

    const response = await fetch(`${mock.baseUrl}/storage/expire`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const body = await response.json();

    assert.equal(response.status, 401);
    assert.equal(body.message, 'expire: signature verification failed');
  } finally {
    await mock.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('storage sequence applies requests in order and surfaces intermediate state', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'deep-mock-'));
  const mock = await startMockService({ port: randomPort(), stateDir });

  try {
    const pubkey = '05sequence';
    const timestamp = Date.now();
    const ttl = 60_000;

    const response = await fetch(`${mock.baseUrl}/storage/sequence`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        requests: [
          {
            method: 'store',
            params: {
              pubkey,
              timestamp,
              ttl,
              data: Buffer.from('sequence-a', 'utf8').toString('base64')
            }
          },
          {
            method: 'retrieve',
            params: {
              pubkey,
              timestamp: Date.now(),
              signature: validPushSignature
            }
          },
          {
            method: 'store',
            params: {
              pubkey,
              timestamp: timestamp + 1_000,
              ttl,
              data: Buffer.from('sequence-b', 'utf8').toString('base64')
            }
          },
          {
            method: 'delete_all',
            params: {
              pubkey,
              timestamp: Date.now(),
              signature: validPushSignature
            }
          },
          {
            method: 'retrieve',
            params: {
              pubkey,
              timestamp: Date.now(),
              signature: validPushSignature
            }
          }
        ]
      })
    });
    const body = await response.json();

    assert.equal(response.status, 200);
    assert.equal(body.results.length, 5);
    assert.deepEqual(body.results.map(result => result.code), [200, 200, 200, 200, 200]);
    assert.equal(body.results[1].body.messages.length, 1);
    assert.equal(body.results[1].body.messages[0].hash, body.results[0].body.hash);
    assert.deepEqual(
      body.results[3].body.swarm[compatRelayId].deleted,
      [body.results[0].body.hash, body.results[2].body.hash].sort()
    );
    assert.deepEqual(body.results[4].body.messages, []);
  } finally {
    await mock.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('storage sequence stops on the first error while batch continues', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'deep-mock-'));
  const mock = await startMockService({ port: randomPort(), stateDir });

  try {
    const pubkey = '05sequence-error';
    const storeResponse = await fetch(`${mock.baseUrl}/storage/store`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        pubkey,
        timestamp: Date.now(),
        ttl: 60_000,
        data: Buffer.from('sequence-error', 'utf8').toString('base64')
      })
    });
    const stored = await storeResponse.json();
    assert.equal(storeResponse.status, 200);

    const requests = [
      {
        method: 'store',
        params: {
          pubkey,
          namespace: 33,
          timestamp: Date.now(),
          ttl: 60_000,
          data: Buffer.from('missing-signature-private-store', 'utf8').toString('base64')
        }
      },
      {
        method: 'retrieve',
        params: {
          pubkey,
          timestamp: Date.now(),
          signature: validPushSignature
        }
      }
    ];

    const sequenceResponse = await fetch(`${mock.baseUrl}/storage/sequence`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ requests })
    });
    const sequenceBody = await sequenceResponse.json();

    const batchResponse = await fetch(`${mock.baseUrl}/storage/batch`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ requests })
    });
    const batchBody = await batchResponse.json();

    assert.equal(sequenceResponse.status, 200);
    assert.equal(sequenceBody.results.length, 1);
    assert.equal(sequenceBody.results[0].code, 401);
    assert.equal(sequenceBody.results[0].body, 'store: signature required to store to namespace 33');

    assert.equal(batchResponse.status, 200);
    assert.equal(batchBody.results.length, 2);
    assert.equal(batchBody.results[0].code, 401);
    assert.equal(batchBody.results[0].body, 'store: signature required to store to namespace 33');
    assert.equal(batchBody.results[1].code, 200);
    assert.equal(batchBody.results[1].body.messages.length, 1);
    assert.equal(batchBody.results[1].body.messages[0].hash, stored.hash);
  } finally {
    await mock.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('storage delete_all removes all messages for a pubkey in the default namespace', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'deep-mock-'));
  const mock = await startMockService({ port: randomPort(), stateDir });

  try {
    const pubkey = '05delete-all';
    const firstStore = await fetch(`${mock.baseUrl}/storage/store`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        pubkey,
        namespace: 0,
        timestamp: Date.now(),
        ttl: 60_000,
        data: Buffer.from('first-delete-me', 'utf8').toString('base64')
      })
    });
    const firstBody = await firstStore.json();
    assert.equal(firstStore.status, 200);

    const secondStore = await fetch(`${mock.baseUrl}/storage/store`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        pubkey,
        namespace: 0,
        timestamp: Date.now() + 1,
        ttl: 60_000,
        data: Buffer.from('second-delete-me', 'utf8').toString('base64')
      })
    });
    const secondBody = await secondStore.json();
    assert.equal(secondStore.status, 200);

    const deleteResponse = await fetch(`${mock.baseUrl}/storage/delete_all`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        pubkey,
        timestamp: Date.now(),
        signature: validPushSignature
      })
    });
    const deleted = await deleteResponse.json();

    assert.equal(deleteResponse.status, 200);

    const deletedHashes = [...deleted.swarm[compatRelayId].deleted];
    assert.deepEqual(deletedHashes, [firstBody.hash, secondBody.hash].sort());

    const retrieveResponse = await fetch(`${mock.baseUrl}/storage/retrieve`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(createStorageRetrievePayload({ pubkey, namespace: 0 }))
    });
    const retrieved = await retrieveResponse.json();

    assert.equal(retrieveResponse.status, 200);
    assert.deepEqual(retrieved.messages, []);
  } finally {
    await mock.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('storage delete_all with namespace="all" removes messages across namespaces', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'deep-mock-'));
  const mock = await startMockService({ port: randomPort(), stateDir });

  try {
    const pubkey = '05delete-all-namespaces';
    const namespaceZeroResponse = await fetch(`${mock.baseUrl}/storage/store`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        pubkey,
        namespace: 0,
        timestamp: Date.now(),
        ttl: 60_000,
        data: Buffer.from('default-namespace', 'utf8').toString('base64')
      })
    });
    const namespaceZero = await namespaceZeroResponse.json();
    assert.equal(namespaceZeroResponse.status, 200);

    const namespaceNegativeResponse = await fetch(`${mock.baseUrl}/storage/store`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(createStorageStorePayload({
        pubkey,
        namespace: -42,
        timestamp: Date.now() + 1,
        ttl: 60_000,
        data: Buffer.from('negative-namespace', 'utf8').toString('base64')
      }))
    });
    const namespaceNegative = await namespaceNegativeResponse.json();
    assert.equal(namespaceNegativeResponse.status, 200);

    const deleteResponse = await fetch(`${mock.baseUrl}/storage/delete_all`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        pubkey,
        namespace: 'all',
        timestamp: Date.now(),
        signature: validPushSignature
      })
    });
    const deleted = await deleteResponse.json();

    assert.equal(deleteResponse.status, 200);
    assert.deepEqual(deleted.swarm[compatRelayId].deleted, {
      '-42': [namespaceNegative.hash],
      '0': [namespaceZero.hash]
    });

    const retrieveResponse = await fetch(`${mock.baseUrl}/storage/retrieve`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(createStorageRetrievePayload({ pubkey }))
    });
    const retrieved = await retrieveResponse.json();

    assert.equal(retrieveResponse.status, 200);
    assert.deepEqual(retrieved.messages, []);
  } finally {
    await mock.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('storage delete_all rejects timestamps outside the Session tolerance window', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'deep-mock-'));
  const mock = await startMockService({ port: randomPort(), stateDir });

  try {
    const pubkey = '05delete-all-stale';
    const tooOldResponse = await fetch(`${mock.baseUrl}/storage/delete_all`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        pubkey,
        timestamp: Date.now() - 120_000,
        signature: validPushSignature
      })
    });
    const tooOld = await tooOldResponse.json();

    assert.equal(tooOldResponse.status, 406);
    assert.equal(tooOld.message, 'delete_all timestamp too far from current time');

    const tooNewResponse = await fetch(`${mock.baseUrl}/storage/delete_all`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        pubkey,
        timestamp: Date.now() + 120_000,
        signature: validPushSignature
      })
    });
    const tooNew = await tooNewResponse.json();

    assert.equal(tooNewResponse.status, 406);
    assert.equal(tooNew.message, 'delete_all timestamp too far from current time');
  } finally {
    await mock.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('storage delete_all rejects invalid signatures for verifiable identities', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'deep-mock-'));
  const mock = await startMockService({ port: randomPort(), stateDir });

  try {
    await storeSignedStorageMessage(mock, storageSigningIdentity, {
      namespace: 42,
      timestamp: Date.now(),
      data: Buffer.from('delete-all-signed-message', 'utf8').toString('base64')
    });

    const payload = createSignedStorageDeleteAllPayload(storageSigningIdentity, {
      namespace: 42,
      timestamp: Date.now()
    });
    payload.signature = invalidateSignature(payload.signature);

    const response = await fetch(`${mock.baseUrl}/storage/delete_all`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const body = await response.json();

    assert.equal(response.status, 401);
    assert.equal(body.message, 'delete_all signature verification failed');
  } finally {
    await mock.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('storage delete removes only matching hashes and leaves the rest retrievable', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'deep-mock-'));
  const mock = await startMockService({ port: randomPort(), stateDir });

  try {
    const pubkey = '05delete-selective';
    const firstStore = await fetch(`${mock.baseUrl}/storage/store`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(createStorageStorePayload({
        pubkey,
        namespace: 9,
        timestamp: Date.now(),
        ttl: 60_000,
        data: Buffer.from('delete-selective-1', 'utf8').toString('base64')
      }))
    });
    const first = await firstStore.json();
    assert.equal(firstStore.status, 200);

    const secondStore = await fetch(`${mock.baseUrl}/storage/store`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(createStorageStorePayload({
        pubkey,
        namespace: 9,
        timestamp: Date.now() + 1,
        ttl: 60_000,
        data: Buffer.from('delete-selective-2', 'utf8').toString('base64')
      }))
    });
    const second = await secondStore.json();
    assert.equal(secondStore.status, 200);

    const thirdStore = await fetch(`${mock.baseUrl}/storage/store`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(createStorageStorePayload({
        pubkey,
        namespace: 9,
        timestamp: Date.now() + 2,
        ttl: 60_000,
        data: Buffer.from('delete-selective-3', 'utf8').toString('base64')
      }))
    });
    const third = await thirdStore.json();
    assert.equal(thirdStore.status, 200);

    const deleteResponse = await fetch(`${mock.baseUrl}/storage/delete`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        pubkey,
        messages: ['garbage-hash', second.hash, first.hash],
        signature: validPushSignature
      })
    });
    const deleted = await deleteResponse.json();

    assert.equal(deleteResponse.status, 200);
    assert.deepEqual(deleted.swarm[compatRelayId].deleted, [first.hash, second.hash].sort());

    const retrieveResponse = await fetch(`${mock.baseUrl}/storage/retrieve`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(createStorageRetrievePayload({ pubkey, namespace: 9 }))
    });
    const retrieved = await retrieveResponse.json();

    assert.equal(retrieveResponse.status, 200);
    assert.equal(retrieved.messages.length, 1);
    assert.equal(retrieved.messages[0].hash, third.hash);
  } finally {
    await mock.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('storage delete with required=true returns 404 when nothing is removed', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'deep-mock-'));
  const mock = await startMockService({ port: randomPort(), stateDir });

  try {
    const pubkey = '05delete-required';
    const firstStore = await fetch(`${mock.baseUrl}/storage/store`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        pubkey,
        namespace: 0,
        timestamp: Date.now(),
        ttl: 60_000,
        data: Buffer.from('delete-required-1', 'utf8').toString('base64')
      })
    });
    const first = await firstStore.json();
    assert.equal(firstStore.status, 200);

    const secondStore = await fetch(`${mock.baseUrl}/storage/store`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        pubkey,
        namespace: 0,
        timestamp: Date.now() + 1,
        ttl: 60_000,
        data: Buffer.from('delete-required-2', 'utf8').toString('base64')
      })
    });
    const second = await secondStore.json();
    assert.equal(secondStore.status, 200);

    const payload = {
      pubkey,
      messages: [second.hash, first.hash, 'garbage-hash'],
      signature: validPushSignature,
      required: true
    };

    const firstDeleteResponse = await fetch(`${mock.baseUrl}/storage/delete`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const firstDeleted = await firstDeleteResponse.json();

    assert.equal(firstDeleteResponse.status, 200);
    assert.deepEqual(firstDeleted.swarm[compatRelayId].deleted, [first.hash, second.hash].sort());

    const secondDeleteResponse = await fetch(`${mock.baseUrl}/storage/delete`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const secondDeleted = await secondDeleteResponse.json();

    assert.equal(secondDeleteResponse.status, 404);
    assert.equal(secondDeleted.message, 'required deletion did not remove any messages');

    const optionalDeleteResponse = await fetch(`${mock.baseUrl}/storage/delete`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        ...payload,
        required: false
      })
    });
    const optionalDeleted = await optionalDeleteResponse.json();

    assert.equal(optionalDeleteResponse.status, 200);
    assert.deepEqual(optionalDeleted.swarm[compatRelayId].deleted, []);
  } finally {
    await mock.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('storage delete rejects invalid signatures for verifiable identities', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'deep-mock-'));
  const mock = await startMockService({ port: randomPort(), stateDir });

  try {
    const stored = await storeSignedStorageMessage(mock, storageSigningIdentity, {
      namespace: 42,
      timestamp: Date.now(),
      data: Buffer.from('delete-signed-message', 'utf8').toString('base64')
    });

    const payload = createSignedStorageDeletePayload(storageSigningIdentity, {
      messages: [stored.hash]
    });
    payload.signature = invalidateSignature(payload.signature);

    const response = await fetch(`${mock.baseUrl}/storage/delete`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const body = await response.json();

    assert.equal(response.status, 401);
    assert.equal(body.message, 'delete_msgs signature verification failed');
  } finally {
    await mock.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('storage delete_before removes messages at or before the cutoff and returns empty when nothing matches', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'deep-mock-'));
  const mock = await startMockService({ port: randomPort(), stateDir });

  try {
    const pubkey = '05delete-before';
    const baseTimestamp = Date.now();
    const newestResponse = await fetch(`${mock.baseUrl}/storage/store`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        pubkey,
        namespace: 0,
        timestamp: baseTimestamp,
        ttl: 60_000,
        data: Buffer.from('delete-before-newest', 'utf8').toString('base64')
      })
    });
    const newest = await newestResponse.json();
    assert.equal(newestResponse.status, 200);

    const middleResponse = await fetch(`${mock.baseUrl}/storage/store`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        pubkey,
        namespace: 0,
        timestamp: baseTimestamp - 1_000,
        ttl: 60_000,
        data: Buffer.from('delete-before-middle', 'utf8').toString('base64')
      })
    });
    const middle = await middleResponse.json();
    assert.equal(middleResponse.status, 200);

    const oldestResponse = await fetch(`${mock.baseUrl}/storage/store`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        pubkey,
        namespace: 0,
        timestamp: baseTimestamp - 2_000,
        ttl: 60_000,
        data: Buffer.from('delete-before-oldest', 'utf8').toString('base64')
      })
    });
    const oldest = await oldestResponse.json();
    assert.equal(oldestResponse.status, 200);

    const deleteResponse = await fetch(`${mock.baseUrl}/storage/delete_before`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        pubkey,
        before: baseTimestamp - 1_000,
        signature: validPushSignature
      })
    });
    const deleted = await deleteResponse.json();

    assert.equal(deleteResponse.status, 200);
    assert.deepEqual(deleted.swarm[compatRelayId].deleted, [middle.hash, oldest.hash].sort());

    const retrieveResponse = await fetch(`${mock.baseUrl}/storage/retrieve`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(createStorageRetrievePayload({ pubkey, namespace: 0 }))
    });
    const retrieved = await retrieveResponse.json();

    assert.equal(retrieveResponse.status, 200);
    assert.equal(retrieved.messages.length, 1);
    assert.equal(retrieved.messages[0].hash, newest.hash);

    const emptyDeleteResponse = await fetch(`${mock.baseUrl}/storage/delete_before`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        pubkey,
        before: baseTimestamp - 10_000,
        signature: validPushSignature
      })
    });
    const emptyDeleted = await emptyDeleteResponse.json();

    assert.equal(emptyDeleteResponse.status, 200);
    assert.deepEqual(emptyDeleted.swarm[compatRelayId].deleted, []);
  } finally {
    await mock.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('storage delete_before rejects cutoffs that are too far in the future', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'deep-mock-'));
  const mock = await startMockService({ port: randomPort(), stateDir });

  try {
    const response = await fetch(`${mock.baseUrl}/storage/delete_before`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        pubkey: '05delete-before-future',
        before: Date.now() + 120_000,
        signature: validPushSignature
      })
    });
    const body = await response.json();

    assert.equal(response.status, 401);
    assert.equal(body.message, 'delete_before timestamp too far in the future');
  } finally {
    await mock.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('storage delete_before rejects invalid signatures for verifiable identities', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'deep-mock-'));
  const mock = await startMockService({ port: randomPort(), stateDir });

  try {
    await storeSignedStorageMessage(mock, storageSigningIdentity, {
      namespace: 42,
      timestamp: Date.now() - 1_000,
      data: Buffer.from('delete-before-signed-message', 'utf8').toString('base64')
    });

    const payload = createSignedStorageDeleteBeforePayload(storageSigningIdentity, {
      namespace: 42,
      before: Date.now()
    });
    payload.signature = invalidateSignature(payload.signature);

    const response = await fetch(`${mock.baseUrl}/storage/delete_before`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const body = await response.json();

    assert.equal(response.status, 401);
    assert.equal(body.message, 'delete_before signature verification failed');
  } finally {
    await mock.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('file GET prunes expired records from persisted state', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'deep-mock-'));
  await mkdir(stateDir, { recursive: true });
  const fileStatePath = path.join(stateDir, 'file.json');
  await writeFile(
    fileStatePath,
    JSON.stringify([
      {
        id: 'expired-file-id',
        contentBase64: Buffer.from('stale-file', 'utf8').toString('base64'),
        uploaded: 1,
        expires: 2
      }
    ])
  );

  const mock = await startMockService({ port: randomPort(), stateDir });

  try {
    const infoResponse = await fetch(`${mock.baseUrl}/file/expired-file-id/info`);
    const infoBody = await infoResponse.json();

    assert.equal(infoResponse.status, 404);
    assert.equal(infoBody.status_code, 404);

    const persistedRaw = await readFile(fileStatePath, 'utf8');
    const persisted = JSON.parse(persistedRaw);
    assert.deepEqual(persisted, []);
  } finally {
    await mock.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('file download returns Session-style 404 for missing files', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'deep-mock-'));
  const mock = await startMockService({ port: randomPort(), stateDir });

  try {
    const response = await fetch(`${mock.baseUrl}/file/missing-file-id`);
    const body = await response.json();

    assert.equal(response.status, 404);
    assert.equal(body.status_code, 404);
  } finally {
    await mock.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('file upload rejects oversized payloads with Session-style HTTP 413', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'deep-mock-'));
  const mock = await startMockService({ port: randomPort(), stateDir });

  try {
    const response = await fetch(`${mock.baseUrl}/file`, {
      method: 'POST',
      body: Buffer.alloc(6_000_001, 0x61)
    });
    const body = await response.json();

    assert.equal(response.status, 413);
    assert.equal(body.status_code, 413);
  } finally {
    await mock.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

const expectedFileTtlSeconds = 21 * 24 * 60 * 60;

test('file upload rejects empty payloads with Session-style HTTP 413', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'deep-mock-'));
  const mock = await startMockService({ port: randomPort(), stateDir });

  try {
    const response = await fetch(`${mock.baseUrl}/file`, {
      method: 'POST',
      body: Buffer.alloc(0)
    });
    const body = await response.json();

    assert.equal(response.status, 413);
    assert.equal(body.status_code, 413);
  } finally {
    await mock.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('file upload returns expires and preserves original metadata on duplicate content', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'deep-mock-'));
  const mock = await startMockService({ port: randomPort(), stateDir });

  try {
    const firstResponse = await fetch(`${mock.baseUrl}/file`, {
      method: 'POST',
      body: Buffer.from('same-content', 'utf8')
    });
    const first = await firstResponse.json();
    const firstNow = Math.floor(Date.now() / 1000);
    assert.equal(firstResponse.status, 200);
    assert.equal(typeof first.expires, 'number');
    assert.ok(first.expires >= firstNow + expectedFileTtlSeconds - 2);
    assert.ok(first.expires <= firstNow + expectedFileTtlSeconds + 2);

    const firstInfoResponse = await fetch(`${mock.baseUrl}/file/${first.id}/info`);
    const firstInfo = await firstInfoResponse.json();
    assert.equal(firstInfoResponse.status, 200);

    const secondResponse = await fetch(`${mock.baseUrl}/file`, {
      method: 'POST',
      body: Buffer.from('same-content', 'utf8')
    });
    const second = await secondResponse.json();
    assert.equal(secondResponse.status, 200);

    const secondInfoResponse = await fetch(`${mock.baseUrl}/file/${second.id}/info`);
    const secondInfo = await secondInfoResponse.json();
    assert.equal(secondInfoResponse.status, 200);

    assert.equal(first.id, second.id);
    assert.equal(secondInfo.uploaded, firstInfo.uploaded);
    assert.ok(second.expires >= first.expires);
    assert.ok(secondInfo.expires >= firstInfo.expires);
  } finally {
    await mock.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('file upload id matches upstream Session salted BLAKE2b contract', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'deep-mock-'));
  const mock = await startMockService({ port: randomPort(), stateDir });

  try {
    const response = await fetch(`${mock.baseUrl}/file`, {
      method: 'POST',
      body: Buffer.from('Deep attachment fixture v1\n', 'utf8')
    });
    const body = await response.json();

    assert.equal(response.status, 200);
    assert.equal(body.id, expectedSessionFileId);
  } finally {
    await mock.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('avatar lifecycle publishes profile image metadata and survives restart', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'deep-mock-'));
  const avatarStatePath = path.join(stateDir, 'avatar.json');
  let mock = await startMockService({
    port: randomPort(),
    stateDir,
    extraEnv: { MAX_FILE_TTL_SECONDS: '7200' }
  });

  try {
    const sessionId = '05compat-avatar-owner';
    const firstAvatar = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x01]);
    const firstResponse = await fetch(`${mock.baseUrl}/avatar/${encodeURIComponent(sessionId)}`, {
      method: 'PUT',
      headers: {
        'content-type': 'image/png',
        'x-fs-ttl': '3600'
      },
      body: firstAvatar
    });
    const first = await firstResponse.json();
    assert.equal(firstResponse.status, 200);
    assert.equal(first.sessionId, sessionId);
    assert.match(first.fileId, /^[A-Za-z0-9_-]{44}$/);
    assert.equal(first.contentType, 'image/png');
    assert.equal(first.size, firstAvatar.length);

    const firstDownloadResponse = await fetch(`${mock.baseUrl}/avatar/${encodeURIComponent(sessionId)}`);
    assert.equal(firstDownloadResponse.status, 200);
    assert.equal(firstDownloadResponse.headers.get('content-type'), 'image/png');
    assert.deepEqual(Buffer.from(await firstDownloadResponse.arrayBuffer()), firstAvatar);

    await mock.stop();
    mock = await startMockService({
      port: randomPort(),
      stateDir,
      extraEnv: { MAX_FILE_TTL_SECONDS: '7200' }
    });

    const reloadedInfoResponse = await fetch(`${mock.baseUrl}/avatar/${encodeURIComponent(sessionId)}/info`);
    assert.equal(reloadedInfoResponse.status, 200);
    assert.deepEqual(await reloadedInfoResponse.json(), first);

    const secondAvatar = Buffer.from([0xff, 0xd8, 0xff, 0xe0, 0x02]);
    const secondResponse = await fetch(`${mock.baseUrl}/avatar/${encodeURIComponent(sessionId)}`, {
      method: 'PUT',
      headers: {
        'content-type': 'image/jpeg',
        'x-fs-ttl': '3600'
      },
      body: secondAvatar
    });
    const second = await secondResponse.json();
    assert.equal(secondResponse.status, 200);
    assert.notEqual(second.fileId, first.fileId);
    assert.equal(second.contentType, 'image/jpeg');

    const secondDownloadResponse = await fetch(`${mock.baseUrl}/avatar/${encodeURIComponent(sessionId)}`);
    assert.equal(secondDownloadResponse.status, 200);
    assert.equal(secondDownloadResponse.headers.get('content-type'), 'image/jpeg');
    assert.deepEqual(Buffer.from(await secondDownloadResponse.arrayBuffer()), secondAvatar);

    const persistedAvatars = JSON.parse(await readFile(avatarStatePath, 'utf8'));
    assert.equal(persistedAvatars.length, 1);
    assert.equal(persistedAvatars[0].fileId, second.fileId);
  } finally {
    await mock.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('avatar lifecycle rejects unsupported and empty uploads without state mutation', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'deep-mock-'));
  const mock = await startMockService({ port: randomPort(), stateDir });

  try {
    const unsupportedResponse = await fetch(`${mock.baseUrl}/avatar/05compat-avatar-owner`, {
      method: 'PUT',
      headers: { 'content-type': 'text/plain' },
      body: Buffer.from('not-an-image', 'utf8')
    });
    assert.equal(unsupportedResponse.status, 415);
    assert.equal((await unsupportedResponse.json()).status_code, 415);

    const emptyResponse = await fetch(`${mock.baseUrl}/avatar/05compat-avatar-owner`, {
      method: 'PUT',
      headers: { 'content-type': 'image/png' },
      body: Buffer.alloc(0)
    });
    assert.equal(emptyResponse.status, 413);
    assert.equal((await emptyResponse.json()).status_code, 413);

    const missingResponse = await fetch(`${mock.baseUrl}/avatar/05compat-avatar-owner`);
    assert.equal(missingResponse.status, 404);
    assert.equal((await missingResponse.json()).status_code, 404);

    const statsResponse = await fetch(`${mock.baseUrl}/stats`);
    const stats = await statsResponse.json();
    assert.equal(statsResponse.status, 200);
    assert.equal(stats.stats.avatarUpload, 2);
    assert.equal(stats.inventory.avatars, 0);
    assert.equal(stats.inventory.files, 0);
  } finally {
    await mock.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('file upload honors X-FS-TTL when max file ttl is configured', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'deep-mock-'));
  const mock = await startMockService({
    port: randomPort(),
    stateDir,
    extraEnv: { MAX_FILE_TTL_SECONDS: '120' }
  });

  try {
    const requestedTtl = 90;
    const now = Math.floor(Date.now() / 1000);
    const response = await fetch(`${mock.baseUrl}/file`, {
      method: 'POST',
      headers: { 'x-fs-ttl': String(requestedTtl) },
      body: Buffer.from('ttl-controlled-upload', 'utf8')
    });
    const body = await response.json();

    assert.equal(response.status, 200);
    assert.ok(body.expires >= now + requestedTtl - 2);
    assert.ok(body.expires <= now + requestedTtl + 2);
  } finally {
    await mock.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('file extend rejects invalid X-FS-TTL when max file ttl is configured', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'deep-mock-'));
  const mock = await startMockService({
    port: randomPort(),
    stateDir,
    extraEnv: { MAX_FILE_TTL_SECONDS: '120' }
  });

  try {
    const uploadResponse = await fetch(`${mock.baseUrl}/file`, {
      method: 'POST',
      body: Buffer.from('ttl-extend-upload', 'utf8')
    });
    const upload = await uploadResponse.json();
    assert.equal(uploadResponse.status, 200);

    const extendResponse = await fetch(`${mock.baseUrl}/file/${upload.id}/extend`, {
      method: 'POST',
      headers: { 'x-fs-ttl': '121' }
    });
    const body = await extendResponse.json();

    assert.equal(extendResponse.status, 400);
    assert.equal(body.status_code, 400);
  } finally {
    await mock.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('deprecated /files uploads return numeric ids, skip dedupe, and download base64 content', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'deep-mock-'));
  const mock = await startMockService({ port: randomPort(), stateDir });

  try {
    const payload = {
      file: Buffer.from('legacy-upload', 'utf8').toString('base64')
    };
    const firstResponse = await fetch(`${mock.baseUrl}/files`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const first = await firstResponse.json();
    assert.equal(firstResponse.status, 200);
    assert.equal(first.status_code, 200);
    assert.equal(typeof first.result, 'number');

    const secondResponse = await fetch(`${mock.baseUrl}/files`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const second = await secondResponse.json();
    assert.equal(secondResponse.status, 200);
    assert.equal(second.status_code, 200);
    assert.notEqual(second.result, first.result);

    const getResponse = await fetch(`${mock.baseUrl}/files/${first.result}`);
    const downloaded = await getResponse.json();
    assert.equal(getResponse.status, 200);
    assert.equal(downloaded.status_code, 200);
    assert.equal(Buffer.from(downloaded.result, 'base64').toString('utf8'), 'legacy-upload');
  } finally {
    await mock.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('deprecated /files returns Session-style 404 for missing files', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'deep-mock-'));
  const mock = await startMockService({ port: randomPort(), stateDir });

  try {
    const response = await fetch(`${mock.baseUrl}/files/404`);
    const body = await response.json();

    assert.equal(response.status, 404);
    assert.equal(body.status_code, 404);
  } finally {
    await mock.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('file extend returns metadata and does not reduce expiry', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'deep-mock-'));
  const mock = await startMockService({ port: randomPort(), stateDir });

  try {
    const uploadResponse = await fetch(`${mock.baseUrl}/file`, {
      method: 'POST',
      body: Buffer.from('extend-me', 'utf8')
    });
    const upload = await uploadResponse.json();
    assert.equal(uploadResponse.status, 200);

    const infoResponse = await fetch(`${mock.baseUrl}/file/${upload.id}/info`);
    const info = await infoResponse.json();
    assert.equal(infoResponse.status, 200);

    const extendResponse = await fetch(`${mock.baseUrl}/file/${upload.id}/extend`, {
      method: 'POST'
    });
    const extended = await extendResponse.json();

    assert.equal(extendResponse.status, 200);
    assert.equal(extended.size, Buffer.byteLength('extend-me'));
    assert.equal(extended.uploaded, info.uploaded);
    assert.ok(extended.expires >= info.expires);
  } finally {
    await mock.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('file extend returns Session-style 404 for missing files', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'deep-mock-'));
  const mock = await startMockService({ port: randomPort(), stateDir });

  try {
    const response = await fetch(`${mock.baseUrl}/file/missing-file-id/extend`, {
      method: 'POST'
    });
    const body = await response.json();

    assert.equal(response.status, 404);
    assert.equal(body.status_code, 404);
  } finally {
    await mock.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('session_version returns Session-style 404 for invalid platform', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'deep-mock-'));
  const mock = await startMockService({ port: randomPort(), stateDir });

  try {
    const response = await fetch(`${mock.baseUrl}/session_version?platform=linux`);
    const body = await response.json();

    assert.equal(response.status, 404);
    assert.equal(body.status_code, 404);
  } finally {
    await mock.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('session_version returns env-backed stable and prerelease metadata', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'deep-mock-'));
  const mock = await startMockService({
    port: randomPort(),
    stateDir,
    extraEnv: {
      SESSION_VERSION_DESKTOP: '1.2.3',
      SESSION_VERSION_DESKTOP_PRERELEASE: '1.2.4-beta1',
      SESSION_VERSION_UPDATED_AT: '1717027200'
    }
  });

  try {
    const response = await fetch(`${mock.baseUrl}/session_version?platform=desktop`);
    const body = await response.json();

    assert.equal(response.status, 200);
    assert.equal(body.status_code, 200);
    assert.equal(body.result, '1.2.3');
    assert.equal(body.updated, 1717027200);
    assert.equal(body.prerelease.result, '1.2.4-beta1');
  } finally {
    await mock.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('session_version returns Session-style 502 when metadata is unavailable', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'deep-mock-'));
  const mock = await startMockService({ port: randomPort(), stateDir });

  try {
    const response = await fetch(`${mock.baseUrl}/session_version?platform=desktop`);
    const body = await response.json();

    assert.equal(response.status, 502);
    assert.equal(body.status_code, 502);
  } finally {
    await mock.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('token_info returns env-backed stats and filters history by days window', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'deep-mock-'));
  const nowSeconds = Math.floor(Date.now() / 1000);
  const mock = await startMockService({
    port: randomPort(),
    stateDir,
    extraEnv: {
      TOKEN_INFO_MAXIMUM_SUPPLY: '240000000',
      TOKEN_INFO_SENT_PER_NODE: '15000',
      TOKEN_INFO_STAKING_REWARD_POOL: '9000000',
      TOKEN_INFO_HISTORY_JSON: JSON.stringify([
        {
          current_value: 0.42,
          circulating_supply: 123456,
          total_nodes: 321,
          updated: nowSeconds - 2 * 24 * 60 * 60
        },
        {
          current_value: 0.41,
          circulating_supply: 120000,
          total_nodes: 300,
          updated: nowSeconds - 12 * 24 * 60 * 60
        }
      ])
    }
  });

  try {
    const response = await fetch(`${mock.baseUrl}/token_info?days=7`);
    const body = await response.json();

    assert.equal(response.status, 200);
    assert.equal(body.status_code, 200);
    assert.equal(body.info.maximum_supply, 240000000);
    assert.equal(body.info.sent_per_node, 15000);
    assert.equal(body.info.staking_reward_pool, 9000000);
    assert.equal(body.info.history.length, 1);
    assert.equal(body.info.history[0].total_nodes, 321);
  } finally {
    await mock.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('token_info returns Session-style 502 when metadata is unavailable', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'deep-mock-'));
  const mock = await startMockService({ port: randomPort(), stateDir });

  try {
    const response = await fetch(`${mock.baseUrl}/token_info?days=7`);
    const body = await response.json();

    assert.equal(response.status, 502);
    assert.equal(body.status_code, 502);
  } finally {
    await mock.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('push subscribe supports idempotency key replay', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'deep-mock-'));
  const mock = await startMockService({ port: randomPort(), stateDir });

  try {
    const payload = createPushSubscribePayload({
      idempotency_key: 'push-idem-1',
      ttlSeconds: 30
    });

    const firstResponse = await fetch(`${mock.baseUrl}/subscribe`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const first = await firstResponse.json();
    assert.equal(firstResponse.status, 200);
    assert.equal(first.success, true);
    assert.equal(first.added, true);
    assert.equal(first.message, 'Subscription successful');

    const secondResponse = await fetch(`${mock.baseUrl}/subscribe`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const second = await secondResponse.json();
    assert.equal(secondResponse.status, 200);
    assert.equal(second.success, true);
    assert.equal(second.updated, true);
    assert.equal(second.idempotent, true);
    assert.equal(second.message, 'Resubscription successful');

    const listResponse = await fetch(`${mock.baseUrl}/subscriptions/${encodeURIComponent(payload.pubkey)}`);
    const list = await listResponse.json();
    assert.equal(listResponse.status, 200);
    assert.equal(list.subscriptions.length, 1);
    assert.equal(list.subscriptions[0].service_info.token, payload.service_info.token);
  } finally {
    await mock.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('push subscribe preserves validated subaccount fields through listing and unsubscribe', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'deep-mock-'));
  const mock = await startMockService({ port: randomPort(), stateDir });

  try {
    const payload = createPushSubscribePayload({
      subaccount: 'ab'.repeat(36),
      subaccount_sig: 'cd'.repeat(64)
    });

    const subscribeResponse = await fetch(`${mock.baseUrl}/subscribe`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const subscribed = await subscribeResponse.json();
    assert.equal(subscribeResponse.status, 200);
    assert.equal(subscribed.success, true);

    const listResponse = await fetch(`${mock.baseUrl}/subscriptions/${payload.pubkey}`);
    const list = await listResponse.json();
    assert.equal(listResponse.status, 200);
    assert.equal(list.subscriptions.length, 1);
    assert.equal(list.subscriptions[0].subaccount, payload.subaccount);
    assert.equal(list.subscriptions[0].subaccount_sig, payload.subaccount_sig);

    const unsubscribeResponse = await fetch(`${mock.baseUrl}/unsubscribe`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(
        createPushUnsubscribePayload({
          subaccount: payload.subaccount,
          subaccount_sig: payload.subaccount_sig
        })
      )
    });
    const unsubscribed = await unsubscribeResponse.json();
    assert.equal(unsubscribeResponse.status, 200);
    assert.equal(unsubscribed.success, true);
    assert.equal(unsubscribed.removed, true);
  } finally {
    await mock.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('push unsubscribe removes an existing subscription and reports absent removals', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'deep-mock-'));
  const mock = await startMockService({ port: randomPort(), stateDir });

  try {
    const subscribePayload = createPushSubscribePayload();
    const subscribeResponse = await fetch(`${mock.baseUrl}/subscribe`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(subscribePayload)
    });
    assert.equal(subscribeResponse.status, 200);

    const unsubscribePayload = createPushUnsubscribePayload();
    const firstResponse = await fetch(`${mock.baseUrl}/unsubscribe`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(unsubscribePayload)
    });
    const first = await firstResponse.json();

    assert.equal(firstResponse.status, 200);
    assert.equal(first.success, true);
    assert.equal(first.removed, true);

    const secondResponse = await fetch(`${mock.baseUrl}/unsubscribe`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(unsubscribePayload)
    });
    const second = await secondResponse.json();

    assert.equal(secondResponse.status, 200);
    assert.equal(second.success, true);
    assert.equal(second.removed, false);

    const listResponse = await fetch(`${mock.baseUrl}/subscriptions/${encodeURIComponent(subscribePayload.pubkey)}`);
    const list = await listResponse.json();
    assert.equal(listResponse.status, 200);
    assert.deepEqual(list.subscriptions, []);
  } finally {
    await mock.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('push unsubscribe supports Session-style array payload with per-item results', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'deep-mock-'));
  const mock = await startMockService({ port: randomPort(), stateDir });

  try {
    const subscribePayload = createPushSubscribePayload({
      pubkey: '05unsub-batch',
      service_info: { token: 'token-batch-1' }
    });
    const subscribeResponse = await fetch(`${mock.baseUrl}/subscribe`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(subscribePayload)
    });
    assert.equal(subscribeResponse.status, 200);

    const response = await fetch(`${mock.baseUrl}/unsubscribe`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify([
        createPushUnsubscribePayload({
          pubkey: '05unsub-batch',
          service_info: { token: 'token-batch-1' }
        }),
        createPushUnsubscribePayload({
          pubkey: '05unsub-batch',
          service_info: { token: 'token-batch-missing' }
        })
      ])
    });
    const body = await response.json();

    assert.equal(response.status, 200);
    assert.equal(Array.isArray(body), true);
    assert.equal(body.length, 2);
    assert.equal(body[0].success, true);
    assert.equal(body[0].removed, true);
    assert.equal(body[1].success, true);
    assert.equal(body[1].removed, false);

    const listResponse = await fetch(`${mock.baseUrl}/subscriptions/${encodeURIComponent('05unsub-batch')}`);
    const list = await listResponse.json();

    assert.equal(listResponse.status, 200);
    assert.deepEqual(list.subscriptions, []);
  } finally {
    await mock.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('push subscriptions listing prunes expired persisted entries', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'deep-mock-'));
  await mkdir(stateDir, { recursive: true });
  const pushStatePath = path.join(stateDir, 'push.json');
  await writeFile(
    pushStatePath,
    JSON.stringify([
      {
        key: '05push:apns:token-old',
        pubkey: '05push',
        service: 'apns',
        service_info: { token: 'token-old' },
        namespaces: [0],
        subscribedAt: '1970-01-01T00:00:00.000Z',
        expiresAt: 2
      }
    ])
  );

  const mock = await startMockService({ port: randomPort(), stateDir });

  try {
    const listResponse = await fetch(`${mock.baseUrl}/subscriptions/${encodeURIComponent('05push')}`);
    const list = await listResponse.json();

    assert.equal(listResponse.status, 200);
    assert.deepEqual(list.subscriptions, []);

    const persistedRaw = await readFile(pushStatePath, 'utf8');
    const persisted = JSON.parse(persistedRaw);
    assert.deepEqual(persisted, []);
  } finally {
    await mock.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('push subscribe returns Session-style BAD_INPUT error code', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'deep-mock-'));
  const mock = await startMockService({ port: randomPort(), stateDir });

  try {
    const response = await fetch(`${mock.baseUrl}/subscribe`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ service: 'apns', namespaces: [0] })
    });
    const body = await response.json();

    assert.equal(response.status, 400);
    assert.equal(body.error, 1);
  } finally {
    await mock.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('push subscribe returns Session-style SERVICE_NOT_AVAILABLE error code', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'deep-mock-'));
  const mock = await startMockService({ port: randomPort(), stateDir });

  try {
    const response = await fetch(`${mock.baseUrl}/subscribe`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(createPushSubscribePayload({
        service: 'unknown-service',
        service_info: { token: 'token-unknown' },
        namespaces: [0]
      }))
    });
    const body = await response.json();

    assert.equal(response.status, 400);
    assert.equal(body.error, 2);
  } finally {
    await mock.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('push subscribe supports Session-style array payload with per-item results', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'deep-mock-'));
  const mock = await startMockService({ port: randomPort(), stateDir });

  try {
    const response = await fetch(`${mock.baseUrl}/subscribe`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify([
        createPushSubscribePayload({
          pubkey: '05batch',
          service_info: { token: 'token-batch-1' }
        }),
        createPushSubscribePayload({
          pubkey: '05batch',
          service: 'unsupported-service',
          service_info: { token: 'token-batch-2' },
          namespaces: [0]
        })
      ])
    });
    const body = await response.json();

    assert.equal(response.status, 200);
    assert.equal(Array.isArray(body), true);
    assert.equal(body.length, 2);
    assert.equal(body[0].success, true);
    assert.equal(body[0].added, true);
    assert.equal(body[1].error, 2);

    const listResponse = await fetch(`${mock.baseUrl}/subscriptions/${encodeURIComponent('05batch')}`);
    const list = await listResponse.json();

    assert.equal(listResponse.status, 200);
    assert.equal(list.subscriptions.length, 1);
    assert.equal(list.subscriptions[0].service_info.token, 'token-batch-1');
  } finally {
    await mock.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('push subscribe requires Session signature payload fields', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'deep-mock-'));
  const mock = await startMockService({ port: randomPort(), stateDir });

  try {
    const response = await fetch(`${mock.baseUrl}/subscribe`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        pubkey: '05push',
        service: 'apns',
        service_info: { token: 'token-1' },
        namespaces: [0]
      })
    });
    const body = await response.json();

    assert.equal(response.status, 400);
    assert.equal(body.error, 1);
    assert.equal(body.message, 'Missing required parameter');
  } finally {
    await mock.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('push subscribe verifies real owner signatures for verifiable Session identities', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'deep-mock-'));
  const mock = await startMockService({ port: randomPort(), stateDir });

  try {
    const payload = createSignedPushSubscribePayload(pushSigningIdentity, {
      service_info: { token: 'signed-owner-1' }
    });

    const subscribeResponse = await fetch(`${mock.baseUrl}/subscribe`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const subscribed = await subscribeResponse.json();

    assert.equal(subscribeResponse.status, 200);
    assert.equal(subscribed.success, true);
    assert.equal(subscribed.added, true);

    const invalidResponse = await fetch(`${mock.baseUrl}/subscribe`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(createSignedPushSubscribePayload(pushSigningIdentity, {
        service_info: { token: 'signed-owner-bad' },
        signature: invalidateSignature(payload.signature)
      }))
    });
    const invalidBody = await invalidResponse.json();

    assert.equal(invalidResponse.status, 400);
    assert.equal(invalidBody.error, 4);
    assert.equal(invalidBody.message, 'Signature verification failed');

    const listResponse = await fetch(`${mock.baseUrl}/subscriptions/${encodeURIComponent(payload.pubkey)}`);
    const list = await listResponse.json();

    assert.equal(listResponse.status, 200);
    assert.equal(list.subscriptions.length, 1);
    assert.equal(list.subscriptions[0].service_info.token, 'signed-owner-1');
  } finally {
    await mock.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('push subscribe enforces delegated subaccount signatures and read access', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'deep-mock-'));
  const mock = await startMockService({ port: randomPort(), stateDir });
  const ownerIdentity = createTestStorageSigningIdentity();
  const validSubaccount = ownerIdentity.createSubaccount({ ownerPubkey: ownerIdentity.sessionPubkey });
  const writeOnlySubaccount = ownerIdentity.createSubaccount({ ownerPubkey: ownerIdentity.sessionPubkey, read: false });

  try {
    const subscribedPayload = withStorageSubaccount(createSignedPushSubscribePayload(validSubaccount, {
      pubkey: ownerIdentity.sessionPubkey,
      session_ed25519: ownerIdentity.pubkeyEd25519,
      service_info: { token: 'signed-subaccount-1' }
    }), validSubaccount);
    const subscribeResponse = await fetch(`${mock.baseUrl}/subscribe`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(subscribedPayload)
    });
    const subscribed = await subscribeResponse.json();

    assert.equal(subscribeResponse.status, 200);
    assert.equal(subscribed.success, true);
    assert.equal(subscribed.added, true);

    const invalidMainPayload = withStorageSubaccount(createSignedPushSubscribePayload(validSubaccount, {
      pubkey: ownerIdentity.sessionPubkey,
      session_ed25519: ownerIdentity.pubkeyEd25519,
      service_info: { token: 'signed-subaccount-bad-main' }
    }), validSubaccount);
    invalidMainPayload.signature = invalidateSignature(invalidMainPayload.signature);

    const invalidMainResponse = await fetch(`${mock.baseUrl}/subscribe`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(invalidMainPayload)
    });
    const invalidMainBody = await invalidMainResponse.json();

    assert.equal(invalidMainResponse.status, 400);
    assert.equal(invalidMainBody.error, 4);
    assert.equal(invalidMainBody.message, 'Subaccount main signature verification failed');

    const writeOnlyPayload = withStorageSubaccount(createSignedPushSubscribePayload(writeOnlySubaccount, {
      pubkey: ownerIdentity.sessionPubkey,
      session_ed25519: ownerIdentity.pubkeyEd25519,
      service_info: { token: 'signed-subaccount-write-only' }
    }), writeOnlySubaccount);

    const writeOnlyResponse = await fetch(`${mock.baseUrl}/subscribe`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(writeOnlyPayload)
    });
    const writeOnlyBody = await writeOnlyResponse.json();

    assert.equal(writeOnlyResponse.status, 400);
    assert.equal(writeOnlyBody.error, 4);
    assert.equal(writeOnlyBody.message, 'Invalid subaccount: this subaccount does not have read permission');
  } finally {
    await mock.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('push delivery queue records matching storage stores for active subscriptions', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'deep-mock-'));
  const mock = await startMockService({ port: randomPort(), stateDir });

  try {
    const subscription = createSignedPushSubscribePayload(pushSigningIdentity, {
      namespaces: [0],
      service_info: { token: 'delivery-token-1' }
    });
    const subscribeResponse = await fetch(`${mock.baseUrl}/subscribe`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(subscription)
    });
    assert.equal(subscribeResponse.status, 200);

    const messageData = Buffer.from('push delivery message', 'utf8').toString('base64');
    const storeResponse = await fetch(`${mock.baseUrl}/storage/store`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        pubkey: subscription.pubkey,
        namespace: 0,
        timestamp: Date.now(),
        ttl: 60_000,
        data: messageData
      })
    });
    const stored = await storeResponse.json();

    assert.equal(storeResponse.status, 200);
    assert.equal(typeof stored.hash, 'string');

    const listResponse = await fetch(`${mock.baseUrl}/subscriptions/${encodeURIComponent(subscription.pubkey)}`);
    const list = await listResponse.json();

    assert.equal(listResponse.status, 200);
    assert.equal(list.subscriptions.length, 1);
    assert.equal(Array.isArray(list.deliveries), true);
    assert.equal(list.deliveries.length, 1);
    assert.equal(list.deliveries[0].hash, stored.hash);
    assert.equal(list.deliveries[0].service, subscription.service);
    assert.equal(list.deliveries[0].token, subscription.service_info.token);
    assert.equal(list.deliveries[0].namespace, 0);
    assert.equal(list.deliveries[0].data, messageData);
  } finally {
    await mock.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('push subscribe rejects too old sig_ts with BAD_INPUT', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'deep-mock-'));
  const mock = await startMockService({ port: randomPort(), stateDir });

  try {
    const response = await fetch(`${mock.baseUrl}/subscribe`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(createPushSubscribePayload({ sig_ts: 1, namespaces: [0] }))
    });
    const body = await response.json();

    assert.equal(response.status, 400);
    assert.equal(body.error, 1);
    assert.equal(body.message, 'Subscription: sig_ts timestamp is too old');
  } finally {
    await mock.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('push subscribe rejects invalid signature length with BAD_INPUT', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'deep-mock-'));
  const mock = await startMockService({ port: randomPort(), stateDir });

  try {
    const response = await fetch(`${mock.baseUrl}/subscribe`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(createPushSubscribePayload({
        signature: 'deadbeef',
        namespaces: [0]
      }))
    });
    const body = await response.json();

    assert.equal(response.status, 400);
    assert.equal(body.error, 1);
    assert.equal(body.message, 'Missing required parameter');
  } finally {
    await mock.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('push unsubscribe rejects too old sig_ts with BAD_INPUT', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'deep-mock-'));
  const mock = await startMockService({ port: randomPort(), stateDir });

  try {
    const response = await fetch(`${mock.baseUrl}/unsubscribe`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(createPushUnsubscribePayload({ sig_ts: 1 }))
    });
    const body = await response.json();

    assert.equal(response.status, 400);
    assert.equal(body.error, 1);
    assert.equal(body.message, 'Unsubscribe: sig_ts timestamp is too old');
  } finally {
    await mock.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('push unsubscribe verifies real signatures for verifiable Session identities', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'deep-mock-'));
  const mock = await startMockService({ port: randomPort(), stateDir });

  try {
    const subscribePayload = createSignedPushSubscribePayload(pushSigningIdentity, {
      service_info: { token: 'signed-unsubscribe-1' }
    });
    const subscribeResponse = await fetch(`${mock.baseUrl}/subscribe`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(subscribePayload)
    });
    assert.equal(subscribeResponse.status, 200);

    const invalidUnsubscribeResponse = await fetch(`${mock.baseUrl}/unsubscribe`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(createSignedPushUnsubscribePayload(pushSigningIdentity, {
        service_info: { token: 'signed-unsubscribe-1' },
        signature: invalidateSignature(createSignedPushUnsubscribePayload(pushSigningIdentity, {
          service_info: { token: 'signed-unsubscribe-1' }
        }).signature)
      }))
    });
    const invalidUnsubscribeBody = await invalidUnsubscribeResponse.json();

    assert.equal(invalidUnsubscribeResponse.status, 400);
    assert.equal(invalidUnsubscribeBody.error, 4);
    assert.equal(invalidUnsubscribeBody.message, 'Signature verification failed');

    const unsubscribePayload = createSignedPushUnsubscribePayload(pushSigningIdentity, {
      service_info: { token: 'signed-unsubscribe-1' }
    });
    const unsubscribeResponse = await fetch(`${mock.baseUrl}/unsubscribe`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(unsubscribePayload)
    });
    const unsubscribed = await unsubscribeResponse.json();

    assert.equal(unsubscribeResponse.status, 200);
    assert.equal(unsubscribed.success, true);
    assert.equal(unsubscribed.removed, true);
  } finally {
    await mock.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('stats endpoint reports request counters and inventory', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'deep-mock-'));
  const mock = await startMockService({ port: randomPort(), stateDir });

  try {
    const storeResponse = await fetch(`${mock.baseUrl}/storage/store`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(createStorageStorePayload({
        pubkey: '05stats',
        namespace: 1,
        timestamp: Date.now(),
        ttl: 60_000,
        data: Buffer.from('stats-data', 'utf8').toString('base64')
      }))
    });
    assert.equal(storeResponse.status, 200);

    const statsResponse = await fetch(`${mock.baseUrl}/stats`);
    const statsBody = await statsResponse.json();

    assert.equal(statsResponse.status, 200);
    assert.equal(statsBody.service, 'deep-all-compat');
    assert.equal(statsBody.mode, 'all');
    assert.equal(statsBody.inventory.storageMessages, 1);
    assert.equal(statsBody.stats.storageStore, 1);
    assert.ok(statsBody.stats.requestsTotal >= 2);
    assert.ok(statsBody.stats.healthChecks >= 1);
  } finally {
    await mock.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('health and stats endpoints honor SERVICE_NAME override', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'deep-mock-'));
  const mock = await startMockService({
    port: randomPort(),
    stateDir,
    extraEnv: {
      SERVICE_MODE: 'storage',
      SERVICE_NAME: 'deep-storage-service'
    }
  });

  try {
    const healthResponse = await fetch(`${mock.baseUrl}/health/ready`);
    const healthBody = await healthResponse.json();
    const statsResponse = await fetch(`${mock.baseUrl}/stats`);
    const statsBody = await statsResponse.json();

    assert.equal(healthResponse.status, 200);
    assert.equal(healthBody.service, 'deep-storage-service');
    assert.equal(statsResponse.status, 200);
    assert.equal(statsBody.service, 'deep-storage-service');
    assert.equal(statsBody.mode, 'storage');
  } finally {
    await mock.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('compat push v2 dispatch binds every field, preserves state on tamper, and isolates legacy compatibility', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'compat-push-v2-'));
  const mock = await startMockService({ port: randomPort(), stateDir });
  const post = (route, payload) => fetch(`${mock.baseUrl}/${route}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(payload)
  });
  const list = async () => {
    const response = await fetch(
      `${mock.baseUrl}/subscriptions/${encodeURIComponent(pushSigningIdentity.sessionPubkey)}`
    );
    assert.equal(response.status, 200);
    return response.json();
  };

  try {
    const valid = createSignedPushSubscribePayloadV2(pushSigningIdentity, {
      service_info: { token: 'v2-compat-token' }
    });
    assert.equal((await post('subscribe', valid)).status, 200);

    const legacyAbsent = createSignedPushSubscribePayload(pushSigningIdentity, {
      service_info: { token: 'legacy-absent-compat' }
    });
    const legacyV1 = createSignedPushSubscribePayload(pushSigningIdentity, {
      service_info: { token: 'legacy-v1-compat' },
      sig_v: 1
    });
    assert.equal((await post('subscribe', legacyAbsent)).status, 200);
    assert.equal((await post('subscribe', legacyV1)).status, 200);

    const persistedBeforeSubscribeTamper = await readFile(path.join(stateDir, 'push.json'), 'utf8');
    const flipLastHex = value => value.slice(0, -1) + (value.endsWith('0') ? '1' : '0');
    const oldSignedSubscribe = overrides => {
      const payload = { ...valid, ...overrides };
      payload.signature = signOldCoerciveSubscribeV2(pushSigningIdentity, payload);
      return payload;
    };
    const subscribeTamper = [
      { ...valid, pubkey: flipLastHex(valid.pubkey) },
      { ...valid, session_ed25519: flipLastHex(valid.session_ed25519) },
      { ...valid, sig_ts: valid.sig_ts + 1 },
      { ...valid, service: 'firebase' },
      { ...valid, service_info: { token: `${valid.service_info.token}-tampered` } },
      { ...valid, enc_key: flipLastHex(valid.enc_key) },
      { ...valid, data: !valid.data },
      { ...valid, namespaces: [0, 12] },
      { ...valid, app_id: `${valid.app_id}.tampered` },
      { ...valid, app_version: `${valid.app_version}.tampered` },
      { ...valid, signature: invalidateSignature(valid.signature) },
      { ...valid, sig_v: 3 },
      { ...valid, sig_v: '2' },
      { ...valid, sig_v: 1 },
      oldSignedSubscribe({ sig_ts: String(valid.sig_ts) }),
      oldSignedSubscribe({ namespaces: ['0', 10] }),
      oldSignedSubscribe({ namespaces: [null, 10] }),
      oldSignedSubscribe({ namespaces: [0, '0'] }),
      oldSignedSubscribe({ namespaces: [0, 10.5] }),
      oldSignedSubscribe({ namespaces: [0, Number.MAX_SAFE_INTEGER + 1] }),
      oldSignedSubscribe({ namespaces: [-2_147_483_649, 0] }),
      oldSignedSubscribe({ namespaces: [0, 2_147_483_648] }),
      oldSignedSubscribe({ service_info: { token: 12345 } }),
      oldSignedSubscribe({ pubkey: valid.pubkey.toUpperCase() }),
      oldSignedSubscribe({ session_ed25519: valid.session_ed25519.toUpperCase() }),
      oldSignedSubscribe({ data: 1 }),
      createSignedPushSubscribePayload(pushSigningIdentity, {
        service_info: { token: 'no-v2-to-legacy-fallback-compat' },
        app_id: valid.app_id,
        app_version: valid.app_version,
        sig_v: 2
      })
    ];
    for (const [index, payload] of subscribeTamper.entries()) {
      const response = await post('subscribe', payload);
      assert.equal(response.status, 400);
      assert.equal(
        await readFile(path.join(stateDir, 'push.json'), 'utf8'),
        persistedBeforeSubscribeTamper,
        `subscribe adversarial vector ${index} must not mutate persisted state`
      );
    }

    const afterSubscribeTamper = await list();
    assert.deepEqual(
      afterSubscribeTamper.subscriptions.map(record => record.service_info.token).sort(),
      ['legacy-absent-compat', 'legacy-v1-compat', 'v2-compat-token']
    );

    const validUnsubscribe = createSignedPushUnsubscribePayloadV2(pushSigningIdentity, {
      service_info: { token: valid.service_info.token }
    });
    const persistedBeforeUnsubscribeTamper = await readFile(path.join(stateDir, 'push.json'), 'utf8');
    const oldSignedUnsubscribe = overrides => {
      const payload = { ...validUnsubscribe, ...overrides };
      payload.signature = signOldCoerciveUnsubscribeV2(pushSigningIdentity, payload);
      return payload;
    };
    const unsubscribeTamper = [
      { ...validUnsubscribe, pubkey: flipLastHex(validUnsubscribe.pubkey) },
      { ...validUnsubscribe, session_ed25519: flipLastHex(validUnsubscribe.session_ed25519) },
      { ...validUnsubscribe, sig_ts: validUnsubscribe.sig_ts + 1 },
      { ...validUnsubscribe, service: 'firebase' },
      {
        ...validUnsubscribe,
        service_info: { token: `${validUnsubscribe.service_info.token}-tampered` }
      },
      { ...validUnsubscribe, signature: invalidateSignature(validUnsubscribe.signature) },
      { ...validUnsubscribe, sig_v: 0 },
      { ...validUnsubscribe, sig_v: '2' },
      { ...validUnsubscribe, sig_v: 1 },
      oldSignedUnsubscribe({ sig_ts: String(validUnsubscribe.sig_ts) }),
      oldSignedUnsubscribe({ service_info: { token: 12345 } }),
      oldSignedUnsubscribe({ pubkey: validUnsubscribe.pubkey.toUpperCase() }),
      oldSignedUnsubscribe({
        session_ed25519: validUnsubscribe.session_ed25519.toUpperCase()
      }),
      createSignedPushUnsubscribePayload(pushSigningIdentity, {
        service_info: { token: valid.service_info.token },
        sig_v: 2
      })
    ];
    for (const [index, payload] of unsubscribeTamper.entries()) {
      const response = await post('unsubscribe', payload);
      assert.equal(response.status, 400);
      assert.equal(
        await readFile(path.join(stateDir, 'push.json'), 'utf8'),
        persistedBeforeUnsubscribeTamper,
        `unsubscribe adversarial vector ${index} must not mutate persisted state`
      );
    }
    assert.equal((await list()).subscriptions.length, 3);

    const unsubscribeResponse = await post('unsubscribe', validUnsubscribe);
    assert.equal(unsubscribeResponse.status, 200);
    assert.equal((await unsubscribeResponse.json()).removed, true);
    assert.deepEqual(
      (await list()).subscriptions.map(record => record.service_info.token).sort(),
      ['legacy-absent-compat', 'legacy-v1-compat']
    );
  } finally {
    await mock.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});
