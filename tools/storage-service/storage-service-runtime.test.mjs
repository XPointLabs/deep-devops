import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import http from 'node:http';
import { createHash, generateKeyPairSync, verify } from 'node:crypto';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { spawn } from 'node:child_process';
import { createTestStorageSigningIdentity } from '../compat-services/storage-signatures.mjs';
import { fileURLToPath } from 'node:url';

const scriptPath = path.resolve(path.dirname(fileURLToPath(import.meta.url)), 'storage-service.mjs');
const compatRelayId = '1111111111111111111111111111111111111111111111111111111111111111';
const storageSigningIdentity = createTestStorageSigningIdentity();

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

  throw new Error('storage-service did not become ready in time');
}

async function waitFor(condition, timeoutMs, description) {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    if (condition()) {
      return;
    }

    await new Promise(resolve => setTimeout(resolve, 25));
  }

  throw new Error(description);
}

async function startStorageService({ port, stateDir, extraEnv = {} }) {
  const child = spawn(process.execPath, [scriptPath], {
    env: {
      ...process.env,
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
        assert.fail(`storage-service stderr was not empty:\n${stderr}`);
      }
    }
  };
}

async function startPushNotifyReceiver(options = {}) {
  const {
    responseStatus = 202,
    responseBody = { queued: 1 }
  } = options;
  const requests = [];
  const server = http.createServer(async (req, res) => {
    const chunks = [];
    for await (const chunk of req) {
      chunks.push(Buffer.from(chunk));
    }

    const raw = Buffer.concat(chunks);
    const url = new URL(req.url ?? '/', 'http://127.0.0.1');
    requests.push({
      method: req.method,
      pathname: url.pathname,
      headers: req.headers,
      raw,
      body: raw.length === 0 ? null : JSON.parse(raw.toString('utf8'))
    });

    const body = Buffer.from(JSON.stringify(responseBody));
    res.writeHead(responseStatus, {
      'content-type': 'application/json',
      'content-length': body.length
    });
    res.end(body);
  });

  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();

  return {
    baseUrl: `http://127.0.0.1:${address.port}`,
    requests,
    async stop() {
      await new Promise(resolve => server.close(resolve));
    }
  };
}

let nextPort = 22000 + Math.floor(Math.random() * 1000);

function randomPort() {
  nextPort += 1;
  return nextPort;
}

function withStorageSubaccount(payload, subaccount) {
  return {
    ...payload,
    subaccount: subaccount.subaccount,
    subaccount_sig: subaccount.subaccountSig
  };
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

function createSignedStorageExpireAllPayload(identity, overrides = {}) {
  const payload = { ...overrides };
  const namespace = payload.namespace ?? 0;
  const expiry = Number(payload.expiry ?? Date.now() + 60_000);

  return {
    pubkey: identity.directPubkey,
    namespace,
    expiry,
    signature: identity.signExpireAll(namespace, expiry),
    ...payload
  };
}

function createSignedStorageExpirePayload(identity, overrides = {}) {
  const payload = { ...overrides };
  const messages = Array.isArray(payload.messages) ? payload.messages.map(value => String(value)) : [];
  const expiry = payload.expiry ?? Date.now() + 60_000;
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

function createSignedStorageDeleteBeforePayload(identity, overrides = {}) {
  const payload = { ...overrides };
  const namespace = payload.namespace ?? 0;
  const before = Number(payload.before ?? Date.now());

  return {
    pubkey: identity.directPubkey,
    namespace,
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

async function storeSignedStorageMessage(service, identity, overrides = {}) {
  const payload = createSignedStorageStorePayload(identity, overrides);
  const response = await fetch(`${service.baseUrl}/storage/store`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(payload)
  });
  const body = await response.json();
  assert.equal(response.status, 200);
  return body;
}

test('health and stats endpoints honor SERVICE_NAME override', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'storage-service-runtime-'));
  const service = await startStorageService({
    port: randomPort(),
    stateDir,
    extraEnv: {
      SERVICE_NAME: 'storage-runtime-override'
    }
  });

  try {
    const healthResponse = await fetch(`${service.baseUrl}/health/ready`);
    assert.equal(healthResponse.status, 200);
    assert.deepEqual(await healthResponse.json(), { ok: true, service: 'storage-runtime-override' });

    const statsResponse = await fetch(`${service.baseUrl}/stats`);
    assert.equal(statsResponse.status, 200);
    const statsBody = await statsResponse.json();
    assert.equal(statsBody.service, 'storage-runtime-override');
    assert.equal(statsBody.mode, 'storage');
    assert.equal(statsBody.inventory.storageMessages, 0);
    assert.equal(statsBody.inventory.revokedSubaccounts, 0);
    assert.equal(statsBody.inventory.files, 0);
    assert.equal(statsBody.inventory.subscriptions, 0);
    assert.equal(statsBody.inventory.pushDeliveries, 0);
  } finally {
    await service.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('storage runtime fails closed for every protected operation', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'storage-service-runtime-'));
  const service = await startStorageService({ port: randomPort(), stateDir });
  const timestamp = Date.now();
  const uncheckableSessionPubkey = `05${'0'.repeat(64)}`;
  const subaccount = storageSigningIdentity.createSubaccount();
  const protectedRequests = [
    ['/storage/store', {
      pubkey: uncheckableSessionPubkey,
      namespace: 42,
      timestamp,
      ttl: 60_000,
      data: Buffer.from('uncheckable-store', 'utf8').toString('base64'),
      signature: 'deep-client-storage-retrieve'
    }],
    ['/storage/retrieve', { pubkey: uncheckableSessionPubkey, namespace: 0, timestamp, signature: 'deep-client-storage-retrieve' }],
    ['/storage/get_expiries', { pubkey: uncheckableSessionPubkey, timestamp, messages: ['message'], signature: 'deep-client-storage-retrieve' }],
    ['/storage/revoke_subaccount', { pubkey: uncheckableSessionPubkey, timestamp, revoke: subaccount.subaccount, signature: 'deep-client-storage-retrieve' }],
    ['/storage/unrevoke_subaccount', { pubkey: uncheckableSessionPubkey, timestamp, unrevoke: subaccount.subaccount, signature: 'deep-client-storage-retrieve' }],
    ['/storage/revoked_subaccounts', { pubkey: uncheckableSessionPubkey, timestamp, signature: 'deep-client-storage-retrieve' }],
    ['/storage/expire_all', { pubkey: uncheckableSessionPubkey, namespace: 0, expiry: timestamp + 60_000, signature: 'deep-client-storage-retrieve' }],
    ['/storage/expire', { pubkey: uncheckableSessionPubkey, messages: ['message'], expiry: timestamp + 60_000, signature: 'deep-client-storage-retrieve' }],
    ['/storage/delete', { pubkey: uncheckableSessionPubkey, messages: ['message'], signature: 'deep-client-storage-retrieve' }],
    ['/storage/delete_all', { pubkey: uncheckableSessionPubkey, namespace: 0, timestamp, signature: 'deep-client-storage-retrieve' }],
    ['/storage/delete_before', { pubkey: uncheckableSessionPubkey, namespace: 0, before: timestamp, signature: 'deep-client-storage-retrieve' }]
  ];

  try {
    for (const [pathname, payload] of protectedRequests) {
      const response = await fetch(`${service.baseUrl}${pathname}`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(payload)
      });
      assert.equal(response.status, 401, pathname);
    }

    const publicInboxResponse = await fetch(`${service.baseUrl}/storage/store`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        pubkey: uncheckableSessionPubkey,
        namespace: 0,
        timestamp,
        ttl: 60_000,
        data: Buffer.from('public-inbox-remains-open', 'utf8').toString('base64')
      })
    });
    assert.equal(publicInboxResponse.status, 200);
  } finally {
    await service.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('storage runtime requires bound 05 companions and exact signed request values', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'storage-service-runtime-'));
  const service = await startStorageService({ port: randomPort(), stateDir });
  const sessionIdentity = createTestStorageSigningIdentity();
  const otherIdentity = createTestStorageSigningIdentity();
  const timestamp = Date.now();

  try {
    const sessionStore = createSignedStorageStorePayload(sessionIdentity, {
      pubkey: sessionIdentity.sessionPubkey,
      pubkey_ed25519: sessionIdentity.pubkeyEd25519,
      namespace: 42,
      timestamp
    });
    const sessionStoreResponse = await fetch(`${service.baseUrl}/storage/store`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(sessionStore)
    });
    assert.equal(sessionStoreResponse.status, 200);

    const missingCompanionResponse = await fetch(`${service.baseUrl}/storage/retrieve`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(createSignedStorageRetrievePayload(sessionIdentity, {
        pubkey: sessionIdentity.sessionPubkey,
        namespace: 42,
        timestamp
      }))
    });
    assert.equal(missingCompanionResponse.status, 401);

    const wrongCompanionResponse = await fetch(`${service.baseUrl}/storage/retrieve`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(createSignedStorageRetrievePayload(sessionIdentity, {
        pubkey: sessionIdentity.sessionPubkey,
        pubkey_ed25519: otherIdentity.pubkeyEd25519,
        namespace: 42,
        timestamp
      }))
    });
    assert.equal(wrongCompanionResponse.status, 401);

    const malformedSignatureResponse = await fetch(`${service.baseUrl}/storage/retrieve`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        pubkey: sessionIdentity.directPubkey,
        namespace: 42,
        timestamp,
        signature: 'not base64!'
      })
    });
    assert.equal(malformedSignatureResponse.status, 401);

    const missingRetrieveTimestampResponse = await fetch(`${service.baseUrl}/storage/retrieve`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        pubkey: sessionIdentity.directPubkey,
        namespace: 42,
        signature: sessionIdentity.signRetrieve(42, timestamp)
      })
    });
    assert.equal(missingRetrieveTimestampResponse.status, 400);

    const { timestamp: ignoredTimestamp, ...missingStoreTimestamp } = createSignedStorageStorePayload(sessionIdentity, {
      namespace: 42,
      timestamp
    });
    const missingStoreTimestampResponse = await fetch(`${service.baseUrl}/storage/store`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(missingStoreTimestamp)
    });
    assert.equal(missingStoreTimestampResponse.status, 400);

    const wrongKeyResponse = await fetch(`${service.baseUrl}/storage/retrieve`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(createSignedStorageRetrievePayload(sessionIdentity, {
        pubkey: otherIdentity.directPubkey,
        namespace: 42,
        timestamp
      }))
    });
    assert.equal(wrongKeyResponse.status, 401);

    const wrongNamespaceResponse = await fetch(`${service.baseUrl}/storage/store`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        ...createSignedStorageStorePayload(sessionIdentity, { namespace: 43, timestamp }),
        namespace: 42
      })
    });
    assert.equal(wrongNamespaceResponse.status, 401);

    const wrongTimestampResponse = await fetch(`${service.baseUrl}/storage/retrieve`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        ...createSignedStorageRetrievePayload(sessionIdentity, { namespace: 42, timestamp }),
        timestamp: timestamp + 1
      })
    });
    assert.equal(wrongTimestampResponse.status, 401);

    const signedSessionRetrieveResponse = await fetch(`${service.baseUrl}/storage/retrieve`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(createSignedStorageRetrievePayload(sessionIdentity, {
        pubkey: sessionIdentity.sessionPubkey,
        pubkey_ed25519: sessionIdentity.pubkeyEd25519,
        namespace: 42,
        timestamp
      }))
    });
    assert.equal(signedSessionRetrieveResponse.status, 200);
    assert.equal((await signedSessionRetrieveResponse.json()).messages.length, 1);
  } finally {
    await service.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('storage runtime accepts canonical real signatures for expiry and delete operations', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'storage-service-runtime-'));
  const service = await startStorageService({ port: randomPort(), stateDir });
  const timestamp = Date.now();

  try {
    const stored = [];
    for (const suffix of ['one', 'two', 'three']) {
      stored.push(await storeSignedStorageMessage(service, storageSigningIdentity, {
        namespace: 42,
        timestamp,
        ttl: 120_000,
        data: Buffer.from(`canonical-${suffix}`, 'utf8').toString('base64')
      }));
    }

    const expireAllResponse = await fetch(`${service.baseUrl}/storage/expire_all`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(createSignedStorageExpireAllPayload(storageSigningIdentity, {
        namespace: 42,
        expiry: timestamp + 60_000
      }))
    });
    assert.equal(expireAllResponse.status, 200);

    const expireResponse = await fetch(`${service.baseUrl}/storage/expire`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(createSignedStorageExpirePayload(storageSigningIdentity, {
        messages: [stored[0].hash],
        expiry: timestamp + 90_000,
        extend: true
      }))
    });
    assert.equal(expireResponse.status, 200);

    const deleteResponse = await fetch(`${service.baseUrl}/storage/delete`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(createSignedStorageDeletePayload(storageSigningIdentity, {
        messages: [stored[1].hash]
      }))
    });
    assert.equal(deleteResponse.status, 200);

    const deleteBeforeResponse = await fetch(`${service.baseUrl}/storage/delete_before`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(createSignedStorageDeleteBeforePayload(storageSigningIdentity, {
        namespace: 42,
        before: Date.now()
      }))
    });
    assert.equal(deleteBeforeResponse.status, 200);
    const deleteBeforeBody = await deleteBeforeResponse.json();
    assert.deepEqual(deleteBeforeBody.swarm[compatRelayId].deleted.sort(), [stored[0].hash, stored[2].hash].sort());
  } finally {
    await service.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('storage runtime preserves signed lifecycle and emits push notify hop', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'storage-service-runtime-'));
  const receiver = await startPushNotifyReceiver();
  const service = await startStorageService({
    port: randomPort(),
    stateDir,
    extraEnv: {
      PUSH_COMPAT_NOTIFY_URL: receiver.baseUrl
    }
  });


test('storage runtime preserves signed store when push notify hop fails downstream', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'storage-service-runtime-'));
  const receiver = await startPushNotifyReceiver({
    responseStatus: 503,
    responseBody: { error: 'push-unavailable' }
  });
  const service = await startStorageService({
    port: randomPort(),
    stateDir,
    extraEnv: {
      PUSH_COMPAT_NOTIFY_URL: receiver.baseUrl
    }
  });

  try {
    const storePayload = createSignedStorageStorePayload(storageSigningIdentity, {
      namespace: 43,
      timestamp: Date.now(),
      data: Buffer.from('storage-runtime-notify-failure', 'utf8').toString('base64')
    });
    const storeResponse = await fetch(`${service.baseUrl}/storage/store`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(storePayload)
    });
    const stored = await storeResponse.json();
    assert.equal(storeResponse.status, 200);

    await waitFor(() => receiver.requests.length === 1, 5000, 'storage-service did not attempt the push notify hop');
    assert.equal(receiver.requests[0].pathname, '/_compat/push-notify');
    assert.equal(receiver.requests[0].body.hash, stored.hash);
    assert.equal(receiver.requests[0].body.namespace, 43);

    const retrieveResponse = await fetch(`${service.baseUrl}/storage/retrieve`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(createSignedStorageRetrievePayload(storageSigningIdentity, {
        namespace: 43,
        timestamp: Date.now()
      }))
    });
    const retrieved = await retrieveResponse.json();
    assert.equal(retrieveResponse.status, 200);
    assert.equal(retrieved.messages.length, 1);
    assert.equal(retrieved.messages[0].hash, stored.hash);

    const statsResponse = await fetch(`${service.baseUrl}/stats`);
    assert.equal(statsResponse.status, 200);
    const statsBody = await statsResponse.json();
    assert.equal(statsBody.stats.storageStore, 1);
    assert.equal(statsBody.stats.storageRetrieve, 1);
    assert.equal(statsBody.stats.errors, 0);
    assert.equal(statsBody.inventory.storageMessages, 1);
  } finally {
    await service.stop();
    await receiver.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});
  try {
    const storePayload = createSignedStorageStorePayload(storageSigningIdentity, {
      namespace: 42,
      timestamp: Date.now(),
      data: Buffer.from('storage-runtime-message', 'utf8').toString('base64'),
      idempotency_key: 'storage-idem-1'
    });
    const firstStoreResponse = await fetch(`${service.baseUrl}/storage/store`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(storePayload)
    });
    const firstStored = await firstStoreResponse.json();
    assert.equal(firstStoreResponse.status, 200);

    const secondStoreResponse = await fetch(`${service.baseUrl}/storage/store`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        ...storePayload,
        data: Buffer.from('storage-runtime-message-updated', 'utf8').toString('base64')
      })
    });
    const secondStored = await secondStoreResponse.json();
    assert.equal(secondStoreResponse.status, 200);
    assert.equal(secondStored.hash, firstStored.hash);
    assert.equal(secondStored.idempotent, true);

    await waitFor(() => receiver.requests.length === 1, 5000, 'storage-service did not emit a single push notify request');
    assert.equal(receiver.requests[0].pathname, '/_compat/push-notify');
    assert.equal(receiver.requests[0].body.hash, firstStored.hash);
    assert.equal(receiver.requests[0].body.namespace, 42);

    const retrieveResponse = await fetch(`${service.baseUrl}/storage/retrieve`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(createSignedStorageRetrievePayload(storageSigningIdentity, {
        namespace: 42,
        timestamp: Date.now()
      }))
    });
    const retrieved = await retrieveResponse.json();
    assert.equal(retrieveResponse.status, 200);
    assert.equal(retrieved.messages.length, 1);
    assert.equal(retrieved.messages[0].hash, firstStored.hash);

    const expiriesResponse = await fetch(`${service.baseUrl}/storage/get_expiries`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(createSignedStorageGetExpiriesPayload(storageSigningIdentity, {
        timestamp: Date.now(),
        messages: [firstStored.hash]
      }))
    });
    const expiriesBody = await expiriesResponse.json();
    assert.equal(expiriesResponse.status, 200);
    assert.equal(typeof expiriesBody.expiries[firstStored.hash], 'number');

    const deleteAllResponse = await fetch(`${service.baseUrl}/storage/delete_all`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(createSignedStorageDeleteAllPayload(storageSigningIdentity, {
        namespace: 42,
        timestamp: Date.now()
      }))
    });
    const deleteAllBody = await deleteAllResponse.json();
    assert.equal(deleteAllResponse.status, 200);
    assert.deepEqual(deleteAllBody.swarm[compatRelayId].deleted, [firstStored.hash]);

    const finalRetrieveResponse = await fetch(`${service.baseUrl}/storage/retrieve`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(createSignedStorageRetrievePayload(storageSigningIdentity, {
        namespace: 42,
        timestamp: Date.now()
      }))
    });
    const finalRetrieved = await finalRetrieveResponse.json();
    assert.equal(finalRetrieveResponse.status, 200);
    assert.deepEqual(finalRetrieved.messages, []);
  } finally {
    await service.stop();
    await receiver.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('storage runtime prunes expired messages from retrieve and persisted state', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'storage-service-runtime-'));
  let service = await startStorageService({ port: randomPort(), stateDir });

  try {
    const stored = await storeSignedStorageMessage(service, storageSigningIdentity, {
      namespace: 42,
      timestamp: Date.now(),
      ttl: 200,
      data: Buffer.from('storage-expired-message', 'utf8').toString('base64')
    });

    const initialRetrieveResponse = await fetch(`${service.baseUrl}/storage/retrieve`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(createSignedStorageRetrievePayload(storageSigningIdentity, {
        namespace: 42,
        timestamp: Date.now()
      }))
    });
    assert.equal(initialRetrieveResponse.status, 200);
    assert.equal((await initialRetrieveResponse.json()).messages.length, 1);

    await new Promise(resolve => setTimeout(resolve, 300));

    const expiredRetrieveResponse = await fetch(`${service.baseUrl}/storage/retrieve`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(createSignedStorageRetrievePayload(storageSigningIdentity, {
        namespace: 42,
        timestamp: Date.now()
      }))
    });
    assert.equal(expiredRetrieveResponse.status, 200);
    const expiredRetrieved = await expiredRetrieveResponse.json();
    assert.deepEqual(expiredRetrieved.messages, []);

    const expiriesResponse = await fetch(`${service.baseUrl}/storage/get_expiries`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(createSignedStorageGetExpiriesPayload(storageSigningIdentity, {
        timestamp: Date.now(),
        messages: [stored.hash]
      }))
    });
    assert.equal(expiriesResponse.status, 200);
    assert.deepEqual((await expiriesResponse.json()).expiries, {});

    const statsResponse = await fetch(`${service.baseUrl}/stats`);
    assert.equal(statsResponse.status, 200);
    const statsBody = await statsResponse.json();
    assert.equal(statsBody.inventory.storageMessages, 0);

    await service.stop();
    service = await startStorageService({ port: randomPort(), stateDir });
    const restartedRetrieve = await fetch(`${service.baseUrl}/storage/retrieve`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(createSignedStorageRetrievePayload(storageSigningIdentity, {
        namespace: 42,
        timestamp: Date.now()
      }))
    });
    assert.equal(restartedRetrieve.status, 200);
    assert.deepEqual((await restartedRetrieve.json()).messages, []);
  } finally {
    await service.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('storage revoke lifecycle blocks revoked subaccounts except for unrevocable namespaces', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'storage-service-runtime-'));
  const service = await startStorageService({ port: randomPort(), stateDir });

  try {
    const baseTimestamp = Date.now();
    const privateStore = await storeSignedStorageMessage(service, storageSigningIdentity, {
      namespace: 42,
      timestamp: baseTimestamp,
      data: Buffer.from('revoked-private', 'utf8').toString('base64')
    });
    const unrevocableStore = await storeSignedStorageMessage(service, storageSigningIdentity, {
      namespace: -11,
      timestamp: baseTimestamp + 1,
      data: Buffer.from('revoked-unrevocable', 'utf8').toString('base64')
    });
    const subaccount = storageSigningIdentity.createSubaccount();

    const initialRetrieveResponse = await fetch(`${service.baseUrl}/storage/retrieve`, {
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

    const emptyRevocationListResponse = await fetch(`${service.baseUrl}/storage/revoked_subaccounts`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(createSignedStorageRevokedSubaccountsPayload(storageSigningIdentity, {
        timestamp: baseTimestamp + 3
      }))
    });
    assert.equal(emptyRevocationListResponse.status, 200);
    assert.deepEqual((await emptyRevocationListResponse.json()).revoked_subaccounts, []);

    const revokeResponse = await fetch(`${service.baseUrl}/storage/revoke_subaccount`, {
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

    const revokedRetrieveResponse = await fetch(`${service.baseUrl}/storage/retrieve`, {
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

    const revokedListResponse = await fetch(`${service.baseUrl}/storage/revoked_subaccounts`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(createSignedStorageRevokedSubaccountsPayload(storageSigningIdentity, {
        timestamp: baseTimestamp + 6
      }))
    });
    assert.equal(revokedListResponse.status, 200);
    assert.deepEqual((await revokedListResponse.json()).revoked_subaccounts, [subaccount.subaccount]);

    const unrevocableRetrieveResponse = await fetch(`${service.baseUrl}/storage/retrieve`, {
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

    const unrevokeResponse = await fetch(`${service.baseUrl}/storage/unrevoke_subaccount`, {
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

    const restoredRetrieveResponse = await fetch(`${service.baseUrl}/storage/retrieve`, {
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
  } finally {
    await service.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('storage sequence stops on the first error while batch continues', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'storage-service-runtime-'));
  const service = await startStorageService({ port: randomPort(), stateDir });

  try {
    const pubkey = storageSigningIdentity.directPubkey;
    const storeResponse = await fetch(`${service.baseUrl}/storage/store`, {
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
    const retrieveTimestamp = Date.now();

    const requests = [
      {
        method: 'store',
        params: {
          pubkey,
          namespace: 33,
          timestamp: Date.now(),
          ttl: 60_000,
          data: Buffer.from('missing-signature-private-store', 'utf8').toString('base64'),
          signature: ''
        }
      },
      {
        method: 'retrieve',
        params: {
          pubkey,
          namespace: 0,
          timestamp: retrieveTimestamp,
          signature: storageSigningIdentity.signRetrieve(0, retrieveTimestamp)
        }
      }
    ];

    const sequenceResponse = await fetch(`${service.baseUrl}/storage/sequence`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ requests })
    });
    const sequenceBody = await sequenceResponse.json();

    const batchResponse = await fetch(`${service.baseUrl}/storage/batch`, {
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
    await service.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('storage runtime reloads persisted messages and subaccount revocations across restart', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'storage-service-runtime-'));
  const subaccount = storageSigningIdentity.createSubaccount();
  let service = await startStorageService({ port: randomPort(), stateDir });

  try {
    const baseTimestamp = Date.now();
    const stored = await storeSignedStorageMessage(service, storageSigningIdentity, {
      namespace: 42,
      timestamp: baseTimestamp,
      data: Buffer.from('storage-restart-persisted', 'utf8').toString('base64')
    });

    const revokeResponse = await fetch(`${service.baseUrl}/storage/revoke_subaccount`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(createSignedStorageRevokeSubaccountPayload(storageSigningIdentity, {
        timestamp: baseTimestamp + 1,
        revoke: subaccount
      }))
    });
    assert.equal(revokeResponse.status, 200);
    assert.equal((await revokeResponse.json()).swarm[compatRelayId].count, 1);

    await service.stop();
    service = await startStorageService({ port: randomPort(), stateDir });

    const ownerRetrieveResponse = await fetch(`${service.baseUrl}/storage/retrieve`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(createSignedStorageRetrievePayload(storageSigningIdentity, {
        namespace: 42,
        timestamp: baseTimestamp + 2
      }))
    });
    assert.equal(ownerRetrieveResponse.status, 200);
    const ownerRetrieved = await ownerRetrieveResponse.json();
    assert.equal(ownerRetrieved.messages.length, 1);
    assert.equal(ownerRetrieved.messages[0].hash, stored.hash);

    const revokedListResponse = await fetch(`${service.baseUrl}/storage/revoked_subaccounts`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(createSignedStorageRevokedSubaccountsPayload(storageSigningIdentity, {
        timestamp: baseTimestamp + 3
      }))
    });
    assert.equal(revokedListResponse.status, 200);
    assert.deepEqual((await revokedListResponse.json()).revoked_subaccounts, [subaccount.subaccount]);

    const revokedRetrieveResponse = await fetch(`${service.baseUrl}/storage/retrieve`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(withStorageSubaccount(createSignedStorageRetrievePayload(storageSigningIdentity, {
        namespace: 42,
        timestamp: baseTimestamp + 4,
        signature: subaccount.signRetrieve(42, baseTimestamp + 4)
      }), subaccount))
    });
    assert.equal(revokedRetrieveResponse.status, 401);
    assert.equal((await revokedRetrieveResponse.json()).message, 'retrieve signature verification failed');

    const unrevokeResponse = await fetch(`${service.baseUrl}/storage/unrevoke_subaccount`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(createSignedStorageUnrevokeSubaccountPayload(storageSigningIdentity, {
        timestamp: baseTimestamp + 5,
        unrevoke: subaccount
      }))
    });
    assert.equal(unrevokeResponse.status, 200);
    assert.equal((await unrevokeResponse.json()).swarm[compatRelayId].count, 1);

    const restoredRetrieveResponse = await fetch(`${service.baseUrl}/storage/retrieve`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(withStorageSubaccount(createSignedStorageRetrievePayload(storageSigningIdentity, {
        namespace: 42,
        timestamp: baseTimestamp + 6,
        signature: subaccount.signRetrieve(42, baseTimestamp + 6)
      }), subaccount))
    });
    assert.equal(restoredRetrieveResponse.status, 200);
    const restoredRetrieved = await restoredRetrieveResponse.json();
    assert.equal(restoredRetrieved.messages.length, 1);
    assert.equal(restoredRetrieved.messages[0].hash, stored.hash);

    const statsResponse = await fetch(`${service.baseUrl}/stats`);
    assert.equal(statsResponse.status, 200);
    const statsBody = await statsResponse.json();
    assert.equal(statsBody.inventory.storageMessages, 1);
    assert.equal(statsBody.inventory.revokedSubaccounts, 0);
  } finally {
    await service.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('storage runtime authenticates push notifications with its node identity', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'storage-service-push-signing-'));
  const keyFile = path.join(stateDir, 'key_ed25519');
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const publicKeyBytes = Buffer.from(publicKey.export({ type: 'spki', format: 'der' })).subarray(-32);
  const seed = Buffer.from(privateKey.export({ type: 'pkcs8', format: 'der' })).subarray(-32);
  const nodeId = publicKeyBytes.toString('hex');
  await writeFile(keyFile, `0x${seed.toString('hex')}\n`);
  const receiver = await startPushNotifyReceiver();
  const service = await startStorageService({
    port: randomPort(),
    stateDir,
    extraEnv: {
      PUSH_COMPAT_NOTIFY_URL: receiver.baseUrl,
      PUSH_COMPAT_NOTIFY_NODE_ID: nodeId,
      PUSH_COMPAT_NOTIFY_ED25519_PRIVATE_KEY_FILE: keyFile
    }
  });

  try {
    const payload = createSignedStorageStorePayload(storageSigningIdentity, {
      namespace: 42,
      timestamp: Date.now(),
      data: Buffer.from('signed-push-hop').toString('base64')
    });
    const response = await fetch(`${service.baseUrl}/storage/store`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(payload)
    });
    assert.equal(response.status, 200);
    await waitFor(() => receiver.requests.length === 1, 5000, 'signed push notification was not emitted');

    const request = receiver.requests[0];
    const timestamp = request.headers['x-xpoint-notify-timestamp'];
    const signature = Buffer.from(request.headers['x-xpoint-notify-signature'], 'base64');
    const bodyHash = createHash('sha256').update(request.raw).digest('hex');
    const canonical = `XPOINT_PUSH_NOTIFY_V1\n${nodeId}\n${timestamp}\n${bodyHash}`;
    assert.equal(request.headers['x-xpoint-node-id'], nodeId);
    assert.equal(verify(null, Buffer.from(canonical), publicKey, signature), true);
  } finally {
    await service.stop();
    await receiver.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('storage runtime enforces request, message, account, and retrieve-page quotas', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'storage-service-runtime-'));
  const service = await startStorageService({
    port: randomPort(),
    stateDir,
    extraEnv: {
      STORAGE_MAX_REQUEST_BYTES: '512',
      STORAGE_MAX_MESSAGE_BYTES: '32',
      STORAGE_MAX_MESSAGES_PER_ACCOUNT: '2',
      STORAGE_RETRIEVE_PAGE_SIZE: '1'
    }
  });

  try {
    const requestTooLarge = await fetch(`${service.baseUrl}/storage/retrieve`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ padding: 'x'.repeat(1024) })
    });
    assert.equal(requestTooLarge.status, 413);

    const oversizedData = await fetch(`${service.baseUrl}/storage/store`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(createSignedStorageStorePayload(storageSigningIdentity, {
        namespace: 42,
        timestamp: Date.now(),
        data: Buffer.alloc(33, 7).toString('base64')
      }))
    });
    assert.equal(oversizedData.status, 413);

    const stored = [];
    for (const suffix of ['one', 'two']) {
      stored.push(await storeSignedStorageMessage(service, storageSigningIdentity, {
        namespace: 42,
        timestamp: Date.now(),
        data: Buffer.from(suffix).toString('base64')
      }));
    }

    const accountQuota = await fetch(`${service.baseUrl}/storage/store`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(createSignedStorageStorePayload(storageSigningIdentity, {
        namespace: 42,
        timestamp: Date.now(),
        data: Buffer.from('three').toString('base64')
      }))
    });
    assert.equal(accountQuota.status, 413);

    const firstPage = await fetch(`${service.baseUrl}/storage/retrieve`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(createSignedStorageRetrievePayload(storageSigningIdentity, {
        namespace: 42,
        timestamp: Date.now()
      }))
    });
    const firstPageBody = await firstPage.json();
    assert.equal(firstPage.status, 200);
    assert.equal(firstPageBody.messages.length, 1);
    assert.equal(firstPageBody.more, true);

    const secondPage = await fetch(`${service.baseUrl}/storage/retrieve`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(createSignedStorageRetrievePayload(storageSigningIdentity, {
        namespace: 42,
        last_hash: firstPageBody.messages[0].hash,
        timestamp: Date.now()
      }))
    });
    const secondPageBody = await secondPage.json();
    assert.equal(secondPage.status, 200);
    assert.equal(secondPageBody.messages.length, 1);
    assert.equal(secondPageBody.messages[0].hash, stored[1].hash);
  } finally {
    await service.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('storage runtime rate limits public storage requests with no queue', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'storage-service-runtime-'));
  const service = await startStorageService({
    port: randomPort(),
    stateDir,
    extraEnv: { STORAGE_RATE_LIMIT_PER_MINUTE: '1' }
  });

  try {
    const first = await fetch(`${service.baseUrl}/storage/unknown`, { method: 'POST' });
    const second = await fetch(`${service.baseUrl}/storage/unknown`, { method: 'POST' });

    assert.equal(first.status, 404);
    assert.equal(second.status, 429);
  } finally {
    await service.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('storage runtime journals concurrent mutations and reloads without lost messages', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'storage-service-runtime-'));
  const storageJournalPath = path.join(stateDir, 'storage.journal.ndjson');
  let service = await startStorageService({
    port: randomPort(),
    stateDir,
    extraEnv: { STORAGE_SNAPSHOT_EVERY_MUTATIONS: '1000' }
  });

  try {
    const stored = await Promise.all(
      Array.from({ length: 12 }, (_, index) => storeSignedStorageMessage(service, storageSigningIdentity, {
        namespace: 42,
        timestamp: Date.now(),
        data: Buffer.from(`concurrent-${index}`).toString('base64')
      }))
    );
    assert.equal(new Set(stored.map(message => message.hash)).size, 12);

    const journal = await readFile(storageJournalPath, 'utf8');
    assert.equal(journal.trim().split('\n').length, 12);

    await service.stop();
    service = await startStorageService({ port: randomPort(), stateDir });
    const retrieve = await fetch(`${service.baseUrl}/storage/retrieve`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(createSignedStorageRetrievePayload(storageSigningIdentity, {
        namespace: 42,
        timestamp: Date.now(),
        limit: 100
      }))
    });
    assert.equal(retrieve.status, 200);
    assert.equal((await retrieve.json()).messages.length, 12);
  } finally {
    await service.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});
