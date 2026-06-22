import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import http from 'node:http';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { spawn } from 'node:child_process';
import { createTestStorageSigningIdentity } from '../compat-services/storage-signatures.mjs';

const scriptPath = path.resolve('c:/Work/Deep/deep-devops/tools/storage-service/storage-service.mjs');
const validPushSignature = 'f8efdd12000700000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000';
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

function randomPort() {
  return 21000 + Math.floor(Math.random() * 1000);
}

function withStorageSubaccount(payload, subaccount) {
  return {
    ...payload,
    subaccount: subaccount.subaccount,
    subaccount_sig: subaccount.subaccountSig
  };
}

function createStorageStorePayload(overrides = {}) {
  const payload = { ...overrides };
  const namespace = Number(payload.namespace ?? 0);
  if (namespace % 10 !== 0 && payload.signature === undefined) {
    payload.signature = validPushSignature;
  }
  return payload;
}

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
  const storageStatePath = path.join(stateDir, 'storage.json');
  const service = await startStorageService({ port: randomPort(), stateDir });

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

    const persistedState = JSON.parse(await readFile(storageStatePath, 'utf8'));
    assert.deepEqual(persistedState, []);
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
    const pubkey = '05sequence-error';
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
          timestamp: Date.now(),
          signature: validPushSignature
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