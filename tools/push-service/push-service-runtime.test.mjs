import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { spawn } from 'node:child_process';
import http from 'node:http';
import { createTestStorageSigningIdentity } from '../compat-services/storage-signatures.mjs';
import { fileURLToPath } from 'node:url';

const scriptPath = path.resolve(path.dirname(fileURLToPath(import.meta.url)), 'push-service.mjs');
const validEncKey = 'abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd';
const pushSigningIdentity = createTestStorageSigningIdentity();

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

  throw new Error('push-service did not become ready in time');
}

async function startPushService({ port, stateDir, extraEnv = {} }) {
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
        assert.fail(`push-service stderr was not empty:\n${stderr}`);
      }
    }
  };
}

function randomPort() {
  return 20000 + Math.floor(Math.random() * 1000);
}

async function startProviderSink({ port = 0, status = 202, delayMs = 0 }) {
  const requests = [];
  const server = http.createServer(async (req, res) => {
    const chunks = [];
    for await (const chunk of req) {
      chunks.push(Buffer.from(chunk));
    }

    if (delayMs > 0) {
      await new Promise(resolve => setTimeout(resolve, delayMs));
    }

    requests.push({
      method: req.method,
      url: req.url,
      headers: req.headers,
      body: Buffer.concat(chunks).toString('utf8')
    });
    res.writeHead(status, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ ok: status >= 200 && status < 300 }));
  });

  await new Promise(resolve => server.listen(port, '127.0.0.1', resolve));
  const address = server.address();
  assert.ok(address && typeof address === 'object');

  return {
    baseUrl: `http://127.0.0.1:${address.port}`,
    requests,
    async stop() {
      await new Promise(resolve => server.close(resolve));
    }
  };
}

function currentSigTs(offsetSeconds = 0) {
  return Math.floor(Date.now() / 1000) + offsetSeconds;
}

function invalidateSignature(signature) {
  const bytes = Buffer.from(signature, 'base64');
  bytes[0] ^= 0xff;
  return bytes.toString('base64');
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

test('health and stats endpoints honor SERVICE_NAME override', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'push-service-runtime-'));
  const service = await startPushService({
    port: randomPort(),
    stateDir,
    extraEnv: {
      SERVICE_NAME: 'push-runtime-override'
    }
  });

  try {
    const healthResponse = await fetch(`${service.baseUrl}/health/ready`);
    assert.equal(healthResponse.status, 200);
    const healthBody = await healthResponse.json();
    assert.deepEqual(healthBody, { ok: true, service: 'push-runtime-override' });

    const statsResponse = await fetch(`${service.baseUrl}/stats`);
    assert.equal(statsResponse.status, 200);
    const statsBody = await statsResponse.json();
    assert.equal(statsBody.service, 'push-runtime-override');
    assert.equal(statsBody.mode, 'push');
    assert.equal(statsBody.inventory.storageMessages, 0);
    assert.equal(statsBody.inventory.files, 0);
    assert.equal(statsBody.inventory.subscriptions, 0);
    assert.equal(statsBody.inventory.pushDeliveries, 0);
    assert.equal(typeof statsBody.state.push, 'string');
  } finally {
    await service.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('push runtime verifies signed subscribe and unsubscribe for verifiable identities', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'push-service-runtime-'));
  const service = await startPushService({ port: randomPort(), stateDir });

  try {
    const subscribePayload = createSignedPushSubscribePayload(pushSigningIdentity, {
      service_info: { token: 'signed-unsubscribe-1' }
    });
    const subscribeResponse = await fetch(`${service.baseUrl}/subscribe`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(subscribePayload)
    });
    assert.equal(subscribeResponse.status, 200);
    assert.deepEqual(await subscribeResponse.json(), {
      success: true,
      added: true,
      message: 'Subscription successful'
    });

    const invalidResponse = await fetch(`${service.baseUrl}/unsubscribe`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(createSignedPushUnsubscribePayload(pushSigningIdentity, {
        service_info: { token: 'signed-unsubscribe-1' },
        signature: invalidateSignature(createSignedPushUnsubscribePayload(pushSigningIdentity, {
          service_info: { token: 'signed-unsubscribe-1' }
        }).signature)
      }))
    });
    assert.equal(invalidResponse.status, 400);
    const invalidBody = await invalidResponse.json();
    assert.equal(invalidBody.error, 4);

    const unsubscribeResponse = await fetch(`${service.baseUrl}/unsubscribe`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(createSignedPushUnsubscribePayload(pushSigningIdentity, {
        service_info: { token: 'signed-unsubscribe-1' }
      }))
    });
    assert.equal(unsubscribeResponse.status, 200);
    assert.deepEqual(await unsubscribeResponse.json(), {
      success: true,
      removed: true,
      message: 'Device unsubscribed from push notifications'
    });
  } finally {
    await service.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('push runtime rejects invalid subscribe shapes without mutating persisted state', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'push-service-runtime-'));
  const pushStatePath = path.join(stateDir, 'push.json');
  const service = await startPushService({ port: randomPort(), stateDir });

  try {
    const unsupportedServiceResponse = await fetch(`${service.baseUrl}/subscribe`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(createSignedPushSubscribePayload(pushSigningIdentity, {
        pubkey: pushSigningIdentity.directPubkey,
        session_ed25519: undefined,
        service: 'wns',
        service_info: { token: 'unsupported-service-token-1' }
      }))
    });
    assert.equal(unsupportedServiceResponse.status, 400);
    assert.deepEqual(await unsupportedServiceResponse.json(), {
      error: 2,
      message: "Service 'wns' is not available"
    });

    const invalidEncKeyResponse = await fetch(`${service.baseUrl}/subscribe`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(createSignedPushSubscribePayload(pushSigningIdentity, {
        pubkey: pushSigningIdentity.directPubkey,
        session_ed25519: undefined,
        service_info: { token: 'invalid-enc-key-token-1' },
        enc_key: 'bad-key'
      }))
    });
    assert.equal(invalidEncKeyResponse.status, 400);
    assert.deepEqual(await invalidEncKeyResponse.json(), {
      error: 1,
      message: 'Missing required parameter'
    });

    const listResponse = await fetch(`${service.baseUrl}/subscriptions/${encodeURIComponent(pushSigningIdentity.directPubkey)}`);
    assert.equal(listResponse.status, 200);
    const listed = await listResponse.json();
    assert.deepEqual(listed.subscriptions, []);
    assert.deepEqual(listed.deliveries, []);

    const statsResponse = await fetch(`${service.baseUrl}/stats`);
    assert.equal(statsResponse.status, 200);
    const statsBody = await statsResponse.json();
    assert.equal(statsBody.stats.pushSubscribe, 2);
    assert.equal(statsBody.stats.errors, 0);
    assert.equal(statsBody.inventory.subscriptions, 0);

    const persistedState = JSON.parse(await readFile(pushStatePath, 'utf8').catch(error => {
      if (error && typeof error === 'object' && 'code' in error && error.code === 'ENOENT') {
        return '[]';
      }

      throw error;
    }));
    assert.deepEqual(persistedState, []);
  } finally {
    await service.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('push runtime supports mixed batch subscribe and unsubscribe results', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'push-service-runtime-'));
  const service = await startPushService({ port: randomPort(), stateDir });

  try {
    const batchSubscribeResponse = await fetch(`${service.baseUrl}/subscribe`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify([
        createSignedPushSubscribePayload(pushSigningIdentity, {
          pubkey: pushSigningIdentity.directPubkey,
          session_ed25519: undefined,
          namespaces: [11],
          service_info: { token: 'batch-token-1' }
        }),
        createSignedPushSubscribePayload(pushSigningIdentity, {
          pubkey: pushSigningIdentity.directPubkey,
          session_ed25519: undefined,
          namespaces: [12, 11],
          service_info: { token: 'batch-token-2' }
        })
      ])
    });
    assert.equal(batchSubscribeResponse.status, 200);
    const batchSubscribeBody = await batchSubscribeResponse.json();
    assert.deepEqual(batchSubscribeBody[0], {
      success: true,
      added: true,
      message: 'Subscription successful'
    });
    assert.deepEqual(batchSubscribeBody[1], {
      error: 1,
      message: 'Invalid request: namespaces must be sorted'
    });

    const listAfterBatchSubscribeResponse = await fetch(`${service.baseUrl}/subscriptions/${encodeURIComponent(pushSigningIdentity.directPubkey)}`);
    assert.equal(listAfterBatchSubscribeResponse.status, 200);
    const listAfterBatchSubscribe = await listAfterBatchSubscribeResponse.json();
    assert.equal(listAfterBatchSubscribe.subscriptions.length, 1);
    assert.equal(listAfterBatchSubscribe.subscriptions[0].service_info.token, 'batch-token-1');

    const invalidBatchUnsubscribe = createSignedPushUnsubscribePayload(pushSigningIdentity, {
      pubkey: pushSigningIdentity.directPubkey,
      session_ed25519: undefined,
      service_info: { token: 'batch-token-2' }
    });
    invalidBatchUnsubscribe.signature = invalidateSignature(invalidBatchUnsubscribe.signature);

    const batchUnsubscribeResponse = await fetch(`${service.baseUrl}/unsubscribe`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify([
        createSignedPushUnsubscribePayload(pushSigningIdentity, {
          pubkey: pushSigningIdentity.directPubkey,
          session_ed25519: undefined,
          service_info: { token: 'batch-token-1' }
        }),
        invalidBatchUnsubscribe
      ])
    });
    assert.equal(batchUnsubscribeResponse.status, 200);
    const batchUnsubscribeBody = await batchUnsubscribeResponse.json();
    assert.deepEqual(batchUnsubscribeBody[0], {
      success: true,
      removed: true,
      message: 'Device unsubscribed from push notifications'
    });
    assert.equal(batchUnsubscribeBody[1].error, 4);

    const listAfterBatchUnsubscribeResponse = await fetch(`${service.baseUrl}/subscriptions/${encodeURIComponent(pushSigningIdentity.directPubkey)}`);
    assert.equal(listAfterBatchUnsubscribeResponse.status, 200);
    const listAfterBatchUnsubscribe = await listAfterBatchUnsubscribeResponse.json();
    assert.deepEqual(listAfterBatchUnsubscribe.subscriptions, []);

    const statsResponse = await fetch(`${service.baseUrl}/stats`);
    assert.equal(statsResponse.status, 200);
    const statsBody = await statsResponse.json();
    assert.equal(statsBody.stats.pushSubscribe, 1);
    assert.equal(statsBody.stats.pushSubscribeBatch, 1);
    assert.equal(statsBody.stats.pushUnsubscribe, 1);
    assert.equal(statsBody.stats.pushUnsubscribeBatch, 1);
    assert.equal(statsBody.stats.errors, 0);
    assert.equal(statsBody.inventory.subscriptions, 0);
  } finally {
    await service.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('push runtime honors idempotent resubscribe and prunes expired subscriptions', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'push-service-runtime-'));
  const pushStatePath = path.join(stateDir, 'push.json');
  const service = await startPushService({ port: randomPort(), stateDir });

  try {
    const subscribePayload = createSignedPushSubscribePayload(pushSigningIdentity, {
      namespaces: [0],
      service_info: { token: 'idempotent-token-1' },
      ttl: 1,
      idempotency_key: 'push-idem-1'
    });
    const subscribeResponse = await fetch(`${service.baseUrl}/subscribe`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(subscribePayload)
    });
    assert.equal(subscribeResponse.status, 200);
    assert.deepEqual(await subscribeResponse.json(), {
      success: true,
      added: true,
      message: 'Subscription successful'
    });

    const secondSubscribeResponse = await fetch(`${service.baseUrl}/subscribe`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(subscribePayload)
    });
    assert.equal(secondSubscribeResponse.status, 200);
    assert.deepEqual(await secondSubscribeResponse.json(), {
      success: true,
      updated: true,
      idempotent: true,
      message: 'Resubscription successful'
    });

    const listBeforeExpiryResponse = await fetch(`${service.baseUrl}/subscriptions/${encodeURIComponent(pushSigningIdentity.sessionPubkey)}`);
    assert.equal(listBeforeExpiryResponse.status, 200);
    const listBeforeExpiry = await listBeforeExpiryResponse.json();
    assert.equal(listBeforeExpiry.subscriptions.length, 1);
    assert.equal(listBeforeExpiry.subscriptions[0].service_info.token, 'idempotent-token-1');
    assert.equal(listBeforeExpiry.subscriptions[0].idempotencyKey, 'push-idem-1');

    await new Promise(resolve => setTimeout(resolve, 1_200));

    const listAfterExpiryResponse = await fetch(`${service.baseUrl}/subscriptions/${encodeURIComponent(pushSigningIdentity.sessionPubkey)}`);
    assert.equal(listAfterExpiryResponse.status, 200);
    const listAfterExpiry = await listAfterExpiryResponse.json();
    assert.deepEqual(listAfterExpiry.subscriptions, []);

    const persistedState = JSON.parse(await readFile(pushStatePath, 'utf8'));
    assert.deepEqual(persistedState, []);
  } finally {
    await service.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('internal push notify prunes expired subscriptions before queueing deliveries', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'push-service-runtime-'));
  const pushStatePath = path.join(stateDir, 'push.json');
  const service = await startPushService({ port: randomPort(), stateDir });

  try {
    const subscribePayload = createSignedPushSubscribePayload(pushSigningIdentity, {
      pubkey: pushSigningIdentity.directPubkey,
      session_ed25519: undefined,
      namespaces: [11],
      service_info: { token: 'expired-notify-token-1' },
      ttl: 1
    });
    const subscribeResponse = await fetch(`${service.baseUrl}/subscribe`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(subscribePayload)
    });
    assert.equal(subscribeResponse.status, 200);

    const listBeforeExpiryResponse = await fetch(`${service.baseUrl}/subscriptions/${encodeURIComponent(pushSigningIdentity.directPubkey)}`);
    assert.equal(listBeforeExpiryResponse.status, 200);
    assert.equal((await listBeforeExpiryResponse.json()).subscriptions.length, 1);

    await new Promise(resolve => setTimeout(resolve, 1_200));

    const notifyResponse = await fetch(`${service.baseUrl}/_compat/push-notify`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        pubkey: pushSigningIdentity.directPubkey,
        hash: 'expired-notify-hash-1',
        namespace: 11,
        timestamp: Date.now(),
        expiration: Date.now() + 60_000,
        data: Buffer.from('expired-notify-body', 'utf8').toString('base64')
      })
    });
    assert.equal(notifyResponse.status, 202);
    assert.deepEqual(await notifyResponse.json(), { queued: 0 });

    const listAfterNotifyResponse = await fetch(`${service.baseUrl}/subscriptions/${encodeURIComponent(pushSigningIdentity.directPubkey)}`);
    assert.equal(listAfterNotifyResponse.status, 200);
    const listAfterNotify = await listAfterNotifyResponse.json();
    assert.deepEqual(listAfterNotify.subscriptions, []);
    assert.deepEqual(listAfterNotify.deliveries, []);

    const statsResponse = await fetch(`${service.baseUrl}/stats`);
    assert.equal(statsResponse.status, 200);
    const statsBody = await statsResponse.json();
    assert.equal(statsBody.stats.pushNotificationRequests, 1);
    assert.equal(statsBody.stats.pushNotificationsQueued, 0);
    assert.equal(statsBody.stats.errors, 0);
    assert.equal(statsBody.inventory.subscriptions, 0);
    assert.equal(statsBody.inventory.pushDeliveries, 0);

    const persistedState = JSON.parse(await readFile(pushStatePath, 'utf8'));
    assert.deepEqual(persistedState, []);
  } finally {
    await service.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('internal push notify queues delivery artifacts for matching subscriptions', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'push-service-runtime-'));
  const service = await startPushService({ port: randomPort(), stateDir });

  try {
    const subscribePayload = createSignedPushSubscribePayload(pushSigningIdentity, {
      pubkey: pushSigningIdentity.directPubkey,
      session_ed25519: undefined,
      namespaces: [11],
      service_info: { token: 'notify-token-1' }
    });
    const subscribeResponse = await fetch(`${service.baseUrl}/subscribe`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(subscribePayload)
    });
    assert.equal(subscribeResponse.status, 200);

    const payloadData = Buffer.from('queued-push-body', 'utf8').toString('base64');
    const notifyResponse = await fetch(`${service.baseUrl}/_compat/push-notify`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        pubkey: pushSigningIdentity.directPubkey,
        hash: 'hash-1',
        namespace: 11,
        timestamp: Date.now(),
        expiration: Date.now() + 60_000,
        data: payloadData
      })
    });
    assert.equal(notifyResponse.status, 202);
    assert.deepEqual(await notifyResponse.json(), { queued: 1 });

    const listResponse = await fetch(`${service.baseUrl}/subscriptions/${encodeURIComponent(pushSigningIdentity.directPubkey)}`);
    assert.equal(listResponse.status, 200);
    const listed = await listResponse.json();
    assert.equal(listed.subscriptions.length, 1);
    assert.equal(listed.deliveries.length, 1);
    assert.equal(listed.deliveries[0].hash, 'hash-1');
    assert.equal(listed.deliveries[0].data, payloadData);

    const statsResponse = await fetch(`${service.baseUrl}/stats`);
    assert.equal(statsResponse.status, 200);
    const statsBody = await statsResponse.json();
    assert.equal(statsBody.stats.pushNotificationRequests, 1);
    assert.equal(statsBody.stats.pushNotificationsQueued, 1);
    assert.equal(statsBody.inventory.subscriptions, 1);
    assert.equal(statsBody.inventory.pushDeliveries, 1);
  } finally {
    await service.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('internal push notify deduplicates repeated hashes and truncates oversized delivery bodies', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'push-service-runtime-'));
  const service = await startPushService({ port: randomPort(), stateDir });

  try {
    const subscribePayload = createSignedPushSubscribePayload(pushSigningIdentity, {
      pubkey: pushSigningIdentity.directPubkey,
      session_ed25519: undefined,
      namespaces: [11],
      data: true,
      service_info: { token: 'dedupe-token-1' }
    });
    const subscribeResponse = await fetch(`${service.baseUrl}/subscribe`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(subscribePayload)
    });
    assert.equal(subscribeResponse.status, 200);

    const oversizedPayloadData = Buffer.alloc(2_600, 0x61).toString('base64');
    const firstNotifyResponse = await fetch(`${service.baseUrl}/_compat/push-notify`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        pubkey: pushSigningIdentity.directPubkey,
        hash: 'dedupe-hash-1',
        namespace: 11,
        timestamp: Date.now(),
        expiration: Date.now() + 60_000,
        data: oversizedPayloadData
      })
    });
    assert.equal(firstNotifyResponse.status, 202);
    assert.deepEqual(await firstNotifyResponse.json(), { queued: 1 });

    const secondNotifyResponse = await fetch(`${service.baseUrl}/_compat/push-notify`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        pubkey: pushSigningIdentity.directPubkey,
        hash: 'dedupe-hash-1',
        namespace: 11,
        timestamp: Date.now(),
        expiration: Date.now() + 60_000,
        data: oversizedPayloadData
      })
    });
    assert.equal(secondNotifyResponse.status, 202);
    assert.deepEqual(await secondNotifyResponse.json(), { queued: 0 });

    const listResponse = await fetch(`${service.baseUrl}/subscriptions/${encodeURIComponent(pushSigningIdentity.directPubkey)}`);
    assert.equal(listResponse.status, 200);
    const listed = await listResponse.json();
    assert.equal(listed.subscriptions.length, 1);
    assert.equal(listed.deliveries.length, 1);
    assert.equal(listed.deliveries[0].hash, 'dedupe-hash-1');
    assert.equal(listed.deliveries[0].data, null);
    assert.equal(listed.deliveries[0].bodyTooLarge, true);

    const statsResponse = await fetch(`${service.baseUrl}/stats`);
    assert.equal(statsResponse.status, 200);
    const statsBody = await statsResponse.json();
    assert.equal(statsBody.stats.pushNotificationRequests, 2);
    assert.equal(statsBody.stats.pushNotificationsQueued, 1);
    assert.equal(statsBody.stats.errors, 0);
    assert.equal(statsBody.inventory.pushDeliveries, 1);
  } finally {
    await service.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('push runtime reloads persisted subscriptions across restart and accepts notify traffic', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'push-service-runtime-'));
  let service = await startPushService({ port: randomPort(), stateDir });

  try {
    const subscribePayload = createSignedPushSubscribePayload(pushSigningIdentity, {
      pubkey: pushSigningIdentity.directPubkey,
      session_ed25519: undefined,
      namespaces: [11],
      service_info: { token: 'restart-token-1' }
    });
    const subscribeResponse = await fetch(`${service.baseUrl}/subscribe`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(subscribePayload)
    });
    assert.equal(subscribeResponse.status, 200);

    await service.stop();
    service = await startPushService({ port: randomPort(), stateDir });

    const listAfterRestartResponse = await fetch(`${service.baseUrl}/subscriptions/${encodeURIComponent(pushSigningIdentity.directPubkey)}`);
    assert.equal(listAfterRestartResponse.status, 200);
    const listAfterRestart = await listAfterRestartResponse.json();
    assert.equal(listAfterRestart.subscriptions.length, 1);
    assert.equal(listAfterRestart.subscriptions[0].service_info.token, 'restart-token-1');
    assert.deepEqual(listAfterRestart.deliveries, []);

    const payloadData = Buffer.from('restart-notify-body', 'utf8').toString('base64');
    const notifyResponse = await fetch(`${service.baseUrl}/_compat/push-notify`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        pubkey: pushSigningIdentity.directPubkey,
        hash: 'restart-hash-1',
        namespace: 11,
        timestamp: Date.now(),
        expiration: Date.now() + 60_000,
        data: payloadData
      })
    });
    assert.equal(notifyResponse.status, 202);
    assert.deepEqual(await notifyResponse.json(), { queued: 1 });

    const listAfterNotifyResponse = await fetch(`${service.baseUrl}/subscriptions/${encodeURIComponent(pushSigningIdentity.directPubkey)}`);
    assert.equal(listAfterNotifyResponse.status, 200);
    const listAfterNotify = await listAfterNotifyResponse.json();
    assert.equal(listAfterNotify.subscriptions.length, 1);
    assert.equal(listAfterNotify.deliveries.length, 1);
    assert.equal(listAfterNotify.deliveries[0].hash, 'restart-hash-1');
    assert.equal(listAfterNotify.deliveries[0].data, payloadData);

    const unsubscribeResponse = await fetch(`${service.baseUrl}/unsubscribe`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(createSignedPushUnsubscribePayload(pushSigningIdentity, {
        pubkey: pushSigningIdentity.directPubkey,
        session_ed25519: undefined,
        service_info: { token: 'restart-token-1' }
      }))
    });
    assert.equal(unsubscribeResponse.status, 200);
    assert.equal((await unsubscribeResponse.json()).removed, true);

    const statsResponse = await fetch(`${service.baseUrl}/stats`);
    assert.equal(statsResponse.status, 200);
    const statsBody = await statsResponse.json();
    assert.equal(statsBody.inventory.subscriptions, 0);
    assert.equal(statsBody.inventory.pushDeliveries, 1);
  } finally {
    await service.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('internal push notify dispatches configured provider delivery and persists the result across restart', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'push-service-runtime-'));
  const provider = await startProviderSink({});
  let service = await startPushService({
    port: randomPort(),
    stateDir,
    extraEnv: {
      PUSH_PROVIDER_APNS_URL: `${provider.baseUrl}/apns`,
      PUSH_PROVIDER_APNS_AUTH_HEADER: 'Authorization: Bearer provider-secret-1'
    }
  });

  try {
    const subscribePayload = createSignedPushSubscribePayload(pushSigningIdentity, {
      pubkey: pushSigningIdentity.directPubkey,
      session_ed25519: undefined,
      namespaces: [11],
      service_info: { token: 'provider-token-1' }
    });
    const subscribeResponse = await fetch(`${service.baseUrl}/subscribe`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(subscribePayload)
    });
    assert.equal(subscribeResponse.status, 200);

    const payloadData = Buffer.from('provider-dispatch-body', 'utf8').toString('base64');
    const notifyResponse = await fetch(`${service.baseUrl}/_compat/push-notify`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        pubkey: pushSigningIdentity.directPubkey,
        hash: 'provider-hash-1',
        namespace: 11,
        timestamp: Date.now(),
        expiration: Date.now() + 60_000,
        data: payloadData
      })
    });
    assert.equal(notifyResponse.status, 202);
    assert.deepEqual(await notifyResponse.json(), { queued: 1 });

    assert.equal(provider.requests.length, 1);
    assert.equal(provider.requests[0].method, 'POST');
    assert.equal(provider.requests[0].url, '/apns');
    assert.equal(provider.requests[0].headers.authorization, 'Bearer provider-secret-1');
    const providerBody = JSON.parse(provider.requests[0].body);
    assert.equal(providerBody.service, 'apns');
    assert.equal(providerBody.token, 'provider-token-1');
    assert.equal(providerBody.pubkey, pushSigningIdentity.directPubkey);
    assert.equal(providerBody.hash, 'provider-hash-1');
    assert.equal(providerBody.namespace, 11);
    assert.equal(providerBody.data, payloadData);

    const listResponse = await fetch(`${service.baseUrl}/subscriptions/${encodeURIComponent(pushSigningIdentity.directPubkey)}`);
    assert.equal(listResponse.status, 200);
    const listed = await listResponse.json();
    assert.equal(listed.deliveries.length, 1);
    assert.equal(listed.deliveries[0].provider.status, 'delivered');
    assert.equal(listed.deliveries[0].provider.httpStatus, 202);
    assert.equal(listed.deliveries[0].provider.attempts, 1);

    const statsBeforeRestartResponse = await fetch(`${service.baseUrl}/stats`);
    assert.equal(statsBeforeRestartResponse.status, 200);
    const statsBeforeRestart = await statsBeforeRestartResponse.json();
    assert.equal(statsBeforeRestart.stats.pushProviderAttempts, 1);
    assert.equal(statsBeforeRestart.stats.pushProviderDelivered, 1);
    assert.equal(statsBeforeRestart.inventory.pushProviderDelivered, 1);
    assert.equal(typeof statsBeforeRestart.state.pushDeliveries, 'string');

    await service.stop();
    service = await startPushService({
      port: randomPort(),
      stateDir,
      extraEnv: {
        PUSH_PROVIDER_APNS_URL: `${provider.baseUrl}/apns`
      }
    });

    const listAfterRestartResponse = await fetch(`${service.baseUrl}/subscriptions/${encodeURIComponent(pushSigningIdentity.directPubkey)}`);
    assert.equal(listAfterRestartResponse.status, 200);
    const listAfterRestart = await listAfterRestartResponse.json();
    assert.equal(listAfterRestart.subscriptions.length, 1);
    assert.equal(listAfterRestart.deliveries.length, 1);
    assert.equal(listAfterRestart.deliveries[0].hash, 'provider-hash-1');
    assert.equal(listAfterRestart.deliveries[0].provider.status, 'delivered');
    assert.equal(listAfterRestart.deliveries[0].provider.httpStatus, 202);

    const statsAfterRestartResponse = await fetch(`${service.baseUrl}/stats`);
    assert.equal(statsAfterRestartResponse.status, 200);
    const statsAfterRestart = await statsAfterRestartResponse.json();
    assert.equal(statsAfterRestart.inventory.pushDeliveries, 1);
    assert.equal(statsAfterRestart.inventory.pushProviderDelivered, 1);
  } finally {
    await service.stop();
    await provider.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('internal push notify preserves concurrent deliveries for the same pubkey', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'push-service-runtime-'));
  const provider = await startProviderSink({ delayMs: 25 });
  const service = await startPushService({
    port: randomPort(),
    stateDir,
    extraEnv: {
      PUSH_PROVIDER_APNS_URL: `${provider.baseUrl}/apns`
    }
  });

  try {
    const subscribePayload = createSignedPushSubscribePayload(pushSigningIdentity, {
      pubkey: pushSigningIdentity.directPubkey,
      session_ed25519: undefined,
      namespaces: [11],
      service_info: { token: 'concurrent-token-1' }
    });
    const subscribeResponse = await fetch(`${service.baseUrl}/subscribe`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(subscribePayload)
    });
    assert.equal(subscribeResponse.status, 200);

    const notifications = Array.from({ length: 5 }, (_, index) => ({
      pubkey: pushSigningIdentity.directPubkey,
      hash: `concurrent-hash-${index}`,
      namespace: 11,
      timestamp: Date.now() + index,
      expiration: Date.now() + 60_000 + index,
      data: Buffer.from(`concurrent-body-${index}`, 'utf8').toString('base64')
    }));

    const notifyResponses = await Promise.all(notifications.map(payload => fetch(`${service.baseUrl}/_compat/push-notify`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(payload)
    })));
    for (const response of notifyResponses) {
      assert.equal(response.status, 202);
      assert.deepEqual(await response.json(), { queued: 1 });
    }

    const listResponse = await fetch(`${service.baseUrl}/subscriptions/${encodeURIComponent(pushSigningIdentity.directPubkey)}`);
    assert.equal(listResponse.status, 200);
    const listed = await listResponse.json();
    assert.equal(listed.deliveries.length, notifications.length);
    assert.deepEqual(
      new Set(listed.deliveries.map(delivery => delivery.hash)),
      new Set(notifications.map(payload => payload.hash))
    );
    assert.ok(listed.deliveries.every(delivery => delivery.provider?.status === 'delivered'));

    const statsResponse = await fetch(`${service.baseUrl}/stats`);
    assert.equal(statsResponse.status, 200);
    const statsBody = await statsResponse.json();
    assert.equal(statsBody.stats.pushNotificationsQueued, notifications.length);
    assert.equal(statsBody.stats.pushProviderDelivered, notifications.length);
    assert.equal(statsBody.inventory.pushDeliveries, notifications.length);

    assert.equal(provider.requests.length, notifications.length);
  } finally {
    await service.stop();
    await provider.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('internal push notify records configured provider failures without dropping the queued delivery', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'push-service-runtime-'));
  const provider = await startProviderSink({ status: 503 });
  const service = await startPushService({
    port: randomPort(),
    stateDir,
    extraEnv: {
      PUSH_PROVIDER_APNS_URL: `${provider.baseUrl}/apns`
    }
  });

  try {
    const subscribePayload = createSignedPushSubscribePayload(pushSigningIdentity, {
      pubkey: pushSigningIdentity.directPubkey,
      session_ed25519: undefined,
      namespaces: [11],
      service_info: { token: 'provider-failure-token-1' }
    });
    const subscribeResponse = await fetch(`${service.baseUrl}/subscribe`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(subscribePayload)
    });
    assert.equal(subscribeResponse.status, 200);

    const notifyResponse = await fetch(`${service.baseUrl}/_compat/push-notify`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        pubkey: pushSigningIdentity.directPubkey,
        hash: 'provider-failure-hash-1',
        namespace: 11,
        timestamp: Date.now(),
        expiration: Date.now() + 60_000,
        data: Buffer.from('provider-failure-body', 'utf8').toString('base64')
      })
    });
    assert.equal(notifyResponse.status, 202);
    assert.deepEqual(await notifyResponse.json(), { queued: 1 });

    const listResponse = await fetch(`${service.baseUrl}/subscriptions/${encodeURIComponent(pushSigningIdentity.directPubkey)}`);
    assert.equal(listResponse.status, 200);
    const listed = await listResponse.json();
    assert.equal(listed.deliveries.length, 1);
    assert.equal(listed.deliveries[0].provider.status, 'failed');
    assert.equal(listed.deliveries[0].provider.httpStatus, 503);

    const statsResponse = await fetch(`${service.baseUrl}/stats`);
    assert.equal(statsResponse.status, 200);
    const statsBody = await statsResponse.json();
    assert.equal(statsBody.stats.pushProviderAttempts, 1);
    assert.equal(statsBody.stats.pushProviderFailed, 1);
    assert.equal(statsBody.inventory.pushProviderFailed, 1);
    assert.equal(statsBody.inventory.pushDeliveries, 1);
  } finally {
    await service.stop();
    await provider.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});
