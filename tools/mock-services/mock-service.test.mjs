import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const scriptPath = fileURLToPath(new URL('./mock-service.mjs', import.meta.url));

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

  throw new Error('mock-service did not become ready in time');
}

function waitForExit(child, timeoutMs) {
  if (child.exitCode !== null) return Promise.resolve(true);
  return new Promise(resolve => {
    const timer = setTimeout(() => {
      child.off('exit', onExit);
      resolve(false);
    }, timeoutMs);
    const onExit = () => {
      clearTimeout(timer);
      resolve(true);
    };
    child.once('exit', onExit);
  });
}

async function terminateChild(child) {
  if (child.exitCode !== null) return;
  child.kill('SIGTERM');
  if (await waitForExit(child, 1000)) return;
  child.kill('SIGKILL');
  if (!await waitForExit(child, 2000)) {
    throw new Error('mock-service did not terminate within the bounded cleanup deadline');
  }
}

async function startMockService({ stateDir }) {
  const child = spawn(process.execPath, [scriptPath], {
    env: {
      ...process.env,
      SERVICE_MODE: 'all',
      PORT: '0',
      MOCK_STATE_DIR: stateDir
    },
    stdio: ['ignore', 'pipe', 'pipe', 'ipc']
  });

  let stderr = '';
  child.stderr.on('data', chunk => {
    stderr += String(chunk);
  });

  const port = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('mock-service did not publish its bound port in time')), 5000);
    child.once('exit', code => {
      clearTimeout(timer);
      reject(new Error(`mock-service exited before readiness with code ${code}`));
    });
    child.on('message', message => {
      if (message?.type === 'listening' && Number.isInteger(message.port) && message.port > 0) {
        clearTimeout(timer);
        resolve(message.port);
      }
    });
  }).catch(async error => {
    await terminateChild(child);
    throw error;
  });
  const baseUrl = `http://127.0.0.1:${port}`;
  try {
    await waitForReady(baseUrl);
  } catch (error) {
    await terminateChild(child);
    throw error;
  }

  return {
    baseUrl,
    async stop() {
      await terminateChild(child);

      if (stderr.trim()) {
        assert.fail(`mock-service stderr was not empty:\n${stderr}`);
      }
    }
  };
}

test('storage store supports idempotency key replay', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'deep-mock-'));
  const mock = await startMockService({ stateDir });

  try {
    const payload = {
      pubkey: '05abc',
      namespace: 11,
      timestamp: Date.now(),
      ttl: 60000,
      data: Buffer.from('hello', 'utf8').toString('base64'),
      idempotency_key: 'idem-1'
    };

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
      body: JSON.stringify({ pubkey: payload.pubkey, namespace: payload.namespace })
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

test('storage retrieve prunes expired messages', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'deep-mock-'));
  const mock = await startMockService({ stateDir });

  try {
    const storeResponse = await fetch(`${mock.baseUrl}/storage/store`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        pubkey: '05expired',
        namespace: 22,
        timestamp: Date.now() - 10_000,
        ttl: 1,
        data: Buffer.from('expires-fast', 'utf8').toString('base64')
      })
    });

    assert.equal(storeResponse.status, 200);

    const retrieveResponse = await fetch(`${mock.baseUrl}/storage/retrieve`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ pubkey: '05expired', namespace: 22 })
    });
    const retrieved = await retrieveResponse.json();

    assert.equal(retrieveResponse.status, 200);
    assert.equal(retrieved.messages.length, 0);
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

  const mock = await startMockService({ stateDir });

  try {
    const infoResponse = await fetch(`${mock.baseUrl}/file/expired-file-id/info`);
    const infoBody = await infoResponse.json();

    assert.equal(infoResponse.status, 404);
    assert.equal(infoBody.error, 'file-not-found');

    const persistedRaw = await readFile(fileStatePath, 'utf8');
    const persisted = JSON.parse(persistedRaw);
    assert.deepEqual(persisted, []);
  } finally {
    await mock.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('push subscribe supports idempotency key replay', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'deep-mock-'));
  const mock = await startMockService({ stateDir });

  try {
    const payload = {
      pubkey: '05push',
      session_ed25519: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      data: true,
      sig_ts: Math.floor(Date.now() / 1000),
      signature: 'f8efdd12000700000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
      service: 'apns',
      service_info: { token: 'token-1' },
      enc_key: 'abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd',
      namespaces: [0, 11],
      idempotency_key: 'push-idem-1',
      ttlSeconds: 30
    };

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

  const mock = await startMockService({ stateDir });

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
  const mock = await startMockService({ stateDir });

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
  const mock = await startMockService({ stateDir });

  try {
    const response = await fetch(`${mock.baseUrl}/subscribe`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        pubkey: '05push',
        session_ed25519: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        data: true,
        sig_ts: Math.floor(Date.now() / 1000),
        signature: 'f8efdd12000700000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
        service: 'unknown-service',
        service_info: { token: 'token-unknown' },
        enc_key: 'abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd',
        namespaces: [0]
      })
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
  const mock = await startMockService({ stateDir });

  try {
    const response = await fetch(`${mock.baseUrl}/subscribe`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify([
        {
          pubkey: '05batch',
          session_ed25519: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
          data: true,
          sig_ts: Math.floor(Date.now() / 1000),
          signature: 'f8efdd12000700000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
          service: 'apns',
          service_info: { token: 'token-batch-1' },
          enc_key: 'abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd',
          namespaces: [0, 11]
        },
        {
          pubkey: '05batch',
          session_ed25519: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
          data: true,
          sig_ts: Math.floor(Date.now() / 1000),
          signature: 'f8efdd12000700000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
          service: 'unsupported-service',
          service_info: { token: 'token-batch-2' },
          enc_key: 'abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd',
          namespaces: [0]
        }
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
  const mock = await startMockService({ stateDir });

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

test('push subscribe rejects too old sig_ts with BAD_INPUT', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'deep-mock-'));
  const mock = await startMockService({ stateDir });

  try {
    const response = await fetch(`${mock.baseUrl}/subscribe`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        pubkey: '05push',
        session_ed25519: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        data: true,
        sig_ts: 1,
        signature: 'f8efdd12000700000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
        service: 'apns',
        service_info: { token: 'token-1' },
        enc_key: 'abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd',
        namespaces: [0]
      })
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
  const mock = await startMockService({ stateDir });

  try {
    const response = await fetch(`${mock.baseUrl}/subscribe`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        pubkey: '05push',
        session_ed25519: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        data: true,
        sig_ts: Math.floor(Date.now() / 1000),
        signature: 'deadbeef',
        service: 'apns',
        service_info: { token: 'token-1' },
        enc_key: 'abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd',
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

test('stats endpoint reports request counters and inventory', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'deep-mock-'));
  const mock = await startMockService({ stateDir });

  try {
    const storeResponse = await fetch(`${mock.baseUrl}/storage/store`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        pubkey: '05stats',
        namespace: 1,
        timestamp: Date.now(),
        ttl: 60_000,
        data: Buffer.from('stats-data', 'utf8').toString('base64')
      })
    });
    assert.equal(storeResponse.status, 200);

    const statsResponse = await fetch(`${mock.baseUrl}/stats`);
    const statsBody = await statsResponse.json();

    assert.equal(statsResponse.status, 200);
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
