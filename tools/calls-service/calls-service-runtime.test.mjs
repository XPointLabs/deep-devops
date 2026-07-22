import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import path from 'node:path';
import { tmpdir } from 'node:os';
import test from 'node:test';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const scriptPath = path.resolve(path.dirname(fileURLToPath(import.meta.url)), 'calls-service.mjs');
const alice = `05${'a'.repeat(64)}`;
const bob = `05${'b'.repeat(64)}`;
const carol = `05${'c'.repeat(64)}`;

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

  throw new Error('calls-service did not become ready in time');
}

async function startCallsService({ port, stateDir, extraEnv = {} }) {
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
        assert.fail(`calls-service stderr was not empty:\n${stderr}`);
      }
    }
  };
}

function randomPort() {
  return 23000 + Math.floor(Math.random() * 1000);
}

function callSignal(overrides = {}) {
  return {
    callId: 'call-1',
    conversationId: 'conversation-1',
    sender: { value: alice },
    recipient: { value: bob },
    type: 0,
    payload: '{"sdp":"offer"}',
    createdAt: '2026-06-01T00:00:00.000Z',
    ...overrides
  };
}

async function postSignal(service, payload) {
  const response = await fetch(`${service.baseUrl}/api/calls/signal`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(payload)
  });
  const body = await response.json();
  return { response, body };
}

test('health and stats endpoints honor SERVICE_NAME override', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'calls-service-runtime-'));
  const service = await startCallsService({
    port: randomPort(),
    stateDir,
    extraEnv: {
      SERVICE_NAME: 'calls-runtime-override'
    }
  });

  try {
    const healthResponse = await fetch(`${service.baseUrl}/health/ready`);
    assert.equal(healthResponse.status, 200);
    assert.deepEqual(await healthResponse.json(), { ok: true, service: 'calls-runtime-override' });

    const statsResponse = await fetch(`${service.baseUrl}/stats`);
    assert.equal(statsResponse.status, 200);
    const statsBody = await statsResponse.json();
    assert.equal(statsBody.service, 'calls-runtime-override');
    assert.equal(statsBody.mode, 'calls');
    assert.equal(statsBody.inventory.callSignals, 0);
    assert.equal(typeof statsBody.state.calls, 'string');
  } finally {
    await service.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('calls runtime queues, returns, and drains recipient inbox signals', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'calls-service-runtime-'));
  const service = await startCallsService({ port: randomPort(), stateDir });

  try {
    const invalid = await postSignal(service, { callId: 'call-missing-parties' });
    assert.equal(invalid.response.status, 400);
    assert.equal(invalid.body.error, 'invalid-request');

    const posted = await postSignal(service, callSignal());
    assert.equal(posted.response.status, 202);
    assert.deepEqual(posted.body, { accepted: true, callId: 'call-1' });

    const bobInboxResponse = await fetch(`${service.baseUrl}/api/calls/inbox/${encodeURIComponent(bob)}`);
    assert.equal(bobInboxResponse.status, 200);
    const bobInbox = await bobInboxResponse.json();
    assert.equal(bobInbox.length, 1);
    assert.equal(bobInbox[0].callId, 'call-1');
    assert.deepEqual(bobInbox[0].sender, { value: alice });
    assert.deepEqual(bobInbox[0].recipient, { value: bob });

    const drainedResponse = await fetch(`${service.baseUrl}/api/calls/inbox/${encodeURIComponent(bob)}`);
    assert.equal(drainedResponse.status, 200);
    assert.deepEqual(await drainedResponse.json(), []);

    const statsResponse = await fetch(`${service.baseUrl}/stats`);
    assert.equal(statsResponse.status, 200);
    const statsBody = await statsResponse.json();
    assert.equal(statsBody.stats.callSignal, 2);
    assert.equal(statsBody.stats.callInbox, 2);
    assert.equal(statsBody.stats.errors, 0);
    assert.equal(statsBody.inventory.callSignals, 0);
  } finally {
    await service.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('calls runtime rejects every noncanonical party shape without queue or drain mutation', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'calls-service-runtime-'));
  const service = await startCallsService({ port: randomPort(), stateDir });
  const malformed = [
    '', '04' + 'a'.repeat(64), '05' + 'a'.repeat(63), '05' + 'a'.repeat(65),
    '05' + 'g'.repeat(64), '05' + 'A'.repeat(64), 'a'.repeat(64)
  ];

  try {
    const accepted = await postSignal(service, callSignal({ callId: 'preserved' }));
    assert.equal(accepted.response.status, 202);

    for (const party of malformed) {
      for (const field of ['sender', 'recipient']) {
        const result = await postSignal(service, callSignal({ callId: `bad-${field}`, [field]: { value: party } }));
        assert.equal(result.response.status, 400, `${field}=${party}`);
      }
      const inbox = await fetch(`${service.baseUrl}/api/calls/inbox/${encodeURIComponent(party)}`);
      assert.equal(inbox.status, 400, `inbox=${party}`);
    }

    const statsResponse = await fetch(`${service.baseUrl}/stats`);
    assert.equal((await statsResponse.json()).inventory.callSignals, 1);
    const preserved = await fetch(`${service.baseUrl}/api/calls/inbox/${encodeURIComponent(bob)}`);
    assert.equal(preserved.status, 200);
    assert.deepEqual((await preserved.json()).map(signal => signal.callId), ['preserved']);
  } finally {
    await service.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('calls runtime reloads pending signals across restart', async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), 'calls-service-runtime-'));
  const callStatePath = path.join(stateDir, 'calls.json');
  let service = await startCallsService({ port: randomPort(), stateDir });

  try {
    const bobSignal = await postSignal(service, callSignal({ callId: 'call-bob', recipient: bob }));
    assert.equal(bobSignal.response.status, 202);

    const carolSignal = await postSignal(service, callSignal({
      callId: 'call-carol',
      sender: alice,
      recipient: { Value: carol }
    }));
    assert.equal(carolSignal.response.status, 202);

    const persistedBeforeRestart = JSON.parse(await readFile(callStatePath, 'utf8'));
    assert.equal(persistedBeforeRestart.length, 2);

    await service.stop();
    service = await startCallsService({ port: randomPort(), stateDir });

    const bobInboxResponse = await fetch(`${service.baseUrl}/api/calls/inbox/${encodeURIComponent(bob)}`);
    assert.equal(bobInboxResponse.status, 200);
    const bobInbox = await bobInboxResponse.json();
    assert.deepEqual(bobInbox.map(signal => signal.callId), ['call-bob']);

    const statsAfterBobResponse = await fetch(`${service.baseUrl}/stats`);
    assert.equal(statsAfterBobResponse.status, 200);
    assert.equal((await statsAfterBobResponse.json()).inventory.callSignals, 1);

    const carolInboxResponse = await fetch(`${service.baseUrl}/api/calls/inbox/${encodeURIComponent(carol)}`);
    assert.equal(carolInboxResponse.status, 200);
    const carolInbox = await carolInboxResponse.json();
    assert.deepEqual(carolInbox.map(signal => signal.callId), ['call-carol']);

    const persistedAfterDrain = JSON.parse(await readFile(callStatePath, 'utf8'));
    assert.deepEqual(persistedAfterDrain, []);
  } finally {
    await service.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});
