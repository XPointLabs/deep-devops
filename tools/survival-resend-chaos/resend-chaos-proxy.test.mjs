import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { startResendChaosProxy } from './resend-chaos-proxy.mjs';

function listen(server) {
  return new Promise((resolve, reject) => server.listen(0, '127.0.0.1', resolve).once('error', reject));
}

function control(socketPath, token, action, ttlSeconds) {
  const body = action === 'arm' ? Buffer.from(JSON.stringify({ ttlSeconds })) : Buffer.alloc(0);
  return new Promise((resolve, reject) => {
    const request = http.request({
      socketPath,
      method: action === 'status' ? 'GET' : 'POST',
      path: action === 'status' ? '/status' : `/${action}`,
      agent: false,
      headers: { authorization: `Bearer ${token}`, connection: 'close', 'content-length': body.length },
    }, (response) => {
      const chunks = [];
      response.on('data', (chunk) => chunks.push(chunk));
      response.on('end', () => response.statusCode === 200
        ? resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')))
        : reject(new Error(`control returned ${response.statusCode}`)));
    });
    request.on('error', reject);
    request.end(body);
  });
}

function send(port, route, body = Buffer.alloc(0)) {
  return new Promise((resolve, reject) => {
    const request = http.request({ host: '127.0.0.1', port, path: route, method: 'POST', headers: { 'content-type': 'application/octet-stream', 'content-length': body.length }, timeout: 3_000 }, (response) => {
      const chunks = [];
      response.on('data', (chunk) => chunks.push(chunk));
      response.on('end', () => resolve({ status: response.statusCode, body: Buffer.concat(chunks).toString('utf8') }));
    });
    request.on('timeout', () => request.destroy(new Error('request timed out')));
    request.on('error', reject);
    request.end(body);
  });
}

test('one-shot chaos drops only one completed durable response and restart/TTL disarm', { timeout: 20_000 }, async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'deep-resend-chaos-'));
  const token = crypto.randomBytes(32).toString('hex');
  const tokenFile = path.join(root, 'token');
  const controlSocket = process.platform === 'win32'
    ? `\\\\.\\pipe\\deep-resend-chaos-${crypto.randomBytes(12).toString('hex')}`
    : path.join(root, 'control.sock');
  fs.writeFileSync(tokenFile, `${token}\n`, { mode: 0o600 });
  const items = new Set();
  let duplicateStores = 0;
  let upstreamRequests = 0;
  const upstream = http.createServer((request, response) => {
    const chunks = [];
    request.on('data', (chunk) => chunks.push(chunk));
    request.on('end', () => {
      upstreamRequests += 1;
      const key = crypto.createHash('sha256').update(Buffer.concat(chunks)).digest('hex');
      if (items.has(key)) duplicateStores += 1; else items.add(key);
      response.writeHead(200, { 'content-type': 'application/octet-stream' });
      response.end('durable-response');
    });
  });
  await listen(upstream);
  const upstreamPort = upstream.address().port;
  let proxy;
  try {
    proxy = await startResendChaosProxy({
      upstreamOrigin: `http://127.0.0.1:${upstreamPort}`,
      tokenFile,
      controlSocket,
      dataHost: '127.0.0.1',
      dataPort: 0,
    });
    let proxyPort = proxy.address.port;
    const sendStore = (body) => send(proxyPort, '/api/client/mailbox/v2/store', body);

    const passthrough = await sendStore(Buffer.from('first-mau2'));
    assert.equal(passthrough.status, 200);
    assert.equal(passthrough.body, 'durable-response');
    assert.equal(items.size, 1);

    const armed = await control(controlSocket, token, 'arm', 5);
    assert.equal(armed.armed, true);
    await assert.rejects(sendStore(Buffer.from('uncertain-mau2')));
    assert.equal(items.size, 2, 'upstream durable state must exist before the downstream drop');

    const retry = await sendStore(Buffer.from('uncertain-mau2'));
    assert.equal(retry.status, 200);
    assert.equal(retry.body, 'durable-response');
    assert.equal(items.size, 2, 'exact retry must not create another server item');
    assert.equal(duplicateStores, 1);
    assert.equal(upstreamRequests, 3);
    const consumed = await control(controlSocket, token, 'status');
    assert.deepEqual({
      armed: consumed.armed,
      consumed: consumed.consumed,
      upstreamSuccessObserved: consumed.upstreamSuccessObserved,
      downstreamDropped: consumed.downstreamDropped,
      requestCount: consumed.requestCount,
      identifiersIncluded: consumed.identifiersIncluded,
      payloadInspected: consumed.payloadInspected,
    }, {
      armed: false, consumed: true, upstreamSuccessObserved: 2,
      downstreamDropped: 1, requestCount: 2,
      identifiersIncluded: false, payloadInspected: false,
    });

    await control(controlSocket, token, 'arm', 5);
    await new Promise((resolve) => setTimeout(resolve, 5_100));
    assert.equal((await control(controlSocket, token, 'status')).armed, false);

    await control(controlSocket, token, 'arm', 30);
    await proxy.close();
    proxy = await startResendChaosProxy({
      upstreamOrigin: `http://127.0.0.1:${upstreamPort}`,
      tokenFile,
      controlSocket,
      dataHost: '127.0.0.1',
      dataPort: 0,
    });
    proxyPort = proxy.address.port;
    const restarted = await control(controlSocket, token, 'status');
    assert.equal(restarted.armed, false);
    assert.equal(restarted.consumed, false);
    assert.equal(restarted.downstreamDropped, 0);
    assert.equal(restarted.requestCount, 0);

    const denied = await send(proxyPort, '/status');
    assert.equal(denied.status, 404, 'control state must never be exposed on the data listener');
    assert.equal(upstreamRequests, 3);
  } finally {
    if (proxy) await proxy.close();
    await new Promise((resolve) => upstream.close(resolve));
    fs.rmSync(root, { recursive: true, force: true });
  }
});
