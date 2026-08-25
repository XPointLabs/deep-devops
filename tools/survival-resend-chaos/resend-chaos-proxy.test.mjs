import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import http2 from 'node:http2';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { startResendChaosProxy } from './resend-chaos-proxy.mjs';

function listen(server) {
  return new Promise((resolve, reject) => server.listen(0, '127.0.0.1', resolve).once('error', reject));
}

function control(socketPath, token, action, ttlSeconds, fault) {
  const body = action === 'arm' ? Buffer.from(JSON.stringify({ ttlSeconds, fault })) : Buffer.alloc(0);
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

function send(port, route, body = Buffer.alloc(0), method = 'POST') {
  return new Promise((resolve, reject) => {
    const session = http2.connect(`http://127.0.0.1:${port}`);
    const request = session.request({
      ':method': method,
      ':path': route,
      ':scheme': 'https',
      ':authority': 'uat.test:41803',
      'content-type': 'application/octet-stream',
      'content-length': String(body.length),
    }, { endStream: body.length === 0 });
    let responseHeaders;
    const chunks = [];
    request.on('response', (headers) => { responseHeaders = headers; });
    request.on('data', (chunk) => chunks.push(chunk));
    request.on('end', () => {
      session.close();
      if (!responseHeaders) {
        reject(new Error('response stream ended before headers'));
        return;
      }
      resolve({
        status: Number(responseHeaders?.[':status']),
        headers: responseHeaders ?? {},
        body: Buffer.concat(chunks),
      });
    });
    request.on('error', (error) => { session.destroy(); reject(error); });
    session.on('error', reject);
    request.setTimeout(3_000, () => request.close(http2.constants.NGHTTP2_CANCEL));
    if (body.length !== 0) request.end(body);
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
  let upstreamForwardedProto;
  let upstreamScheme;
  const upstream = http2.createServer((request, response) => {
    const chunks = [];
    request.on('data', (chunk) => chunks.push(chunk));
    request.on('end', () => {
      upstreamRequests += 1;
      upstreamForwardedProto = request.headers['x-forwarded-proto'];
      upstreamScheme = request.headers[':scheme'];
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
    const sendIngress = (body) => send(proxyPort, '/api/ingress/v1/frame', body);

    const passthrough = await sendIngress(Buffer.from('first-opaque-frame'));
    assert.equal(passthrough.status, 200);
    assert.equal(upstreamForwardedProto, 'https');
    assert.equal(upstreamScheme, 'http');
    assert.equal(passthrough.headers['content-length'], String('durable-response'.length));
    assert.equal(passthrough.body.toString('utf8'), 'durable-response');
    assert.equal(items.size, 1);

    const armed = await control(controlSocket, token, 'arm', 5, 'post-durable-response-drop');
    assert.equal(armed.armed, true);
    await assert.rejects(sendIngress(Buffer.from('uncertain-opaque-frame')));
    assert.equal(items.size, 2, 'upstream durable state must exist before the downstream drop');

    const retry = await sendIngress(Buffer.from('uncertain-opaque-frame'));
    assert.equal(retry.status, 200);
    assert.equal(retry.body.toString('utf8'), 'durable-response');
    assert.equal(items.size, 2, 'exact retry must not create another server item');
    assert.equal(duplicateStores, 1);
    assert.equal(upstreamRequests, 3);
    const consumed = await control(controlSocket, token, 'status');
    assert.deepEqual({
      schema: consumed.schema,
      operation: consumed.operation,
      fault: consumed.fault,
      armed: consumed.armed,
      consumed: consumed.consumed,
      operationAttemptCount: consumed.operationAttemptCount,
      operationUpstreamDispatchCount: consumed.operationUpstreamDispatchCount,
      operationUpstreamSuccessCount: consumed.operationUpstreamSuccessCount,
      injectedFaultCount: consumed.injectedFaultCount,
      postDurableResponseDropCount: consumed.postDurableResponseDropCount,
      postDurableAckResponseDropCount: consumed.postDurableAckResponseDropCount,
      preDispatchOutageCount: consumed.preDispatchOutageCount,
      requestCount: consumed.requestCount,
      identifiersIncluded: consumed.identifiersIncluded,
      payloadInspected: consumed.payloadInspected,
    }, {
      schema: 'deep-survival-resend-chaos-status.v2',
      operation: 'mailbox-store', fault: 'post-durable-response-drop',
      armed: false, consumed: true,
      operationAttemptCount: 2, operationUpstreamDispatchCount: 2,
      operationUpstreamSuccessCount: 2, injectedFaultCount: 1,
      postDurableResponseDropCount: 1, postDurableAckResponseDropCount: 0,
      preDispatchOutageCount: 0,
      requestCount: 2,
      identifiersIncluded: false, payloadInspected: false,
    });

    await control(controlSocket, token, 'arm', 5, 'pre-dispatch-outage');
    const outage = await sendIngress(Buffer.from('not-dispatched'));
    assert.equal(outage.status, 503);
    assert.equal(upstreamRequests, 3, 'pre-dispatch fault must not reach the durable store');
    const afterOutage = await control(controlSocket, token, 'status');
    assert.equal(afterOutage.operationAttemptCount, 1);
    assert.equal(afterOutage.operationUpstreamDispatchCount, 0);
    assert.equal(afterOutage.operationUpstreamSuccessCount, 0);
    assert.equal(afterOutage.injectedFaultCount, 1);
    assert.equal(afterOutage.preDispatchOutageCount, 1);
    assert.equal(afterOutage.postDurableResponseDropCount, 0);

    const outageRetry = await sendIngress(Buffer.from('not-dispatched'));
    assert.equal(outageRetry.status, 200);
    assert.equal(items.size, 3);
    assert.equal(upstreamRequests, 4);

    await control(controlSocket, token, 'arm', 5, 'primary-ingress-rejected-before-forward');
    const beforeForward = await sendIngress(Buffer.from('fallback-candidate'));
    assert.equal(beforeForward.status, 503);
    assert.equal(beforeForward.headers['content-type'], 'application/vnd.xpoint.deep.ingress-error-v1');
    assert.equal(beforeForward.headers['content-length'], '64');
    assert.equal(beforeForward.headers['retry-after'], '1');
    assert.equal(beforeForward.headers['cache-control'], 'no-store');
    assert.equal(beforeForward.body.length, 64);
    assert.equal(beforeForward.body.subarray(0, 4).toString('ascii'), 'DIE1');
    assert.deepEqual([...beforeForward.body.subarray(4, 12)], [1, 1, 9, 1, 1, 0, 0, 1]);
    assert.ok(beforeForward.body.subarray(12).every((value) => value === 0));
    assert.equal(upstreamRequests, 4, 'canonical before-forward fault must not reach the primary router');
    const afterBeforeForward = await control(controlSocket, token, 'status');
    assert.equal(afterBeforeForward.operationAttemptCount, 1);
    assert.equal(afterBeforeForward.operationUpstreamDispatchCount, 0);
    assert.equal(afterBeforeForward.operationUpstreamSuccessCount, 0);
    assert.equal(afterBeforeForward.injectedFaultCount, 1);
    assert.equal(afterBeforeForward.preDispatchOutageCount, 1);

    await control(controlSocket, token, 'arm', 5, 'post-durable-ack-response-drop');
    const wrongMethod = await send(proxyPort, '/api/ingress/v1/frame', Buffer.alloc(0), 'GET');
    assert.equal(wrongMethod.status, 404);
    const stillArmedForAck = await control(controlSocket, token, 'status');
    assert.equal(stillArmedForAck.armed, true);
    assert.equal(stillArmedForAck.operationAttemptCount, 0);
    assert.equal(stillArmedForAck.injectedFaultCount, 0);
    await assert.rejects(sendIngress(Buffer.from('opaque-ack-once')));
    assert.equal(upstreamRequests, 5, 'ACK must reach upstream before its response is dropped');
    const ackRetry = await sendIngress(Buffer.from('opaque-ack-once'));
    assert.equal(ackRetry.status, 200);
    assert.equal(upstreamRequests, 6);
    const afterAck = await control(controlSocket, token, 'status');
    assert.equal(afterAck.operation, 'mailbox-ack');
    assert.equal(afterAck.operationAttemptCount, 2);
    assert.equal(afterAck.operationUpstreamDispatchCount, 2);
    assert.equal(afterAck.operationUpstreamSuccessCount, 2);
    assert.equal(afterAck.injectedFaultCount, 1);
    assert.equal(afterAck.postDurableAckResponseDropCount, 1);
    assert.equal(afterAck.postDurableResponseDropCount, 0);
    assert.equal(afterAck.preDispatchOutageCount, 0);

    await control(controlSocket, token, 'arm', 5, 'post-durable-response-drop');
    await new Promise((resolve) => setTimeout(resolve, 5_100));
    assert.equal((await control(controlSocket, token, 'status')).armed, false);

    await control(controlSocket, token, 'arm', 30, 'pre-dispatch-outage');
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
    assert.equal(restarted.operation, null);
    assert.equal(restarted.consumed, false);
    assert.equal(restarted.injectedFaultCount, 0);
    assert.equal(restarted.requestCount, 0);

    const denied = await send(proxyPort, '/status');
    assert.equal(denied.status, 404, 'control state must never be exposed on the data listener');
    assert.equal(upstreamRequests, 6);
  } finally {
    if (proxy) await proxy.close();
    await new Promise((resolve) => upstream.close(resolve));
    fs.rmSync(root, { recursive: true, force: true });
  }
});
