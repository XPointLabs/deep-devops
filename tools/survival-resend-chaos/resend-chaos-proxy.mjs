import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const ROUTES = new Map([
  ['GET', new Set([
    '/api/bootstrap/client',
    '/api/network/contact',
    '/api/network/membership-route-catalog',
  ])],
  ['POST', new Set([
    '/api/session/rpc',
    '/api/client/mailbox/v2/store',
    '/api/client/mailbox/v2/retrieve',
    '/api/client/mailbox/v2/acknowledge',
  ])],
]);
const DROP_ROUTE = '/api/client/mailbox/v2/store';
const HOP_HEADERS = new Set([
  'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
  'te', 'trailer', 'transfer-encoding', 'upgrade',
]);

function exactTokenEqual(actual, expected) {
  const left = Buffer.from(actual ?? '', 'utf8');
  const right = Buffer.from(expected, 'utf8');
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}

function copyHeaders(headers, upstreamHost) {
  const result = {};
  for (const [name, value] of Object.entries(headers)) {
    if (!HOP_HEADERS.has(name.toLowerCase()) && value !== undefined) result[name] = value;
  }
  if (upstreamHost) result.host = upstreamHost;
  return result;
}

function publicState(state, now = Date.now()) {
  if (state.armed && now >= state.expiresAtMs) {
    state.armed = false;
    state.expiresAtMs = 0;
  }
  return {
    schema: 'deep-survival-resend-chaos-status.v1',
    mode: 'development-only',
    armed: state.armed,
    consumed: state.consumed,
    upstreamSuccessObserved: state.upstreamSuccessObserved,
    downstreamDropped: state.downstreamDropped,
    requestCount: state.requestCount,
    expiresInSeconds: state.armed ? Math.max(0, Math.ceil((state.expiresAtMs - now) / 1000)) : 0,
    identifiersIncluded: false,
    payloadInspected: false,
  };
}

export async function startResendChaosProxy(options) {
  const upstream = new URL(options.upstreamOrigin);
  if (upstream.protocol !== 'http:' || upstream.username || upstream.password || upstream.pathname !== '/' || upstream.search || upstream.hash) {
    throw new Error('Chaos upstream must be one exact internal HTTP origin.');
  }
  const token = fs.readFileSync(options.tokenFile, 'utf8').trim();
  if (!/^[0-9a-f]{64}$/.test(token)) throw new Error('Chaos control token must be exactly 32 random bytes encoded as lowercase hex.');
  const windowsPipe = process.platform === 'win32' && String(options.controlSocket).startsWith('\\\\.\\pipe\\');
  const controlSocket = windowsPipe ? options.controlSocket : path.resolve(options.controlSocket);
  const maximumResponseBytes = Number(options.maximumResponseBytes ?? 2_097_152);
  const upstreamTimeoutMs = Number(options.upstreamTimeoutMs ?? 30_000);
  if (!Number.isSafeInteger(maximumResponseBytes) || maximumResponseBytes < 1024 || maximumResponseBytes > 8_388_608) throw new Error('Invalid response bound.');
  if (!Number.isSafeInteger(upstreamTimeoutMs) || upstreamTimeoutMs < 1_000 || upstreamTimeoutMs > 60_000) throw new Error('Invalid upstream timeout.');

  const state = { armed: false, consumed: false, expiresAtMs: 0, upstreamSuccessObserved: 0, downstreamDropped: 0, requestCount: 0 };
  let expiryTimer;
  const disarm = () => { state.armed = false; state.expiresAtMs = 0; clearTimeout(expiryTimer); expiryTimer = undefined; };
  const arm = (ttlSeconds) => {
    if (!Number.isSafeInteger(ttlSeconds) || ttlSeconds < 5 || ttlSeconds > 300) throw new Error('TTL must be an integer from 5 through 300 seconds.');
    disarm();
    state.armed = true;
    state.consumed = false;
    state.upstreamSuccessObserved = 0;
    state.downstreamDropped = 0;
    state.requestCount = 0;
    state.expiresAtMs = Date.now() + ttlSeconds * 1000;
    expiryTimer = setTimeout(disarm, ttlSeconds * 1000);
    expiryTimer.unref();
  };

  const dataServer = http.createServer((request, response) => {
    let requestPath;
    try { requestPath = new URL(request.url, 'http://chaos.invalid').pathname; }
    catch { response.writeHead(404).end(); return; }
    if (request.url !== requestPath || !ROUTES.get(request.method)?.has(requestPath)) {
      response.writeHead(404).end();
      return;
    }
    state.requestCount += 1;
    const upstreamRequest = http.request({
      protocol: upstream.protocol,
      hostname: upstream.hostname,
      port: upstream.port || 80,
      method: request.method,
      path: requestPath,
      headers: copyHeaders(request.headers, upstream.host),
      timeout: upstreamTimeoutMs,
    }, (upstreamResponse) => {
      const chunks = [];
      let length = 0;
      let overflow = false;
      upstreamResponse.on('data', (chunk) => {
        length += chunk.length;
        if (length > maximumResponseBytes) { overflow = true; upstreamResponse.destroy(); return; }
        chunks.push(chunk);
      });
      const failUpstreamResponse = () => {
        if (!response.headersSent && !response.destroyed) response.writeHead(502).end();
      };
      upstreamResponse.on('aborted', failUpstreamResponse);
      upstreamResponse.on('error', failUpstreamResponse);
      upstreamResponse.on('end', () => {
        if (overflow) { failUpstreamResponse(); return; }
        if (response.destroyed) return;
        const status = upstreamResponse.statusCode ?? 502;
        const successful = status >= 200 && status <= 299;
        if (successful) state.upstreamSuccessObserved += 1;
        const snapshot = publicState(state);
        if (successful && request.method === 'POST' && requestPath === DROP_ROUTE && snapshot.armed) {
          disarm();
          state.consumed = true;
          state.downstreamDropped += 1;
          response.destroy();
          return;
        }
        const headers = copyHeaders(upstreamResponse.headers);
        response.writeHead(status, headers);
        response.end(Buffer.concat(chunks));
      });
    });
    upstreamRequest.on('timeout', () => upstreamRequest.destroy(new Error('upstream timeout')));
    upstreamRequest.on('error', () => { if (!response.headersSent && !response.destroyed) response.writeHead(502).end(); });
    request.on('aborted', () => upstreamRequest.destroy());
    request.pipe(upstreamRequest);
  });
  dataServer.on('clientError', (_error, socket) => socket.destroy());

  const controlServer = http.createServer((request, response) => {
    if (!exactTokenEqual(request.headers.authorization, `Bearer ${token}`)) { response.writeHead(404).end(); return; }
    const chunks = [];
    let length = 0;
    request.on('data', (chunk) => {
      length += chunk.length;
      if (length > 4096) request.destroy(); else chunks.push(chunk);
    });
    request.on('end', () => {
      try {
        if (request.method === 'GET' && request.url === '/status') {
          response.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify(publicState(state)));
          return;
        }
        if (request.method === 'POST' && request.url === '/arm') {
          const body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
          if (!body || Object.keys(body).length !== 1) throw new Error('invalid arm request');
          arm(body.ttlSeconds);
          response.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify(publicState(state)));
          return;
        }
        if (request.method === 'POST' && request.url === '/disarm' && length === 0) {
          disarm();
          response.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify(publicState(state)));
          return;
        }
        response.writeHead(404).end();
      } catch { response.writeHead(400).end(); }
    });
  });

  if (!windowsPipe) {
    fs.mkdirSync(path.dirname(controlSocket), { recursive: true, mode: 0o700 });
    try { fs.rmSync(controlSocket, { force: true }); } catch {}
  }
  try {
    await Promise.all([
      new Promise((resolve, reject) => dataServer.listen(options.dataPort, options.dataHost, resolve).once('error', reject)),
      new Promise((resolve, reject) => controlServer.listen(controlSocket, resolve).once('error', reject)),
    ]);
    if (!windowsPipe) fs.chmodSync(controlSocket, 0o600);
  } catch (error) {
    disarm();
    if (dataServer.listening) dataServer.close();
    if (controlServer.listening) controlServer.close();
    dataServer.closeAllConnections();
    controlServer.closeAllConnections();
    if (!windowsPipe) fs.rmSync(controlSocket, { force: true });
    throw error;
  }
  return {
    address: dataServer.address(),
    state: () => publicState(state),
    close: async () => {
      disarm();
      const dataClosed = new Promise((resolve) => dataServer.close(resolve));
      const controlClosed = new Promise((resolve) => controlServer.close(resolve));
      dataServer.closeAllConnections();
      controlServer.closeAllConnections();
      await Promise.all([dataClosed, controlClosed]);
      if (!windowsPipe) fs.rmSync(controlSocket, { force: true });
    },
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  const instance = await startResendChaosProxy({
    upstreamOrigin: process.env.DEEP_CHAOS_UPSTREAM_ORIGIN,
    tokenFile: process.env.DEEP_CHAOS_TOKEN_FILE,
    controlSocket: process.env.DEEP_CHAOS_CONTROL_SOCKET,
    dataHost: process.env.DEEP_CHAOS_DATA_HOST ?? '0.0.0.0',
    dataPort: Number(process.env.DEEP_CHAOS_DATA_PORT ?? 8080),
    maximumResponseBytes: Number(process.env.DEEP_CHAOS_MAX_RESPONSE_BYTES ?? 2_097_152),
    upstreamTimeoutMs: Number(process.env.DEEP_CHAOS_UPSTREAM_TIMEOUT_MS ?? 30_000),
  });
  const shutdown = async () => { await instance.close(); process.exit(0); };
  process.once('SIGTERM', shutdown);
  process.once('SIGINT', shutdown);
  process.stdout.write('{"schema":"deep-survival-resend-chaos-runtime.v1","status":"ready","developmentOnly":true}\n');
}
