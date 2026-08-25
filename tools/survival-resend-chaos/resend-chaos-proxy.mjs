import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import http2 from 'node:http2';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const ROUTES = new Map([
  ['GET', new Set([
    '/api/bootstrap/client',
    '/api/network/privacy-contact',
    '/api/network/membership-route-catalog',
  ])],
  ['POST', new Set([
    '/api/ingress/v1/frame',
  ])],
]);
const FAULTS = new Map([
  ['post-durable-response-drop', { operation: 'mailbox-store', route: '/api/ingress/v1/frame', phase: 'post-durable' }],
  ['pre-dispatch-outage', { operation: 'mailbox-store', route: '/api/ingress/v1/frame', phase: 'pre-dispatch' }],
  ['primary-ingress-rejected-before-forward', { operation: 'mailbox-store', route: '/api/ingress/v1/frame', phase: 'canonical-before-forward' }],
  ['post-durable-ack-response-drop', { operation: 'mailbox-ack', route: '/api/ingress/v1/frame', phase: 'post-durable' }],
]);
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

function copyHttp2RequestHeaders(request, requestPath, upstreamScheme) {
  const authority = request.headers[':authority'] ?? request.headers.host;
  if (typeof authority !== 'string' || authority.length === 0) {
    throw new Error('Public ingress authority is missing.');
  }
  const result = {
    ':method': request.method,
    ':path': requestPath,
    // This hop is h2c. Kestrel validates the HTTP/2 pseudo-header against
    // the transport; the original public HTTPS scheme is carried only in the
    // trusted, exact X-Forwarded-Proto boundary below.
    ':scheme': upstreamScheme,
    ':authority': authority,
    'x-forwarded-proto': 'https',
  };
  for (const [name, value] of Object.entries(request.headers)) {
    const lower = name.toLowerCase();
    if (!lower.startsWith(':') && !HOP_HEADERS.has(lower)
      && lower !== 'host' && lower !== 'x-forwarded-proto' && value !== undefined) {
      result[lower] = value;
    }
  }
  return result;
}

function publicState(state, now = Date.now()) {
  if (state.armed && now >= state.expiresAtMs) {
    state.armed = false;
    state.expiresAtMs = 0;
  }
  return {
    schema: 'deep-survival-resend-chaos-status.v2',
    mode: 'development-only',
    running: true,
    operation: state.operation,
    fault: state.fault,
    armed: state.armed,
    consumed: state.consumed,
    requestCount: state.requestCount,
    operationAttemptCount: state.operationAttemptCount,
    operationUpstreamDispatchCount: state.operationUpstreamDispatchCount,
    operationUpstreamSuccessCount: state.operationUpstreamSuccessCount,
    injectedFaultCount: state.injectedFaultCount,
    postDurableResponseDropCount: state.postDurableResponseDropCount,
    postDurableAckResponseDropCount: state.postDurableAckResponseDropCount,
    preDispatchOutageCount: state.preDispatchOutageCount,
    faultWindowStartedUnixMilliseconds: state.faultWindowStartedUnixMilliseconds,
    faultWindowDeadlineUnixMilliseconds: state.faultWindowDeadlineUnixMilliseconds,
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

  const state = {
    armed: false,
    consumed: false,
    fault: null,
    operation: null,
    targetRoute: null,
    faultPhase: null,
    expiresAtMs: 0,
    requestCount: 0,
    operationAttemptCount: 0,
    operationUpstreamDispatchCount: 0,
    operationUpstreamSuccessCount: 0,
    injectedFaultCount: 0,
    postDurableResponseDropCount: 0,
    postDurableAckResponseDropCount: 0,
    preDispatchOutageCount: 0,
    faultWindowStartedUnixMilliseconds: 0,
    faultWindowDeadlineUnixMilliseconds: 0,
  };
  let expiryTimer;
  const disarm = () => { state.armed = false; clearTimeout(expiryTimer); expiryTimer = undefined; };
  const arm = (ttlSeconds, fault) => {
    if (!Number.isSafeInteger(ttlSeconds) || ttlSeconds < 5 || ttlSeconds > 300) throw new Error('TTL must be an integer from 5 through 300 seconds.');
    const definition = FAULTS.get(fault);
    if (!definition) throw new Error('Unsupported chaos fault.');
    disarm();
    state.armed = true;
    state.consumed = false;
    state.fault = fault;
    state.operation = definition.operation;
    state.targetRoute = definition.route;
    state.faultPhase = definition.phase;
    state.requestCount = 0;
    state.operationAttemptCount = 0;
    state.operationUpstreamDispatchCount = 0;
    state.operationUpstreamSuccessCount = 0;
    state.injectedFaultCount = 0;
    state.postDurableResponseDropCount = 0;
    state.postDurableAckResponseDropCount = 0;
    state.preDispatchOutageCount = 0;
    state.faultWindowStartedUnixMilliseconds = Date.now();
    state.expiresAtMs = state.faultWindowStartedUnixMilliseconds + ttlSeconds * 1000;
    state.faultWindowDeadlineUnixMilliseconds = state.expiresAtMs;
    expiryTimer = setTimeout(disarm, ttlSeconds * 1000);
    expiryTimer.unref();
  };

  const dataServer = http2.createServer((request, response) => {
    let requestPath;
    try { requestPath = new URL(request.url, 'http://chaos.invalid').pathname; }
    catch { response.writeHead(404).end(); return; }
    if (request.url !== requestPath || !ROUTES.get(request.method)?.has(requestPath)) {
      response.writeHead(404).end();
      return;
    }
    state.requestCount += 1;
    const eligibleOperation = request.method === 'POST' && requestPath === state.targetRoute;
    if (eligibleOperation) {
      state.operationAttemptCount += 1;
      const snapshot = publicState(state);
      if (snapshot.armed && (state.faultPhase === 'pre-dispatch'
        || state.faultPhase === 'canonical-before-forward')) {
        disarm();
        state.consumed = true;
        state.injectedFaultCount += 1;
        state.preDispatchOutageCount += 1;
        request.resume();
        if (state.faultPhase === 'canonical-before-forward') {
          const errorFrame = Buffer.alloc(64);
          errorFrame.write('DIE1', 0, 4, 'ascii');
          errorFrame[4] = 1;
          errorFrame[5] = 1;
          errorFrame[6] = 9;
          errorFrame[7] = 1;
          errorFrame[8] = 1;
          errorFrame.writeUInt16BE(1, 10);
          response.writeHead(503, {
            'cache-control': 'no-store',
            'content-length': String(errorFrame.length),
            'content-type': 'application/vnd.xpoint.deep.ingress-error-v1',
            'retry-after': '1',
          }).end(errorFrame);
        } else {
          response.writeHead(503, { 'retry-after': '1' }).end();
        }
        return;
      }
      state.operationUpstreamDispatchCount += 1;
    }
    const upstreamSession = http2.connect(upstream.origin);
    const upstreamRequest = upstreamSession.request(
      copyHttp2RequestHeaders(request, requestPath, upstream.protocol.slice(0, -1)));
    const timeout = setTimeout(
      () => upstreamRequest.close(http2.constants.NGHTTP2_CANCEL),
      upstreamTimeoutMs);
    timeout.unref();
    upstreamRequest.on('response', (upstreamHeaders) => {
      const chunks = [];
      let length = 0;
      let overflow = false;
      upstreamRequest.on('data', (chunk) => {
        length += chunk.length;
        if (length > maximumResponseBytes) { overflow = true; upstreamRequest.close(http2.constants.NGHTTP2_CANCEL); return; }
        chunks.push(chunk);
      });
      const failUpstreamResponse = () => {
        if (!response.headersSent && !response.destroyed) response.writeHead(502).end();
      };
      upstreamRequest.on('aborted', failUpstreamResponse);
      upstreamRequest.on('end', () => {
        clearTimeout(timeout);
        upstreamSession.close();
        if (overflow) { failUpstreamResponse(); return; }
        if (response.destroyed) return;
        const status = Number(upstreamHeaders[':status'] ?? 502);
        const successful = status >= 200 && status <= 299;
        if (successful && eligibleOperation) state.operationUpstreamSuccessCount += 1;
        const snapshot = publicState(state);
        if (successful && eligibleOperation && snapshot.armed && state.faultPhase === 'post-durable') {
          disarm();
          state.consumed = true;
          state.injectedFaultCount += 1;
          if (state.operation === 'mailbox-ack') state.postDurableAckResponseDropCount += 1;
          else state.postDurableResponseDropCount += 1;
          // Model a lost response as a connection failure after the upstream
          // durable result. Closing only one compatibility stream can leave an
          // h2 intermediary waiting on a reusable but poisoned connection.
          // Destroy the downstream h2 session so HAProxy observes a definite
          // transport failure and establishes a fresh connection for retry.
          response.stream.session.destroy();
          return;
        }
        const headers = copyHeaders(Object.fromEntries(
          Object.entries(upstreamHeaders).filter(([name]) => !name.startsWith(':'))));
        // The interposer has already bounded and fully buffered the body. Emit
        // an exact downstream length even when an h2 upstream omitted it.
        headers['content-length'] = String(length);
        response.writeHead(status, headers);
        response.end(Buffer.concat(chunks));
      });
    });
    upstreamSession.on('error', () => { if (!response.headersSent && !response.destroyed) response.writeHead(502).end(); });
    upstreamRequest.on('error', () => {
      clearTimeout(timeout);
      upstreamSession.destroy();
      if (!response.headersSent && !response.destroyed) response.writeHead(502).end();
    });
    request.on('aborted', () => upstreamRequest.close(http2.constants.NGHTTP2_CANCEL));
    request.pipe(upstreamRequest);
  });
  dataServer.on('clientError', (_error, socket) => socket.destroy());
  const dataSessions = new Set();
  dataServer.on('session', (session) => {
    dataSessions.add(session);
    session.once('close', () => dataSessions.delete(session));
  });
  const closeDataSessions = () => {
    for (const session of dataSessions) session.destroy();
  };

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
          if (!body || Object.keys(body).length !== 2) throw new Error('invalid arm request');
          arm(body.ttlSeconds, body.fault);
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
    closeDataSessions();
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
      closeDataSessions();
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
  process.stdout.write('{"schema":"deep-survival-resend-chaos-runtime.v2","status":"ready","developmentOnly":true}\n');
}
