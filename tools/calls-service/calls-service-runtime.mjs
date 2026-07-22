import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { mkdir, readFile, writeFile } from 'node:fs/promises';

const mode = 'calls';
const port = Number(process.env.PORT ?? 8080);
const serviceName = String(process.env.SERVICE_NAME ?? 'deep-calls-service');
const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const stateDir = process.env.CALLS_STATE_DIR
  ?? process.env.COMPAT_STATE_DIR
  ?? process.env.MOCK_STATE_DIR
  ?? path.resolve(scriptDir, '..', '..', 'artifacts', 'calls-state');
const callStatePath = path.join(stateDir, 'calls.json');

const callSignals = normalizeLoadedSignals(await loadJson(callStatePath, []));
let callStateWrite = Promise.resolve();

const stats = {
  startedAt: new Date().toISOString(),
  requestsTotal: 0,
  healthChecks: 0,
  callSignal: 0,
  callInbox: 0,
  errors: 0
};

function json(res, status, value) {
  const body = Buffer.from(JSON.stringify(value));
  res.writeHead(status, {
    'content-type': 'application/json',
    'content-length': body.length
  });
  res.end(body);
}

function notFound(res) {
  json(res, 404, { error: 'not-found', service: mode });
}

async function ensureStateDir() {
  await mkdir(stateDir, { recursive: true });
}

async function loadJson(filePath, fallback) {
  try {
    const raw = await readFile(filePath, 'utf8');
    return JSON.parse(raw);
  } catch (error) {
    if (error && typeof error === 'object' && 'code' in error && error.code === 'ENOENT') {
      return fallback;
    }

    throw error;
  }
}

async function saveJson(filePath, value) {
  await ensureStateDir();
  await writeFile(filePath, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

async function saveCallState() {
  callStateWrite = callStateWrite.catch(() => {}).then(() => saveJson(callStatePath, callSignals));
  await callStateWrite;
}

function pathOf(req) {
  return new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`);
}

async function body(req) {
  const chunks = [];
  for await (const chunk of req) {
    chunks.push(Buffer.from(chunk));
  }
  return Buffer.concat(chunks);
}

async function bodyJson(req) {
  const raw = await body(req);
  return raw.length === 0 ? {} : JSON.parse(raw.toString('utf8'));
}

function incrementStat(key, value = 1) {
  if (Object.hasOwn(stats, key)) {
    stats[key] += value;
  }
}

function sessionIdValue(value) {
  if (typeof value === 'string') {
    return value;
  }

  if (value && typeof value === 'object' && typeof value.value === 'string') {
    return value.value;
  }

  if (value && typeof value === 'object' && typeof value.Value === 'string') {
    return value.Value;
  }

  return '';
}

function isCanonicalSessionId(value) {
  return /^05[0-9a-f]{64}$/.test(value);
}

function normalizeCallSignal(envelope) {
  if (!envelope || typeof envelope !== 'object' || Array.isArray(envelope)) {
    return null;
  }

  const callId = String(envelope.callId ?? envelope.CallId ?? '');
  const conversationId = String(envelope.conversationId ?? envelope.ConversationId ?? '');
  const sender = sessionIdValue(envelope.sender ?? envelope.Sender);
  const recipient = sessionIdValue(envelope.recipient ?? envelope.Recipient);

  if (!callId || !conversationId || !isCanonicalSessionId(sender) || !isCanonicalSessionId(recipient)) {
    return null;
  }

  return {
    ...envelope,
    callId,
    conversationId,
    sender: { value: sender },
    recipient: { value: recipient },
    createdAt: envelope.createdAt ?? envelope.CreatedAt ?? new Date().toISOString()
  };
}

function normalizeLoadedSignals(value) {
  if (!Array.isArray(value)) {
    return [];
  }

  return value.map(normalizeCallSignal).filter(Boolean);
}

async function handleCalls(req, res, url) {
  if (req.method === 'POST' && url.pathname === '/api/calls/signal') {
    incrementStat('callSignal');

    let envelope;
    try {
      envelope = await bodyJson(req);
    } catch {
      json(res, 400, {
        error: 'invalid-request',
        message: 'request body must be valid JSON'
      });
      return true;
    }

    const normalized = normalizeCallSignal(envelope);
    if (!normalized) {
      json(res, 400, {
        error: 'invalid-request',
        message: 'callId, conversationId, sender, and recipient are required'
      });
      return true;
    }

    callSignals.push(normalized);
    await saveCallState();
    json(res, 202, { accepted: true, callId: normalized.callId });
    return true;
  }

  if (req.method === 'GET' && url.pathname.startsWith('/api/calls/inbox/')) {
    incrementStat('callInbox');

    const recipient = decodeURIComponent(url.pathname.slice('/api/calls/inbox/'.length));
    if (!isCanonicalSessionId(recipient)) {
      json(res, 400, {
        error: 'invalid-request',
        message: 'recipient must be a canonical Session ID'
      });
      return true;
    }
    const selected = [];
    const remaining = [];
    for (const signal of callSignals) {
      if (sessionIdValue(signal.recipient ?? signal.Recipient) === recipient) {
        selected.push(signal);
      } else {
        remaining.push(signal);
      }
    }

    if (selected.length > 0) {
      callSignals.splice(0, callSignals.length, ...remaining);
      await saveCallState();
    }

    json(res, 200, selected);
    return true;
  }

  return false;
}

const server = http.createServer(async (req, res) => {
  try {
    incrementStat('requestsTotal');

    const url = pathOf(req);
    if (req.method === 'GET' && (url.pathname === '/health/live' || url.pathname === '/health/ready')) {
      incrementStat('healthChecks');
      json(res, 200, { ok: true, service: serviceName });
      return;
    }

    if (req.method === 'GET' && url.pathname === '/stats') {
      json(res, 200, {
        service: serviceName,
        mode,
        stats,
        inventory: {
          callSignals: callSignals.length
        },
        state: {
          dir: stateDir,
          calls: callStatePath
        }
      });
      return;
    }

    if (await handleCalls(req, res, url)) {
      return;
    }

    notFound(res);
  } catch (error) {
    incrementStat('errors');
    json(res, 500, {
      service: serviceName,
      message: error instanceof Error ? error.message : String(error)
    });
  }
});

server.listen(port, '0.0.0.0', () => {
  console.log(`${serviceName} listening on ${port}`);
});
