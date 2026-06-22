import { createHash } from 'node:crypto';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { mkdir, readFile, writeFile } from 'node:fs/promises';

const mode = process.env.SERVICE_MODE ?? 'all';
const port = Number(process.env.PORT ?? 8080);
const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const stateDir = process.env.MOCK_STATE_DIR ?? path.resolve(scriptDir, '..', '..', 'artifacts', 'mock-state');
const storageStatePath = path.join(stateDir, 'storage.json');
const fileStatePath = path.join(stateDir, 'file.json');
const pushStatePath = path.join(stateDir, 'push.json');

const messages = await loadJson(storageStatePath, []);
const files = new Map(
  (await loadJson(fileStatePath, [])).map(record => [
    record.id,
    {
      ...record,
      content: Buffer.from(record.contentBase64 ?? '', 'base64')
    }
  ])
);
const subscriptions = new Map((await loadJson(pushStatePath, [])).map(record => [record.key, record]));

const stats = {
  startedAt: new Date().toISOString(),
  requestsTotal: 0,
  healthChecks: 0,
  storageStore: 0,
  storageRetrieve: 0,
  fileUpload: 0,
  fileDownload: 0,
  fileInfo: 0,
  pushSubscribe: 0,
  pushSubscribeBatch: 0,
  subscriptionsList: 0,
  errors: 0
};

const relayId = '1111111111111111111111111111111111111111111111111111111111111111';
const defaultStorageTtlMs = 86_400_000;
const maxStorageTtlMs = 30 * 24 * 60 * 60 * 1000;
const defaultPushTtlSeconds = 30 * 24 * 60 * 60;
const maxPushTtlSeconds = 365 * 24 * 60 * 60;
const pushSubscribeCode = {
  OK: 0,
  BAD_INPUT: 1,
  SERVICE_NOT_AVAILABLE: 2,
  SERVICE_TIMEOUT: 3,
  ERROR: 4,
  INTERNAL_ERROR: 5
};
const supportedPushServices = new Set(['apns', 'firebase', 'huawei']);
const signatureExpirySeconds = 14 * 24 * 60 * 60;
const signatureFutureGraceSeconds = 24 * 60 * 60;

function json(res, status, value) {
  const body = Buffer.from(JSON.stringify(value));
  res.writeHead(status, {
    'content-type': 'application/json',
    'content-length': body.length
  });
  res.end(body);
}

function bytes(res, status, value, contentType = 'application/octet-stream') {
  res.writeHead(status, {
    'content-type': contentType,
    'content-length': value.length
  });
  res.end(value);
}

function notFound(res) {
  json(res, 404, { error: 'not-found', service: mode });
}

function sha256(value, encoding = 'hex') {
  return createHash('sha256').update(value).digest(encoding);
}

function nowMs() {
  return Date.now();
}

function nowSeconds() {
  return Math.floor(nowMs() / 1000);
}

function parsePositiveInteger(value, fallback, maxValue) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return fallback;
  }

  const intValue = Math.floor(parsed);
  return maxValue === undefined ? intValue : Math.min(intValue, maxValue);
}

function isHexWithLength(value, length) {
  return typeof value === 'string' && value.length === length && /^[0-9a-f]+$/i.test(value);
}

function isBase64WithDecodedLength(value, byteLength) {
  if (typeof value !== 'string' || value.length === 0 || !/^[A-Za-z0-9+/=_-]+$/.test(value)) {
    return false;
  }

  try {
    const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
    return Buffer.from(normalized, 'base64').length === byteLength;
  } catch {
    return false;
  }
}

function isHexOrBase64Bytes(value, byteLength) {
  return isHexWithLength(value, byteLength * 2) || isBase64WithDecodedLength(value, byteLength);
}

function pruneStorageExpired() {
  const before = messages.length;
  const current = nowMs();
  for (let i = messages.length - 1; i >= 0; i -= 1) {
    if (Number(messages[i].expiration ?? 0) <= current) {
      messages.splice(i, 1);
    }
  }

  return before !== messages.length;
}

function pruneFileExpired() {
  let changed = false;
  const current = nowSeconds();
  for (const [id, record] of files.entries()) {
    if (Number(record.expires ?? 0) <= current) {
      files.delete(id);
      changed = true;
    }
  }

  return changed;
}

function prunePushExpired() {
  let changed = false;
  const current = nowSeconds();
  for (const [key, record] of subscriptions.entries()) {
    if (record.expiresAt && Number(record.expiresAt) <= current) {
      subscriptions.delete(key);
      changed = true;
    }
  }

  return changed;
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

async function saveStorageState() {
  await saveJson(storageStatePath, messages);
}

async function saveFileState() {
  await saveJson(
    fileStatePath,
    [...files.values()].map(record => ({
      id: record.id,
      contentBase64: record.content.toString('base64'),
      uploaded: record.uploaded,
      expires: record.expires
    }))
  );
}

async function savePushState() {
  await saveJson(pushStatePath, [...subscriptions.values()]);
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

function routeIs(enabledMode) {
  return mode === enabledMode || mode === 'all';
}

function incrementStat(key, value = 1) {
  if (Object.hasOwn(stats, key)) {
    stats[key] += value;
  }
}

function processPushSubscribeRequest(request) {
  if (!request || typeof request !== 'object' || Array.isArray(request)) {
    return {
      ok: false,
      changed: false,
      body: {
        error: pushSubscribeCode.BAD_INPUT,
        message: 'Invalid request: expected object'
      }
    };
  }

  const pubkey = String(request.pubkey ?? '');
  const service = String(request.service ?? '');
  if (!pubkey || !service) {
    return {
      ok: false,
      changed: false,
      body: {
        error: pushSubscribeCode.BAD_INPUT,
        message: 'Invalid request: pubkey and service are required'
      }
    };
  }

  if (pubkey.startsWith('05')) {
    const sessionEd25519 = String(request.session_ed25519 ?? '');
    if (!sessionEd25519 || !isHexOrBase64Bytes(sessionEd25519, 32)) {
      return {
        ok: false,
        changed: false,
        body: {
          error: pushSubscribeCode.BAD_INPUT,
          message: 'Missing required parameter'
        }
      };
    }
  }

  if (typeof request.data !== 'boolean') {
    return {
      ok: false,
      changed: false,
      body: {
        error: pushSubscribeCode.BAD_INPUT,
        message: 'Missing required parameter'
      }
    };
  }

  const sigTs = Number(request.sig_ts);
  if (!Number.isFinite(sigTs) || sigTs <= 0) {
    return {
      ok: false,
      changed: false,
      body: {
        error: pushSubscribeCode.BAD_INPUT,
        message: 'Missing required parameter'
      }
    };
  }

  const now = nowSeconds();
  if (sigTs <= now - signatureExpirySeconds) {
    return {
      ok: false,
      changed: false,
      body: {
        error: pushSubscribeCode.BAD_INPUT,
        message: 'Subscription: sig_ts timestamp is too old'
      }
    };
  }

  if (sigTs >= now + signatureFutureGraceSeconds) {
    return {
      ok: false,
      changed: false,
      body: {
        error: pushSubscribeCode.BAD_INPUT,
        message: 'Subscription: sig_ts timestamp is too far in the future'
      }
    };
  }

  const signature = String(request.signature ?? '');
  if (!signature || !isHexOrBase64Bytes(signature, 64)) {
    return {
      ok: false,
      changed: false,
      body: {
        error: pushSubscribeCode.BAD_INPUT,
        message: 'Missing required parameter'
      }
    };
  }

  const encKey = String(request.enc_key ?? '');
  if (!encKey || !isHexOrBase64Bytes(encKey, 32)) {
    return {
      ok: false,
      changed: false,
      body: {
        error: pushSubscribeCode.BAD_INPUT,
        message: 'Missing required parameter'
      }
    };
  }

  if (!request.service_info || typeof request.service_info !== 'object' || Array.isArray(request.service_info)) {
    return {
      ok: false,
      changed: false,
      body: {
        error: pushSubscribeCode.BAD_INPUT,
        message: 'Missing required parameter'
      }
    };
  }

  const token = String(request.service_info.token ?? '');
  if (!token) {
    return {
      ok: false,
      changed: false,
      body: {
        error: pushSubscribeCode.BAD_INPUT,
        message: 'Missing required parameter'
      }
    };
  }

  if (!supportedPushServices.has(service)) {
    return {
      ok: false,
      changed: false,
      body: {
        error: pushSubscribeCode.SERVICE_NOT_AVAILABLE,
        message: `Service '${service}' is not available`
      }
    };
  }

  const namespaces = request.namespaces ?? [];
  if (!Array.isArray(namespaces)) {
    return {
      ok: false,
      changed: false,
      body: {
        error: pushSubscribeCode.BAD_INPUT,
        message: 'Invalid request: namespaces must be an array'
      }
    };
  }

  if (namespaces.length === 0) {
    return {
      ok: false,
      changed: false,
      body: {
        error: pushSubscribeCode.BAD_INPUT,
        message: 'Subscription: namespaces missing or empty'
      }
    };
  }

  const sorted = [...namespaces].sort((a, b) => a - b);
  if (JSON.stringify(namespaces) !== JSON.stringify(sorted)) {
    return {
      ok: false,
      changed: false,
      body: {
        error: pushSubscribeCode.BAD_INPUT,
        message: 'Invalid request: namespaces must be sorted'
      }
    };
  }

  for (let i = 0; i < namespaces.length - 1; i += 1) {
    if (namespaces[i] === namespaces[i + 1]) {
      return {
        ok: false,
        changed: false,
        body: {
          error: pushSubscribeCode.BAD_INPUT,
          message: 'Subscription: namespaces contains duplicates'
        }
      };
    }
  }

  const key = `${pubkey}:${service}:${token}`;
  const idempotencyKey = request.idempotency_key ?? request.idempotencyKey;
  const normalizedIdempotencyKey = idempotencyKey ? String(idempotencyKey) : null;
  const ttlSeconds = parsePositiveInteger(request.ttlSeconds ?? request.ttl, defaultPushTtlSeconds, maxPushTtlSeconds);
  const subscribedAtSeconds = nowSeconds();
  const existing = subscriptions.get(key);

  if (existing && normalizedIdempotencyKey && existing.idempotencyKey === normalizedIdempotencyKey) {
    return {
      ok: true,
      changed: false,
      body: {
        success: true,
        updated: true,
        idempotent: true,
        message: 'Resubscription successful'
      }
    };
  }

  const existed = subscriptions.has(key);
  subscriptions.set(key, {
    key,
    ...request,
    pubkey,
    service,
    idempotencyKey: normalizedIdempotencyKey,
    subscribedAt: new Date(subscribedAtSeconds * 1000).toISOString(),
    expiresAt: subscribedAtSeconds + ttlSeconds
  });

  return {
    ok: true,
    changed: true,
    body: existed
      ? { success: true, updated: true, message: 'Resubscription successful' }
      : { success: true, added: true, message: 'Subscription successful' }
  };
}

async function handleStorage(req, res, url) {
  if (!routeIs('storage')) {
    return false;
  }

  if (req.method === 'POST' && url.pathname === '/storage/store') {
    incrementStat('storageStore');

    if (pruneStorageExpired()) {
      await saveStorageState();
    }

    const request = await bodyJson(req);
    const pubkey = String(request.pubkey ?? '');
    const namespace = Number(request.namespace ?? 0);
    const timestamp = parsePositiveInteger(request.timestamp, nowMs());
    const ttl = parsePositiveInteger(request.ttl, defaultStorageTtlMs, maxStorageTtlMs);
    const data = String(request.data ?? '');
    const idempotencyKey = request.idempotency_key ?? request.idempotencyKey;
    const normalizedIdempotencyKey = idempotencyKey ? String(idempotencyKey) : null;
    const decoded = Buffer.from(data, 'base64');

    if (!pubkey || Number.isNaN(namespace) || !data) {
      json(res, 400, { error: 'invalid-request', message: 'pubkey, namespace, and data are required' });
      return true;
    }

    if (normalizedIdempotencyKey) {
      const existing = messages.find(
        message => message.pubkey === pubkey &&
          message.namespace === namespace &&
          message.idempotencyKey === normalizedIdempotencyKey
      );

      if (existing) {
        json(res, 200, {
          hash: existing.hash,
          idempotent: true,
          swarm: {
            [relayId]: {
              hash: existing.hash,
              signature: 'mock-signature'
            }
          },
          t: existing.timestamp
        });
        return true;
      }
    }

    const hash = sha256(Buffer.concat([Buffer.from(pubkey), decoded]), 'base64url');
    const stored = {
      hash,
      pubkey,
      namespace,
      timestamp,
      expiration: timestamp + ttl,
      data,
      idempotencyKey: normalizedIdempotencyKey
    };
    messages.push(stored);
    await saveStorageState();
    json(res, 200, {
      hash,
      swarm: {
        [relayId]: {
          hash,
          signature: 'mock-signature'
        }
      },
      t: timestamp
    });
    return true;
  }

  if (req.method === 'POST' && url.pathname === '/storage/retrieve') {
    incrementStat('storageRetrieve');

    if (pruneStorageExpired()) {
      await saveStorageState();
    }

    const request = await bodyJson(req);
    const pubkey = String(request.pubkey ?? '');
    const namespace = request.namespace === undefined ? undefined : Number(request.namespace);
    const lastHash = request.last_hash ?? request.lastHash;
    let selected = messages.filter(message => message.pubkey === pubkey);
    if (namespace !== undefined) {
      selected = selected.filter(message => message.namespace === namespace);
    }
    if (lastHash) {
      const index = selected.findIndex(message => message.hash === lastHash);
      selected = index >= 0 ? selected.slice(index + 1) : selected;
    }
    json(res, 200, { messages: selected });
    return true;
  }

  return false;
}

async function handleFile(req, res, url) {
  if (!routeIs('file')) {
    return false;
  }

  if (req.method === 'POST' && url.pathname === '/file') {
    incrementStat('fileUpload');

    if (pruneFileExpired()) {
      await saveFileState();
    }

    const content = await body(req);
    const id = sha256(content, 'base64url');
    const now = nowSeconds();
    files.set(id, {
      id,
      content,
      uploaded: now,
      expires: now + 30 * 24 * 60 * 60
    });
    await saveFileState();
    json(res, 200, { id });
    return true;
  }

  const fileMatch = url.pathname.match(/^\/file\/([^/]+)(?:\/info)?$/);
  if (req.method === 'GET' && fileMatch) {
    if (pruneFileExpired()) {
      await saveFileState();
    }

    const id = fileMatch[1];
    const record = files.get(id);
    if (!record) {
      json(res, 404, { error: 'file-not-found' });
      return true;
    }

    if (url.pathname.endsWith('/info')) {
      incrementStat('fileInfo');
      json(res, 200, {
        size: record.content.length,
        uploaded: record.uploaded,
        expires: record.expires
      });
      return true;
    }

    incrementStat('fileDownload');
    bytes(res, 200, record.content);
    return true;
  }

  return false;
}

async function handlePush(req, res, url) {
  if (!routeIs('push')) {
    return false;
  }

  if (req.method === 'POST' && url.pathname === '/subscribe') {
    incrementStat('pushSubscribe');

    let changed = false;
    if (prunePushExpired()) {
      changed = true;
    }

    const request = await bodyJson(req);
    if (Array.isArray(request)) {
      incrementStat('pushSubscribeBatch');
      const results = request.map(item => {
        const result = processPushSubscribeRequest(item);
        changed = changed || result.changed;
        return result.body;
      });
      if (changed) {
        await savePushState();
      }
      json(res, 200, results);
      return true;
    }

    const result = processPushSubscribeRequest(request);
    changed = changed || result.changed;
    if (changed) {
      await savePushState();
    }
    if (!result.ok) {
      json(res, 400, result.body);
      return true;
    }

    json(res, 200, result.body);
    return true;
  }

  if (req.method === 'GET' && url.pathname.startsWith('/subscriptions/')) {
    incrementStat('subscriptionsList');

    if (prunePushExpired()) {
      await savePushState();
    }

    const pubkey = decodeURIComponent(url.pathname.slice('/subscriptions/'.length));
    const records = [...subscriptions.values()].filter(value => value.pubkey === pubkey);
    json(res, 200, { subscriptions: records });
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
      json(res, 200, { ok: true, service: `deep-${mode}-mock` });
      return;
    }

    if (req.method === 'GET' && url.pathname === '/stats') {
      json(res, 200, {
        service: `deep-${mode}-mock`,
        mode,
        stats,
        inventory: {
          storageMessages: messages.length,
          files: files.size,
          subscriptions: subscriptions.size
        },
        state: {
          dir: stateDir,
          storage: storageStatePath,
          file: fileStatePath,
          push: pushStatePath
        }
      });
      return;
    }

    if (await handleStorage(req, res, url)) {
      return;
    }
    if (await handleFile(req, res, url)) {
      return;
    }
    if (await handlePush(req, res, url)) {
      return;
    }

    notFound(res);
  } catch (error) {
    incrementStat('errors');
    json(res, 500, {
      error: 'mock-service-error',
      message: error instanceof Error ? error.message : String(error)
    });
  }
});

server.listen(port, '0.0.0.0', () => {
  console.log(`deep ${mode} mock listening on ${port}`);
});

