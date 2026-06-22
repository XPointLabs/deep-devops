import { createHash } from 'node:crypto';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { decodeHexOrBase64Bytes, storageSubaccountAccess, verifyStorageSignature } from '../compat-services/storage-signatures.mjs';

const mode = 'storage';
const port = Number(process.env.PORT ?? 8080);
const serviceName = String(process.env.SERVICE_NAME ?? 'deep-storage-service');
const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const stateDir = process.env.COMPAT_STATE_DIR ?? process.env.MOCK_STATE_DIR ?? path.resolve(scriptDir, '..', '..', 'artifacts', 'compat-state');
const storageStatePath = path.join(stateDir, 'storage.json');
const storageSubaccountsStatePath = path.join(stateDir, 'storage-subaccounts.json');
const fileStatePath = path.join(stateDir, 'file.json');
const pushStatePath = path.join(stateDir, 'push.json');
const compatPushNotifyPath = '/_compat/push-notify';
const pushCompatNotifyUrl = String(process.env.PUSH_COMPAT_NOTIFY_URL ?? '');

const messages = await loadJson(storageStatePath, []);
const loadedStorageSubaccountRevocations = await loadJson(storageSubaccountsStatePath, []);
const storageSubaccountRevocations = new Map(
  (Array.isArray(loadedStorageSubaccountRevocations) ? loadedStorageSubaccountRevocations : [])
    .map(record => {
      const pubkey = typeof record?.pubkey === 'string' ? record.pubkey : '';
      const revocations = Array.isArray(record?.revocations)
        ? record.revocations
          .map((entry, index) => ({
            tokenHex: typeof entry?.tokenHex === 'string' && /^[0-9a-f]{72}$/i.test(entry.tokenHex)
              ? entry.tokenHex.toLowerCase()
              : null,
            timestamp: Number(entry?.timestamp ?? 0),
            sequence: Number.isFinite(Number(entry?.sequence)) ? Number(entry.sequence) : index + 1
          }))
          .filter(entry => entry.tokenHex && Number.isFinite(entry.timestamp) && Number.isFinite(entry.sequence))
          .sort((left, right) => left.timestamp === right.timestamp ? left.sequence - right.sequence : left.timestamp - right.timestamp)
        : [];

      return pubkey ? [pubkey, revocations] : null;
    })
    .filter(Boolean)
);
let storageSubaccountRevocationSequence = 0;
for (const revocations of storageSubaccountRevocations.values()) {
  for (const revocation of revocations) {
    storageSubaccountRevocationSequence = Math.max(storageSubaccountRevocationSequence, revocation.sequence);
  }
}

const stats = {
  startedAt: new Date().toISOString(),
  requestsTotal: 0,
  healthChecks: 0,
  storageStore: 0,
  storageRetrieve: 0,
  storageGetExpiries: 0,
  storageSequence: 0,
  storageBatch: 0,
  storageExpireAll: 0,
  storageExpire: 0,
  storageDelete: 0,
  storageDeleteAll: 0,
  storageDeleteBefore: 0,
  storageRevokeSubaccount: 0,
  storageUnrevokeSubaccount: 0,
  storageRevokedSubaccounts: 0,
  errors: 0
};

const relayId = '1111111111111111111111111111111111111111111111111111111111111111';
const defaultStorageTtlMs = 86_400_000;
const maxStorageTtlMs = 30 * 24 * 60 * 60 * 1000;
const storageSignatureToleranceMs = 60_000;
const zeroInventory = Object.freeze({
  files: 0,
  subscriptions: 0,
  pushDeliveries: 0
});

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

function sha256(value, encoding = 'hex') {
  return createHash('sha256').update(value).digest(encoding);
}

function nowMs() {
  return Date.now();
}

function parsePositiveInteger(value, fallback, maxValue) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return fallback;
  }

  const intValue = Math.floor(parsed);
  return maxValue === undefined ? intValue : Math.min(intValue, maxValue);
}

function pruneStorageExpired() {
  const before = messages.length;
  const current = nowMs();
  for (let index = messages.length - 1; index >= 0; index -= 1) {
    if (Number(messages[index].expiration ?? 0) <= current) {
      messages.splice(index, 1);
    }
  }

  return before !== messages.length;
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

async function saveStorageSubaccountState() {
  await saveJson(
    storageSubaccountsStatePath,
    [...storageSubaccountRevocations.entries()]
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([pubkey, revocations]) => ({
        pubkey,
        revocations: revocations.map(revocation => ({
          tokenHex: revocation.tokenHex,
          timestamp: revocation.timestamp,
          sequence: revocation.sequence
        }))
      }))
  );
}

async function emitPushNotification(notification) {
  if (!pushCompatNotifyUrl) {
    return { queued: 0 };
  }

  try {
    const response = await fetch(new URL(compatPushNotifyPath, pushCompatNotifyUrl), {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(notification)
    });
    if (!response.ok) {
      return { queued: 0 };
    }

    return await response.json();
  } catch {
    return { queued: 0 };
  }
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

function storageDeleteAllResponse(deleted) {
  return {
    swarm: {
      [relayId]: {
        deleted,
        signature: 'mock-signature'
      }
    }
  };
}

function storageExpireResponse(expiry, updated, unchanged = undefined) {
  const result = {
    swarm: {
      [relayId]: {
        expiry,
        updated,
        signature: 'mock-signature'
      }
    }
  };

  if (unchanged !== undefined) {
    result.swarm[relayId].unchanged = unchanged;
  }

  return result;
}

function clampStorageExpiry(expiry, currentTimeMs = nowMs()) {
  return Math.min(expiry, currentTimeMs + maxStorageTtlMs);
}

function isPublicInboxNamespace(namespace) {
  return namespace % 10 === 0;
}

function isPublicOutboxNamespace(namespace) {
  return namespace < 0 && (-namespace % 20) === 1;
}

function isNoAuthRetrieveNamespace(namespace) {
  return namespace === -10 || isPublicOutboxNamespace(namespace);
}

function isUnrevocableNamespace(namespace) {
  return namespace < 0 && (-namespace % 100) === 11;
}

function normalizeStorageSubaccountTokens(value, fieldName, maxCount = null) {
  const rawValues = Array.isArray(value)
    ? value
    : value === undefined || value === null || value === ''
      ? []
      : [value];

  if (rawValues.length === 0) {
    return {
      ok: false,
      message: `${fieldName} is required`
    };
  }

  if (maxCount !== null && rawValues.length > maxCount) {
    return {
      ok: false,
      message: `invalid ${fieldName}: cannot revoke more than ${maxCount} subaccounts at once`
    };
  }

  const tokens = [];
  for (const rawValue of rawValues) {
    const decoded = decodeHexOrBase64Bytes(rawValue, 36);
    if (!decoded) {
      return {
        ok: false,
        message: `invalid ${fieldName}: expected base64 or hex-encoded subaccount tag`
      };
    }

    tokens.push({
      tokenHex: decoded.toString('hex'),
      tokenBase64: decoded.toString('base64')
    });
  }

  return {
    ok: true,
    tokens,
    signatureTokens: tokens.map(token => token.tokenBase64)
  };
}

function totalRevokedStorageSubaccounts() {
  let total = 0;
  for (const revocations of storageSubaccountRevocations.values()) {
    total += revocations.length;
  }

  return total;
}

function isStorageSubaccountRevoked(pubkey, tokenHex) {
  return (storageSubaccountRevocations.get(pubkey) ?? []).some(revocation => revocation.tokenHex === tokenHex);
}

function revokeStorageSubaccounts(pubkey, tokens, timestamp) {
  const existing = [...(storageSubaccountRevocations.get(pubkey) ?? [])];
  let count = 0;
  let changed = false;

  for (const token of tokens) {
    const existingIndex = existing.findIndex(entry => entry.tokenHex === token.tokenHex);
    if (existingIndex >= 0) {
      if (timestamp > existing[existingIndex].timestamp) {
        existing[existingIndex] = {
          ...existing[existingIndex],
          timestamp,
          sequence: ++storageSubaccountRevocationSequence
        };
        changed = true;
      }
      continue;
    }

    existing.push({
      tokenHex: token.tokenHex,
      timestamp,
      sequence: ++storageSubaccountRevocationSequence
    });
    count += 1;
    changed = true;
  }

  existing.sort((left, right) => left.timestamp === right.timestamp ? left.sequence - right.sequence : left.timestamp - right.timestamp);
  while (existing.length > 50) {
    existing.shift();
    changed = true;
  }

  if (existing.length > 0) {
    storageSubaccountRevocations.set(pubkey, existing);
  } else {
    storageSubaccountRevocations.delete(pubkey);
  }

  return { count, changed };
}

function unrevokeStorageSubaccounts(pubkey, tokens) {
  const existing = storageSubaccountRevocations.get(pubkey) ?? [];
  if (existing.length === 0) {
    return { count: 0, changed: false };
  }

  const tokenSet = new Set(tokens.map(token => token.tokenHex));
  const remaining = existing.filter(entry => !tokenSet.has(entry.tokenHex));
  const count = existing.length - remaining.length;

  if (remaining.length > 0) {
    storageSubaccountRevocations.set(pubkey, remaining);
  } else {
    storageSubaccountRevocations.delete(pubkey);
  }

  return { count, changed: count > 0 };
}

function getRevokedStorageSubaccounts(pubkey) {
  return (storageSubaccountRevocations.get(pubkey) ?? []).map(entry => Buffer.from(entry.tokenHex, 'hex').toString('base64'));
}

async function rejectRevokedStorageSubaccount(res, { pubkey, verification, message, skipRevokeCheck = false, saveState = null }) {
  if (!verification?.usingSubaccount || !verification?.subaccount?.tokenHex || skipRevokeCheck) {
    return false;
  }

  if (!isStorageSubaccountRevoked(pubkey, verification.subaccount.tokenHex)) {
    return false;
  }

  if (typeof saveState === 'function') {
    await saveState();
  }

  json(res, 401, {
    error: 'unauthorized',
    message
  });
  return true;
}

const storagePipelineMethods = new Set([
  'store',
  'retrieve',
  'get_expiries',
  'revoke_subaccount',
  'unrevoke_subaccount',
  'revoked_subaccounts',
  'expire_all',
  'expire',
  'delete',
  'delete_all',
  'delete_before'
]);

function createSyntheticJsonRequest(pathname, value) {
  return Object.assign([Buffer.from(JSON.stringify(value ?? {}))], {
    method: 'POST',
    url: pathname,
    headers: {
      host: 'localhost'
    }
  });
}

function createCapturedResponse() {
  let status = 200;
  let headers = {};
  const chunks = [];

  return {
    writeHead(nextStatus, nextHeaders = {}) {
      status = nextStatus;
      headers = { ...nextHeaders };
    },
    end(chunk) {
      if (chunk !== undefined) {
        chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk)));
      }
    },
    result() {
      const raw = Buffer.concat(chunks);
      if (raw.length === 0) {
        return { status, headers, body: null };
      }

      const text = raw.toString('utf8');
      try {
        return { status, headers, body: JSON.parse(text) };
      } catch {
        return { status, headers, body: text };
      }
    }
  };
}

function storagePipelinePath(method) {
  return storagePipelineMethods.has(method) ? `/storage/${method}` : null;
}

async function runStoragePipelineRequest(method, params) {
  const pathname = storagePipelinePath(method);
  if (!pathname) {
    return {
      status: 400,
      body: {
        error: 'invalid-request',
        message: `unsupported storage pipeline method: ${method}`
      }
    };
  }

  const syntheticReq = createSyntheticJsonRequest(pathname, params);
  const syntheticRes = createCapturedResponse();
  await handleStorage(syntheticReq, syntheticRes, pathOf(syntheticReq));
  return syntheticRes.result();
}

async function executeStoragePipeline(requests, stopOnError) {
  const results = [];

  for (const request of requests) {
    const method = String(request?.method ?? '');
    const params = request?.params && typeof request.params === 'object' && !Array.isArray(request.params)
      ? request.params
      : {};
    const result = await runStoragePipelineRequest(method, params);

    results.push({
      code: result.status,
      body: result.status >= 400 && result.body && typeof result.body === 'object' && typeof result.body.message === 'string'
        ? result.body.message
        : result.body
    });

    if (stopOnError && result.status >= 400) {
      break;
    }
  }

  return { results };
}

function resolveStorageExpireTargets(requestedMessages, expiryInput) {
  if (Number.isFinite(Number(expiryInput))) {
    return {
      byHash: new Map(requestedMessages.map(hash => [hash, clampStorageExpiry(Number(expiryInput))])),
      isMulti: false
    };
  }

  if (!Array.isArray(expiryInput) || expiryInput.length !== requestedMessages.length) {
    return null;
  }

  const byHash = new Map();
  for (let index = 0; index < requestedMessages.length; index += 1) {
    const expiry = Number(expiryInput[index]);
    if (!Number.isFinite(expiry)) {
      return null;
    }

    byHash.set(requestedMessages[index], clampStorageExpiry(expiry));
  }

  return { byHash, isMulti: true };
}

function normalizeDeleteAllNamespace(value) {
  if (value === undefined || value === null || value === '') {
    return 0;
  }

  if (typeof value === 'string' && value.toLowerCase() === 'all') {
    return 'all';
  }

  const parsed = Number(value);
  return Number.isNaN(parsed) ? null : parsed;
}

async function handleStorage(req, res, url) {
  if (req.method === 'POST' && url.pathname === '/storage/store') {
    incrementStat('storageStore');

    if (pruneStorageExpired()) {
      await saveStorageState();
    }

    const request = await bodyJson(req);
    const pubkey = String(request.pubkey ?? '');
    const namespace = Number(request.namespace ?? 0);
    const signature = String(request.signature ?? '');
    const timestamp = parsePositiveInteger(request.timestamp, nowMs());
    const signatureTimestamp = parsePositiveInteger(request.sig_timestamp ?? request.sigTimestamp, timestamp);
    const ttl = parsePositiveInteger(request.ttl, defaultStorageTtlMs, maxStorageTtlMs);
    const data = String(request.data ?? '');
    const idempotencyKey = request.idempotency_key ?? request.idempotencyKey;
    const normalizedIdempotencyKey = idempotencyKey ? String(idempotencyKey) : null;
    const decoded = Buffer.from(data, 'base64');

    if (!pubkey || Number.isNaN(namespace) || !data) {
      json(res, 400, { error: 'invalid-request', message: 'pubkey, namespace, and data are required' });
      return true;
    }

    if (namespace < -32768 || namespace > 32767) {
      json(res, 400, {
        error: 'invalid-request',
        message: "invalid request: Invalid value given for 'namespace': value out of range"
      });
      return true;
    }

    if (!isPublicInboxNamespace(namespace) && !signature) {
      json(res, 401, {
        error: 'unauthorized',
        message: `store: signature required to store to namespace ${namespace}`
      });
      return true;
    }

    if (!isPublicInboxNamespace(namespace) &&
      (signatureTimestamp < nowMs() - storageSignatureToleranceMs || signatureTimestamp > nowMs() + storageSignatureToleranceMs)) {
      json(res, 406, {
        error: 'not-acceptable',
        message: 'store signature timestamp too far from current time'
      });
      return true;
    }

    if (!isPublicInboxNamespace(namespace)) {
      const verification = verifyStorageSignature({
        operation: 'store',
        pubkey,
        pubkeyEd25519: request.pubkey_ed25519,
        signature,
        subaccount: request.subaccount,
        subaccountSig: request.subaccount_sig ?? request.subaccountSig,
        requiredSubaccountAccess: isPublicOutboxNamespace(namespace)
          ? storageSubaccountAccess.WRITE | storageSubaccountAccess.DELETE
          : storageSubaccountAccess.WRITE,
        namespace,
        timestamp: signatureTimestamp
      });
      if (verification.checked && !verification.verified) {
        json(res, 401, {
          error: 'unauthorized',
          message: 'store signature verification failed'
        });
        return true;
      }

      if (await rejectRevokedStorageSubaccount(res, {
        pubkey,
        verification,
        message: 'store signature verification failed'
      })) {
        return true;
      }
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
    await emitPushNotification(stored);
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
    const signature = String(request.signature ?? '');
    const hasTimestamp = request.timestamp !== undefined;
    const lastHash = request.last_hash ?? request.lastHash;

    if (hasTimestamp && !signature) {
      json(res, 400, {
        error: 'invalid-request',
        message: "invalid request: Required field 'signature' missing"
      });
      return true;
    }

    if (!signature && (namespace === undefined || !isNoAuthRetrieveNamespace(namespace))) {
      json(res, 401, {
        error: 'unauthorized',
        message: 'retrieve: request signature required'
      });
      return true;
    }

    if (signature && hasTimestamp) {
      const timestamp = Number(request.timestamp);
      const current = nowMs();
      if (!Number.isFinite(timestamp) ||
        timestamp < current - storageSignatureToleranceMs ||
        timestamp > current + storageSignatureToleranceMs) {
        json(res, 406, {
          error: 'not-acceptable',
          message: 'retrieve timestamp too far from current time'
        });
        return true;
      }

      const verification = verifyStorageSignature({
        operation: 'retrieve',
        pubkey,
        pubkeyEd25519: request.pubkey_ed25519,
        signature,
        subaccount: request.subaccount,
        subaccountSig: request.subaccount_sig ?? request.subaccountSig,
        requiredSubaccountAccess: storageSubaccountAccess.READ,
        namespace,
        timestamp
      });
      if (verification.checked && !verification.verified) {
        json(res, 401, {
          error: 'unauthorized',
          message: 'retrieve signature verification failed'
        });
        return true;
      }

      if (await rejectRevokedStorageSubaccount(res, {
        pubkey,
        verification,
        message: 'retrieve signature verification failed',
        skipRevokeCheck: namespace !== undefined && isUnrevocableNamespace(namespace)
      })) {
        return true;
      }
    }

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

  if (req.method === 'POST' && url.pathname === '/storage/get_expiries') {
    incrementStat('storageGetExpiries');

    if (pruneStorageExpired()) {
      await saveStorageState();
    }

    const request = await bodyJson(req);
    const pubkey = String(request.pubkey ?? '');
    const signature = String(request.signature ?? '');
    const timestamp = Number(request.timestamp);
    const requestedMessages = Array.isArray(request.messages)
      ? request.messages.map(value => String(value)).filter(Boolean)
      : null;

    if (!pubkey || !signature || !Number.isFinite(timestamp) || !requestedMessages || requestedMessages.length === 0) {
      json(res, 400, {
        error: 'invalid-request',
        message: 'pubkey, messages, timestamp, and signature are required'
      });
      return true;
    }

    const current = nowMs();
    if (timestamp < current - storageSignatureToleranceMs || timestamp > current + storageSignatureToleranceMs) {
      json(res, 406, {
        error: 'not-acceptable',
        message: 'get_expiries timestamp too far from current time'
      });
      return true;
    }

    const verification = verifyStorageSignature({
      operation: 'get_expiries',
      pubkey,
      pubkeyEd25519: request.pubkey_ed25519,
      signature,
      subaccount: request.subaccount,
      subaccountSig: request.subaccount_sig ?? request.subaccountSig,
      requiredSubaccountAccess: storageSubaccountAccess.READ,
      timestamp,
      messages: requestedMessages
    });
    if (verification.checked && !verification.verified) {
      json(res, 401, {
        error: 'unauthorized',
        message: 'get_expiries signature verification failed'
      });
      return true;
    }

    if (await rejectRevokedStorageSubaccount(res, {
      pubkey,
      verification,
      message: 'get_expiries signature verification failed'
    })) {
      return true;
    }

    const requestedSet = new Set(requestedMessages);
    const expiries = Object.fromEntries(
      messages
        .filter(message => message.pubkey === pubkey && requestedSet.has(message.hash))
        .map(message => [message.hash, message.expiration])
    );

    json(res, 200, { expiries });
    return true;
  }

  if (req.method === 'POST' && url.pathname === '/storage/revoke_subaccount') {
    incrementStat('storageRevokeSubaccount');

    const request = await bodyJson(req);
    const pubkey = String(request.pubkey ?? '');
    const signature = String(request.signature ?? '');
    const timestamp = Number(request.timestamp);
    const revoke = normalizeStorageSubaccountTokens(request.revoke, 'revoke', 50);

    if (!pubkey || !signature || !Number.isFinite(timestamp) || !revoke.ok) {
      json(res, 400, {
        error: 'invalid-request',
        message: !revoke.ok && pubkey && signature && Number.isFinite(timestamp)
          ? revoke.message
          : 'pubkey, revoke, timestamp, and signature are required'
      });
      return true;
    }

    const current = nowMs();
    if (timestamp < current - storageSignatureToleranceMs || timestamp > current + storageSignatureToleranceMs) {
      json(res, 406, {
        error: 'not-acceptable',
        message: 'revoke_subaccount timestamp too far from current time'
      });
      return true;
    }

    const verification = verifyStorageSignature({
      operation: 'revoke_subaccount',
      pubkey,
      pubkeyEd25519: request.pubkey_ed25519,
      signature,
      timestamp,
      subaccounts: revoke.signatureTokens
    });
    if (verification.checked && !verification.verified) {
      json(res, 401, {
        error: 'unauthorized',
        message: 'revoke_subaccount signature verification failed'
      });
      return true;
    }

    const result = revokeStorageSubaccounts(pubkey, revoke.tokens, timestamp);
    if (result.changed) {
      await saveStorageSubaccountState();
    }

    json(res, 200, {
      swarm: {
        [relayId]: {
          count: result.count,
          signature: 'mock-signature'
        }
      }
    });
    return true;
  }

  if (req.method === 'POST' && url.pathname === '/storage/unrevoke_subaccount') {
    incrementStat('storageUnrevokeSubaccount');

    const request = await bodyJson(req);
    const pubkey = String(request.pubkey ?? '');
    const signature = String(request.signature ?? '');
    const timestamp = Number(request.timestamp);
    const unrevoke = normalizeStorageSubaccountTokens(request.unrevoke, 'unrevoke');

    if (!pubkey || !signature || !Number.isFinite(timestamp) || !unrevoke.ok) {
      json(res, 400, {
        error: 'invalid-request',
        message: !unrevoke.ok && pubkey && signature && Number.isFinite(timestamp)
          ? unrevoke.message
          : 'pubkey, unrevoke, timestamp, and signature are required'
      });
      return true;
    }

    const current = nowMs();
    if (timestamp < current - storageSignatureToleranceMs || timestamp > current + storageSignatureToleranceMs) {
      json(res, 406, {
        error: 'not-acceptable',
        message: 'unrevoke_subaccount timestamp too far from current time'
      });
      return true;
    }

    const verification = verifyStorageSignature({
      operation: 'unrevoke_subaccount',
      pubkey,
      pubkeyEd25519: request.pubkey_ed25519,
      signature,
      timestamp,
      subaccounts: unrevoke.signatureTokens
    });
    if (verification.checked && !verification.verified) {
      json(res, 401, {
        error: 'unauthorized',
        message: 'unrevoke_subaccount signature verification failed'
      });
      return true;
    }

    const result = unrevokeStorageSubaccounts(pubkey, unrevoke.tokens);
    if (result.changed) {
      await saveStorageSubaccountState();
    }

    json(res, 200, {
      swarm: {
        [relayId]: {
          count: result.count,
          signature: 'mock-signature'
        }
      }
    });
    return true;
  }

  if (req.method === 'POST' && url.pathname === '/storage/revoked_subaccounts') {
    incrementStat('storageRevokedSubaccounts');

    const request = await bodyJson(req);
    const pubkey = String(request.pubkey ?? '');
    const signature = String(request.signature ?? '');
    const timestamp = Number(request.timestamp);

    if (!pubkey || !signature || !Number.isFinite(timestamp)) {
      json(res, 400, {
        error: 'invalid-request',
        message: 'pubkey, timestamp, and signature are required'
      });
      return true;
    }

    const current = nowMs();
    if (timestamp < current - storageSignatureToleranceMs || timestamp > current + storageSignatureToleranceMs) {
      json(res, 406, {
        error: 'not-acceptable',
        message: 'revoked_subaccounts timestamp too far from current time'
      });
      return true;
    }

    const verification = verifyStorageSignature({
      operation: 'revoked_subaccounts',
      pubkey,
      pubkeyEd25519: request.pubkey_ed25519,
      signature,
      timestamp
    });
    if (verification.checked && !verification.verified) {
      json(res, 401, {
        error: 'unauthorized',
        message: 'revoked_subaccounts signature verification failed'
      });
      return true;
    }

    json(res, 200, {
      revoked_subaccounts: getRevokedStorageSubaccounts(pubkey)
    });
    return true;
  }

  if (req.method === 'POST' && (url.pathname === '/storage/sequence' || url.pathname === '/storage/batch')) {
    incrementStat(url.pathname === '/storage/sequence' ? 'storageSequence' : 'storageBatch');

    const request = await bodyJson(req);
    const requests = Array.isArray(request.requests) ? request.requests : null;
    if (!requests) {
      json(res, 400, {
        error: 'invalid-request',
        message: 'requests array is required'
      });
      return true;
    }

    json(res, 200, await executeStoragePipeline(requests, url.pathname === '/storage/sequence'));
    return true;
  }

  if (req.method === 'POST' && url.pathname === '/storage/expire_all') {
    incrementStat('storageExpireAll');

    let stateChanged = false;
    if (pruneStorageExpired()) {
      stateChanged = true;
    }

    const request = await bodyJson(req);
    const pubkey = String(request.pubkey ?? '');
    const signature = String(request.signature ?? '');
    const expiry = Number(request.expiry);

    if (!pubkey || !signature || !Number.isFinite(expiry)) {
      if (stateChanged) {
        await saveStorageState();
      }
      json(res, 400, {
        error: 'invalid-request',
        message: 'pubkey, expiry, and signature are required'
      });
      return true;
    }

    if (expiry < nowMs()) {
      if (stateChanged) {
        await saveStorageState();
      }
      json(res, 406, {
        error: 'not-acceptable',
        message: 'expire_all timestamp should be >= current time'
      });
      return true;
    }

    const verification = verifyStorageSignature({
      operation: 'expire_all',
      pubkey,
      pubkeyEd25519: request.pubkey_ed25519,
      signature,
      subaccount: request.subaccount,
      subaccountSig: request.subaccount_sig ?? request.subaccountSig,
      requiredSubaccountAccess: storageSubaccountAccess.DELETE,
      namespace: request.namespace,
      expiry
    });
    if (verification.checked && !verification.verified) {
      if (stateChanged) {
        await saveStorageState();
      }
      json(res, 401, {
        error: 'unauthorized',
        message: 'expire_all signature verification failed'
      });
      return true;
    }

    if (await rejectRevokedStorageSubaccount(res, {
      pubkey,
      verification,
      message: 'expire_all signature verification failed',
      saveState: stateChanged ? saveStorageState : null
    })) {
      return true;
    }

    const updated = [];
    for (const message of messages) {
      if (message.pubkey !== pubkey || Number(message.expiration) <= expiry) {
        continue;
      }

      message.expiration = expiry;
      updated.push(message.hash);
      stateChanged = true;
    }

    updated.sort();
    if (stateChanged) {
      await saveStorageState();
    }

    json(res, 200, storageExpireResponse(expiry, updated));
    return true;
  }

  if (req.method === 'POST' && url.pathname === '/storage/expire') {
    incrementStat('storageExpire');

    let stateChanged = false;
    if (pruneStorageExpired()) {
      stateChanged = true;
    }

    const request = await bodyJson(req);
    const pubkey = String(request.pubkey ?? '');
    const signature = String(request.signature ?? '');
    const requestedMessages = Array.isArray(request.messages)
      ? request.messages.map(value => String(value)).filter(Boolean)
      : null;
    const expireTargets = requestedMessages ? resolveStorageExpireTargets(requestedMessages, request.expiry) : null;
    const shorten = request.shorten === true;
    const extend = request.extend === true;

    if (!pubkey || !signature || !requestedMessages || requestedMessages.length === 0 || !expireTargets) {
      if (stateChanged) {
        await saveStorageState();
      }
      json(res, 400, {
        error: 'invalid-request',
        message: 'pubkey, messages, expiry, and signature are required'
      });
      return true;
    }

    if (shorten && extend) {
      if (stateChanged) {
        await saveStorageState();
      }
      json(res, 400, {
        error: 'invalid-request',
        message: 'extend and shorten are mutually exclusive'
      });
      return true;
    }

    const verification = verifyStorageSignature({
      operation: 'expire',
      pubkey,
      pubkeyEd25519: request.pubkey_ed25519,
      signature,
      subaccount: request.subaccount,
      subaccountSig: request.subaccount_sig ?? request.subaccountSig,
      requiredSubaccountAccess: storageSubaccountAccess.WRITE,
      mode: shorten ? 'shorten' : extend ? 'extend' : '',
      expiry: request.expiry,
      messages: requestedMessages
    });
    if (verification.checked && !verification.verified) {
      if (stateChanged) {
        await saveStorageState();
      }
      json(res, 401, {
        error: 'unauthorized',
        message: 'expire: signature verification failed'
      });
      return true;
    }

    if (await rejectRevokedStorageSubaccount(res, {
      pubkey,
      verification,
      message: 'expire: signature verification failed',
      saveState: stateChanged ? saveStorageState : null
    })) {
      return true;
    }

    let extendOnly = extend;
    if (verification.usingSubaccount && !verification.subaccount?.hasDelete) {
      if (shorten) {
        if (stateChanged) {
          await saveStorageState();
        }
        json(res, 400, {
          error: 'invalid-request',
          message: 'expire: shorten parameter cannot be used with this subaccount token (missing delete access)'
        });
        return true;
      }

      if (!extend) {
        extendOnly = true;
      }
    }

    const requestedSet = new Set(requestedMessages);
    const updated = [];
    const updatedExpiries = [];
    const unchanged = {};

    for (const message of messages) {
      if (message.pubkey !== pubkey || !requestedSet.has(message.hash)) {
        continue;
      }

      const currentExpiry = Number(message.expiration);
      const effectiveExpiry = expireTargets.byHash.get(message.hash);
      const shouldUpdate = shorten
        ? currentExpiry > effectiveExpiry
        : extendOnly
          ? currentExpiry < effectiveExpiry
          : currentExpiry !== effectiveExpiry;

      if (!shouldUpdate) {
        if (shorten || extend) {
          unchanged[message.hash] = currentExpiry;
        }
        continue;
      }

      message.expiration = effectiveExpiry;
      updated.push({ hash: message.hash, expiry: effectiveExpiry });
      stateChanged = true;
    }

    updated.sort((left, right) => left.hash.localeCompare(right.hash));
    const updatedHashes = updated.map(item => item.hash);
    for (const item of updated) {
      updatedExpiries.push(item.expiry);
    }

    if (stateChanged) {
      await saveStorageState();
    }

    json(
      res,
      200,
      storageExpireResponse(
        expireTargets.isMulti ? updatedExpiries : (updatedExpiries[0] ?? expireTargets.byHash.values().next().value),
        updatedHashes,
        shorten || extend ? unchanged : undefined
      )
    );
    return true;
  }

  if (req.method === 'POST' && url.pathname === '/storage/delete') {
    incrementStat('storageDelete');

    let stateChanged = false;
    if (pruneStorageExpired()) {
      stateChanged = true;
    }

    const request = await bodyJson(req);
    const pubkey = String(request.pubkey ?? '');
    const signature = String(request.signature ?? '');
    const requestedMessages = Array.isArray(request.messages)
      ? request.messages.map(value => String(value)).filter(Boolean)
      : null;
    const required = request.required === true;

    if (!pubkey || !signature || !requestedMessages || requestedMessages.length === 0) {
      if (stateChanged) {
        await saveStorageState();
      }
      json(res, 400, {
        error: 'invalid-request',
        message: 'pubkey, messages, and signature are required'
      });
      return true;
    }

    const verification = verifyStorageSignature({
      operation: 'delete',
      pubkey,
      pubkeyEd25519: request.pubkey_ed25519,
      signature,
      subaccount: request.subaccount,
      subaccountSig: request.subaccount_sig ?? request.subaccountSig,
      requiredSubaccountAccess: storageSubaccountAccess.DELETE,
      messages: requestedMessages
    });
    if (verification.checked && !verification.verified) {
      if (stateChanged) {
        await saveStorageState();
      }
      json(res, 401, {
        error: 'unauthorized',
        message: 'delete_msgs signature verification failed'
      });
      return true;
    }

    if (await rejectRevokedStorageSubaccount(res, {
      pubkey,
      verification,
      message: 'delete_msgs signature verification failed',
      saveState: stateChanged ? saveStorageState : null
    })) {
      return true;
    }

    const requestedSet = new Set(requestedMessages);
    const deleted = [];
    const remaining = [];
    for (const message of messages) {
      if (message.pubkey === pubkey && requestedSet.has(message.hash)) {
        deleted.push(message.hash);
        continue;
      }

      remaining.push(message);
    }

    deleted.sort();
    if (deleted.length > 0) {
      messages.splice(0, messages.length, ...remaining);
      stateChanged = true;
    }

    if (stateChanged) {
      await saveStorageState();
    }

    const response = storageDeleteAllResponse(deleted);
    if (required && deleted.length === 0) {
      json(res, 404, {
        error: 'not-found',
        message: 'required deletion did not remove any messages',
        ...response
      });
      return true;
    }

    json(res, 200, response);
    return true;
  }

  if (req.method === 'POST' && url.pathname === '/storage/delete_all') {
    incrementStat('storageDeleteAll');

    let stateChanged = false;
    if (pruneStorageExpired()) {
      stateChanged = true;
    }

    const request = await bodyJson(req);
    const pubkey = String(request.pubkey ?? '');
    const signature = String(request.signature ?? '');
    const timestamp = Number(request.timestamp);
    const namespace = normalizeDeleteAllNamespace(request.namespace);

    if (!pubkey || !signature || !Number.isFinite(timestamp)) {
      if (stateChanged) {
        await saveStorageState();
      }
      json(res, 400, {
        error: 'invalid-request',
        message: 'pubkey, timestamp, and signature are required'
      });
      return true;
    }

    if (namespace === null) {
      if (stateChanged) {
        await saveStorageState();
      }
      json(res, 400, {
        error: 'invalid-request',
        message: 'namespace must be an integer or "all"'
      });
      return true;
    }

    const current = nowMs();
    if (timestamp < current - storageSignatureToleranceMs || timestamp > current + storageSignatureToleranceMs) {
      if (stateChanged) {
        await saveStorageState();
      }
      json(res, 406, {
        error: 'not-acceptable',
        message: 'delete_all timestamp too far from current time'
      });
      return true;
    }

    const verification = verifyStorageSignature({
      operation: 'delete_all',
      pubkey,
      pubkeyEd25519: request.pubkey_ed25519,
      signature,
      subaccount: request.subaccount,
      subaccountSig: request.subaccount_sig ?? request.subaccountSig,
      requiredSubaccountAccess: storageSubaccountAccess.DELETE,
      namespace,
      timestamp
    });
    if (verification.checked && !verification.verified) {
      if (stateChanged) {
        await saveStorageState();
      }
      json(res, 401, {
        error: 'unauthorized',
        message: 'delete_all signature verification failed'
      });
      return true;
    }

    if (await rejectRevokedStorageSubaccount(res, {
      pubkey,
      verification,
      message: 'delete_all signature verification failed',
      saveState: stateChanged ? saveStorageState : null
    })) {
      return true;
    }

    const remaining = [];
    const deletedByNamespace = new Map();
    for (const message of messages) {
      if (message.pubkey !== pubkey) {
        remaining.push(message);
        continue;
      }

      if (namespace !== 'all' && message.namespace !== namespace) {
        remaining.push(message);
        continue;
      }

      const namespaceKey = String(message.namespace);
      if (!deletedByNamespace.has(namespaceKey)) {
        deletedByNamespace.set(namespaceKey, []);
      }
      deletedByNamespace.get(namespaceKey).push(message.hash);
    }

    for (const hashes of deletedByNamespace.values()) {
      hashes.sort();
    }

    if (deletedByNamespace.size > 0) {
      messages.splice(0, messages.length, ...remaining);
      stateChanged = true;
    }

    if (stateChanged) {
      await saveStorageState();
    }

    if (namespace === 'all') {
      const deleted = Object.fromEntries([...deletedByNamespace.entries()].sort(([left], [right]) => left.localeCompare(right)));
      json(res, 200, storageDeleteAllResponse(deleted));
      return true;
    }

    const deleted = deletedByNamespace.get(String(namespace)) ?? [];
    json(res, 200, storageDeleteAllResponse(deleted));
    return true;
  }

  if (req.method === 'POST' && url.pathname === '/storage/delete_before') {
    incrementStat('storageDeleteBefore');

    let stateChanged = false;
    if (pruneStorageExpired()) {
      stateChanged = true;
    }

    const request = await bodyJson(req);
    const pubkey = String(request.pubkey ?? '');
    const signature = String(request.signature ?? '');
    const before = Number(request.before);
    const namespace = normalizeDeleteAllNamespace(request.namespace);

    if (!pubkey || !signature || !Number.isFinite(before)) {
      if (stateChanged) {
        await saveStorageState();
      }
      json(res, 400, {
        error: 'invalid-request',
        message: 'pubkey, before, and signature are required'
      });
      return true;
    }

    if (namespace === null) {
      if (stateChanged) {
        await saveStorageState();
      }
      json(res, 400, {
        error: 'invalid-request',
        message: 'namespace must be an integer or "all"'
      });
      return true;
    }

    if (before > nowMs() + storageSignatureToleranceMs) {
      if (stateChanged) {
        await saveStorageState();
      }
      json(res, 401, {
        error: 'unauthorized',
        message: 'delete_before timestamp too far in the future'
      });
      return true;
    }

    const verification = verifyStorageSignature({
      operation: 'delete_before',
      pubkey,
      pubkeyEd25519: request.pubkey_ed25519,
      signature,
      subaccount: request.subaccount,
      subaccountSig: request.subaccount_sig ?? request.subaccountSig,
      requiredSubaccountAccess: storageSubaccountAccess.DELETE,
      namespace,
      before
    });
    if (verification.checked && !verification.verified) {
      if (stateChanged) {
        await saveStorageState();
      }
      json(res, 401, {
        error: 'unauthorized',
        message: 'delete_before signature verification failed'
      });
      return true;
    }

    if (await rejectRevokedStorageSubaccount(res, {
      pubkey,
      verification,
      message: 'delete_before signature verification failed',
      saveState: stateChanged ? saveStorageState : null
    })) {
      return true;
    }

    const remaining = [];
    const deletedByNamespace = new Map();
    for (const message of messages) {
      const matchesPubkey = message.pubkey === pubkey;
      const matchesNamespace = namespace === 'all' || message.namespace === namespace;
      const matchesBefore = Number(message.timestamp) <= before;
      if (matchesPubkey && matchesNamespace && matchesBefore) {
        const namespaceKey = String(message.namespace);
        if (!deletedByNamespace.has(namespaceKey)) {
          deletedByNamespace.set(namespaceKey, []);
        }
        deletedByNamespace.get(namespaceKey).push(message.hash);
        continue;
      }

      remaining.push(message);
    }

    for (const hashes of deletedByNamespace.values()) {
      hashes.sort();
    }

    if (deletedByNamespace.size > 0) {
      messages.splice(0, messages.length, ...remaining);
      stateChanged = true;
    }

    if (stateChanged) {
      await saveStorageState();
    }

    if (namespace === 'all') {
      const deleted = Object.fromEntries([...deletedByNamespace.entries()].sort(([left], [right]) => left.localeCompare(right)));
      json(res, 200, storageDeleteAllResponse(deleted));
      return true;
    }

    const deleted = deletedByNamespace.get(String(namespace)) ?? [];
    json(res, 200, storageDeleteAllResponse(deleted));
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
          storageMessages: messages.length,
          revokedSubaccounts: totalRevokedStorageSubaccounts(),
          ...zeroInventory
        },
        state: {
          dir: stateDir,
          storage: storageStatePath,
          storageSubaccounts: storageSubaccountsStatePath,
          file: fileStatePath,
          push: pushStatePath
        }
      });
      return;
    }

    if (await handleStorage(req, res, url)) {
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