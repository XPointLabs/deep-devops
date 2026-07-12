import { createHash } from 'node:crypto';
import http from 'node:http';
import { createPrivateKey, sign } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { appendFile, mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { decodeHexOrBase64Bytes, storageSubaccountAccess, verifyStorageSignature } from '../compat-services/storage-signatures.mjs';

const mode = 'storage';
const port = Number(process.env.PORT ?? 8080);
const serviceName = String(process.env.SERVICE_NAME ?? 'deep-storage-service');
const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const stateDir = process.env.COMPAT_STATE_DIR ?? process.env.MOCK_STATE_DIR ?? path.resolve(scriptDir, '..', '..', 'artifacts', 'compat-state');
const storageStatePath = path.join(stateDir, 'storage.json');
const storageJournalPath = path.join(stateDir, 'storage.journal.ndjson');
const storageSubaccountsStatePath = path.join(stateDir, 'storage-subaccounts.json');
const fileStatePath = path.join(stateDir, 'file.json');
const pushStatePath = path.join(stateDir, 'push.json');
const compatPushNotifyPath = '/_compat/push-notify';
const pushCompatNotifyUrl = String(process.env.PUSH_COMPAT_NOTIFY_URL ?? '');
const pushNotifyNodeId = String(process.env.PUSH_COMPAT_NOTIFY_NODE_ID ?? '').trim().toLowerCase();
const pushNotifyPrivateKeyFile = String(process.env.PUSH_COMPAT_NOTIFY_ED25519_PRIVATE_KEY_FILE ?? '').trim();
const pushNotifyBearerTokenFile = String(process.env.PUSH_COMPAT_NOTIFY_BEARER_TOKEN_FILE ?? '').trim();
const pushNotifySigner = await loadPushNotifySigner();

const maxStorageRequestBytes = parsePositiveInteger(process.env.STORAGE_MAX_REQUEST_BYTES, 256 * 1024, 4 * 1024 * 1024);
const maxStorageMessageBytes = parsePositiveInteger(process.env.STORAGE_MAX_MESSAGE_BYTES, 64 * 1024, maxStorageRequestBytes);
const maxStorageMessagesPerAccount = parsePositiveInteger(process.env.STORAGE_MAX_MESSAGES_PER_ACCOUNT, 10_000, 1_000_000);
const maxStorageBytesPerAccount = parsePositiveInteger(process.env.STORAGE_MAX_BYTES_PER_ACCOUNT, 256 * 1024 * 1024, 4 * 1024 * 1024 * 1024);
const maxStorageMessages = parsePositiveInteger(process.env.STORAGE_MAX_MESSAGES, 100_000, 2_000_000);
const maxStorageBytes = parsePositiveInteger(process.env.STORAGE_MAX_BYTES, 2 * 1024 * 1024 * 1024, 16 * 1024 * 1024 * 1024);
const storageRetrievePageSize = parsePositiveInteger(process.env.STORAGE_RETRIEVE_PAGE_SIZE, 100, 1_000);
const maxStorageRetrievePageBytes = parsePositiveInteger(process.env.STORAGE_MAX_RETRIEVE_PAGE_BYTES, 1024 * 1024, 8 * 1024 * 1024);
const maxStorageMutationHashes = parsePositiveInteger(process.env.STORAGE_MAX_MUTATION_HASHES, 1_000, 10_000);
const maxStoragePipelineRequests = parsePositiveInteger(process.env.STORAGE_MAX_PIPELINE_REQUESTS, 20, 100);
const storageRateLimitPerMinute = parsePositiveInteger(process.env.STORAGE_RATE_LIMIT_PER_MINUTE, 600, 100_000);
const maxStorageRateLimitClients = parsePositiveInteger(process.env.STORAGE_RATE_LIMIT_MAX_CLIENTS, 10_000, 100_000);
const storageSnapshotEveryMutations = parsePositiveInteger(process.env.STORAGE_SNAPSHOT_EVERY_MUTATIONS, 100, 10_000);

const storageMessageIds = new WeakMap();
const persistedStorageMessages = new Map();
const storageRateLimitClients = new Map();
let storageMessageSequence = 0;
let storagePersistQueue = Promise.resolve();
let storageMutationCount = 0;

const messages = await loadStorageSnapshot();
await replayStorageJournal(messages);
refreshPersistedStorageMessages();
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

async function loadStorageSnapshot() {
  const persisted = await loadJson(storageStatePath, []);
  if (Array.isArray(persisted)) {
    return persisted.map((message, index) => {
      setStorageMessageId(message, `legacy-${index + 1}`);
      return message;
    });
  }

  if (!persisted || persisted.version !== 1 || !Array.isArray(persisted.messages)) {
    throw new Error('storage snapshot has an unsupported format');
  }

  return persisted.messages
    .filter(entry => entry && typeof entry === 'object' && typeof entry.id === 'string' && entry.message && typeof entry.message === 'object')
    .map(entry => {
      setStorageMessageId(entry.message, entry.id);
      return entry.message;
    });
}

async function replayStorageJournal(target) {
  let raw;
  try {
    raw = await readFile(storageJournalPath, 'utf8');
  } catch (error) {
    if (error && typeof error === 'object' && 'code' in error && error.code === 'ENOENT') {
      return;
    }
    throw error;
  }

  const lines = raw.split('\n');
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    if (!line.trim()) {
      continue;
    }

    let event;
    try {
      event = JSON.parse(line);
    } catch {
      if (index === lines.length - 1 && !raw.endsWith('\n')) {
        // A process can be interrupted during append. Earlier complete events are
        // durable and this incomplete trailing event was never acknowledged.
        return;
      }
      throw new Error('storage journal contains invalid JSON');
    }

    applyStorageJournalEvent(target, event);
  }
}

function applyStorageJournalEvent(target, event) {
  if (!event || typeof event !== 'object' || typeof event.type !== 'string') {
    throw new Error('storage journal contains an invalid event');
  }

  if (event.type === 'append') {
    if (typeof event.id !== 'string' || !event.message || typeof event.message !== 'object') {
      throw new Error('storage journal append event is invalid');
    }
    if (!target.some(message => getStorageMessageId(message) === event.id)) {
      setStorageMessageId(event.message, event.id);
      target.push(event.message);
    }
    return;
  }

  if (event.type === 'replace') {
    if (typeof event.id !== 'string' || !event.message || typeof event.message !== 'object') {
      throw new Error('storage journal replace event is invalid');
    }
    const index = target.findIndex(message => getStorageMessageId(message) === event.id);
    if (index >= 0) {
      setStorageMessageId(event.message, event.id);
      target[index] = event.message;
    }
    return;
  }

  if (event.type === 'remove') {
    if (!Array.isArray(event.ids) || !event.ids.every(id => typeof id === 'string')) {
      throw new Error('storage journal remove event is invalid');
    }
    const ids = new Set(event.ids);
    for (let index = target.length - 1; index >= 0; index -= 1) {
      if (ids.has(getStorageMessageId(target[index]))) {
        target.splice(index, 1);
      }
    }
    return;
  }

  throw new Error('storage journal event type is unsupported');
}

function getStorageMessageId(message) {
  return storageMessageIds.get(message);
}

function setStorageMessageId(message, id = undefined) {
  const nextId = id ?? `message-${++storageMessageSequence}`;
  storageMessageIds.set(message, nextId);
  const sequence = /^message-(\d+)$/.exec(nextId);
  if (sequence) {
    storageMessageSequence = Math.max(storageMessageSequence, Number(sequence[1]));
  }
  return nextId;
}

function ensureStorageMessageId(message) {
  return getStorageMessageId(message) ?? setStorageMessageId(message);
}

function captureStorageMessages() {
  return new Map(messages.map(message => [
    ensureStorageMessageId(message),
    JSON.stringify(message)
  ]));
}

function refreshPersistedStorageMessages(snapshot = captureStorageMessages()) {
  persistedStorageMessages.clear();
  for (const [id, serialized] of snapshot) {
    persistedStorageMessages.set(id, serialized);
  }
}

function collectStorageJournalEvents() {
  const current = captureStorageMessages();
  const events = [];

  for (const [id, serialized] of current) {
    const previous = persistedStorageMessages.get(id);
    if (previous === undefined) {
      const message = messages.find(candidate => getStorageMessageId(candidate) === id);
      events.push({ type: 'append', id, message });
    } else if (previous !== serialized) {
      const message = messages.find(candidate => getStorageMessageId(candidate) === id);
      events.push({ type: 'replace', id, message });
    }
  }

  const removed = [...persistedStorageMessages.keys()].filter(id => !current.has(id));
  if (removed.length > 0) {
    events.push({ type: 'remove', ids: removed });
  }

  return { events, current };
}

async function writeStorageSnapshot() {
  await ensureStateDir();
  const tempPath = `${storageStatePath}.${process.pid}.${Date.now()}.${storageMessageSequence}.tmp`;
  const snapshot = {
    version: 1,
    messages: messages.map(message => ({
      id: ensureStorageMessageId(message),
      message
    }))
  };

  await writeFile(tempPath, `${JSON.stringify(snapshot)}\n`, 'utf8');
  await rename(tempPath, storageStatePath);
}

function saveStorageState() {
  const write = storagePersistQueue.then(async () => {
    const { events, current } = collectStorageJournalEvents();
    if (events.length === 0) {
      return;
    }

    await ensureStateDir();
    await appendFile(storageJournalPath, `${events.map(event => JSON.stringify(event)).join('\n')}\n`, 'utf8');
    refreshPersistedStorageMessages(current);
    storageMutationCount += events.length;

    if (storageMutationCount >= storageSnapshotEveryMutations) {
      await writeStorageSnapshot();
      // Journal events are idempotent against the snapshot; truncation after the
      // replacement preserves recoverability across a process crash.
      await writeFile(storageJournalPath, '', 'utf8');
      storageMutationCount = 0;
    }
  });

  storagePersistQueue = write.catch(() => undefined);
  return write;
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
    const requestBody = JSON.stringify(notification);
    const response = await fetch(new URL(compatPushNotifyPath, pushCompatNotifyUrl), {
      method: 'POST',
      headers: pushNotifyHeaders(requestBody),
      body: requestBody
    });
    if (!response.ok) {
      return { queued: 0 };
    }

    return await response.json();
  } catch {
    return { queued: 0 };
  }
}

function isPositiveSafeInteger(value) {
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed > 0;
}

async function loadPushNotifySigner() {
  if (pushNotifyBearerTokenFile) {
    const bearerToken = (await readFile(pushNotifyBearerTokenFile, 'utf8')).trim();
    if (!bearerToken) {
      throw new Error('PUSH_COMPAT_NOTIFY_BEARER_TOKEN_FILE is empty');
    }
    return { bearerToken };
  }

  if (!pushNotifyPrivateKeyFile && !pushNotifyNodeId) {
    return null;
  }
  if (!/^[0-9a-f]{64}$/.test(pushNotifyNodeId) || !pushNotifyPrivateKeyFile) {
    throw new Error('Signed push notifications require a 64-hex node id and an Ed25519 private key file');
  }

  const value = (await readFile(pushNotifyPrivateKeyFile, 'utf8')).trim().replace(/^0x/i, '');
  if (!/^[0-9a-f]{64}(?:[0-9a-f]{64})?$/i.test(value)) {
    throw new Error('Push notification Ed25519 key must contain a 32-byte seed or 64-byte secret key');
  }
  const seed = Buffer.from(value.slice(0, 64), 'hex');
  const pkcs8SeedPrefix = Buffer.from('302e020100300506032b657004220420', 'hex');
  return {
    privateKey: createPrivateKey({ key: Buffer.concat([pkcs8SeedPrefix, seed]), format: 'der', type: 'pkcs8' })
  };
}

function pushNotifyHeaders(requestBody) {
  const headers = { 'content-type': 'application/json' };
  if (pushNotifySigner?.bearerToken) {
    headers.authorization = `Bearer ${pushNotifySigner.bearerToken}`;
    return headers;
  }
  if (!pushNotifySigner?.privateKey) {
    return headers;
  }

  const timestamp = Math.floor(Date.now() / 1000);
  const bodyHash = createHash('sha256').update(requestBody).digest('hex');
  const canonical = `XPOINT_PUSH_NOTIFY_V1\n${pushNotifyNodeId}\n${timestamp}\n${bodyHash}`;
  headers['x-xpoint-node-id'] = pushNotifyNodeId;
  headers['x-xpoint-notify-timestamp'] = String(timestamp);
  headers['x-xpoint-notify-signature'] = sign(null, Buffer.from(canonical), pushNotifySigner.privateKey).toString('base64');
  return headers;
}

function pathOf(req) {
  return new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`);
}

class RequestTooLargeError extends Error {}

class MalformedJsonError extends Error {}

async function body(req, maxBytes = maxStorageRequestBytes) {
  const contentLength = Number(req.headers?.['content-length']);
  if (Number.isSafeInteger(contentLength) && contentLength > maxBytes) {
    throw new RequestTooLargeError('request body exceeds the configured limit');
  }

  const chunks = [];
  let total = 0;
  for await (const chunk of req) {
    const buffer = Buffer.from(chunk);
    total += buffer.length;
    if (total > maxBytes) {
      if (typeof req.resume === 'function') {
        req.resume();
      }
      throw new RequestTooLargeError('request body exceeds the configured limit');
    }
    chunks.push(buffer);
  }
  return Buffer.concat(chunks);
}

async function bodyJson(req) {
  const raw = await body(req);
  if (raw.length === 0) {
    return {};
  }

  try {
    return JSON.parse(raw.toString('utf8'));
  } catch {
    throw new MalformedJsonError('request body is not valid JSON');
  }
}

function decodeStorageData(data) {
  if (typeof data !== 'string' || data.length === 0) {
    return null;
  }

  const maxBase64Length = Math.ceil(maxStorageMessageBytes / 3) * 4 + 4;
  if (data.length > maxBase64Length || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(data)) {
    return null;
  }

  const decoded = Buffer.from(data, 'base64');
  return decoded.length <= maxStorageMessageBytes ? decoded : null;
}

function storageMessageBytes(message) {
  return Buffer.byteLength(String(message.data ?? ''), 'base64');
}

function storageUsage(pubkey = undefined) {
  let count = 0;
  let bytes = 0;
  for (const message of messages) {
    if (pubkey !== undefined && message.pubkey !== pubkey) {
      continue;
    }
    count += 1;
    bytes += storageMessageBytes(message);
  }
  return { count, bytes };
}

function isStorageQuotaAvailable(pubkey, dataBytes) {
  const account = storageUsage(pubkey);
  const global = storageUsage();
  return account.count < maxStorageMessagesPerAccount
    && account.bytes + dataBytes <= maxStorageBytesPerAccount
    && global.count < maxStorageMessages
    && global.bytes + dataBytes <= maxStorageBytes;
}

function normalizeBoundedHashes(value) {
  if (!Array.isArray(value) || value.length === 0 || value.length > maxStorageMutationHashes) {
    return null;
  }
  return value.map(item => String(item)).filter(Boolean);
}

function readRetrievePage(request) {
  const requested = request.limit ?? request.max_results ?? request.maxResults;
  return parsePositiveInteger(requested, storageRetrievePageSize, storageRetrievePageSize);
}

function selectRetrievePage(pubkey, namespace, lastHash, limit) {
  const selected = [];
  let selectedBytes = 0;
  const hasLastHash = lastHash && messages.some(message =>
    message.pubkey === pubkey &&
    (namespace === undefined || message.namespace === namespace) &&
    message.hash === lastHash
  );
  let started = !hasLastHash;
  let more = false;

  for (const message of messages) {
    if (message.pubkey !== pubkey || (namespace !== undefined && message.namespace !== namespace)) {
      continue;
    }
    if (!started) {
      if (message.hash === lastHash) {
        started = true;
      }
      continue;
    }

    const messageBytes = Buffer.byteLength(JSON.stringify(message));
    if (selected.length >= limit || selectedBytes + messageBytes > maxStorageRetrievePageBytes) {
      more = true;
      break;
    }

    selected.push(message);
    selectedBytes += messageBytes;
  }

  return { messages: selected, more };
}

function storageClientKey(req) {
  return req.socket?.remoteAddress ?? 'unknown';
}

function isStorageRateLimitAllowed(req) {
  const now = nowMs();
  const key = storageClientKey(req);
  let entry = storageRateLimitClients.get(key);
  if (!entry || now - entry.windowStartedAt >= 60_000) {
    if (!entry && storageRateLimitClients.size >= maxStorageRateLimitClients) {
      const oldest = storageRateLimitClients.keys().next().value;
      if (oldest !== undefined) {
        storageRateLimitClients.delete(oldest);
      }
    }
    entry = { windowStartedAt: now, count: 0 };
    storageRateLimitClients.set(key, entry);
  }

  if (entry.count >= storageRateLimitPerMinute) {
    return false;
  }

  entry.count += 1;
  return true;
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

  if (Buffer.byteLength(JSON.stringify(params ?? {})) > maxStorageRequestBytes) {
    return {
      status: 413,
      body: {
        error: 'quota-exceeded',
        message: 'storage pipeline item exceeds the configured request limit'
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
    const signatureTimestampInput = request.sig_timestamp ?? request.sigTimestamp ?? request.timestamp;
    const signatureTimestamp = parsePositiveInteger(signatureTimestampInput, timestamp);
    const ttl = parsePositiveInteger(request.ttl, defaultStorageTtlMs, maxStorageTtlMs);
    const data = String(request.data ?? '');
    const idempotencyKey = request.idempotency_key ?? request.idempotencyKey;
    const normalizedIdempotencyKey = idempotencyKey ? String(idempotencyKey) : null;

    if (!pubkey || Number.isNaN(namespace) || !data) {
      json(res, 400, { error: 'invalid-request', message: 'pubkey, namespace, and data are required' });
      return true;
    }

    if (data.length > Math.ceil(maxStorageMessageBytes / 3) * 4 + 4) {
      json(res, 413, { error: 'quota-exceeded', message: 'storage message exceeds the configured size limit' });
      return true;
    }

    const decoded = decodeStorageData(data);
    if (!decoded) {
      const validBase64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(data);
      json(res, validBase64 ? 413 : 400, {
        error: validBase64 ? 'quota-exceeded' : 'invalid-request',
        message: validBase64
          ? 'storage message exceeds the configured size limit'
          : 'data must be valid base64 within the configured size limit'
      });
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

    if (!isPublicInboxNamespace(namespace) && !isPositiveSafeInteger(signatureTimestampInput)) {
      json(res, 400, {
        error: 'invalid-request',
        message: 'store signature timestamp is required'
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
      if (verification.checked !== true || verification.verified !== true) {
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

    if (!isStorageQuotaAvailable(pubkey, decoded.length)) {
      json(res, 413, { error: 'quota-exceeded', message: 'storage account or global quota exceeded' });
      return true;
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

    if (signature && !hasTimestamp) {
      json(res, 400, {
        error: 'invalid-request',
        message: "invalid request: Required field 'timestamp' missing"
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

    if (signature) {
      const timestamp = Number(request.timestamp);
      const current = nowMs();
      if (!isPositiveSafeInteger(timestamp) ||
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
      if (verification.checked !== true || verification.verified !== true) {
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

    const page = selectRetrievePage(pubkey, namespace, lastHash, readRetrievePage(request));
    json(res, 200, page);
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
    const requestedMessages = normalizeBoundedHashes(request.messages);

    if (!pubkey || !signature || !isPositiveSafeInteger(timestamp) || !requestedMessages || requestedMessages.length === 0) {
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
    if (verification.checked !== true || verification.verified !== true) {
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

    if (!pubkey || !signature || !isPositiveSafeInteger(timestamp) || !revoke.ok) {
      json(res, 400, {
        error: 'invalid-request',
        message: !revoke.ok && pubkey && signature && isPositiveSafeInteger(timestamp)
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
    if (verification.checked !== true || verification.verified !== true) {
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

    if (!pubkey || !signature || !isPositiveSafeInteger(timestamp) || !unrevoke.ok) {
      json(res, 400, {
        error: 'invalid-request',
        message: !unrevoke.ok && pubkey && signature && isPositiveSafeInteger(timestamp)
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
    if (verification.checked !== true || verification.verified !== true) {
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

    if (!pubkey || !signature || !isPositiveSafeInteger(timestamp)) {
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
    if (verification.checked !== true || verification.verified !== true) {
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
    const requests = Array.isArray(request.requests) && request.requests.length <= maxStoragePipelineRequests
      ? request.requests
      : null;
    if (!requests) {
      json(res, 400, {
        error: 'invalid-request',
        message: `requests array is required and limited to ${maxStoragePipelineRequests} items`
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
    if (verification.checked !== true || verification.verified !== true) {
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
    const requestedMessages = normalizeBoundedHashes(request.messages);
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
    if (verification.checked !== true || verification.verified !== true) {
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
    const requestedMessages = normalizeBoundedHashes(request.messages);
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
    if (verification.checked !== true || verification.verified !== true) {
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

    if (!pubkey || !signature || !isPositiveSafeInteger(timestamp)) {
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
    if (verification.checked !== true || verification.verified !== true) {
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
    if (verification.checked !== true || verification.verified !== true) {
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

    if (url.pathname.startsWith('/storage/') && !isStorageRateLimitAllowed(req)) {
      json(res, 429, {
        error: 'rate-limited',
        message: 'storage request rate limit exceeded'
      });
      return;
    }

    if (await handleStorage(req, res, url)) {
      return;
    }

    notFound(res);
  } catch (error) {
    incrementStat('errors');
    if (error instanceof RequestTooLargeError) {
      json(res, 413, {
        service: serviceName,
        error: 'quota-exceeded',
        message: error.message
      });
      return;
    }
    if (error instanceof MalformedJsonError) {
      json(res, 400, {
        service: serviceName,
        error: 'invalid-request',
        message: error.message
      });
      return;
    }
    json(res, 500, {
      service: serviceName,
      message: error instanceof Error ? error.message : String(error)
    });
  }
});

server.listen(port, '0.0.0.0', () => {
  console.log(`${serviceName} listening on ${port}`);
});
