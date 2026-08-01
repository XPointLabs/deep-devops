import { createHash } from 'node:crypto';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { blake2b } from './blake2b.mjs';
import {
  decodeHexOrBase64Bytes,
  pushSignatureVersion,
  storageSubaccountAccess,
  validatePushRequestV2Wire,
  verifyStorageSignature
} from './storage-signatures.mjs';

const mode = process.env.SERVICE_MODE ?? 'all';
const port = Number(process.env.PORT ?? 8080);
const serviceName = String(process.env.SERVICE_NAME ?? `deep-${mode}-compat`);
const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const stateDir = process.env.COMPAT_STATE_DIR ?? process.env.MOCK_STATE_DIR ?? path.resolve(scriptDir, '..', '..', 'artifacts', 'compat-state');
const storageStatePath = path.join(stateDir, 'storage.json');
const storageSubaccountsStatePath = path.join(stateDir, 'storage-subaccounts.json');
const fileStatePath = path.join(stateDir, 'file.json');
const avatarStatePath = path.join(stateDir, 'avatar.json');
const pushStatePath = path.join(stateDir, 'push.json');
const callStatePath = path.join(stateDir, 'calls.json');
const compatPushNotifyPath = '/_compat/push-notify';

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
const files = new Map(
  (await loadJson(fileStatePath, [])).map(record => [
    record.id,
    {
      ...record,
      content: Buffer.from(record.contentBase64 ?? '', 'base64')
    }
  ])
);
const avatars = new Map(
  (await loadJson(avatarStatePath, [])).map(record => [
    record.sessionId,
    {
      sessionId: String(record.sessionId),
      fileId: String(record.fileId),
      contentType: String(record.contentType ?? 'application/octet-stream'),
      size: Number(record.size ?? 0),
      updated: Number(record.updated ?? 0),
      expires: Number(record.expires ?? 0)
    }
  ])
);
const subscriptions = new Map((await loadJson(pushStatePath, [])).map(record => [record.key, record]));
const pushDeliveries = new Map();
const callSignals = await loadJson(callStatePath, []);

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
  fileUpload: 0,
  fileDownload: 0,
  fileInfo: 0,
  fileExtend: 0,
  avatarUpload: 0,
  avatarDownload: 0,
  avatarInfo: 0,
  sessionVersion: 0,
  tokenInfo: 0,
  pushSubscribe: 0,
  pushSubscribeBatch: 0,
  pushUnsubscribe: 0,
  pushUnsubscribeBatch: 0,
  subscriptionsList: 0,
  pushNotificationRequests: 0,
  pushNotificationsQueued: 0,
  callSignal: 0,
  callInbox: 0,
  errors: 0
};

const relayId = '1111111111111111111111111111111111111111111111111111111111111111';
const defaultStorageTtlMs = 86_400_000;
const maxStorageTtlMs = 30 * 24 * 60 * 60 * 1000;
const storageSignatureToleranceMs = 60_000;
const maxFileSizeBytes = 6_000_000;
const maxFileSizeBase64Bytes = 8_000_000;
const maxAvatarSizeBytes = 1_500_000;
const supportedAvatarContentTypes = new Set(['image/jpeg', 'image/png', 'image/webp']);
const defaultFileTtlSeconds = 21 * 24 * 60 * 60;
let fileStateWrite = Promise.resolve();
let avatarStateWrite = Promise.resolve();
const maxFileTtlSeconds = (() => {
  const raw = process.env.MAX_FILE_TTL_SECONDS;
  if (raw == null || raw === '') {
    return null;
  }

  const parsed = Number(raw);
  return Number.isInteger(parsed) && parsed >= 0 ? parsed : null;
})();
const defaultPushTtlSeconds = 30 * 24 * 60 * 60;
const maxPushTtlSeconds = 365 * 24 * 60 * 60;
const unsubscribeSignatureGraceSeconds = 24 * 60 * 60;
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
const maxPushDeliveryBodyBytes = 2500;
const maxPushDeliveriesPerPubkey = 100;
const pushCompatNotifyUrl = String(process.env.PUSH_COMPAT_NOTIFY_URL ?? '');

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

function sessionFileId(value) {
  return Buffer.from(
    blake2b(value, {
      digestLength: 33,
      salt: Buffer.from('SessionFileSvr\0\0')
    })
  ).toString('base64url');
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

function parseNonNegativeIntegerStrict(value) {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 0) {
    return null;
  }

  return parsed;
}

function resolveFileTtlSeconds(req) {
  if (maxFileTtlSeconds == null) {
    return { ok: true, ttlSeconds: defaultFileTtlSeconds };
  }

  const raw = req.headers['x-fs-ttl'];
  if (raw == null) {
    return { ok: true, ttlSeconds: defaultFileTtlSeconds };
  }

  const value = Array.isArray(raw) ? raw[0] : raw;
  const requested = parseNonNegativeIntegerStrict(value);
  if (requested == null || requested > maxFileTtlSeconds) {
    return { ok: false };
  }

  return { ok: true, ttlSeconds: requested };
}

function readEnvText(name) {
  const value = process.env[name];
  return value == null || value === '' ? null : value;
}

function resolveSessionVersion(platform, channel) {
  const envName = `SESSION_VERSION_${platform.toUpperCase()}${channel === 'stable' ? '' : `_${channel.toUpperCase()}`}`;
  const result = readEnvText(envName);
  if (!result) {
    return null;
  }

  const updated = parsePositiveInteger(process.env.SESSION_VERSION_UPDATED_AT, nowSeconds());
  const response = {
    status_code: 200,
    result,
    updated
  };

  if (channel === 'stable') {
    const prerelease = readEnvText(`SESSION_VERSION_${platform.toUpperCase()}_PRERELEASE`);
    if (prerelease) {
      response.prerelease = {
        result: prerelease,
        updated
      };
    }
  }

  return response;
}

function resolveTokenInfo(days) {
  const maximumSupply = readEnvText('TOKEN_INFO_MAXIMUM_SUPPLY');
  const sentPerNode = readEnvText('TOKEN_INFO_SENT_PER_NODE');
  const stakingRewardPool = readEnvText('TOKEN_INFO_STAKING_REWARD_POOL');
  const historyJson = readEnvText('TOKEN_INFO_HISTORY_JSON');

  if (!maximumSupply || !sentPerNode || !stakingRewardPool || !historyJson) {
    return null;
  }

  let history;
  try {
    history = JSON.parse(historyJson);
  } catch {
    return null;
  }

  if (!Array.isArray(history)) {
    return null;
  }

  const dayWindow = Number.isInteger(days) && days >= 1 && days <= 30 ? days : 7;
  const startOfToday = new Date();
  startOfToday.setHours(0, 0, 0, 0);
  const earliestUpdated = Math.floor(startOfToday.getTime() / 1000) - dayWindow * 24 * 60 * 60;

  return {
    status_code: 200,
    info: {
      maximum_supply: Number(maximumSupply),
      sent_per_node: Number(sentPerNode),
      staking_reward_pool: Number(stakingRewardPool),
      history: history.filter(entry => Number(entry?.updated ?? 0) >= earliestUpdated)
    }
  };
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

async function saveFileState() {
  fileStateWrite = fileStateWrite.catch(() => {}).then(() => saveJson(
      fileStatePath,
      [...files.values()].map(record => ({
        id: record.id,
        contentBase64: record.content.toString('base64'),
        uploaded: record.uploaded,
        expires: record.expires
      }))
    ));
  await fileStateWrite;
}

async function saveAvatarState() {
  avatarStateWrite = avatarStateWrite.catch(() => {}).then(() => saveJson(
      avatarStatePath,
      [...avatars.values()].map(record => ({
        sessionId: record.sessionId,
        fileId: record.fileId,
        contentType: record.contentType,
        size: record.size,
        updated: record.updated,
        expires: record.expires
      }))
    ));
  await avatarStateWrite;
}

async function savePushState() {
  await saveJson(pushStatePath, [...subscriptions.values()]);
}

async function saveCallState() {
  await saveJson(callStatePath, callSignals);
}

function totalPushDeliveries() {
  let total = 0;
  for (const deliveries of pushDeliveries.values()) {
    total += deliveries.length;
  }
  return total;
}

function normalizePushNotification(request) {
  const pubkey = String(request?.pubkey ?? '');
  const hash = String(request?.hash ?? '');
  const namespace = Number(request?.namespace);
  const timestamp = Number(request?.timestamp);
  const expiration = Number(request?.expiration ?? request?.expires);
  const data = typeof request?.data === 'string' ? request.data : '';

  if (!pubkey || !hash || !Number.isFinite(namespace) || !Number.isFinite(timestamp) || !Number.isFinite(expiration)) {
    return null;
  }

  return {
    pubkey,
    hash,
    namespace,
    timestamp,
    expiration,
    data
  };
}

function queuePushNotification(request) {
  const notification = normalizePushNotification(request);
  if (!notification) {
    return { queued: 0 };
  }

  let queued = 0;
  for (const subscription of subscriptions.values()) {
    const namespaces = Array.isArray(subscription.namespaces)
      ? subscription.namespaces.map(value => Number(value))
      : [];
    if (subscription.pubkey !== notification.pubkey || !namespaces.includes(notification.namespace)) {
      continue;
    }

    const deliveryKey = `${subscription.key}:${notification.hash}`;
    const existing = pushDeliveries.get(notification.pubkey) ?? [];
    if (existing.some(delivery => delivery.key === deliveryKey)) {
      continue;
    }

    let decoded = Buffer.alloc(0);
    try {
      decoded = notification.data ? Buffer.from(notification.data, 'base64') : Buffer.alloc(0);
    } catch {
      decoded = Buffer.alloc(0);
    }

    const wantData = subscription.data === true;
    const bodyTooLarge = wantData && decoded.length > maxPushDeliveryBodyBytes;
    existing.push({
      key: deliveryKey,
      hash: notification.hash,
      pubkey: notification.pubkey,
      namespace: notification.namespace,
      timestamp: notification.timestamp,
      expiration: notification.expiration,
      service: subscription.service,
      token: String(subscription.service_info?.token ?? ''),
      service_info: subscription.service_info,
      enc_key: subscription.enc_key,
      data: wantData && !bodyTooLarge ? notification.data : null,
      bodyTooLarge,
      queuedAt: new Date().toISOString()
    });
    pushDeliveries.set(notification.pubkey, existing.slice(-maxPushDeliveriesPerPubkey));
    queued += 1;
  }

  if (queued > 0) {
    incrementStat('pushNotificationsQueued', queued);
  }

  return { queued };
}

async function emitPushNotification(notification) {
  let pushStateChanged = false;
  if (mode === 'all') {
    if (prunePushExpired()) {
      pushStateChanged = true;
    }

    const result = queuePushNotification(notification);
    if (pushStateChanged) {
      await savePushState();
    }
    return result;
  }

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

function routeIs(enabledMode) {
  return mode === enabledMode || mode === 'all';
}

function incrementStat(key, value = 1) {
  if (Object.hasOwn(stats, key)) {
    stats[key] += value;
  }
}

function nextLegacyFileId() {
  let nextId = 1;

  for (const id of files.keys()) {
    if (!/^\d+$/.test(id)) {
      continue;
    }

    const numericId = Number(id);
    if (Number.isSafeInteger(numericId) && numericId >= nextId) {
      nextId = numericId + 1;
    }
  }

  return String(nextId);
}

function avatarOwnerFromPath(value) {
  try {
    const owner = decodeURIComponent(value).trim();
    return owner.length > 0 && owner.length <= 128 ? owner : null;
  } catch {
    return null;
  }
}

function normalizeContentType(req) {
  const raw = req.headers['content-type'];
  const value = Array.isArray(raw) ? raw[0] : raw;
  return String(value ?? 'application/octet-stream').split(';', 1)[0].trim().toLowerCase();
}

function pruneAvatarPointers() {
  let changed = false;
  for (const [sessionId, avatar] of avatars.entries()) {
    if (!files.has(avatar.fileId)) {
      avatars.delete(sessionId);
      changed = true;
    }
  }

  return changed;
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

function invalidPushRequest(message = 'Missing required parameter', error = pushSubscribeCode.BAD_INPUT) {
  return {
    ok: false,
    changed: false,
    body: {
      error,
      message
    }
  };
}

function validatePushRequestBase(request) {
  if (!request || typeof request !== 'object' || Array.isArray(request)) {
    return invalidPushRequest('Invalid request: expected object');
  }

  const isV2 = request.sig_v === pushSignatureVersion;
  const pubkey = isV2 ? request.pubkey : String(request.pubkey ?? '');
  const service = isV2 ? request.service : String(request.service ?? '');
  if (!pubkey || !service) {
    return invalidPushRequest('Invalid request: pubkey and service are required');
  }

  if (pubkey.startsWith('05')) {
    const sessionEd25519 = isV2
      ? request.session_ed25519
      : String(request.session_ed25519 ?? '');
    if (!sessionEd25519 || !isHexOrBase64Bytes(sessionEd25519, 32)) {
      return invalidPushRequest();
    }
  }

  const subaccount = isV2
    ? (Object.hasOwn(request, 'subaccount') ? request.subaccount : '')
    : String(request.subaccount ?? '');
  const subaccountSig = isV2
    ? (Object.hasOwn(request, 'subaccount_sig') ? request.subaccount_sig : '')
    : String(request.subaccount_sig ?? '');
  const hasSubaccount = subaccount.length > 0;
  const hasSubaccountSig = subaccountSig.length > 0;
  if (hasSubaccount !== hasSubaccountSig) {
    return invalidPushRequest();
  }

  if (hasSubaccount && !isHexOrBase64Bytes(subaccount, 36)) {
    return invalidPushRequest();
  }

  if (hasSubaccountSig && !isHexOrBase64Bytes(subaccountSig, 64)) {
    return invalidPushRequest();
  }

  const sigTs = isV2 ? request.sig_ts : Number(request.sig_ts);
  if (!Number.isFinite(sigTs) || sigTs <= 0) {
    return invalidPushRequest();
  }

  const signature = isV2 ? request.signature : String(request.signature ?? '');
  if (!signature || !isHexOrBase64Bytes(signature, 64)) {
    return invalidPushRequest();
  }

  if (!request.service_info || typeof request.service_info !== 'object' || Array.isArray(request.service_info)) {
    return invalidPushRequest();
  }

  const token = isV2 ? request.service_info.token : String(request.service_info.token ?? '');
  if (!token) {
    return invalidPushRequest();
  }

  if (!supportedPushServices.has(service)) {
    return invalidPushRequest(`Service '${service}' is not available`, pushSubscribeCode.SERVICE_NOT_AVAILABLE);
  }

  return {
    ok: true,
    request,
    pubkey,
    service,
    sigTs,
    token
  };
}

function validatePushSignatureAge(sigTs, maxPastAgeSeconds, maxFutureAgeSeconds, tooOldMessage, tooFutureMessage) {
  const now = nowSeconds();
  if (sigTs <= now - maxPastAgeSeconds) {
    return invalidPushRequest(tooOldMessage);
  }

  if (sigTs >= now + maxFutureAgeSeconds) {
    return invalidPushRequest(tooFutureMessage);
  }

  return null;
}

function validatePushRequestVersionAndWire(request, operation) {
  const isV2 = request?.sig_v === pushSignatureVersion;
  const isLegacy = request?.sig_v === undefined || request?.sig_v === 1;
  if (!isV2 && !isLegacy) {
    return invalidPushRequest(`Unsupported push signature version: ${String(request?.sig_v)}`);
  }

  if (!isV2) {
    return null;
  }

  const error = validatePushRequestV2Wire(request, operation);
  return error ? invalidPushRequest(error) : null;
}

function verifyPushRequestSignature(request, operation) {
  const isV2 = request.sig_v === pushSignatureVersion;
  const isLegacy = request.sig_v === undefined || request.sig_v === 1;
  if (!isV2 && !isLegacy) {
    return invalidPushRequest(`Unsupported push signature version: ${String(request.sig_v)}`);
  }

  if (isV2 &&
      (typeof request.sig_ts !== 'number' ||
       !Number.isSafeInteger(request.sig_ts) ||
       request.sig_ts <= 0)) {
    return invalidPushRequest('Invalid request: sig_ts must be a safe positive integer number for signature v2');
  }

  if (isV2 && operation === 'push_subscribe' &&
      (typeof request.app_id !== 'string' || request.app_id.length === 0 ||
       typeof request.app_version !== 'string' || request.app_version.length === 0)) {
    return invalidPushRequest('Invalid request: app_id and app_version are required for signature v2');
  }

  const verification = verifyStorageSignature({
    operation: isV2 ? `${operation}_v2` : operation,
    pubkey: request.pubkey,
    pubkeyEd25519: request.session_ed25519,
    signature: request.signature,
    subaccount: request.subaccount,
    subaccountSig: request.subaccount_sig,
    requiredSubaccountAccess: storageSubaccountAccess.READ,
    timestamp: request.sig_ts,
    messages: request.namespaces,
    wantData: request.data,
    service: request.service,
    deviceToken: request.service_info?.token,
    encryptionKey: request.enc_key,
    appId: request.app_id,
    appVersion: request.app_version
  });

  if (verification.verified && (verification.checked || isLegacy)) {
    return null;
  }

  return invalidPushRequest(verification.reason ?? 'Signature verification failed', pushSubscribeCode.ERROR);
}

function processPushSubscribeRequest(request) {
  const wireError = validatePushRequestVersionAndWire(request, 'push_subscribe');
  if (wireError) {
    return wireError;
  }

  const base = validatePushRequestBase(request);
  if (!base.ok) {
    return base;
  }

  const signatureAgeError = validatePushSignatureAge(
    base.sigTs,
    signatureExpirySeconds,
    signatureFutureGraceSeconds,
    'Subscription: sig_ts timestamp is too old',
    'Subscription: sig_ts timestamp is too far in the future'
  );
  if (signatureAgeError) {
    return signatureAgeError;
  }

  if (typeof request.data !== 'boolean') {
    return invalidPushRequest();
  }

  const encKey = request.sig_v === pushSignatureVersion
    ? request.enc_key
    : String(request.enc_key ?? '');
  if (!encKey || !isHexOrBase64Bytes(encKey, 32)) {
    return invalidPushRequest();
  }

  const namespaces = request.namespaces ?? [];
  if (!Array.isArray(namespaces)) {
    return invalidPushRequest('Invalid request: namespaces must be an array');
  }

  if (namespaces.length === 0) {
    return invalidPushRequest('Subscription: namespaces missing or empty');
  }

  const sorted = [...namespaces].sort((a, b) => a - b);
  if (JSON.stringify(namespaces) !== JSON.stringify(sorted)) {
    return invalidPushRequest('Invalid request: namespaces must be sorted');
  }

  for (let i = 0; i < namespaces.length - 1; i += 1) {
    if (namespaces[i] === namespaces[i + 1]) {
      return invalidPushRequest('Subscription: namespaces contains duplicates');
    }
  }

  const signatureError = verifyPushRequestSignature(request, 'push_subscribe');
  if (signatureError) {
    return signatureError;
  }

  const key = `${base.pubkey}:${base.service}:${base.token}`;
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
    pubkey: base.pubkey,
    service: base.service,
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

function processPushUnsubscribeRequest(request) {
  const wireError = validatePushRequestVersionAndWire(request, 'push_unsubscribe');
  if (wireError) {
    return wireError;
  }

  const base = validatePushRequestBase(request);
  if (!base.ok) {
    return base;
  }

  const signatureAgeError = validatePushSignatureAge(
    base.sigTs,
    unsubscribeSignatureGraceSeconds,
    unsubscribeSignatureGraceSeconds,
    'Unsubscribe: sig_ts timestamp is too old',
    'Unsubscribe: sig_ts timestamp is too far in the future'
  );
  if (signatureAgeError) {
    return signatureAgeError;
  }

  const signatureError = verifyPushRequestSignature(request, 'push_unsubscribe');
  if (signatureError) {
    return signatureError;
  }

  const key = `${base.pubkey}:${base.service}:${base.token}`;
  const removed = subscriptions.delete(key);
  return {
    ok: true,
    changed: removed,
    body: {
      success: true,
      removed,
      message: removed
        ? 'Device unsubscribed from push notifications'
        : 'Device was not subscribed to push notifications'
    }
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

    updated.sort((left, right) => left.hash < right.hash ? -1 : left.hash > right.hash ? 1 : 0);
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

async function handleFile(req, res, url) {
  if (!routeIs('file')) {
    return false;
  }

  if (req.method === 'GET' && url.pathname === '/session_version') {
    incrementStat('sessionVersion');

    const platform = url.searchParams.get('platform');
    if (!['desktop', 'android', 'ios'].includes(platform)) {
      json(res, 404, { status_code: 404 });
      return true;
    }

    const channel = url.searchParams.get('release_channel') ?? 'stable';
    const response = resolveSessionVersion(platform, channel);
    if (!response) {
      json(res, 502, { status_code: 502 });
      return true;
    }

    json(res, 200, response);
    return true;
  }

  if (req.method === 'GET' && url.pathname === '/token_info') {
    incrementStat('tokenInfo');

    const days = parseNonNegativeIntegerStrict(url.searchParams.get('days'));
    const response = resolveTokenInfo(days);
    if (!response) {
      json(res, 502, { status_code: 502 });
      return true;
    }

    json(res, 200, response);
    return true;
  }

  if (req.method === 'POST' && url.pathname === '/files') {
    incrementStat('fileUpload');

    if (pruneFileExpired()) {
      await saveFileState();
    }

    const ttl = resolveFileTtlSeconds(req);
    if (!ttl.ok) {
      json(res, 400, { status_code: 400 });
      return true;
    }

    let request;
    try {
      request = await bodyJson(req);
    } catch {
      json(res, 400, { status_code: 400 });
      return true;
    }

    const encoded = typeof request.file === 'string' ? request.file : null;
    if (!encoded) {
      json(res, 400, { status_code: 400 });
      return true;
    }

    if (encoded.length > maxFileSizeBase64Bytes) {
      json(res, 413, { status_code: 413 });
      return true;
    }

    const content = Buffer.from(encoded, 'base64');
    if (content.length === 0 || content.length > maxFileSizeBytes) {
      json(res, 413, { status_code: 413 });
      return true;
    }

    const id = nextLegacyFileId();
    const now = nowSeconds();
    files.set(id, {
      id,
      content,
      uploaded: now,
      expires: now + ttl.ttlSeconds
    });
    await saveFileState();
    json(res, 200, {
      status_code: 200,
      result: Number(id)
    });
    return true;
  }

  if (req.method === 'POST' && url.pathname === '/file') {
    incrementStat('fileUpload');

    if (pruneFileExpired()) {
      await saveFileState();
    }

    const ttl = resolveFileTtlSeconds(req);
    if (!ttl.ok) {
      json(res, 400, { status_code: 400 });
      return true;
    }

    const content = await body(req);
    if (content.length === 0 || content.length > maxFileSizeBytes) {
      json(res, 413, { status_code: 413 });
      return true;
    }

    const id = sessionFileId(content);
    const now = nowSeconds();
    const existing = files.get(id);
    files.set(id, {
      id,
      content,
      uploaded: existing?.uploaded ?? now,
      expires: Math.max(existing?.expires ?? 0, now + ttl.ttlSeconds)
    });
    await saveFileState();
    json(res, 200, {
      id,
      expires: files.get(id).expires
    });
    return true;
  }

  const avatarMatch = url.pathname.match(/^\/avatar\/([^/]+)(?:\/info)?$/);
  if ((req.method === 'PUT' || req.method === 'POST') && avatarMatch && !url.pathname.endsWith('/info')) {
    incrementStat('avatarUpload');

    const owner = avatarOwnerFromPath(avatarMatch[1]);
    if (!owner) {
      json(res, 400, { status_code: 400, error: 'invalid-avatar-owner' });
      return true;
    }

    if (pruneFileExpired()) {
      await saveFileState();
    }
    if (pruneAvatarPointers()) {
      await saveAvatarState();
    }

    const ttl = resolveFileTtlSeconds(req);
    if (!ttl.ok) {
      json(res, 400, { status_code: 400 });
      return true;
    }

    const contentType = normalizeContentType(req);
    if (!supportedAvatarContentTypes.has(contentType)) {
      json(res, 415, { status_code: 415, error: 'unsupported-avatar-content-type' });
      return true;
    }

    const content = await body(req);
    if (content.length === 0 || content.length > maxAvatarSizeBytes) {
      json(res, 413, { status_code: 413 });
      return true;
    }

    const id = sessionFileId(content);
    const now = nowSeconds();
    const existingFile = files.get(id);
    files.set(id, {
      id,
      content,
      uploaded: existingFile?.uploaded ?? now,
      expires: Math.max(existingFile?.expires ?? 0, now + ttl.ttlSeconds)
    });

    const fileRecord = files.get(id);
    avatars.set(owner, {
      sessionId: owner,
      fileId: id,
      contentType,
      size: content.length,
      updated: now,
      expires: fileRecord.expires
    });

    await saveFileState();
    await saveAvatarState();
    json(res, 200, avatars.get(owner));
    return true;
  }

  if (req.method === 'GET' && avatarMatch) {
    if (pruneFileExpired()) {
      await saveFileState();
    }
    if (pruneAvatarPointers()) {
      await saveAvatarState();
    }

    const owner = avatarOwnerFromPath(avatarMatch[1]);
    if (!owner) {
      json(res, 400, { status_code: 400, error: 'invalid-avatar-owner' });
      return true;
    }

    const avatar = avatars.get(owner);
    const record = avatar ? files.get(avatar.fileId) : null;
    if (!avatar || !record) {
      json(res, 404, { status_code: 404 });
      return true;
    }

    if (url.pathname.endsWith('/info')) {
      incrementStat('avatarInfo');
      json(res, 200, avatar);
      return true;
    }

    incrementStat('avatarDownload');
    bytes(res, 200, record.content, avatar.contentType);
    return true;
  }

  const legacyFileMatch = url.pathname.match(/^\/files\/([^/]+)$/);
  if (req.method === 'GET' && legacyFileMatch) {
    if (pruneFileExpired()) {
      await saveFileState();
    }

    const id = legacyFileMatch[1];
    const record = files.get(id);
    if (!record) {
      json(res, 404, { status_code: 404 });
      return true;
    }

    incrementStat('fileDownload');
    json(res, 200, {
      status_code: 200,
      result: record.content.toString('base64')
    });
    return true;
  }

  const fileExtendMatch = url.pathname.match(/^\/file\/([^/]+)\/extend$/);
  if (req.method === 'POST' && fileExtendMatch) {
    incrementStat('fileExtend');

    if (pruneFileExpired()) {
      await saveFileState();
    }

    const ttl = resolveFileTtlSeconds(req);
    if (!ttl.ok) {
      json(res, 400, { status_code: 400 });
      return true;
    }

    const id = fileExtendMatch[1];
    const record = files.get(id);
    if (!record) {
      json(res, 404, { status_code: 404 });
      return true;
    }

    record.expires = Math.max(record.expires, nowSeconds() + ttl.ttlSeconds);
    files.set(id, record);
    await saveFileState();
    json(res, 200, {
      size: record.content.length,
      uploaded: record.uploaded,
      expires: record.expires
    });
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
      json(res, 404, { status_code: 404 });
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

  if (req.method === 'POST' && url.pathname === compatPushNotifyPath) {
    incrementStat('pushNotificationRequests');

    let changed = false;
    if (prunePushExpired()) {
      changed = true;
    }

    const request = await bodyJson(req);
    const result = queuePushNotification(request);
    if (changed) {
      await savePushState();
    }

    json(res, 202, { queued: result.queued });
    return true;
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

  if (req.method === 'POST' && url.pathname === '/unsubscribe') {
    incrementStat('pushUnsubscribe');

    let changed = false;
    if (prunePushExpired()) {
      changed = true;
    }

    const request = await bodyJson(req);
    if (Array.isArray(request)) {
      incrementStat('pushUnsubscribeBatch');
      const results = request.map(item => {
        const result = processPushUnsubscribeRequest(item);
        changed = changed || result.changed;
        return result.body;
      });
      if (changed) {
        await savePushState();
      }
      json(res, 200, results);
      return true;
    }

    const result = processPushUnsubscribeRequest(request);
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
    json(res, 200, {
      subscriptions: records,
      deliveries: pushDeliveries.get(pubkey) ?? []
    });
    return true;
  }

  return false;
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

async function handleCalls(req, res, url) {
  if (!routeIs('calls')) {
    return false;
  }

  if (req.method === 'POST' && url.pathname === '/api/calls/signal') {
    incrementStat('callSignal');

    const envelope = await bodyJson(req);
    const callId = String(envelope.callId ?? envelope.CallId ?? '');
    const conversationId = String(envelope.conversationId ?? envelope.ConversationId ?? '');
    const sender = sessionIdValue(envelope.sender ?? envelope.Sender);
    const recipient = sessionIdValue(envelope.recipient ?? envelope.Recipient);

    if (!callId || !conversationId || !sender || !recipient) {
      json(res, 400, {
        error: 'invalid-request',
        message: 'callId, conversationId, sender, and recipient are required'
      });
      return true;
    }

    callSignals.push({
      ...envelope,
      callId,
      conversationId,
      sender: { value: sender },
      recipient: { value: recipient },
      createdAt: envelope.createdAt ?? envelope.CreatedAt ?? new Date().toISOString()
    });
    await saveCallState();
    json(res, 202, { accepted: true, callId });
    return true;
  }

  if (req.method === 'GET' && url.pathname.startsWith('/api/calls/inbox/')) {
    incrementStat('callInbox');

    const recipient = decodeURIComponent(url.pathname.slice('/api/calls/inbox/'.length));
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
          storageMessages: messages.length,
          revokedSubaccounts: totalRevokedStorageSubaccounts(),
          files: files.size,
          avatars: avatars.size,
          subscriptions: subscriptions.size,
          pushDeliveries: totalPushDeliveries(),
          callSignals: callSignals.length
        },
        state: {
          dir: stateDir,
          storage: storageStatePath,
          storageSubaccounts: storageSubaccountsStatePath,
          file: fileStatePath,
          avatar: avatarStatePath,
          push: pushStatePath,
          calls: callStatePath
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
