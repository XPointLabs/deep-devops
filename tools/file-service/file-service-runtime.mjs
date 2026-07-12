import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { createHash, timingSafeEqual } from 'node:crypto';
import { blake2b } from '../compat-services/blake2b.mjs';
import { verifySessionSignature } from '../compat-services/storage-signatures.mjs';

const port = Number(process.env.PORT ?? 8080);
const serviceName = String(process.env.SERVICE_NAME ?? 'deep-file-service');
const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const stateDir = process.env.COMPAT_STATE_DIR ?? process.env.MOCK_STATE_DIR ?? path.resolve(scriptDir, '..', '..', 'artifacts', 'compat-state');
const fileStatePath = path.join(stateDir, 'file.json');
const avatarStatePath = path.join(stateDir, 'avatar.json');

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

const stats = {
  startedAt: new Date().toISOString(),
  requestsTotal: 0,
  healthChecks: 0,
  fileUpload: 0,
  fileDownload: 0,
  fileInfo: 0,
  fileExtend: 0,
  avatarUpload: 0,
  avatarDownload: 0,
  avatarInfo: 0,
  sessionVersion: 0,
  tokenInfo: 0,
  errors: 0
};

const maxFileSizeBytes = 6_000_000;
const maxFileSizeBase64Bytes = 8_000_000;
const maxAvatarSizeBytes = 1_500_000;
const maxRequestBodyBytes = 8_100_000;
const avatarAuthorizationFreshnessMs = 5 * 60 * 1000;
const supportedAvatarContentTypes = new Set(['image/jpeg', 'image/png', 'image/webp']);
const avatarAuthorizationNonces = new Map();
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
  json(res, 404, { error: 'not-found', service: serviceName });
}

function sessionFileId(value) {
  return Buffer.from(
    blake2b(value, {
      digestLength: 33,
      salt: Buffer.from('SessionFileSvr\0\0')
    })
  ).toString('base64url');
}

function nowSeconds() {
  return Math.floor(Date.now() / 1000);
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

function pathOf(req) {
  return new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`);
}

async function body(req, maximumBytes = maxRequestBodyBytes) {
  const declaredLength = Number(req.headers['content-length'] ?? 0);
  if (Number.isFinite(declaredLength) && declaredLength > maximumBytes) {
    throw new RequestBodyTooLargeError();
  }

  const chunks = [];
  let totalBytes = 0;
  for await (const chunk of req) {
    const bytes = Buffer.from(chunk);
    totalBytes += bytes.length;
    if (totalBytes > maximumBytes) {
      throw new RequestBodyTooLargeError();
    }
    chunks.push(bytes);
  }
  return Buffer.concat(chunks);
}

async function bodyJson(req) {
  const raw = await body(req);
  return raw.length === 0 ? {} : JSON.parse(raw.toString('utf8'));
}

class RequestBodyTooLargeError extends Error {
  constructor() {
    super('request-body-too-large');
    this.name = 'RequestBodyTooLargeError';
  }
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

function headerValue(req, name) {
  const raw = req.headers[name];
  return Array.isArray(raw) ? raw[0] : raw;
}

function pruneAvatarAuthorizationNonces(now = Date.now()) {
  for (const [key, expiresAt] of avatarAuthorizationNonces.entries()) {
    if (expiresAt <= now) {
      avatarAuthorizationNonces.delete(key);
    }
  }
}

function parseAvatarAuthorization(req, url, owner) {
  const sessionId = String(headerValue(req, 'x-deep-session-id') ?? '');
  const pubkeyEd25519 = String(headerValue(req, 'x-deep-ed25519') ?? '').toLowerCase();
  const timestampText = String(headerValue(req, 'x-deep-timestamp') ?? '');
  const nonce = String(headerValue(req, 'x-deep-nonce') ?? '').toLowerCase();
  const contentSha256 = String(headerValue(req, 'x-deep-content-sha256') ?? '').toLowerCase();
  const signature = String(headerValue(req, 'x-deep-signature') ?? '');
  const timestamp = Number(timestampText);
  const now = Date.now();

  if (sessionId !== owner
    || !/^05[0-9a-f]{64}$/.test(sessionId)
    || !/^[0-9a-f]{64}$/.test(pubkeyEd25519)
    || !Number.isSafeInteger(timestamp)
    || Math.abs(now - timestamp) > avatarAuthorizationFreshnessMs
    || !/^[0-9a-f]{32}$/.test(nonce)
    || !/^[0-9a-f]{64}$/.test(contentSha256)
    || signature.length === 0) {
    return null;
  }

  const signingPayload = Buffer.from([
    'deep-avatar-upload-v1',
    'PUT',
    url.pathname,
    sessionId,
    pubkeyEd25519,
    timestampText,
    nonce,
    contentSha256
  ].join('\n'), 'utf8');
  if (!verifySessionSignature({
    pubkey: sessionId,
    pubkeyEd25519,
    signature,
    message: signingPayload
  })) {
    return null;
  }

  pruneAvatarAuthorizationNonces(now);
  return {
    contentSha256,
    replayKey: `${sessionId}:${nonce}`,
    replayExpiresAt: timestamp + avatarAuthorizationFreshnessMs
  };
}

function digestMatches(content, expectedHex) {
  const expected = Buffer.from(expectedHex, 'hex');
  const actual = createHash('sha256').update(content).digest();
  return expected.length === actual.length && timingSafeEqual(expected, actual);
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

async function handleFile(req, res, url) {
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

    const authorization = parseAvatarAuthorization(req, url, owner);
    if (!authorization) {
      json(res, 401, { status_code: 401, error: 'invalid-avatar-authorization' });
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

    const content = await body(req, maxAvatarSizeBytes);
    if (content.length === 0 || content.length > maxAvatarSizeBytes) {
      json(res, 413, { status_code: 413 });
      return true;
    }

    if (!digestMatches(content, authorization.contentSha256)) {
      json(res, 401, { status_code: 401, error: 'avatar-content-digest-mismatch' });
      return true;
    }
    if (avatarAuthorizationNonces.has(authorization.replayKey)) {
      json(res, 409, { status_code: 409, error: 'avatar-authorization-replayed' });
      return true;
    }
    avatarAuthorizationNonces.set(authorization.replayKey, authorization.replayExpiresAt);

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
        mode: 'file',
        stats,
        inventory: {
          files: files.size,
          avatars: avatars.size
        },
        state: {
          dir: stateDir,
          file: fileStatePath,
          avatar: avatarStatePath
        }
      });
      return;
    }

    if (await handleFile(req, res, url)) {
      return;
    }

    notFound(res);
  } catch (error) {
    incrementStat('errors');
    if (error instanceof RequestBodyTooLargeError) {
      json(res, 413, { status_code: 413, error: error.message });
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
