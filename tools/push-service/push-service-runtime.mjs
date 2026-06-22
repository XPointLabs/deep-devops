import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { storageSubaccountAccess, verifyStorageSignature } from '../compat-services/storage-signatures.mjs';

const mode = 'push';
const port = Number(process.env.PORT ?? 8080);
const serviceName = String(process.env.SERVICE_NAME ?? 'deep-push-service');
const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const stateDir = process.env.COMPAT_STATE_DIR ?? process.env.MOCK_STATE_DIR ?? path.resolve(scriptDir, '..', '..', 'artifacts', 'compat-state');
const storageStatePath = path.join(stateDir, 'storage.json');
const storageSubaccountsStatePath = path.join(stateDir, 'storage-subaccounts.json');
const fileStatePath = path.join(stateDir, 'file.json');
const pushStatePath = path.join(stateDir, 'push.json');
const pushDeliveryStatePath = path.join(stateDir, 'push-deliveries.json');
const compatPushNotifyPath = '/_compat/push-notify';

const subscriptions = new Map((await loadJson(pushStatePath, [])).map(record => [record.key, record]));
const pushDeliveries = new Map(
  (await loadJson(pushDeliveryStatePath, [])).map(record => [
    record.pubkey,
    Array.isArray(record.deliveries) ? record.deliveries : []
  ])
);

const stats = {
  startedAt: new Date().toISOString(),
  requestsTotal: 0,
  healthChecks: 0,
  pushSubscribe: 0,
  pushSubscribeBatch: 0,
  pushUnsubscribe: 0,
  pushUnsubscribeBatch: 0,
  subscriptionsList: 0,
  pushNotificationRequests: 0,
  pushNotificationsQueued: 0,
  pushProviderAttempts: 0,
  pushProviderDelivered: 0,
  pushProviderFailed: 0,
  errors: 0
};

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
const pushProviderTimeoutMs = parsePositiveInteger(process.env.PUSH_PROVIDER_TIMEOUT_MS, 2500, 30_000);
let pushStateWrite = Promise.resolve();
let pushDeliveryStateWrite = Promise.resolve();

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

async function savePushState() {
  pushStateWrite = pushStateWrite.catch(() => {}).then(() => saveJson(pushStatePath, [...subscriptions.values()]));
  await pushStateWrite;
}

async function savePushDeliveryState() {
  pushDeliveryStateWrite = pushDeliveryStateWrite.catch(() => {}).then(() => saveJson(
    pushDeliveryStatePath,
    [...pushDeliveries.entries()].map(([pubkey, deliveries]) => ({ pubkey, deliveries }))
  ));
  await pushDeliveryStateWrite;
}

function totalPushDeliveries() {
  let total = 0;
  for (const deliveries of pushDeliveries.values()) {
    total += deliveries.length;
  }
  return total;
}

function countProviderDeliveries(status) {
  let total = 0;
  for (const deliveries of pushDeliveries.values()) {
    total += deliveries.filter(delivery => delivery.provider?.status === status).length;
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

function providerUrlForService(service) {
  const directName = `PUSH_PROVIDER_${String(service).toUpperCase()}_URL`;
  const direct = process.env[directName];
  if (direct) {
    return direct;
  }

  const base = process.env.PUSH_PROVIDER_BASE_URL;
  if (!base) {
    return null;
  }

  return new URL(`/push/${encodeURIComponent(service)}`, base.endsWith('/') ? base : `${base}/`).toString();
}

function providerRequestHeadersForService(service) {
  const headers = { 'content-type': 'application/json' };
  const serviceKey = String(service).toUpperCase();
  const authHeader = process.env[`PUSH_PROVIDER_${serviceKey}_AUTH_HEADER`] ?? process.env.PUSH_PROVIDER_AUTH_HEADER;
  if (authHeader) {
    const separator = authHeader.indexOf(':');
    if (separator > 0) {
      const name = authHeader.slice(0, separator).trim();
      const value = authHeader.slice(separator + 1).trim();
      if (name && value) {
        headers[name] = value;
      }
    }
  }

  const bearerToken = process.env[`PUSH_PROVIDER_${serviceKey}_BEARER_TOKEN`] ?? process.env.PUSH_PROVIDER_BEARER_TOKEN;
  if (bearerToken && !Object.keys(headers).some(header => header.toLowerCase() === 'authorization')) {
    headers.authorization = `Bearer ${bearerToken}`;
  }

  return headers;
}

async function dispatchProviderDelivery(delivery) {
  const providerUrl = providerUrlForService(delivery.service);
  if (!providerUrl) {
    delivery.provider = {
      status: 'not_configured',
      attempts: 0,
      updatedAt: new Date().toISOString()
    };
    return delivery.provider;
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), pushProviderTimeoutMs);
  delivery.provider = {
    status: 'pending',
    attempts: Number(delivery.provider?.attempts ?? 0) + 1,
    url: providerUrl,
    updatedAt: new Date().toISOString()
  };
  incrementStat('pushProviderAttempts');

  try {
    const response = await fetch(providerUrl, {
      method: 'POST',
      headers: providerRequestHeadersForService(delivery.service),
      signal: controller.signal,
      body: JSON.stringify({
        service: delivery.service,
        token: delivery.token,
        pubkey: delivery.pubkey,
        hash: delivery.hash,
        namespace: delivery.namespace,
        timestamp: delivery.timestamp,
        expiration: delivery.expiration,
        data: delivery.data,
        bodyTooLarge: delivery.bodyTooLarge,
        service_info: delivery.service_info,
        enc_key: delivery.enc_key
      })
    });

    delivery.provider = {
      ...delivery.provider,
      status: response.ok ? 'delivered' : 'failed',
      httpStatus: response.status,
      updatedAt: new Date().toISOString()
    };
    incrementStat(response.ok ? 'pushProviderDelivered' : 'pushProviderFailed');
  } catch (error) {
    delivery.provider = {
      ...delivery.provider,
      status: 'failed',
      error: error instanceof Error ? error.message : String(error),
      updatedAt: new Date().toISOString()
    };
    incrementStat('pushProviderFailed');
  } finally {
    clearTimeout(timeout);
  }

  return delivery.provider;
}

async function queuePushNotification(request) {
  const notification = normalizePushNotification(request);
  if (!notification) {
    return { queued: 0 };
  }

  let queued = 0;
  const providerResults = [];
  for (const subscription of subscriptions.values()) {
    const namespaces = Array.isArray(subscription.namespaces)
      ? subscription.namespaces.map(value => Number(value))
      : [];
    if (subscription.pubkey !== notification.pubkey || !namespaces.includes(notification.namespace)) {
      continue;
    }

    const deliveryKey = `${subscription.key}:${notification.hash}`;
    let existing = pushDeliveries.get(notification.pubkey);
    if (!existing) {
      existing = [];
      pushDeliveries.set(notification.pubkey, existing);
    }

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
    const delivery = {
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
      queuedAt: new Date().toISOString(),
      provider: {
        status: 'pending',
        attempts: 0,
        updatedAt: new Date().toISOString()
      }
    };

    existing.push(delivery);
    if (existing.length > maxPushDeliveriesPerPubkey) {
      existing.splice(0, existing.length - maxPushDeliveriesPerPubkey);
    }

    await dispatchProviderDelivery(delivery);
    providerResults.push(delivery.provider);
    queued += 1;
  }

  if (queued > 0) {
    incrementStat('pushNotificationsQueued', queued);
    await savePushDeliveryState();
  }

  return { queued, provider: providerResults };
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

  const pubkey = String(request.pubkey ?? '');
  const service = String(request.service ?? '');
  if (!pubkey || !service) {
    return invalidPushRequest('Invalid request: pubkey and service are required');
  }

  if (pubkey.startsWith('05')) {
    const sessionEd25519 = String(request.session_ed25519 ?? '');
    if (!sessionEd25519 || !isHexOrBase64Bytes(sessionEd25519, 32)) {
      return invalidPushRequest();
    }
  }

  const subaccount = String(request.subaccount ?? '');
  const subaccountSig = String(request.subaccount_sig ?? '');
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

  const sigTs = Number(request.sig_ts);
  if (!Number.isFinite(sigTs) || sigTs <= 0) {
    return invalidPushRequest();
  }

  const signature = String(request.signature ?? '');
  if (!signature || !isHexOrBase64Bytes(signature, 64)) {
    return invalidPushRequest();
  }

  if (!request.service_info || typeof request.service_info !== 'object' || Array.isArray(request.service_info)) {
    return invalidPushRequest();
  }

  const token = String(request.service_info.token ?? '');
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

function verifyPushRequestSignature(request, operation) {
  const verification = verifyStorageSignature({
    operation,
    pubkey: request.pubkey,
    pubkeyEd25519: request.session_ed25519,
    signature: request.signature,
    subaccount: request.subaccount,
    subaccountSig: request.subaccount_sig,
    requiredSubaccountAccess: storageSubaccountAccess.READ,
    timestamp: request.sig_ts,
    messages: request.namespaces,
    wantData: request.data
  });

  if (!verification.checked || verification.verified) {
    return null;
  }

  return invalidPushRequest(verification.reason ?? 'Signature verification failed', pushSubscribeCode.ERROR);
}

function processPushSubscribeRequest(request) {
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

  const encKey = String(request.enc_key ?? '');
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

  for (let index = 0; index < namespaces.length - 1; index += 1) {
    if (namespaces[index] === namespaces[index + 1]) {
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

async function handlePush(req, res, url) {
  if (req.method === 'POST' && url.pathname === compatPushNotifyPath) {
    incrementStat('pushNotificationRequests');

    let changed = false;
    if (prunePushExpired()) {
      changed = true;
    }

    const request = await bodyJson(req);
    const result = await queuePushNotification(request);
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
          storageMessages: 0,
          revokedSubaccounts: 0,
          files: 0,
          subscriptions: subscriptions.size,
          pushDeliveries: totalPushDeliveries(),
          pushProviderDelivered: countProviderDeliveries('delivered'),
          pushProviderFailed: countProviderDeliveries('failed'),
          pushProviderNotConfigured: countProviderDeliveries('not_configured')
        },
        state: {
          dir: stateDir,
          storage: storageStatePath,
          storageSubaccounts: storageSubaccountsStatePath,
          file: fileStatePath,
          push: pushStatePath,
          pushDeliveries: pushDeliveryStatePath
        }
      });
      return;
    }

    if (await handlePush(req, res, url)) {
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
