import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import {
  createAvatarAuthorizationHeaders,
  createTestStorageSigningIdentity
} from '../tools/compat-services/storage-signatures.mjs';
import { registrationPayloads } from '../../deep-tests-e2e/src/fixtures.mjs';

const restartPlan = Object.freeze({
  namespace: 2,
  readyTimeoutMs: 30_000,
  readyPollDelayMs: 250,
  deliveryPollAttempts: 40,
  deliveryPollDelayMs: 250
});

function writeArtifact(name, value) {
  const directory = process.env.DEEP_ARTIFACT_DIR;
  if (!directory) {
    return;
  }

  mkdirSync(directory, { recursive: true });
  writeFileSync(join(directory, name), JSON.stringify(value, null, 2));
}

function resolveHostServiceBaseUrl(serviceEnvName, statsEnvName, fallbackUrl) {
  const statsUrl = process.env[statsEnvName];
  if (statsUrl) {
    const parsed = new URL(statsUrl);
    return `${parsed.protocol}//${parsed.host}`;
  }

  return process.env[serviceEnvName] ?? fallbackUrl;
}

async function assertOk(response, context) {
  if (response.ok) {
    return;
  }

  const bodyText = await response.text();
  assert.equal(response.ok, true, `${response.status} ${context}: ${bodyText}`);
}

async function getJson(baseUrl, path) {
  const response = await fetch(new URL(path, baseUrl));
  await assertOk(response, `GET ${path}`);
  return response.json();
}

async function postJson(baseUrl, path, payload) {
  const response = await fetch(new URL(path, baseUrl), {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(payload)
  });
  await assertOk(response, `POST ${path}`);
  return response.json();
}

async function postAccepted(baseUrl, path, payload) {
  const response = await fetch(new URL(path, baseUrl), {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(payload)
  });
  assert.equal(response.status, 202, `POST ${path} must be accepted`);
}

async function getJsonWithHeaders(baseUrl, path, headers) {
  const response = await fetch(new URL(path, baseUrl), { headers });
  await assertOk(response, `GET ${path}`);
  return response.json();
}

async function postBytes(baseUrl, path, bytes, contentType = 'application/octet-stream') {
  const response = await fetch(new URL(path, baseUrl), {
    method: 'POST',
    headers: { 'content-type': contentType },
    body: bytes
  });
  await assertOk(response, `POST ${path}`);
  return response.json();
}

async function getBytes(baseUrl, path) {
  const response = await fetch(new URL(path, baseUrl));
  await assertOk(response, `GET ${path}`);
  return Buffer.from(await response.arrayBuffer());
}

function delay(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function waitForReady(serviceName, baseUrl, healthPath = '/health/ready', timeoutMs = restartPlan.readyTimeoutMs) {
  const deadline = Date.now() + timeoutMs;

  while (Date.now() < deadline) {
    try {
      const response = await fetch(new URL(healthPath, baseUrl));
      if (response.ok) {
        const body = await response.json();
        assert.equal(body.ok, true, `${serviceName} reported non-ready health payload`);
        return body;
      }
    } catch {
      // Keep polling until the restart finishes.
    }

    await delay(restartPlan.readyPollDelayMs);
  }

  throw new Error(`${serviceName} did not become ready within ${timeoutMs}ms`);
}

async function waitForPushDeliveries(baseUrl, pubkey, expectedCount) {
  let lastSnapshot = null;

  for (let attempt = 1; attempt <= restartPlan.deliveryPollAttempts; attempt += 1) {
    lastSnapshot = await getJson(baseUrl, `/subscriptions/${encodeURIComponent(pubkey)}`);
    if (lastSnapshot.deliveries.length >= expectedCount) {
      return {
        attempts: attempt,
        snapshot: lastSnapshot
      };
    }

    await delay(restartPlan.deliveryPollDelayMs);
  }

  throw new Error(`push deliveries for ${pubkey} did not reach ${expectedCount}; last snapshot: ${JSON.stringify(lastSnapshot)}`);
}

function createSignedStorageStorePayload(identity, overrides = {}) {
  const payload = { ...overrides };
  const namespace = Number(payload.namespace ?? 0);
  const signatureTimestamp = Number(payload.sig_timestamp ?? payload.sigTimestamp ?? payload.timestamp ?? Date.now());

  return {
    pubkey: identity.directPubkey,
    timestamp: signatureTimestamp,
    ttl: 60_000,
    namespace,
    data: Buffer.from('backend external restart rehearsal store', 'utf8').toString('base64'),
    signature: identity.signStore(namespace, signatureTimestamp),
    ...payload
  };
}

function createSignedStorageRetrievePayload(identity, overrides = {}) {
  const payload = { ...overrides };
  const namespace = Number(payload.namespace ?? 0);
  const timestamp = Number(payload.timestamp ?? Date.now());

  return {
    pubkey: identity.directPubkey,
    namespace,
    timestamp,
    signature: identity.signRetrieve(namespace, timestamp),
    ...payload
  };
}

function currentSigTs() {
  return Math.floor(Date.now() / 1000);
}

function createCurrentPushSubscriptionPayload(identity, overrides = {}) {
  const payload = { ...registrationPayloads.pushSubscription, ...overrides };
  const sigTs = currentSigTs();
  const namespaces = Array.isArray(payload.namespaces) ? payload.namespaces.map(value => Number(value)) : [];
  const wantData = payload.data === undefined ? true : Boolean(payload.data);

  return {
    ...payload,
    pubkey: identity.directPubkey,
    session_ed25519: undefined,
    subkey_tag: undefined,
    data: wantData,
    namespaces,
    sig_ts: sigTs,
    signature: identity.signPushSubscribe(identity.directPubkey, sigTs, wantData, namespaces)
  };
}

function createPushUnsubscribePayload(identity, subscription) {
  const sigTs = currentSigTs();
  return {
    pubkey: subscription.pubkey,
    sig_ts: sigTs,
    signature: identity.signPushUnsubscribe(subscription.pubkey, sigTs),
    service: subscription.service,
    service_info: subscription.service_info
  };
}

async function getServiceStats(urls) {
  const [storage, file, push, registry] = await Promise.all([
    getJson(urls.storage, '/stats'),
    getJson(urls.file, '/stats'),
    getJson(urls.push, '/stats'),
    getJson(urls.registry, '/health/live')
  ]);

  return { storage, file, push, registry };
}

async function putAvatar(baseUrl, path, bytes, contentType, identity) {
  const response = await fetch(new URL(path, baseUrl), {
    method: 'PUT',
    headers: {
      'content-type': contentType,
      ...createAvatarAuthorizationHeaders(identity, path, bytes)
    },
    body: bytes
  });
  await assertOk(response, `PUT ${path}`);
  return response.json();
}

function restartManagedExternalServices() {
  const composeFile = process.env.DEEP_COMPOSE_FILE;
  assert.ok(composeFile, 'DEEP_COMPOSE_FILE must be set for backend-external restart rehearsal');

  const profile = process.env.DEEP_EXTERNAL_PROFILE ?? 'backend-external';
  const restart = spawnSync(
    'docker',
    ['compose', '-f', composeFile, '--profile', profile, 'restart', 'storage-service', 'file-service', 'push-service', 'registry'],
    {
      stdio: 'inherit',
      env: process.env
    }
  );

  if (restart.error) {
    throw restart.error;
  }

  assert.equal(restart.status, 0, `docker compose restart failed with exit code ${restart.status}`);
}

function sortStrings(values) {
  return [...values].map(value => String(value)).sort((left, right) => left.localeCompare(right));
}

function createSignedCallSignal(senderIdentity, recipientIdentity) {
  const createdAtUnixMs = Date.now();
  const nonce = randomBytes(16).toString('hex');
  const request = {
    callId: `restart-call-${createdAtUnixMs}`,
    conversationId: recipientIdentity.sessionPubkey,
    sender: { value: senderIdentity.sessionPubkey },
    recipient: { value: recipientIdentity.sessionPubkey },
    type: 0,
    payload: `sealed-v1:${Buffer.from('restart-call-envelope').toString('base64')}`,
    createdAt: new Date(createdAtUnixMs).toISOString(),
    senderEd25519: senderIdentity.pubkeyEd25519,
    signature: null,
    nonce
  };
  request.signature = senderIdentity.signMessage(JSON.stringify({
    version: 'deep-call-signal-v2',
    callId: request.callId,
    conversationId: request.conversationId,
    sender: request.sender.value,
    recipient: request.recipient.value,
    type: 'Offer',
    payload: request.payload,
    createdAtUnixMs,
    senderEd25519: request.senderEd25519,
    nonce
  }));
  return request;
}

function createSignedCallGet(identity, route, purpose) {
  const timestamp = Math.floor(Date.now() / 1000);
  const nonce = randomBytes(16).toString('hex');
  const path = `/api/calls/${route}/${identity.sessionPubkey}`;
  return {
    path,
    headers: {
      'X-Deep-Ed25519': identity.pubkeyEd25519,
      'X-Deep-Timestamp': String(timestamp),
      'X-Deep-Nonce': nonce,
      'X-Deep-Signature': identity.signMessage(
        `${purpose}\nGET\n${path}\n${identity.sessionPubkey}\n${timestamp}\n${nonce}`)
    }
  };
}

async function main() {
  const urls = {
    storage: resolveHostServiceBaseUrl('DEEP_STORAGE_URL', 'DEEP_STORAGE_STATS_URL', 'http://127.0.0.1:19100'),
    file: resolveHostServiceBaseUrl('DEEP_FILE_URL', 'DEEP_FILE_STATS_URL', 'http://127.0.0.1:19101'),
    push: resolveHostServiceBaseUrl('DEEP_PUSH_URL', 'DEEP_PUSH_STATS_URL', 'http://127.0.0.1:19102'),
    registry: process.env.DEEP_REGISTRY_URL ?? 'http://127.0.0.1:18080'
  };

  await Promise.all([
    waitForReady('storage-service', urls.storage),
    waitForReady('file-service', urls.file),
    waitForReady('push-service', urls.push),
    waitForReady('registry', urls.registry, '/health/live')
  ]);

  const storageIdentity = createTestStorageSigningIdentity();
  const pushToken = `${registrationPayloads.pushSubscription.service_info.token}-restart-${Date.now()}`;
  const pushSubscription = createCurrentPushSubscriptionPayload(storageIdentity, {
    namespaces: [restartPlan.namespace],
    service_info: {
      ...registrationPayloads.pushSubscription.service_info,
      token: pushToken
    }
  });
  const filePayload = Buffer.from(`backend-external-restart-file-${Date.now()}`, 'utf8');
  const avatarPayload = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x01]);
  const callSender = createTestStorageSigningIdentity();
  const callRecipient = createTestStorageSigningIdentity();
  const callSignal = createSignedCallSignal(callSender, callRecipient);

  const pushSubscribe = await postJson(urls.push, '/subscribe', pushSubscription);
  assert.equal(pushSubscribe.success, true);

  const storedBeforeRestart = await postJson(
    urls.storage,
    '/storage/store',
    createSignedStorageStorePayload(storageIdentity, {
      namespace: restartPlan.namespace,
      timestamp: Date.now(),
      ttl: 120_000,
      data: Buffer.from('backend-external-restart-before', 'utf8').toString('base64')
    })
  );

  const preRestartDelivery = await waitForPushDeliveries(urls.push, storageIdentity.directPubkey, 1);
  assert.equal(preRestartDelivery.snapshot.subscriptions.length, 1);
  assert.equal(preRestartDelivery.snapshot.deliveries.length, 1);
  assert.equal(preRestartDelivery.snapshot.deliveries[0].hash, storedBeforeRestart.hash);
  assert.equal(preRestartDelivery.snapshot.deliveries[0].token, pushToken);

  const uploadedBeforeRestart = await postBytes(urls.file, '/file', filePayload, 'text/plain');
  const fileInfoBeforeRestart = await getJson(urls.file, `/file/${uploadedBeforeRestart.id}/info`);
  const fileBytesBeforeRestart = await getBytes(urls.file, `/file/${uploadedBeforeRestart.id}`);
  assert.deepEqual(fileBytesBeforeRestart, filePayload);

  const avatarPath = `/avatar/${encodeURIComponent(storageIdentity.sessionPubkey)}`;
  const avatarBeforeRestart = await putAvatar(
    urls.file,
    avatarPath,
    avatarPayload,
    'image/png',
    storageIdentity
  );
  const avatarInfoBeforeRestart = await getJson(
    urls.file,
    `${avatarPath}/info`
  );
  const avatarBytesBeforeRestart = await getBytes(urls.file, avatarPath);
  assert.equal(avatarBeforeRestart.fileId, avatarInfoBeforeRestart.fileId);
  assert.equal(avatarInfoBeforeRestart.contentType, 'image/png');
  assert.deepEqual(avatarBytesBeforeRestart, avatarPayload);

  await postAccepted(urls.registry, '/api/calls/signal', callSignal);

  const statsBeforeRestart = await getServiceStats(urls);

  restartManagedExternalServices();

  await Promise.all([
    waitForReady('storage-service', urls.storage),
    waitForReady('file-service', urls.file),
    waitForReady('push-service', urls.push),
    waitForReady('registry', urls.registry, '/health/live')
  ]);

  const statsAfterRestart = await getServiceStats(urls);
  assert.equal(
    statsAfterRestart.storage.inventory.storageMessages,
    statsBeforeRestart.storage.inventory.storageMessages,
    'storage inventory changed across compose restart'
  );
  assert.equal(
    statsAfterRestart.file.inventory.files,
    statsBeforeRestart.file.inventory.files,
    'file inventory changed across compose restart'
  );
  assert.equal(
    statsAfterRestart.file.inventory.avatars,
    statsBeforeRestart.file.inventory.avatars,
    'avatar inventory changed across compose restart'
  );
  assert.equal(
    statsAfterRestart.push.inventory.subscriptions,
    statsBeforeRestart.push.inventory.subscriptions,
    'push subscription inventory changed across compose restart'
  );
  assert.equal(
    statsAfterRestart.push.inventory.pushDeliveries,
    statsBeforeRestart.push.inventory.pushDeliveries,
    'push delivery inventory changed across compose restart'
  );
  const retrievedAfterRestart = await postJson(
    urls.storage,
    '/storage/retrieve',
    createSignedStorageRetrievePayload(storageIdentity, {
      namespace: restartPlan.namespace,
      timestamp: Date.now()
    })
  );
  assert.equal(retrievedAfterRestart.messages.length, 1);
  assert.equal(retrievedAfterRestart.messages[0].hash, storedBeforeRestart.hash);

  const fileInfoAfterRestart = await getJson(urls.file, `/file/${uploadedBeforeRestart.id}/info`);
  assert.equal(fileInfoAfterRestart.size, fileInfoBeforeRestart.size);
  assert.equal(fileInfoAfterRestart.uploaded, fileInfoBeforeRestart.uploaded);
  assert.equal(fileInfoAfterRestart.expires, fileInfoBeforeRestart.expires);

  const fileBytesAfterRestart = await getBytes(urls.file, `/file/${uploadedBeforeRestart.id}`);
  assert.deepEqual(fileBytesAfterRestart, filePayload);

  const avatarInfoAfterRestart = await getJson(
    urls.file,
    `${avatarPath}/info`
  );
  assert.deepEqual(avatarInfoAfterRestart, avatarInfoBeforeRestart);
  const avatarBytesAfterRestart = await getBytes(urls.file, avatarPath);
  assert.deepEqual(avatarBytesAfterRestart, avatarPayload);

  const subscriptionsAfterRestart = await getJson(
    urls.push,
    `/subscriptions/${encodeURIComponent(storageIdentity.directPubkey)}`
  );
  assert.equal(subscriptionsAfterRestart.subscriptions.length, 1);
  assert.equal(subscriptionsAfterRestart.subscriptions[0].service_info.token, pushToken);
  assert.equal(subscriptionsAfterRestart.deliveries.length, 1);
  assert.equal(subscriptionsAfterRestart.deliveries[0].hash, storedBeforeRestart.hash);
  assert.equal(subscriptionsAfterRestart.deliveries[0].token, pushToken);

  const inboxRequest = createSignedCallGet(callRecipient, 'inbox', 'deep-call-inbox-v2');
  const callInboxAfterRestart = await getJsonWithHeaders(
    urls.registry,
    inboxRequest.path,
    inboxRequest.headers);
  assert.equal(callInboxAfterRestart.length, 1);
  assert.equal(callInboxAfterRestart[0].callId, callSignal.callId);

  const extendedAfterRestart = await postJson(urls.file, `/file/${uploadedBeforeRestart.id}/extend`, {});
  assert.equal(extendedAfterRestart.size, fileInfoAfterRestart.size);
  assert.equal(extendedAfterRestart.uploaded, fileInfoAfterRestart.uploaded);
  assert.ok(extendedAfterRestart.expires >= fileInfoAfterRestart.expires);

  const storedAfterRestart = await postJson(
    urls.storage,
    '/storage/store',
    createSignedStorageStorePayload(storageIdentity, {
      namespace: restartPlan.namespace,
      timestamp: Date.now(),
      ttl: 120_000,
      data: Buffer.from('backend-external-restart-after', 'utf8').toString('base64')
    })
  );

  const postRestartDelivery = await waitForPushDeliveries(urls.push, storageIdentity.directPubkey, 2);
  assert.equal(postRestartDelivery.snapshot.subscriptions.length, 1);
  assert.equal(postRestartDelivery.snapshot.deliveries.length, 2);
  const postRestartDeliveryRecord = postRestartDelivery.snapshot.deliveries.find(
    delivery => delivery.hash === storedAfterRestart.hash
  );
  assert.ok(postRestartDeliveryRecord, 'post-restart push delivery was not recorded');
  assert.equal(postRestartDeliveryRecord.token, pushToken);

  const retrievedFinal = await postJson(
    urls.storage,
    '/storage/retrieve',
    createSignedStorageRetrievePayload(storageIdentity, {
      namespace: restartPlan.namespace,
      timestamp: Date.now()
    })
  );
  assert.equal(retrievedFinal.messages.length, 2);
  assert.deepEqual(
    sortStrings(retrievedFinal.messages.map(message => message.hash)),
    sortStrings([storedBeforeRestart.hash, storedAfterRestart.hash])
  );

  const pushUnsubscribe = await postJson(
    urls.push,
    '/unsubscribe',
    createPushUnsubscribePayload(storageIdentity, pushSubscription)
  );
  assert.equal(pushUnsubscribe.success, true);
  assert.equal(pushUnsubscribe.removed, true);

  const statsAfterRehearsal = await getServiceStats(urls);
  assert.ok(
    statsAfterRehearsal.storage.inventory.storageMessages >= statsAfterRestart.storage.inventory.storageMessages + 1,
    'storage inventory did not reflect the post-restart store'
  );
  assert.equal(
    statsAfterRehearsal.push.inventory.subscriptions,
    statsAfterRestart.push.inventory.subscriptions - 1,
    'push subscription inventory did not reflect unsubscribe cleanup'
  );
  assert.ok(
    statsAfterRehearsal.push.inventory.pushDeliveries >= statsAfterRestart.push.inventory.pushDeliveries + 1,
    'push delivery inventory did not reflect post-restart notify activity'
  );
  writeArtifact('backend-restart-smoke.json', {
    status: 'ok',
    backendMode: process.env.DEEP_BACKEND_MODE ?? 'external',
    managedExternalProfile: process.env.DEEP_EXTERNAL_PROFILE ?? 'backend-external',
    rehearsalUrls: urls,
    pushToken,
    pushSubscribe,
    storedBeforeRestart,
    uploadedBeforeRestart,
    fileInfoBeforeRestart,
    avatarBeforeRestart,
    avatarInfoBeforeRestart,
    callRegistry: {
      authenticatedSignalAcceptedBeforeRestart: true,
      registryRestarted: true,
      authenticatedInboxRetrievedAfterRestart: true,
      exactSignalCountAfterRestart: callInboxAfterRestart.length
    },
    statsBeforeRestart,
    statsAfterRestart,
    retrievedAfterRestart,
    fileInfoAfterRestart,
    avatarInfoAfterRestart,
    subscriptionsAfterRestart,
    extendedAfterRestart,
    storedAfterRestart,
    retrievedFinal,
    preRestartDeliveryAttempts: preRestartDelivery.attempts,
    postRestartDeliveryAttempts: postRestartDelivery.attempts,
    pushUnsubscribe,
    statsAfterRehearsal
  });
}

main().catch(error => {
  writeArtifact('backend-restart-smoke.json', {
    status: 'error',
    backendMode: process.env.DEEP_BACKEND_MODE ?? 'external',
    managedExternalProfile: process.env.DEEP_EXTERNAL_PROFILE ?? 'backend-external',
    error: error instanceof Error ? error.stack ?? error.message : String(error)
  });
  console.error(error);
  process.exitCode = 1;
});
