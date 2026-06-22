import assert from 'node:assert/strict';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { createTestStorageSigningIdentity } from '../tools/compat-services/storage-signatures.mjs';

const canaryPlan = Object.freeze({
  readyTimeoutMs: Number(process.env.DEEP_PUSH_PROVIDER_CANARY_READY_TIMEOUT_MS ?? 30_000),
  deliveryPollAttempts: Number(process.env.DEEP_PUSH_PROVIDER_CANARY_POLL_ATTEMPTS ?? 40),
  deliveryPollDelayMs: Number(process.env.DEEP_PUSH_PROVIDER_CANARY_POLL_DELAY_MS ?? 250),
  namespace: Number(process.env.DEEP_PUSH_PROVIDER_CANARY_NAMESPACE ?? 2),
  service: String(process.env.DEEP_PUSH_PROVIDER_CANARY_SERVICE ?? 'firebase'),
  releaseLane: String(process.env.DEEP_PUSH_PROVIDER_CANARY_LANE ?? process.env.DEEP_RELEASE_LANE ?? 'local')
});

const validEncKey = 'abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd';

function artifactDirectory() {
  return process.env.DEEP_ARTIFACT_DIR ?? resolve('artifacts', 'test-results');
}

function writeArtifact(value) {
  const directory = artifactDirectory();
  mkdirSync(directory, { recursive: true });
  writeFileSync(join(directory, 'push-provider-canary.json'), `${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

function resolvePushBaseUrl() {
  const statsUrl = process.env.DEEP_PUSH_STATS_URL;
  if (statsUrl) {
    const parsed = new URL(statsUrl);
    return `${parsed.protocol}//${parsed.host}`;
  }

  return process.env.DEEP_PUSH_URL ?? 'http://127.0.0.1:19102';
}

function providerUrlConfigForService(service) {
  const serviceKey = String(service).toUpperCase();
  const directName = `PUSH_PROVIDER_${serviceKey}_URL`;
  if (process.env[directName]) {
    return { source: directName, url: process.env[directName] };
  }

  if (process.env.PUSH_PROVIDER_BASE_URL) {
    return { source: 'PUSH_PROVIDER_BASE_URL', url: process.env.PUSH_PROVIDER_BASE_URL };
  }

  return { source: null, url: null };
}

function providerAuthConfiguredForService(service) {
  const serviceKey = String(service).toUpperCase();
  return Boolean(
    process.env[`PUSH_PROVIDER_${serviceKey}_AUTH_HEADER`]
    || process.env[`PUSH_PROVIDER_${serviceKey}_BEARER_TOKEN`]
    || process.env.PUSH_PROVIDER_AUTH_HEADER
    || process.env.PUSH_PROVIDER_BEARER_TOKEN
  );
}

function providerHostForService(service) {
  const config = providerUrlConfigForService(service);
  if (!config.url) {
    return null;
  }

  try {
    return new URL(config.url).host;
  } catch {
    return null;
  }
}

function currentSigTs() {
  return Math.floor(Date.now() / 1000);
}

function assertSupportedService(service) {
  assert.ok(
    ['apns', 'firebase', 'huawei'].includes(service),
    `DEEP_PUSH_PROVIDER_CANARY_SERVICE must be apns, firebase, or huawei; got ${service}`
  );
}

async function delay(ms) {
  await new Promise(resolve => setTimeout(resolve, ms));
}

async function assertOk(response, context) {
  if (response.ok) {
    return;
  }

  const body = await response.text();
  assert.equal(response.ok, true, `${response.status} ${context}: ${body}`);
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

async function waitForReady(baseUrl) {
  const deadline = Date.now() + canaryPlan.readyTimeoutMs;
  while (Date.now() < deadline) {
    try {
      const body = await getJson(baseUrl, '/health/ready');
      assert.equal(body.ok, true, 'push service reported non-ready health payload');
      return body;
    } catch {
      await delay(250);
    }
  }

  throw new Error(`push service did not become ready within ${canaryPlan.readyTimeoutMs}ms`);
}

function createSubscribePayload(identity, service, token) {
  const pubkey = identity.sessionPubkey ?? identity.directPubkey;
  const sigTs = currentSigTs();
  const namespaces = [canaryPlan.namespace];
  const wantData = true;
  return {
    pubkey,
    ...(pubkey.startsWith('05') ? { session_ed25519: identity.pubkeyEd25519 } : {}),
    data: wantData,
    sig_ts: sigTs,
    signature: identity.signPushSubscribe(pubkey, sigTs, wantData, namespaces),
    service,
    service_info: { token },
    enc_key: validEncKey,
    namespaces,
    idempotency_key: `push-provider-canary-${Date.now()}`
  };
}

function createUnsubscribePayload(identity, subscription) {
  const sigTs = currentSigTs();
  return {
    pubkey: subscription.pubkey,
    ...(subscription.pubkey.startsWith('05') ? { session_ed25519: identity.pubkeyEd25519 } : {}),
    sig_ts: sigTs,
    signature: identity.signPushUnsubscribe(subscription.pubkey, sigTs),
    service: subscription.service,
    service_info: subscription.service_info
  };
}

function sanitizeProvider(provider) {
  if (!provider || typeof provider !== 'object') {
    return provider;
  }

  return {
    status: provider.status,
    attempts: provider.attempts,
    httpStatus: provider.httpStatus,
    updatedAt: provider.updatedAt,
    hasConfiguredUrl: Boolean(provider.url),
    error: provider.error
  };
}

async function waitForDelivery(baseUrl, pubkey, hash) {
  let lastSnapshot = null;
  for (let attempt = 1; attempt <= canaryPlan.deliveryPollAttempts; attempt += 1) {
    lastSnapshot = await getJson(baseUrl, `/subscriptions/${encodeURIComponent(pubkey)}`);
    const delivery = lastSnapshot.deliveries.find(candidate => candidate.hash === hash);
    if (delivery) {
      return { attempt, snapshot: lastSnapshot, delivery };
    }

    await delay(canaryPlan.deliveryPollDelayMs);
  }

  throw new Error(`push provider canary delivery ${hash} was not recorded; last snapshot: ${JSON.stringify(lastSnapshot)}`);
}

async function main() {
  assertSupportedService(canaryPlan.service);

  const baseUrl = resolvePushBaseUrl();
  const identity = createTestStorageSigningIdentity();
  const configuredToken = process.env.DEEP_PUSH_PROVIDER_CANARY_TOKEN;
  const token = typeof configuredToken === 'string' && configuredToken.trim().length > 0
    ? configuredToken.trim()
    : `deep-provider-canary-${Date.now()}`;
  const hash = `push-provider-canary-${Date.now()}`;
  const data = Buffer.from(`Deep push provider canary ${new Date().toISOString()}`, 'utf8').toString('base64');
  let subscription = null;

  try {
    await waitForReady(baseUrl);
    const statsBefore = await getJson(baseUrl, '/stats');

    const subscribePayload = createSubscribePayload(identity, canaryPlan.service, token);
    const subscribe = await postJson(baseUrl, '/subscribe', subscribePayload);
    assert.equal(subscribe.success, true, 'push canary subscription failed');
    subscription = {
      pubkey: subscribePayload.pubkey,
      service: subscribePayload.service,
      service_info: subscribePayload.service_info
    };

    const notify = await postJson(baseUrl, '/_compat/push-notify', {
      pubkey: subscribePayload.pubkey,
      hash,
      namespace: canaryPlan.namespace,
      timestamp: Date.now(),
      expiration: Date.now() + 60_000,
      data
    });
    assert.equal(notify.queued, 1, 'push canary notification was not queued');

    const deliveryResult = await waitForDelivery(baseUrl, subscribePayload.pubkey, hash);
    const provider = deliveryResult.delivery.provider;
    assert.equal(provider?.status, 'delivered', `push provider canary did not deliver: ${JSON.stringify(sanitizeProvider(provider))}`);

    const statsAfterDelivery = await getJson(baseUrl, '/stats');
    assert.ok(
      statsAfterDelivery.inventory.pushProviderDelivered >= statsBefore.inventory.pushProviderDelivered + 1,
      'push provider delivered inventory did not increase'
    );

    const unsubscribe = await postJson(baseUrl, '/unsubscribe', createUnsubscribePayload(identity, subscription));
    assert.equal(unsubscribe.success, true, 'push canary unsubscribe failed');

    const providerUrlConfig = providerUrlConfigForService(canaryPlan.service);
    const tokenSource = token === configuredToken?.trim() && token.length > 0 ? 'env' : 'generated';
    const artifact = {
      status: 'ok',
      generatedAt: new Date().toISOString(),
      pushUrl: baseUrl,
      service: canaryPlan.service,
      namespace: canaryPlan.namespace,
      releaseLane: canaryPlan.releaseLane,
      tokenSource,
      hash,
      subscribe,
      notify,
      deliveryPollAttempts: deliveryResult.attempt,
      provider: sanitizeProvider(provider),
      providerEvidence: {
        service: canaryPlan.service,
        releaseLane: canaryPlan.releaseLane,
        tokenSource,
        providerUrlSource: providerUrlConfig.source,
        providerHost: providerHostForService(canaryPlan.service),
        providerAuthConfigured: providerAuthConfiguredForService(canaryPlan.service)
      },
      statsBefore,
      statsAfterDelivery,
      unsubscribe
    };
    writeArtifact(artifact);
  } catch (error) {
    writeArtifact({
      status: 'error',
      generatedAt: new Date().toISOString(),
      pushUrl: baseUrl,
      service: canaryPlan.service,
      namespace: canaryPlan.namespace,
      releaseLane: canaryPlan.releaseLane,
      error: error instanceof Error ? error.stack ?? error.message : String(error)
    });
    throw error;
  }
}

main().catch(error => {
  console.error(error);
  process.exitCode = 1;
});
