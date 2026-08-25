import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createTestStorageSigningIdentity } from '../tools/compat-services/storage-signatures.mjs';
import { registrationPayloads } from '../../deep-tests-e2e/src/fixtures.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const devopsRoot = path.resolve(__dirname, '..');
const workspaceRoot = path.resolve(devopsRoot, '..');
const composeFile = process.env.DEEP_COMPOSE_FILE ?? path.join(devopsRoot, 'docker-compose.yml');
const artifactDir = process.env.DEEP_ARTIFACT_DIR ?? path.join(devopsRoot, 'artifacts', 'test-results');
const artifactPath = path.join(artifactDir, 'rollback-drill.json');
const args = new Set(process.argv.slice(2));
const keepStack = args.has('--keep-stack') || process.env.DEEP_ROLLBACK_KEEP_STACK === 'true';
const projectName = process.env.DEEP_ROLLBACK_COMPOSE_PROJECT ?? 'deep-rollback-drill';
const namespace = 2;
const readyTimeoutMs = Number(process.env.DEEP_ROLLBACK_READY_TIMEOUT_MS ?? 120_000);
const readyPollDelayMs = 500;

const urls = Object.freeze({
  router: process.env.XNODE_URL ?? 'http://127.0.0.1:18081',
  registry: process.env.DEEP_REGISTRY_URL ?? 'http://127.0.0.1:18080',
  staking: process.env.DEEP_STAKING_URL ?? 'http://127.0.0.1:18082',
  contracts: process.env.DEEP_DEVNET_RPC_URL ?? 'http://127.0.0.1:18545',
  storage: process.env.DEEP_STORAGE_STATS_URL
    ? new URL('/', process.env.DEEP_STORAGE_STATS_URL).origin
    : 'http://127.0.0.1:19100',
  file: process.env.DEEP_FILE_STATS_URL
    ? new URL('/', process.env.DEEP_FILE_STATS_URL).origin
    : 'http://127.0.0.1:19101',
  push: process.env.DEEP_PUSH_STATS_URL
    ? new URL('/', process.env.DEEP_PUSH_STATS_URL).origin
    : 'http://127.0.0.1:19102'
});

const composeEnv = {
  ...process.env,
  DEEP_ROOT: process.env.DEEP_ROOT ?? workspaceRoot,
  DEEP_DEVOPS_DIR: process.env.DEEP_DEVOPS_DIR ?? devopsRoot,
  XNODE_DOCKERFILE: process.env.XNODE_DOCKERFILE ?? path.join(devopsRoot, 'docker', 'xnode-xray.Dockerfile'),
  XNODE_ASPNETCORE_ENVIRONMENT: process.env.XNODE_ASPNETCORE_ENVIRONMENT ?? 'Production',
  XNODE_VLESS_MOCK_PROCESS: process.env.XNODE_VLESS_MOCK_PROCESS ?? 'false',
  XNODE_XRAY_EXECUTABLE_PATH: process.env.XNODE_XRAY_EXECUTABLE_PATH ?? '/usr/local/bin/xray',
  XNODE_TRANSPORT_MODE: process.env.XNODE_TRANSPORT_MODE ?? 'Tcp',
  DEEP_STORAGE_PUSH_NOTIFY_URL: process.env.DEEP_STORAGE_PUSH_NOTIFY_URL ?? 'http://push-service:8080'
};

const checks = [];
const diagnostics = {};

function addCheck(name, passed, details = {}) {
  checks.push({ name, passed: Boolean(passed), ...details });
  assert.equal(Boolean(passed), true, `${name} failed: ${JSON.stringify(details)}`);
}

function writeArtifact(value) {
  mkdirSync(artifactDir, { recursive: true });
  writeFileSync(artifactPath, JSON.stringify(value, null, 2));
}

function run(command, commandArgs, options = {}) {
  const result = spawnSync(command, commandArgs, {
    cwd: devopsRoot,
    env: composeEnv,
    encoding: 'utf8',
    stdio: options.inherit ? 'inherit' : 'pipe'
  });

  if (result.error) {
    throw result.error;
  }

  if (options.allowFailure !== true && result.status !== 0) {
    throw new Error(`${command} ${commandArgs.join(' ')} failed with exit code ${result.status}\n${result.stdout ?? ''}\n${result.stderr ?? ''}`);
  }

  return {
    status: result.status,
    stdout: result.stdout ?? '',
    stderr: result.stderr ?? ''
  };
}

function compose(commandArgs, options = {}) {
  return run('docker', ['compose', '-p', projectName, '-f', composeFile, ...commandArgs], options);
}

function delay(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function assertOk(response, context) {
  if (response.ok) {
    return;
  }

  throw new Error(`${context} failed with HTTP ${response.status}: ${await response.text()}`);
}

async function getJson(baseUrl, endpoint) {
  const response = await fetch(new URL(endpoint, baseUrl));
  await assertOk(response, `GET ${endpoint}`);
  return response.json();
}

async function postJson(baseUrl, endpoint, payload) {
  const response = await fetch(new URL(endpoint, baseUrl), {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(payload)
  });
  await assertOk(response, `POST ${endpoint}`);
  return response.json();
}

async function postBytes(baseUrl, endpoint, bytes, contentType) {
  const response = await fetch(new URL(endpoint, baseUrl), {
    method: 'POST',
    headers: { 'content-type': contentType },
    body: bytes
  });
  await assertOk(response, `POST ${endpoint}`);
  return response.json();
}

async function getBytes(baseUrl, endpoint) {
  const response = await fetch(new URL(endpoint, baseUrl));
  await assertOk(response, `GET ${endpoint}`);
  return Buffer.from(await response.arrayBuffer());
}

async function waitForJson(name, baseUrl, endpoint, predicate = body => body?.ok === true) {
  const deadline = Date.now() + readyTimeoutMs;
  let lastError = null;

  while (Date.now() < deadline) {
    try {
      const body = await getJson(baseUrl, endpoint);
      if (predicate(body)) {
        addCheck(`${name}:ready`, true, { endpoint, body });
        return body;
      }

      lastError = new Error(`${name} returned unexpected payload: ${JSON.stringify(body)}`);
    } catch (error) {
      lastError = error;
    }

    await delay(readyPollDelayMs);
  }

  throw lastError ?? new Error(`${name} did not become ready`);
}

async function waitForPushDeliveries(baseUrl, pubkey, expectedCount) {
  let lastSnapshot = null;
  for (let attempt = 1; attempt <= 40; attempt += 1) {
    lastSnapshot = await getJson(baseUrl, `/subscriptions/${encodeURIComponent(pubkey)}`);
    if (lastSnapshot.deliveries?.length >= expectedCount) {
      return { attempts: attempt, snapshot: lastSnapshot };
    }

    await delay(250);
  }

  throw new Error(`push deliveries did not reach ${expectedCount}; last snapshot=${JSON.stringify(lastSnapshot)}`);
}

function currentSigTs() {
  return Math.floor(Date.now() / 1000);
}

function createSignedStorageStorePayload(identity, data) {
  const timestamp = Date.now();
  return {
    pubkey: identity.directPubkey,
    namespace,
    timestamp,
    ttl: 120_000,
    data: Buffer.from(data, 'utf8').toString('base64'),
    signature: identity.signStore(namespace, timestamp)
  };
}

function createSignedStorageRetrievePayload(identity) {
  const timestamp = Date.now();
  return {
    pubkey: identity.directPubkey,
    namespace,
    timestamp,
    signature: identity.signRetrieve(namespace, timestamp)
  };
}

function createPushSubscribePayload(identity, token) {
  const sigTs = currentSigTs();
  const namespaces = [namespace];
  const wantsData = true;
  return {
    ...registrationPayloads.pushSubscription,
    pubkey: identity.directPubkey,
    session_ed25519: undefined,
    subkey_tag: undefined,
    data: wantsData,
    namespaces,
    service_info: {
      ...registrationPayloads.pushSubscription.service_info,
      token
    },
    sig_ts: sigTs,
    signature: identity.signPushSubscribe(identity.directPubkey, sigTs, wantsData, namespaces)
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

async function waitForStackReadiness() {
  const [routerReady] = await Promise.all([
    waitForJson('router', urls.router, '/health/ready', body => body?.status === 'Healthy' || body?.ok === true || body?.transportMode),
    waitForJson('registry', urls.registry, '/health/live'),
    waitForJson('staking', urls.staking, '/health/live'),
    waitForJson('storage', urls.storage, '/health/ready'),
    waitForJson('file', urls.file, '/health/ready'),
    waitForJson('push', urls.push, '/health/ready')
  ]);

  addCheck('router:no-mock-transport', routerReady.transportMode !== 'mocked', {
    transportMode: routerReady.transportMode,
    xrayRunning: routerReady.xrayRunning
  });

  const chainResponse = await fetch(urls.contracts, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'eth_chainId', params: [] })
  });
  await assertOk(chainResponse, 'contracts eth_chainId');
  const chain = await chainResponse.json();
  addCheck('contracts:chain-id', chain.result === '0x7a69' || chain.result === '0x7a69'.toLowerCase(), {
    observed: chain.result
  });
}

async function runPostRollbackSmoke() {
  const identity = createTestStorageSigningIdentity();
  const token = `deep-rollback-token-${Date.now()}`;
  const subscription = createPushSubscribePayload(identity, token);
  const avatarBytes = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x02]);
  const fileBytes = Buffer.from(`rollback-drill-file-${Date.now()}`, 'utf8');

  const pushSubscribe = await postJson(urls.push, '/subscribe', subscription);
  addCheck('smoke:push-subscribe', pushSubscribe.success === true, pushSubscribe);

  const stored = await postJson(urls.storage, '/storage/store', createSignedStorageStorePayload(identity, 'rollback-drill-message'));
  addCheck('smoke:storage-store', typeof stored.hash === 'string' && stored.hash.length > 0, { hash: stored.hash });

  const delivery = await waitForPushDeliveries(urls.push, identity.directPubkey, 1);
  addCheck('smoke:push-delivery-recorded', delivery.snapshot.deliveries.some(item => item.hash === stored.hash && item.token === token), {
    attempts: delivery.attempts,
    deliveries: delivery.snapshot.deliveries.length
  });

  const retrieved = await postJson(urls.storage, '/storage/retrieve', createSignedStorageRetrievePayload(identity));
  addCheck('smoke:storage-retrieve', retrieved.messages.some(message => message.hash === stored.hash), {
    messages: retrieved.messages?.length
  });

  const upload = await postBytes(urls.file, '/file', fileBytes, 'text/plain');
  const fileInfo = await getJson(urls.file, `/file/${upload.id}/info`);
  const downloaded = await getBytes(urls.file, `/file/${upload.id}`);
  addCheck('smoke:file-roundtrip', Buffer.compare(downloaded, fileBytes) === 0 && fileInfo.size === fileBytes.length, {
    fileId: upload.id,
    size: fileInfo.size
  });

  const avatar = await postBytes(urls.file, `/avatar/${encodeURIComponent(identity.directPubkey)}`, avatarBytes, 'image/png');
  const avatarInfo = await getJson(urls.file, `/avatar/${encodeURIComponent(identity.directPubkey)}/info`);
  const avatarDownloaded = await getBytes(urls.file, `/avatar/${encodeURIComponent(identity.directPubkey)}`);
  addCheck('smoke:avatar-roundtrip', Buffer.compare(avatarDownloaded, avatarBytes) === 0 && avatarInfo.fileId === avatar.fileId, {
    fileId: avatar.fileId,
    contentType: avatarInfo.contentType
  });

  const unsubscribe = await postJson(urls.push, '/unsubscribe', createPushUnsubscribePayload(identity, subscription));
  addCheck('smoke:push-unsubscribe', unsubscribe.success === true && unsubscribe.removed === true, unsubscribe);

  const [storageStats, fileStats, pushStats, registryRuntime] = await Promise.all([
    getJson(urls.storage, '/stats'),
    getJson(urls.file, '/stats'),
    getJson(urls.push, '/stats'),
    getJson(urls.registry, '/api/nodes/runtime')
  ]);

  addCheck('smoke:stats-no-errors', [storageStats, fileStats, pushStats].every(stats => stats.stats?.errors === 0), {
    storageErrors: storageStats.stats?.errors,
    fileErrors: fileStats.stats?.errors,
    pushErrors: pushStats.stats?.errors
  });

  return {
    status: 'ok',
    passed: true,
    sessionId: identity.directPubkey,
    storedHash: stored.hash,
    fileId: upload.id,
    avatarFileId: avatar.fileId,
    pushDeliveryAttempts: delivery.attempts,
    stats: {
      storage: storageStats,
      file: fileStats,
      push: pushStats
    },
    registryRuntime
  };
}

function captureComposePs(label) {
  const result = compose(['ps', '--format', 'json'], { allowFailure: true });
  diagnostics[label] = {
    status: result.status,
    stdout: result.stdout.trim(),
    stderr: result.stderr.trim()
  };
}

async function main() {
  const startedAt = Date.now();
  const cleanup = [];

  run('docker', ['info'], { allowFailure: false });
  captureComposePs('before');

  try {
    compose(['--profile', 'backend-external', 'up', '--build', '-d', '--wait', 'storage-service', 'file-service', 'push-service'], { inherit: true });
    cleanup.push('backend-external');
    compose(['up', '--build', '-d', '--wait', 'xnode', 'registry', 'staking-backend', 'contracts-devnet'], { inherit: true });
    cleanup.push('core');

    await waitForStackReadiness();
    const postRollbackSmoke = await runPostRollbackSmoke();
    captureComposePs('afterSmoke');

    const completedAt = Date.now();
    writeArtifact({
      status: 'ok',
      executed: true,
      drill: 'compose-known-good-rollback',
      generatedAt: new Date(completedAt).toISOString(),
      composeProject: projectName,
      composeFile,
      mttrSeconds: Number(((completedAt - startedAt) / 1000).toFixed(3)),
      rollbackTarget: {
        routerNoMock: true,
        backendMode: 'external',
        managedExternalProfile: 'backend-external'
      },
      urls,
      postRollbackSmoke,
      checks,
      diagnostics,
      cleanupPlanned: !keepStack
    });
  } catch (error) {
    writeArtifact({
      status: 'error',
      drill: 'compose-known-good-rollback',
      generatedAt: new Date().toISOString(),
      composeProject: projectName,
      composeFile,
      mttrSeconds: Number(((Date.now() - startedAt) / 1000).toFixed(3)),
      checks,
      diagnostics,
      error: error instanceof Error ? error.stack ?? error.message : String(error)
    });
    throw error;
  } finally {
    if (!keepStack && cleanup.length > 0) {
      compose(['--profile', 'backend-external', 'down', '--volumes', '--remove-orphans'], { allowFailure: true, inherit: true });
      captureComposePs('afterCleanup');
    }
  }
}

main().catch(error => {
  console.error(error);
  process.exitCode = 1;
});
