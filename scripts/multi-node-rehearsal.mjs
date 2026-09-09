import assert from 'node:assert/strict';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

const defaultRouters = [
  'http://127.0.0.1:19281',
  'http://127.0.0.1:19282',
  'http://127.0.0.1:19283'
];

const registryUrl = trimSlash(process.env.DEEP_REGISTRY_URL ?? 'http://127.0.0.1:18080');
const routerUrls = (process.env.DEEP_MULTI_NODE_ROUTER_URLS ?? defaultRouters.join(','))
  .split(',')
  .map(value => trimSlash(value.trim()))
  .filter(Boolean);
const artifactDir = resolve(process.env.DEEP_ARTIFACT_DIR ?? join(process.cwd(), 'artifacts', 'test-results'));
const requireNoMock = !/^(0|false|no)$/i.test(process.env.DEEP_MULTI_NODE_REQUIRE_NO_MOCK ?? 'true');

function trimSlash(value) {
  return value.replace(/\/+$/, '');
}

function property(value, ...names) {
  for (const name of names) {
    if (value && Object.prototype.hasOwnProperty.call(value, name)) {
      return value[name];
    }
  }

  return undefined;
}

async function delay(ms) {
  await new Promise(resolveDelay => setTimeout(resolveDelay, ms));
}

async function fetchJson(url, options = {}) {
  const response = await fetch(url, {
    ...options,
    headers: {
      'content-type': 'application/json',
      ...(options.headers ?? {})
    }
  });
  const text = await response.text();
  let body = null;
  if (text.length > 0) {
    body = JSON.parse(text);
  }

  if (!response.ok) {
    throw new Error(`${options.method ?? 'GET'} ${url} failed with ${response.status}: ${text}`);
  }

  return body;
}

async function waitForJson(url, timeoutMs = 60_000) {
  const deadline = Date.now() + timeoutMs;
  let lastError;
  while (Date.now() < deadline) {
    try {
      return await fetchJson(url);
    } catch (error) {
      lastError = error;
      await delay(1_000);
    }
  }

  throw new Error(`${url} did not become ready within ${timeoutMs}ms: ${lastError?.message ?? 'unknown error'}`);
}

function uuidForIndex(index) {
  return `00000000-0000-4000-8000-${String(index + 1).padStart(12, '0')}`;
}

function hexAddress(index) {
  return `0x${String(index + 1).padStart(40, '0')}`;
}

function toRegisterRequest(node, index) {
  const payload = node.registryPayload;
  const transportStatus = node.xray ?? property(payload, 'transport', 'Transport');
  assert.ok(transportStatus, `router ${node.url} did not expose transport runtime status`);
  return {
    nodeId: node.routerId,
    operatorAddress: hexAddress(index),
    rewardsAddress: hexAddress(index + 10),
    blsPublicKey: {
      x: `0x${(index + 1).toString(16)}`,
      y: `0x${(index + 2).toString(16)}`
    },
    ed25519PublicKey: node.routerId,
    ed25519Signature1: String(index + 1).padStart(64, '0'),
    ed25519Signature2: String(index + 11).padStart(64, '0'),
    operatorFeeBps: 0,
    stakeAtomic: 25_000n * 1_000_000_000n,
    contributors: [
      {
        address: hexAddress(index),
        beneficiary: hexAddress(index + 10),
        amountAtomic: 25_000n * 1_000_000_000n
      }
    ],
    signingEndpoint: `http://xnode-${index + 1}:8080/api/staking/quorum/sign`,
    transportStatus: {
      enabled: Boolean(property(transportStatus, 'enabled', 'Enabled')),
      running: Boolean(property(transportStatus, 'running', 'Running')),
      degraded: Boolean(property(transportStatus, 'degraded', 'Degraded')),
      mode: String(property(transportStatus, 'mode', 'Mode') ?? 'unknown'),
      mocked: Boolean(property(transportStatus, 'mocked', 'Mocked')),
      restartCount: Number(property(transportStatus, 'restartCount', 'RestartCount') ?? 0),
      consecutiveFailures: Number(property(transportStatus, 'consecutiveFailures', 'ConsecutiveFailures') ?? 0),
      lastExitReason: property(transportStatus, 'lastExitReason', 'LastExitReason'),
      lastStartedAt: property(transportStatus, 'lastStartedAt', 'LastStartedAt'),
      degradedUntil: property(transportStatus, 'degradedUntil', 'DegradedUntil')
    },
    transport: {
      protocol: 'vless',
      host: property(payload, 'publicHost', 'PublicHost'),
      port: property(payload, 'publicPort', 'PublicPort'),
      uuid: uuidForIndex(index),
      security: String(property(payload, 'transportMode', 'TransportMode') ?? 'reality').toLowerCase(),
      sni: property(payload, 'reality', 'Reality')?.serverName
        ?? property(payload, 'reality', 'Reality')?.ServerName
        ?? property(payload, 'publicHost', 'PublicHost'),
      publicKey: property(payload, 'reality', 'Reality')?.publicKey
        ?? property(payload, 'reality', 'Reality')?.PublicKey
        ?? 'devnet-reality-public-key',
      shortId: property(payload, 'reality', 'Reality')?.shortId
        ?? property(payload, 'reality', 'Reality')?.ShortId
        ?? `multi-node-${index + 1}`,
      fingerprint: property(payload, 'reality', 'Reality')?.fingerprint
        ?? property(payload, 'reality', 'Reality')?.Fingerprint
        ?? 'chrome'
    }
  };
}

async function collectRouter(url, index) {
  const ready = await waitForJson(`${url}/health/ready`);
  const status = await fetchJson(`${url}/status`);
  const registryPayload = property(status, 'registryPayload', 'RegistryPayload');
  const router = property(status, 'router', 'Router');
  const xray = property(status, 'xray', 'Xray');
  const routerId = property(registryPayload, 'routerId', 'RouterId') ?? property(router, 'routerId', 'RouterId');
  assert.ok(routerId, `router ${url} did not expose routerId`);
  const privacyContactResponse = await fetch(`${url}/api/network/privacy-contact`);
  const privacyContactProblem = await privacyContactResponse.json();
  assert.equal(privacyContactResponse.status, 503,
    `router ${url} must fail closed without a verified Contact authority`);
  assert.match(property(privacyContactProblem, 'detail', 'Detail') ?? '', /privacy routing is disabled/i,
    `router ${url} did not explain its unavailable privacy contact boundary`);

  const transportMocked = Boolean(property(property(registryPayload, 'transport', 'Transport'), 'mocked', 'Mocked'))
    || String(property(ready, 'transportMode', 'TransportMode') ?? '').toLowerCase() === 'mocked';
  if (requireNoMock) {
    assert.equal(transportMocked, false, `router ${url} reported mocked transport`);
  }

  return {
    index,
    url,
    routerId,
    ready,
    status,
    registryPayload,
    privacyContactStatus: privacyContactResponse.status,
    xray,
    transportMode: property(ready, 'transportMode', 'TransportMode'),
    transportMocked
  };
}

async function main() {
  assert.equal(routerUrls.length, 3, 'multi-node rehearsal requires exactly three router URLs');
  await waitForJson(`${registryUrl}/health/live`);

  const routers = [];
  for (let index = 0; index < routerUrls.length; index += 1) {
    routers.push(await collectRouter(routerUrls[index], index));
  }

  assert.equal(new Set(routers.map(router => router.routerId)).size, 3, 'router IDs must be unique');
  for (const [index, router] of routers.entries()) {
    const request = toRegisterRequest(router, index);
    request.stakeAtomic = Number(request.stakeAtomic);
    request.contributors = request.contributors.map(contributor => ({
      ...contributor,
      amountAtomic: Number(contributor.amountAtomic)
    }));

    await fetchJson(`${registryUrl}/api/nodes/register`, {
      method: 'POST',
      body: JSON.stringify(request)
    });
  }

  const registryRuntime = await fetchJson(`${registryUrl}/api/nodes/runtime`);
  const registryNodes = await fetchJson(`${registryUrl}/api/nodes`);
  const reconciliation = await fetchJson(`${registryUrl}/api/nodes/reconciliation`);
  assert.ok(property(registryRuntime, 'totalNodes', 'TotalNodes') >= 3, 'registry runtime did not report at least three nodes');
  assert.ok(registryNodes.length >= 3, 'registry /api/nodes did not return at least three nodes');

  const issues = property(reconciliation, 'issues', 'Issues') ?? [];
  const rehearsalIssues = issues.filter(issue => routers.some(router => router.routerId === property(issue, 'nodeId', 'NodeId')));
  assert.deepEqual(rehearsalIssues, [], `registry reconciliation reported multi-node rehearsal issues: ${JSON.stringify(rehearsalIssues)}`);

  const artifact = {
    status: 'ok',
    generatedAt: new Date().toISOString(),
    registryUrl,
    requireNoMock,
    routers: routers.map(router => ({
      url: router.url,
      routerId: router.routerId,
      publicHost: property(router.registryPayload, 'publicHost', 'PublicHost'),
      publicPort: property(router.registryPayload, 'publicPort', 'PublicPort'),
      transportMode: router.transportMode,
      transportMocked: router.transportMocked,
      privacyContactStatus: router.privacyContactStatus,
      xrayRunning: Boolean(property(router.xray, 'running', 'Running')),
      xrayDegraded: Boolean(property(router.xray, 'degraded', 'Degraded'))
    })),
    registryRuntime,
    registryNodeCount: registryNodes.length,
    reconciliationIssues: rehearsalIssues,
    privacyAuthorityBoundary: 'fail-closed-without-verified-authority'
  };

  mkdirSync(artifactDir, { recursive: true });
  const artifactPath = join(artifactDir, 'multi-node-topology.json');
  writeFileSync(artifactPath, `${JSON.stringify(artifact, null, 2)}\n`, 'utf8');
  console.log(JSON.stringify(artifact, null, 2));
}

await main();
