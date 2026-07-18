import assert from 'node:assert/strict';
import { createHash, createPublicKey, randomBytes, verify } from 'node:crypto';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const expectedApis = Object.freeze([
  'http://127.0.0.1:29311',
  'http://127.0.0.1:29312',
  'http://127.0.0.1:29313'
]);
const expectedIps = Object.freeze(['172.30.81.11', '172.30.81.12', '172.30.81.13']);
const contactKeys = Object.freeze([
  'capabilities',
  'expiresAt',
  'isReachable',
  'publicHost',
  'publicIp',
  'publicPort',
  'routerId',
  'routerVersion',
  'rpcEndpoint',
  'serialized',
  'signature',
  'signatureAlgorithm',
  'signedAt',
  'x25519PublicKey'
]);
const ed25519SpkiPrefix = Buffer.from('302a300506032b6570032100', 'hex');

function exactKeys(value, expected, label) {
  assert.deepEqual(Object.keys(value ?? {}).sort(), [...expected].sort(), `${label} has unexpected fields`);
}

function canonicalJsonValue(value) {
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJsonValue).join(',')}]`;
  }
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map(key =>
      `${JSON.stringify(key)}:${canonicalJsonValue(value[key])}`
    ).join(',')}}`;
  }
  return JSON.stringify(value);
}

function canonicalJsonBytes(value) {
  return Buffer.from(canonicalJsonValue(value), 'utf8');
}

function sha256Hex(value) {
  return createHash('sha256').update(value).digest('hex');
}

function publicKeyFromRouterId(routerId) {
  return createPublicKey({
    key: Buffer.concat([ed25519SpkiPrefix, Buffer.from(routerId, 'hex')]),
    format: 'der',
    type: 'spki'
  });
}

function assertLowerHex(value, bytes, label) {
  assert.equal(typeof value, 'string', `${label} must be a string`);
  assert.match(value, new RegExp(`^[0-9a-f]{${bytes * 2}}$`), `${label} must be canonical lowercase hex`);
}

function dateTimeOffsetUnixMs(value, label) {
  assert.equal(typeof value, 'string', `${label} must be a string`);
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,7}))?(Z|[+-]\d{2}:\d{2})$/.exec(value);
  assert.ok(match, `${label} must be a System.Text.Json DateTimeOffset round-trip value`);
  const [, yearText, monthText, dayText, hourText, minuteText, secondText, , offset] = match;
  const [year, month, day, hour, minute, second] =
    [yearText, monthText, dayText, hourText, minuteText, secondText].map(Number);
  assert.ok(year >= 1, `${label} has an invalid year`);
  assert.ok(month >= 1 && month <= 12, `${label} has an invalid month`);
  assert.ok(hour <= 23 && minute <= 59 && second <= 59, `${label} has an invalid time`);
  const calendar = new Date(0);
  calendar.setUTCFullYear(year, month - 1, day);
  calendar.setUTCHours(hour, minute, second, 0);
  assert.deepEqual(
    [
      calendar.getUTCFullYear(),
      calendar.getUTCMonth() + 1,
      calendar.getUTCDate(),
      calendar.getUTCHours(),
      calendar.getUTCMinutes(),
      calendar.getUTCSeconds()
    ],
    [year, month, day, hour, minute, second],
    `${label} has an invalid calendar date`
  );
  if (offset !== 'Z') {
    const offsetHour = Number(offset.slice(1, 3));
    const offsetMinute = Number(offset.slice(4, 6));
    assert.ok(
      offsetHour < 14 || (offsetHour === 14 && offsetMinute === 0),
      `${label} has an invalid UTC offset`
    );
    assert.ok(offsetMinute <= 59, `${label} has an invalid UTC offset`);
  }
  const unixMs = Date.parse(value);
  assert.ok(Number.isSafeInteger(unixMs), `${label} must resolve to an exact Unix millisecond`);
  return unixMs;
}

function relayContactSigningBytes(contact) {
  const signedAtUnixMs = dateTimeOffsetUnixMs(contact.signedAt, 'contact signedAt');
  const expiresAtUnixMs = dateTimeOffsetUnixMs(contact.expiresAt, 'contact expiresAt');
  const payload = {
    version: 'deep-relay-contact-v1',
    routerId: contact.routerId,
    publicHost: contact.publicHost,
    publicIp: contact.publicIp ?? '',
    publicPort: contact.publicPort,
    x25519PublicKey: contact.x25519PublicKey,
    rpcEndpoint: contact.rpcEndpoint,
    signedAtUnixMs,
    expiresAtUnixMs,
    routerVersion: contact.routerVersion,
    isReachable: contact.isReachable,
    capabilities: contact.capabilities
  };
  return Buffer.from(JSON.stringify(payload), 'utf8');
}

export function verifyRelayContact(contact, expected, now = new Date()) {
  assert.ok(contact && typeof contact === 'object' && !Array.isArray(contact), 'contact must be an object');
  exactKeys(contact, contactKeys, 'relay contact');
  assertLowerHex(contact.routerId, 32, 'contact routerId');
  assert.equal(contact.routerId, expected.routerId, 'contact routerId does not match the requested router');
  assert.equal(contact.publicHost, expected.ip, 'contact publicHost does not match the exact private tuple');
  assert.equal(contact.publicIp, expected.ip, 'contact publicIp does not match the exact private tuple');
  assert.equal(contact.publicPort, 443, 'contact VLESS publicPort must be exactly 443');
  assert.equal(
    contact.rpcEndpoint,
    `http://${expected.ip}:8081/api/peer/onion`,
    'contact RPC endpoint does not match the exact private tuple'
  );
  assertLowerHex(contact.x25519PublicKey, 32, 'contact x25519PublicKey');
  assert.equal(contact.signatureAlgorithm, 'ed25519', 'contact signature algorithm must be exact');
  assertLowerHex(contact.signature, 64, 'contact signature');
  assert.equal(contact.serialized, null, 'contact serialized field must be null');
  assert.equal(typeof contact.routerVersion, 'string', 'contact routerVersion must be a string');
  assert.ok(contact.routerVersion.length > 0, 'contact routerVersion must not be empty');
  assert.equal(contact.isReachable, true, 'contact must be reachable');
  assert.deepEqual(
    contact.capabilities,
    ['client-bootstrap', 'onion-v1', 'session-rpc', 'vless-ingress'],
    'contact capabilities must equal the exact canonical private UAT set'
  );

  const nowMs = now.getTime();
  const signedAtMs = dateTimeOffsetUnixMs(contact.signedAt, 'contact signedAt');
  const expiresAtMs = dateTimeOffsetUnixMs(contact.expiresAt, 'contact expiresAt');
  assert.ok(Number.isSafeInteger(nowMs), 'bootstrap clock must be a valid timestamp');
  assert.ok(signedAtMs <= nowMs + 5 * 60_000, 'contact signedAt exceeds allowed future skew');
  assert.ok(nowMs - signedAtMs < 12 * 60 * 60_000, 'contact is outdated');
  assert.ok(expiresAtMs > signedAtMs && expiresAtMs > nowMs, 'contact is expired or has invalid lifetime');
  assert.equal(
    verify(
      null,
      relayContactSigningBytes(contact),
      publicKeyFromRouterId(contact.routerId),
      Buffer.from(contact.signature, 'hex')
    ),
    true,
    'contact Ed25519 signature verification failed'
  );
  return contact;
}

function rpcRequest(id, method, payload) {
  return { id, method, payload };
}

function verifyRpcResponse(request, response, expectedRouterId, now) {
  assert.ok(response && typeof response === 'object' && !Array.isArray(response), 'RPC response must be an object');
  exactKeys(response, [
    'error',
    'id',
    'issuedAtUnixMs',
    'method',
    'nonce',
    'outcomeSha256',
    'requestPayloadSha256',
    'responderRouterId',
    'result',
    'signature',
    'signatureAlgorithm',
    'success',
    'version'
  ], 'RPC response');
  assert.equal(response.id, request.id, 'RPC response id mismatch');
  assert.equal(response.method, request.method, 'RPC response method mismatch');
  assert.equal(response.nonce, request.nonce ?? '', 'RPC response nonce mismatch');
  assert.equal(response.responderRouterId, expectedRouterId, 'RPC responder identity mismatch');
  assert.equal(response.version, 'xpoint-rpc-response-v1', 'RPC response version mismatch');
  assert.equal(response.signatureAlgorithm, 'ed25519', 'RPC response signature algorithm mismatch');
  assertLowerHex(response.requestPayloadSha256, 32, 'RPC request payload hash');
  assertLowerHex(response.outcomeSha256, 32, 'RPC outcome hash');
  assertLowerHex(response.signature, 64, 'RPC response signature');
  assert.equal(
    response.requestPayloadSha256,
    sha256Hex(canonicalJsonBytes(request.payload)),
    'RPC response is not bound to the exact request payload'
  );
  assert.equal(
    response.outcomeSha256,
    sha256Hex(canonicalJsonBytes(response.success ? response.result : response.error)),
    'RPC response outcome hash mismatch'
  );
  assert.ok(
    Number.isSafeInteger(response.issuedAtUnixMs) &&
      Math.abs(now.getTime() - response.issuedAtUnixMs) <= 2 * 60_000,
    'RPC response timestamp is not fresh'
  );
  const signingPayload = {
    version: response.version,
    responderRouterId: response.responderRouterId,
    requestId: response.id,
    method: response.method,
    nonce: response.nonce,
    requestPayloadSha256: response.requestPayloadSha256,
    issuedAtUnixMs: response.issuedAtUnixMs,
    success: response.success,
    outcomeSha256: response.outcomeSha256
  };
  assert.equal(
    verify(
      null,
      canonicalJsonBytes(signingPayload),
      publicKeyFromRouterId(expectedRouterId),
      Buffer.from(response.signature, 'hex')
    ),
    true,
    'RPC response Ed25519 signature verification failed'
  );
  return response;
}

async function fetchJson(fetchImpl, url, options, expectedStatus, label) {
  const response = await fetchImpl(url, options);
  assert.equal(response.status, expectedStatus, `${label} returned unexpected HTTP status`);
  const value = await response.json();
  assert.ok(value && typeof value === 'object', `${label} must return JSON`);
  return value;
}

async function postRpc(fetchImpl, router, request, now) {
  const response = await fetchJson(
    fetchImpl,
    `${router.api}/api/session/rpc`,
    {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(request)
    },
    200,
    `${router.name} ${request.method}`
  );
  verifyRpcResponse(request, response, router.routerId, now);
  assert.equal(response.success, true, `${router.name} ${request.method} failed`);
  assert.equal(response.error, null, `${router.name} ${request.method} returned an error`);
  return response.result;
}

function assertExactRouterConfiguration(routers) {
  assert.equal(routers?.length, 3, 'exactly three routers are required');
  assert.deepEqual(routers.map(router => router.api), expectedApis, 'router APIs must be the exact loopback topology');
  assert.equal(new Set(routers.map(router => router.routerId)).size, 3, 'router ids must be unique');
  for (const [index, router] of routers.entries()) {
    assertLowerHex(router.routerId, 32, `${router.name} routerId`);
    assert.equal(router.name, `xnode-${index + 1}`, 'router names must be exact');
    assert.equal(router.ip, expectedIps[index], 'router private IP must be exact');
  }
}

function assertExactMembershipStatus(status, router) {
  exactKeys(status.router.privateMembership, [
    'enabled',
    'expectedRelays',
    'ready',
    'registeredRelays'
  ], `${router.name} privateMembership`);
  assert.deepEqual(status.router.privateMembership, {
    enabled: true,
    expectedRelays: 3,
    registeredRelays: 3,
    ready: true
  }, `${router.name} private membership is incomplete`);
  assert.equal(status.router.nodeDb.registeredRelays, 3, `${router.name} NodeDb registration count mismatch`);
  assert.equal(status.publicPeerAuthorizationMode, 'DenyAll', `${router.name} public peer mode mismatch`);
}

function assertExactRoute(routeResult, routers, router, now, expectedRouteNonce) {
  exactKeys(routeResult, ['route', 'routeNonce'], `${router.name} route result`);
  assertLowerHex(routeResult.routeNonce, 32, `${router.name} route nonce`);
  assert.equal(
    routeResult.routeNonce,
    expectedRouteNonce,
    `${router.name} route nonce is not bound to the exact storage_route request`
  );
  assert.ok(Array.isArray(routeResult.route), `${router.name} route must be an array`);
  assert.equal(routeResult.route.length, 3, `${router.name} route must contain exactly three hops`);
  const expectedById = new Map(routers.map(item => [item.routerId, item]));
  assert.deepEqual(
    routeResult.route.map(item => item.routerId).sort(),
    routers.map(item => item.routerId).sort(),
    `${router.name} route does not contain the exact registered membership`
  );
  for (const [index, hop] of routeResult.route.entries()) {
    exactKeys(hop, [
      'capabilities',
      'expiresAt',
      'index',
      'isReachable',
      'publicHost',
      'publicIp',
      'publicPort',
      'routerId',
      'routerVersion',
      'rpcEndpoint',
      'signature',
      'signatureAlgorithm',
      'signedAt',
      'x25519PublicKey'
    ], `${router.name} route hop`);
    assert.equal(hop.index, index, `${router.name} route indexes must be canonical`);
    const expected = expectedById.get(hop.routerId);
    assert.ok(expected, `${router.name} route contains an unexpected router`);
    const { index: ignoredIndex, ...contact } = hop;
    void ignoredIndex;
    verifyRelayContact({ ...contact, serialized: null }, expected, now);
  }
}

export async function bootstrapPrivateUat(options) {
  const routers = options.routers;
  const fetchImpl = options.fetchImpl ?? globalThis.fetch;
  const now = options.now ?? new Date();
  const routeNonceFactory = options.routeNonceFactory ?? (() => randomBytes(32).toString('hex'));
  assert.equal(typeof fetchImpl, 'function', 'fetch implementation is required');
  assert.equal(typeof routeNonceFactory, 'function', 'route nonce factory must be a function');
  assertExactRouterConfiguration(routers);

  for (const router of routers) {
    await fetchJson(
      fetchImpl,
      `${router.api}/health/ready`,
      { method: 'GET' },
      503,
      `${router.name} pre-exchange readiness`
    );
  }

  const contacts = [];
  for (const router of routers) {
    const contact = await fetchJson(
      fetchImpl,
      `${router.api}/api/network/contact`,
      { method: 'GET' },
      200,
      `${router.name} contact`
    );
    contacts.push(verifyRelayContact(contact, router, now));
  }
  assert.equal(new Set(contacts.map(contact => contact.routerId)).size, 3, 'contacts must have unique identities');

  let storeRequestCount = 0;
  for (const router of routers) {
    for (const [contactIndex, contact] of contacts.entries()) {
      const request = rpcRequest(
        `i01b-store-${router.name}-${contactIndex + 1}`,
        'store_rc',
        contact
      );
      const stored = await postRpc(fetchImpl, router, request, now);
      exactKeys(stored, ['reason', 'shouldGossip', 'stored'], `${router.name} store_rc result`);
      assert.equal(stored.stored, true, `${router.name} store_rc did not atomically store the contact`);
      assert.equal(typeof stored.shouldGossip, 'boolean', `${router.name} store_rc shouldGossip must be boolean`);
      assert.equal(stored.reason, 'new', `${router.name} store_rc reason must be new`);
      storeRequestCount += 1;
    }
  }
  assert.equal(storeRequestCount, 9, 'bootstrap must perform exactly nine store_rc requests');

  for (const router of routers) {
    const status = await fetchJson(
      fetchImpl,
      `${router.api}/status`,
      { method: 'GET' },
      200,
      `${router.name} status`
    );
    assertExactMembershipStatus(status, router);

    const registeredRequest = rpcRequest(
      `i01b-registered-${router.name}`,
      'fetch_rids',
      {}
    );
    const registered = await postRpc(fetchImpl, router, registeredRequest, now);
    assert.deepEqual(
      [...registered].sort(),
      routers.map(item => item.routerId).sort(),
      `${router.name} registered identities must be exact`
    );

    await fetchJson(
      fetchImpl,
      `${router.api}/health/ready`,
      { method: 'GET' },
      200,
      `${router.name} post-exchange readiness`
    );

    const routeNonce = routeNonceFactory(router);
    assertLowerHex(routeNonce, 32, `${router.name} generated storage_route nonce`);
    const routeRequest = rpcRequest(
      `i01b-route-${router.name}`,
      'storage_route',
      { routeNonce }
    );
    const route = await postRpc(fetchImpl, router, routeRequest, now);
    assertExactRoute(route, routers, router, now, routeNonce);
  }

  return {
    schemaVersion: '1.0.0',
    status: 'accepted-private-membership-bootstrap',
    routerCount: routers.length,
    contactCount: contacts.length,
    storeRequestCount,
    registeredPerRouter: 3,
    routeHopCount: 3,
    readinessBeforeExchange: 503,
    readinessAfterExchange: 200,
    productionReady: false,
    uatRestartAuthorized: false
  };
}

function parse(argv) {
  const values = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    const name = argv[index];
    const value = argv[index + 1];
    if (!/^--router-[123]-(?:api|id)$/.test(name ?? '') ||
        !value ||
        value.startsWith('--') ||
        values.has(name)) {
      throw new Error(`invalid or missing bootstrap argument near ${name ?? '<end>'}`);
    }
    values.set(name, value);
  }
  assert.equal(values.size, 6, 'all six exact router bootstrap arguments are required');
  return {
    routers: [1, 2, 3].map((index, offset) => ({
      name: `xnode-${index}`,
      api: values.get(`--router-${index}-api`),
      routerId: values.get(`--router-${index}-id`),
      ip: expectedIps[offset]
    }))
  };
}

export async function main(argv = process.argv.slice(2)) {
  const result = await bootstrapPrivateUat(parse(argv));
  console.log(JSON.stringify(result, null, 2));
  return result;
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  main().catch(error => {
    console.error(`I01B private UAT bootstrap failed closed: ${error.message}`);
    process.exitCode = 1;
  });
}
