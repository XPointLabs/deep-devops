import assert from 'node:assert/strict';
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign
} from 'node:crypto';
import test from 'node:test';
import { bootstrapPrivateUat } from './i01b-private-uat-bootstrap.mjs';

const now = new Date('2026-07-18T06:00:00.000Z');
const ips = ['172.30.81.11', '172.30.81.12', '172.30.81.13'];
const apis = ['http://127.0.0.1:29311', 'http://127.0.0.1:29312', 'http://127.0.0.1:29313'];
const pkcs8Prefix = Buffer.from('302e020100300506032b657004220420', 'hex');

function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function hash(value) {
  return createHash('sha256').update(Buffer.from(canonical(value))).digest('hex');
}

function makeKey(seedByte) {
  const privateKey = createPrivateKey({
    key: Buffer.concat([pkcs8Prefix, Buffer.alloc(32, seedByte)]),
    format: 'der',
    type: 'pkcs8'
  });
  const publicDer = createPublicKey(privateKey).export({ format: 'der', type: 'spki' });
  return { privateKey, routerId: publicDer.subarray(-32).toString('hex') };
}

function contactSigningBytes(contact) {
  return Buffer.from(JSON.stringify({
    version: 'deep-relay-contact-v1',
    routerId: contact.routerId,
    publicHost: contact.publicHost,
    publicIp: contact.publicIp ?? '',
    publicPort: contact.publicPort,
    x25519PublicKey: contact.x25519PublicKey,
    rpcEndpoint: contact.rpcEndpoint,
    signedAtUnixMs: Date.parse(contact.signedAt),
    expiresAtUnixMs: Date.parse(contact.expiresAt),
    routerVersion: contact.routerVersion,
    isReachable: contact.isReachable,
    capabilities: contact.capabilities
  }));
}

function signContact(contact, privateKey) {
  return {
    ...contact,
    signature: sign(null, contactSigningBytes(contact), privateKey).toString('hex')
  };
}

function response(status, value) {
  return { status, async json() { return structuredClone(value); } };
}

function createSyntheticWorld(options = {}) {
  const keys = [makeKey(1), makeKey(2), makeKey(3)];
  const routers = keys.map((key, index) => ({
    name: `xnode-${index + 1}`,
    api: apis[index],
    ip: ips[index],
    routerId: key.routerId
  }));
  const contacts = keys.map((key, index) => {
    const base = {
      capabilities: ['client-bootstrap', 'onion-v1', 'session-rpc', 'vless-ingress'],
      expiresAt: new Date(now.getTime() + 6 * 60 * 60_000).toISOString(),
      isReachable: true,
      publicHost: ips[index],
      publicIp: ips[index],
      publicPort: 443,
      routerId: key.routerId,
      routerVersion: 'synthetic-test',
      rpcEndpoint: `http://${ips[index]}:8081/api/peer/onion`,
      serialized: null,
      signature: '',
      signatureAlgorithm: 'ed25519',
      signedAt: new Date(now.getTime() - 60_000).toISOString(),
      x25519PublicKey: `${index + 4}`.repeat(64)
    };
    if (options.staleContact === index) {
      base.signedAt = new Date(now.getTime() - 13 * 60 * 60_000).toISOString();
      base.expiresAt = new Date(now.getTime() + 60 * 60_000).toISOString();
    }
    if (options.wrongTupleContact === index) base.publicHost = '172.30.81.99';
    const signed = signContact(base, key.privateKey);
    if (options.badSignatureContact === index) signed.signature = '00'.repeat(64);
    return signed;
  });
  const registered = routers.map(() => new Set());
  const readinessChecks = routers.map(() => 0);
  const requests = [];

  function signedRpc(index, request, result, success = true, error = null) {
    const value = {
      id: request.id,
      success,
      result,
      error,
      version: 'xpoint-rpc-response-v1',
      responderRouterId: routers[index].routerId,
      method: request.method,
      nonce: request.nonce ?? '',
      requestPayloadSha256: hash(request.payload),
      issuedAtUnixMs: now.getTime(),
      outcomeSha256: hash(success ? result : error),
      signatureAlgorithm: 'ed25519',
      signature: ''
    };
    value.signature = sign(null, Buffer.from(canonical({
      version: value.version,
      responderRouterId: value.responderRouterId,
      requestId: value.id,
      method: value.method,
      nonce: value.nonce,
      requestPayloadSha256: value.requestPayloadSha256,
      issuedAtUnixMs: value.issuedAtUnixMs,
      success: value.success,
      outcomeSha256: value.outcomeSha256
    })), keys[index].privateKey).toString('hex');
    return value;
  }

  async function fetchImpl(url, init = {}) {
    const index = apis.findIndex(api => url.startsWith(api));
    assert.notEqual(index, -1, `unexpected synthetic URL ${url}`);
    const suffix = url.slice(apis[index].length);
    requests.push({ index, suffix, method: init.method ?? 'GET' });
    if (suffix === '/health/ready') {
      const check = readinessChecks[index]++;
      if (check === 0) return response(options.initiallyReady ? 200 : 503, { ready: false });
      return response(registered[index].size === 3 ? 200 : 503, { ready: registered[index].size === 3 });
    }
    if (suffix === '/api/network/contact') return response(200, contacts[index]);
    if (suffix === '/status') {
      const count = options.incompleteStatus === index ? 2 : registered[index].size;
      return response(200, {
        router: {
          privateMembership: {
            enabled: true,
            expectedRelays: 3,
            registeredRelays: count,
            ready: count === 3
          },
          nodeDb: { registeredRelays: count }
        },
        publicPeerAuthorizationMode: 'DenyAll'
      });
    }
    assert.equal(suffix, '/api/session/rpc');
    assert.equal(init.method, 'POST');
    const request = JSON.parse(init.body);
    if (request.method === 'store_rc') {
      registered[index].add(request.payload.routerId);
      return response(200, signedRpc(index, request, {
        stored: true,
        shouldGossip: true,
        reason: 'new'
      }));
    }
    if (request.method === 'fetch_rids') {
      return response(200, signedRpc(index, request, [...registered[index]]));
    }
    assert.equal(request.method, 'storage_route');
    let routeRouters = [...routers];
    if (options.duplicateRoute === index) routeRouters = [routers[0], routers[0], routers[2]];
    const route = routeRouters.map((router, hopIndex) => ({
      index: hopIndex,
      routerId: router.routerId,
      publicHost: router.ip,
      publicIp: router.ip,
      publicPort: 443,
      x25519PublicKey: contacts[routers.indexOf(router)].x25519PublicKey,
      rpcEndpoint: `http://${router.ip}:8081/api/peer/onion`,
      isReachable: true,
      capabilities: ['client-bootstrap', 'onion-v1', 'session-rpc', 'vless-ingress'],
      signedAt: contacts[routers.indexOf(router)].signedAt,
      expiresAt: contacts[routers.indexOf(router)].expiresAt,
      routerVersion: 'synthetic-test',
      signatureAlgorithm: 'ed25519',
      signature: contacts[routers.indexOf(router)].signature
    }));
    return response(200, signedRpc(index, request, { routeNonce: request.payload.routeNonce, route }));
  }
  return { routers, fetchImpl, requests };
}

test('performs exactly 3 contact fetches, 9 stores, 3 membership checks, and 3 route checks', async () => {
  const world = createSyntheticWorld();
  const result = await bootstrapPrivateUat({ ...world, now });
  assert.deepEqual({
    contacts: result.contactCount,
    stores: result.storeRequestCount,
    registered: result.registeredPerRouter,
    hops: result.routeHopCount,
    before: result.readinessBeforeExchange,
    after: result.readinessAfterExchange,
    production: result.productionReady,
    restart: result.uatRestartAuthorized
  }, {
    contacts: 3, stores: 9, registered: 3, hops: 3,
    before: 503, after: 200, production: false, restart: false
  });
  assert.equal(world.requests.filter(item => item.suffix === '/api/network/contact').length, 3);
  assert.equal(world.requests.filter(item => item.suffix === '/api/session/rpc').length, 15);
  assert.equal(world.requests.filter(item => item.suffix === '/health/ready').length, 6);
});

for (const [name, options, pattern] of [
  ['unexpected initial readiness', { initiallyReady: true }, /pre-exchange readiness returned unexpected/],
  ['invalid contact signature', { badSignatureContact: 0 }, /signature verification failed/],
  ['stale contact', { staleContact: 1 }, /contact is outdated/],
  ['wrong advertised tuple', { wrongTupleContact: 2 }, /publicHost does not match/],
  ['incomplete membership status', { incompleteStatus: 0 }, /private membership is incomplete/],
  ['duplicate route membership', { duplicateRoute: 1 }, /exact registered membership/]
]) {
  test(`fails closed on ${name}`, async () => {
    const world = createSyntheticWorld(options);
    await assert.rejects(() => bootstrapPrivateUat({ ...world, now }), pattern);
  });
}
