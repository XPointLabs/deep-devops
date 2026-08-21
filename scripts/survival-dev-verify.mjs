import { isIP } from 'node:net';

const hostArgument = process.argv.indexOf('--host');
const host = hostArgument >= 0 ? process.argv[hostArgument + 1] : '127.0.0.1';
if (isIP(host) !== 4) throw new Error('verification host must be an IPv4 address');

const expected = [
  '4cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29',
  '7422b9887598068e32c4448a949adb290d0f4e35b9e01b0ee5f1a1e600fe2674',
  'f381626e41e7027ea431bfe3009e94bdd25a746beec468948d6c3c7c5dc9a54b',
  'fd50b8e3b144ea244fbf7737f550bc8dd0c2650bbc1aada833ca17ff8dbf329b',
  'fde4fba030ad002f7c2f7d4c331f49d13fb0ec747eceebec634f1ff4cbca9def',
  'b4c92afb3ba57f3ab959ffe6d319c98484a2155a0f4c65b2c37011ffd197b075'
].sort();
const expectedEndpoints = new Map([
  ['4cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29', 'http://172.30.82.11:8081/api/peer/onion'],
  ['7422b9887598068e32c4448a949adb290d0f4e35b9e01b0ee5f1a1e600fe2674', 'http://172.30.82.12:8081/api/peer/onion'],
  ['f381626e41e7027ea431bfe3009e94bdd25a746beec468948d6c3c7c5dc9a54b', 'http://172.30.82.13:8081/api/peer/onion'],
  ['fd50b8e3b144ea244fbf7737f550bc8dd0c2650bbc1aada833ca17ff8dbf329b', 'http://172.30.82.14:8081/api/peer/onion'],
  ['fde4fba030ad002f7c2f7d4c331f49d13fb0ec747eceebec634f1ff4cbca9def', 'http://172.30.82.15:8081/api/peer/onion'],
  ['b4c92afb3ba57f3ab959ffe6d319c98484a2155a0f4c65b2c37011ffd197b075', 'http://172.30.82.16:8081/api/peer/onion']
]);

async function rpc(port, method, payload = {}) {
  const response = await fetch(`http://${host}:${port}/api/session/rpc`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ id: `survival-${method}`, method, payload })
  });
  if (!response.ok) throw new Error(`${method} failed on ${port} with ${response.status}`);
  const body = await response.json();
  if (body.success !== true) throw new Error(`${method} was rejected on ${port}`);
  return body.result;
}

for (const port of [41801, 41802, 41803, 41804, 41805, 41806]) {
  const registered = await rpc(port, 'fetch_rids');
  const contacts = await rpc(port, 'fetch_rcs');
  if (!Array.isArray(registered) || JSON.stringify([...registered].sort()) !== JSON.stringify(expected)) {
    throw new Error(`xnode on ${port} does not have exactly six registered relay IDs`);
  }
  const contactIds = Array.isArray(contacts) ? contacts.map(value => value.routerId).sort() : [];
  if (JSON.stringify(contactIds) !== JSON.stringify(expected)) {
    throw new Error(`xnode on ${port} does not have exactly six signed relay contacts`);
  }
  if (contacts.some(value => expectedEndpoints.get(value.routerId) !== value.rpcEndpoint)) {
    throw new Error(`xnode on ${port} has a non-canonical onion peer endpoint`);
  }
  const routeNonce = port.toString(16).padStart(64, '0');
  const routeResult = await rpc(port, 'storage_route', {
    routeNonce,
    attemptId: (port + 100).toString(16).padStart(64, '0'),
    excludedRouterIds: []
  });
  const route = routeResult?.route;
  const routeIds = Array.isArray(route) ? route.map(value => value.routerId) : [];
  if (routeResult?.routeNonce !== routeNonce || routeIds.length !== 3 || new Set(routeIds).size !== 3) {
    throw new Error(`xnode on ${port} did not construct an exact three-hop storage route`);
  }
  if (route.some(value => expectedEndpoints.get(value.routerId) !== value.rpcEndpoint)) {
    throw new Error(`xnode on ${port} selected a route outside the exact private endpoint allowlist`);
  }
}

async function artifact(port) {
  const response = await fetch(`http://${host}:${port}/api/network/membership-route-catalog`);
  if (!response.ok) throw new Error(`membership artifact endpoint on ${port} returned ${response.status}`);
  const body = await response.json();
  if (body.version !== 'deep-membership-route-catalog-v1' || !Array.isArray(body.members) || body.members.length !== 6) {
    throw new Error(`membership artifact endpoint on ${port} has invalid framing`);
  }
  const signed = Buffer.from(body.signedMembership, 'base64');
  if (signed.subarray(0, 4).toString('ascii') !== 'MSM1') throw new Error(`membership artifact endpoint on ${port} lacks MSM1`);
  const leaves = body.members.map(member => Buffer.from(member.leaf, 'base64'));
  if (leaves.some(leaf => leaf.subarray(0, 4).toString('ascii') !== 'MRL1')) throw new Error(`membership artifact endpoint on ${port} lacks MRL1 leaves`);
  const ids = leaves.map(leaf => leaf.subarray(10, 42).toString('hex'));
  if (JSON.stringify(ids) !== JSON.stringify([...ids].sort())) throw new Error(`membership artifact endpoint on ${port} is not sorted`);
  return JSON.stringify(body);
}

const registryArtifact = await artifact(41810);
const ingressArtifact = await artifact(41801);
if (registryArtifact !== ingressArtifact) throw new Error('registry and ingress publish different membership artifacts');
process.stdout.write('All XNodes have exact signed relay contacts, construct exact private three-hop storage routes, and share one six-leaf MRL1/MSM1 artifact.\n');
