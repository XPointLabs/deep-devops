import { readFile } from 'node:fs/promises';
import { isIP } from 'node:net';

const hostArgument = process.argv.indexOf('--host');
const host = hostArgument >= 0 ? process.argv[hostArgument + 1] : '127.0.0.1';
if (isIP(host) !== 4) throw new Error('verification host must be an IPv4 address');

const expectedRouterIds = [
  '4cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29',
  '7422b9887598068e32c4448a949adb290d0f4e35b9e01b0ee5f1a1e600fe2674',
  'f381626e41e7027ea431bfe3009e94bdd25a746beec468948d6c3c7c5dc9a54b',
  'fd50b8e3b144ea244fbf7737f550bc8dd0c2650bbc1aada833ca17ff8dbf329b',
  'fde4fba030ad002f7c2f7d4c331f49d13fb0ec747eceebec634f1ff4cbca9def',
  'b4c92afb3ba57f3ab959ffe6d319c98484a2155a0f4c65b2c37011ffd197b075'
];

const contacts = [];
for (let index = 1; index <= 6; index += 1) {
  const port = 41800 + index;
  const response = await fetch(`http://${host}:${port}/api/network/privacy-contact`);
  if (!response.ok) throw new Error(`privacy contact endpoint on ${port} returned ${response.status}`);
  const contact = await response.json();
  const expectedPeerEndpoint = `http://172.30.82.${10 + index}:8081/api/peer/privacy/v1/frame`;
  if (contact.routerId !== expectedRouterIds[index - 1] ||
      !/^[0-9a-f]{64}$/.test(contact.x25519PublicKey ?? '') ||
      !/^[0-9a-f]{128}$/.test(contact.signature ?? '') ||
      contact.peerEndpoint !== expectedPeerEndpoint ||
      JSON.stringify(contact.capabilities) !== JSON.stringify(['privacy-routing-v1']) ||
      !Number.isSafeInteger(contact.signedAtUnixSeconds) ||
      !Number.isSafeInteger(contact.expiresAtUnixSeconds) ||
      contact.expiresAtUnixSeconds <= contact.signedAtUnixSeconds) {
    throw new Error(`privacy contact endpoint on ${port} is not canonical`);
  }
  contacts.push(contact);
}

if (new Set(contacts.map(value => value.routerId)).size !== 6 ||
    new Set(contacts.map(value => value.x25519PublicKey)).size !== 6 ||
    new Set(contacts.map(value => value.peerEndpoint)).size !== 6) {
  throw new Error('privacy contacts do not provide six independent router ids, agreement keys, and peer endpoints');
}

for (let index = 1; index <= 6; index += 1) {
  const authority = await readFile(
    new URL(`../artifacts/survival-dev/privacy-routing-xnode-${index}.env`, import.meta.url),
    'utf8');
  const expectedPeers = expectedRouterIds.filter((_, peerIndex) => peerIndex !== index - 1);
  if (expectedPeers.some(routerId => !authority.includes(routerId)) ||
      authority.includes(expectedRouterIds[index - 1])) {
    throw new Error(`xnode-${index} privacy peer authority is not the exact other-five set`);
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
process.stdout.write('All XNodes publish independent native privacy contacts, exact other-five peer authority, and one six-leaf MRL1/MSM1 artifact.\n');
