import { createHash, timingSafeEqual } from 'node:crypto';
import { isIP } from 'node:net';
import { pathToFileURL } from 'node:url';

export const MAX_MEMBERSHIP_ARTIFACT_BYTES = 128 * 1024;

function fail(message) {
  throw new Error(`DEV-LOCAL-ONLY membership trust artifact rejected: ${message}`);
}

function exactKeys(value, expected, name) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) fail(`${name} must be an object`);
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    fail(`${name} has unknown or missing fields`);
  }
}

function base64(value, length, name, maximumLength = length) {
  if (typeof value !== 'string' || value.length === 0 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    fail(`${name} is not canonical base64`);
  }
  const decoded = Buffer.from(value, 'base64');
  if (decoded.toString('base64') !== value ||
      decoded.length < length ||
      decoded.length > maximumLength) {
    fail(`${name} is outside its byte bound`);
  }
  return decoded;
}

function positiveSafeInteger(value, name) {
  if (!Number.isSafeInteger(value) || value <= 0) fail(`${name} must be a positive safe integer`);
  return value;
}

function validateAnchor(anchor, name) {
  exactKeys(anchor, ['sequence', 'canonicalHash'], name);
  return {
    sequence: positiveSafeInteger(anchor.sequence, `${name}.sequence`),
    canonicalHash: base64(anchor.canonicalHash, 32, `${name}.canonicalHash`)
  };
}

function rejectPrivateMaterial(value, path = '$') {
  if (value === null || typeof value !== 'object') return;
  for (const [key, child] of Object.entries(value)) {
    if (/(?:private|secret|seed|mnemonic|recovery|phrase)/i.test(key)) {
      fail(`private-material field is prohibited at ${path}.${key}`);
    }
    rejectPrivateMaterial(child, `${path}.${key}`);
  }
}

export function validateDevMembershipArtifact(encoded) {
  const bytes = Buffer.from(encoded);
  if (bytes.length === 0 || bytes.length > MAX_MEMBERSHIP_ARTIFACT_BYTES) {
    fail('artifact is outside its byte bound');
  }

  let document;
  try {
    document = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } catch {
    fail('artifact is not valid UTF-8 JSON');
  }
  exactKeys(document, ['version', 'trustBootstrap', 'signedMembership', 'members'], 'catalog');
  rejectPrivateMaterial(document);
  if (new TextDecoder('utf-8', { fatal: true }).decode(bytes).includes('deep-survival-local-only-')) {
    fail('deterministic signing seed material was published');
  }
  if (document.version !== 'deep-membership-route-catalog-v1') fail('catalog version is invalid');

  const trust = document.trustBootstrap;
  exactKeys(trust, [
    'version',
    'scope',
    'opaqueProfileKey',
    'canonicalGenesis',
    'expectedNetworkId',
    'expectedCanonicalGenesisSha256',
    'signedDelegation',
    'bridgeAnchor',
    'membershipAnchor'
  ], 'trustBootstrap');
  if (trust.version !== 'deep-membership-trust-bootstrap-v1' ||
      trust.scope !== 'DEV-LOCAL-ONLY' ||
      trust.opaqueProfileKey !== 'install:deep-survival-dev-v1') {
    fail('trust bootstrap identity is invalid');
  }

  const canonicalGenesis = base64(
    trust.canonicalGenesis,
    1,
    'trustBootstrap.canonicalGenesis',
    MAX_MEMBERSHIP_ARTIFACT_BYTES);
  base64(trust.expectedNetworkId, 16, 'trustBootstrap.expectedNetworkId');
  const expectedGenesisHash = base64(
    trust.expectedCanonicalGenesisSha256,
    32,
    'trustBootstrap.expectedCanonicalGenesisSha256');
  const actualGenesisHash = createHash('sha256').update(canonicalGenesis).digest();
  if (!timingSafeEqual(actualGenesisHash, expectedGenesisHash)) fail('canonical genesis hash pin mismatches');
  base64(
    trust.signedDelegation,
    1,
    'trustBootstrap.signedDelegation',
    MAX_MEMBERSHIP_ARTIFACT_BYTES);

  const bridgeAnchor = validateAnchor(trust.bridgeAnchor, 'trustBootstrap.bridgeAnchor');
  const membershipAnchor = validateAnchor(trust.membershipAnchor, 'trustBootstrap.membershipAnchor');
  if (bridgeAnchor.sequence !== membershipAnchor.sequence ||
      !timingSafeEqual(bridgeAnchor.canonicalHash, membershipAnchor.canonicalHash)) {
    fail('content anchors do not bind the same verified authority LKG');
  }

  base64(document.signedMembership, 1, 'signedMembership', MAX_MEMBERSHIP_ARTIFACT_BYTES);
  if (!Array.isArray(document.members) || document.members.length !== 6) fail('catalog must contain exactly six MRL1 members');
  for (const [index, member] of document.members.entries()) {
    exactKeys(member, ['leaf', 'leafIndex', 'memberCount', 'siblingHashes'], `members[${index}]`);
    base64(member.leaf, 1, `members[${index}].leaf`, 1024);
    if (!Number.isSafeInteger(member.leafIndex) || member.leafIndex < 0 ||
        member.memberCount !== 6 ||
        !Array.isArray(member.siblingHashes) ||
        member.siblingHashes.length === 0 ||
        member.siblingHashes.length > 64) {
      fail(`members[${index}] MRL1 proof framing is invalid`);
    }
    for (const [proofIndex, hash] of member.siblingHashes.entries()) {
      base64(hash, 32, `members[${index}].siblingHashes[${proofIndex}]`);
    }
  }
  return bytes;
}

export function sha256Hex(encoded) {
  return createHash('sha256').update(Buffer.from(encoded)).digest('hex');
}

export function verifyPinnedDevMembershipArtifact(encoded, expectedSha256) {
  const bytes = validateDevMembershipArtifact(encoded);
  if (typeof expectedSha256 !== 'string' || !/^[0-9a-f]{64}$/.test(expectedSha256)) {
    fail('an exact lowercase SHA-256 pin is mandatory; TOFU is prohibited');
  }
  const actual = Buffer.from(sha256Hex(bytes), 'hex');
  const expected = Buffer.from(expectedSha256, 'hex');
  if (!timingSafeEqual(actual, expected)) fail('whole-artifact SHA-256 pin mismatches');
  return bytes;
}

export function assertDevLocalMembershipUrl(value) {
  let url;
  try {
    url = new URL(value);
  } catch {
    fail('URL is invalid');
  }
  const octets = isIP(url.hostname) === 4
    ? url.hostname.split('.').map(Number)
    : [];
  const isDevLocalAddress = octets.length === 4 && (
    octets[0] === 10 ||
    octets[0] === 127 ||
    octets[0] === 169 && octets[1] === 254 ||
    octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31 ||
    octets[0] === 192 && octets[1] === 168
  );
  if (url.protocol !== 'http:' ||
      !isDevLocalAddress ||
      url.username ||
      url.password ||
      url.search ||
      url.hash ||
      url.pathname !== '/api/network/membership-route-catalog') {
    fail('URL must be the exact DEV-LOCAL-ONLY HTTP IPv4 catalog endpoint');
  }
  return url;
}

async function verifyPublishedPin(urlValue, expectedSha256) {
  const url = assertDevLocalMembershipUrl(urlValue);
  const response = await fetch(url, {
    redirect: 'error',
    signal: AbortSignal.timeout(5_000),
    headers: { accept: 'application/json' }
  });
  if (!response.ok) fail(`catalog endpoint returned HTTP ${response.status}`);
  const declaredLength = response.headers.get('content-length');
  if (declaredLength !== null && Number(declaredLength) > MAX_MEMBERSHIP_ARTIFACT_BYTES) {
    fail('catalog endpoint declared an oversized artifact');
  }
  const bytes = Buffer.from(await response.arrayBuffer());
  verifyPinnedDevMembershipArtifact(bytes, expectedSha256);
  process.stdout.write(`${sha256Hex(bytes)}\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  if (process.argv.length !== 6 ||
      process.argv[2] !== '--url' ||
      process.argv[4] !== '--expected-sha256') {
    fail('usage: node survival-dev-membership-trust.mjs --url URL --expected-sha256 PIN');
  }
  await verifyPublishedPin(process.argv[3], process.argv[5]);
}
