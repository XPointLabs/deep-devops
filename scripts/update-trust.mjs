import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign,
  verify
} from 'node:crypto';
import { spawnSync } from 'node:child_process';
import {
  chmodSync,
  closeSync,
  fstatSync,
  fsyncSync,
  lstatSync,
  mkdtempSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  readSync,
  renameSync,
  realpathSync,
  rmSync,
  unlinkSync,
  writeFileSync
} from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const SPEC_VERSION = '1.0.35';
const MAX_METADATA_BYTES = 1_048_576;
const MAX_APK_BYTES = 1_073_741_824;
const HEX_64 = /^[0-9a-f]{64}$/;
const ISO_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const APK_SIGNER_CLASS = 'com.android.apksigner.ApkSignerTool';
const JAVA_APK_SIGNER_PROFILE = 'java-apksigner-v1';
const NODE_FIXTURE_PROFILE = 'node-test-fixture-v1';
const ED25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

function fail(message) {
  throw new Error(message);
}

function assert(condition, message) {
  if (!condition) fail(message);
}

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function parseExactUtc(value, label) {
  assert(ISO_UTC.test(value ?? ''), `${label} is invalid`);
  const milliseconds = Date.parse(value);
  assert(Number.isFinite(milliseconds) &&
    new Date(milliseconds).toISOString().replace('.000Z', 'Z') === value,
  `${label} is invalid`);
  return new Date(milliseconds);
}

export function canonicalJson(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') {
    return JSON.stringify(value);
  }
  if (typeof value === 'number') {
    assert(Number.isSafeInteger(value), 'canonical metadata permits only safe integers');
    return String(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(',')}]`;
  }
  assert(isObject(value), 'canonical metadata contains an unsupported value');
  return `{${Object.keys(value).sort().map(key =>
    `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
}

export function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

export function metadataBytes(envelope) {
  const bytes = Buffer.from(canonicalJson(envelope), 'utf8');
  assert(bytes.length <= MAX_METADATA_BYTES, 'metadata exceeds the 1 MiB prototype limit');
  return bytes;
}

export function metadataDocumentFromEnvelope(envelope) {
  const rawBytes = metadataBytes(envelope);
  return { envelope, rawBytes };
}

export function parseMetadataDocument(rawValue, label = 'metadata') {
  const rawBytes = Buffer.from(rawValue);
  assert(rawBytes.length <= MAX_METADATA_BYTES,
    `${label} exceeds the 1 MiB prototype limit`);
  const envelope = parseStrictJson(rawBytes.toString('utf8'), label);
  const canonicalBytes = metadataBytes(envelope);
  assert(rawBytes.equals(canonicalBytes),
    `${label} raw bytes are not the exact canonical POUF encoding`);
  return { envelope, rawBytes };
}

function assertMetadataDocument(document, label) {
  assert(isObject(document) && isObject(document.envelope) &&
    Buffer.isBuffer(document.rawBytes), `${label} metadata document is invalid`);
  assert(document.rawBytes.equals(metadataBytes(document.envelope)),
    `${label} raw bytes are not the exact canonical POUF encoding`);
}

export function parseStrictJson(text, label = 'JSON') {
  assert(typeof text === 'string' && Buffer.byteLength(text, 'utf8') <= MAX_METADATA_BYTES,
    `${label} exceeds the 1 MiB prototype limit`);
  let offset = text.charCodeAt(0) === 0xFEFF ? 1 : 0;

  function skipWhitespace() {
    while (offset < text.length && /[\t\n\r ]/.test(text[offset])) offset += 1;
  }

  function parseString() {
    assert(text[offset] === '"', `${label} expected a string at offset ${offset}`);
    const start = offset;
    offset += 1;
    while (offset < text.length) {
      const character = text[offset];
      if (character === '"') {
        offset += 1;
        try {
          return JSON.parse(text.slice(start, offset));
        } catch {
          fail(`${label} contains an invalid string at offset ${start}`);
        }
      }
      if (character === '\\') {
        offset += 2;
      } else {
        assert(character.charCodeAt(0) >= 0x20,
          `${label} contains a control character at offset ${offset}`);
        offset += 1;
      }
    }
    fail(`${label} contains an unterminated string at offset ${start}`);
  }

  function parseNumber() {
    const match = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/
      .exec(text.slice(offset));
    assert(match, `${label} contains an invalid number at offset ${offset}`);
    offset += match[0].length;
    return Number(match[0]);
  }

  function parseArray() {
    offset += 1;
    skipWhitespace();
    const result = [];
    if (text[offset] === ']') {
      offset += 1;
      return result;
    }
    while (true) {
      result.push(parseValue());
      skipWhitespace();
      if (text[offset] === ']') {
        offset += 1;
        return result;
      }
      assert(text[offset] === ',', `${label} expected ',' at offset ${offset}`);
      offset += 1;
      skipWhitespace();
    }
  }

  function parseObject() {
    offset += 1;
    skipWhitespace();
    const result = {};
    const keys = new Set();
    if (text[offset] === '}') {
      offset += 1;
      return result;
    }
    while (true) {
      const key = parseString();
      assert(!keys.has(key), `${label} contains duplicate object key: ${key}`);
      keys.add(key);
      skipWhitespace();
      assert(text[offset] === ':', `${label} expected ':' at offset ${offset}`);
      offset += 1;
      skipWhitespace();
      Object.defineProperty(result, key, {
        value: parseValue(),
        enumerable: true,
        configurable: true,
        writable: true
      });
      skipWhitespace();
      if (text[offset] === '}') {
        offset += 1;
        return result;
      }
      assert(text[offset] === ',', `${label} expected ',' at offset ${offset}`);
      offset += 1;
      skipWhitespace();
    }
  }

  function parseValue() {
    skipWhitespace();
    const character = text[offset];
    if (character === '{') return parseObject();
    if (character === '[') return parseArray();
    if (character === '"') return parseString();
    if (character === '-' || /[0-9]/.test(character ?? '')) return parseNumber();
    for (const [token, value] of [['true', true], ['false', false], ['null', null]]) {
      if (text.startsWith(token, offset)) {
        offset += token.length;
        return value;
      }
    }
    fail(`${label} contains an invalid token at offset ${offset}`);
  }

  const result = parseValue();
  skipWhitespace();
  assert(offset === text.length, `${label} has trailing content at offset ${offset}`);
  return result;
}

export function insecureDeterministicTestKey(label) {
  const seed = createHash('sha256')
    .update(`Deep P02 PUBLIC INSECURE TEST KEY ONLY:${label}`, 'utf8')
    .digest();
  const privateKey = createPrivateKey({
    key: Buffer.concat([ED25519_PKCS8_PREFIX, seed]),
    format: 'der',
    type: 'pkcs8'
  });
  const publicDer = createPublicKey(privateKey).export({ format: 'der', type: 'spki' });
  assert(
    publicDer.subarray(0, ED25519_SPKI_PREFIX.length).equals(ED25519_SPKI_PREFIX),
    'unexpected Ed25519 public key encoding'
  );
  const key = {
    keytype: 'ed25519',
    scheme: 'ed25519',
    keyval: {
      public: publicDer.subarray(ED25519_SPKI_PREFIX.length).toString('hex')
    }
  };
  return {
    key,
    keyid: sha256(Buffer.from(canonicalJson(key), 'utf8')),
    privateKey
  };
}

function publicKeyFromMetadata(key) {
  assert(
    key?.keytype === 'ed25519' &&
    key?.scheme === 'ed25519' &&
    /^[0-9a-f]{64}$/.test(key?.keyval?.public ?? ''),
    'only canonical Ed25519 public test keys are supported'
  );
  return createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(key.keyval.public, 'hex')]),
    format: 'der',
    type: 'spki'
  });
}

export function signMetadata(signed, signers) {
  assert(isObject(signed), 'signed metadata must be an object');
  const payload = Buffer.from(canonicalJson(signed), 'utf8');
  const signatures = signers.map(signer => ({
    keyid: signer.keyid,
    sig: sign(null, payload, signer.privateKey).toString('hex')
  }));
  return { signatures, signed };
}

function validateCommonSigned(document, expectedType) {
  assertMetadataDocument(document, expectedType);
  const envelope = document.envelope;
  assert(isObject(envelope) && isObject(envelope.signed), `${expectedType} envelope is invalid`);
  assert(envelope.signed._type === expectedType, `expected ${expectedType} metadata`);
  assert(envelope.signed.spec_version === SPEC_VERSION, `${expectedType} spec version is unsupported`);
  assert(Number.isSafeInteger(envelope.signed.version) && envelope.signed.version >= 1,
    `${expectedType} version is invalid`);
  parseExactUtc(envelope.signed.expires, `${expectedType} expiry`);
  assert(Array.isArray(envelope.signatures) && envelope.signatures.length > 0,
    `${expectedType} signatures are missing`);
  const keyids = envelope.signatures.map(item => item?.keyid);
  assert(new Set(keyids).size === keyids.length, `${expectedType} contains duplicate signer ids`);
  for (const signature of envelope.signatures) {
    assert(HEX_64.test(signature?.keyid ?? '') && /^[0-9a-f]{128}$/.test(signature?.sig ?? ''),
      `${expectedType} signature encoding is invalid`);
  }
}

function validateRoleDefinition(role, keys, label) {
  assert(isObject(role) && Array.isArray(role.keyids) &&
    Number.isSafeInteger(role.threshold) && role.threshold >= 1,
  `${label} role definition is invalid`);
  assert(new Set(role.keyids).size === role.keyids.length, `${label} role repeats key ids`);
  assert(role.threshold <= role.keyids.length, `${label} role threshold exceeds its keys`);
  for (const keyid of role.keyids) {
    assert(HEX_64.test(keyid) && isObject(keys[keyid]), `${label} references an unknown key`);
  }
}

function validateRoot(rootDocument) {
  validateCommonSigned(rootDocument, 'root');
  const signed = rootDocument.envelope.signed;
  assert(signed.consistent_snapshot === true, 'consistent snapshots must be enabled');
  assert(isObject(signed.keys) && isObject(signed.roles), 'root keys/roles are invalid');
  for (const [keyid, key] of Object.entries(signed.keys)) {
    assert(HEX_64.test(keyid), 'root key id is invalid');
    publicKeyFromMetadata(key);
    assert(sha256(Buffer.from(canonicalJson(key), 'utf8')) === keyid,
      'root key id does not match canonical key bytes');
  }
  for (const roleName of ['root', 'targets', 'snapshot', 'timestamp']) {
    validateRoleDefinition(signed.roles[roleName], signed.keys, roleName);
  }
}

function verifyRoleThreshold(document, role, keys, label, allowedSignatureIds = role.keyids) {
  const envelope = document.envelope;
  const allowed = new Set(allowedSignatureIds);
  const roleIds = new Set(role.keyids);
  const payload = Buffer.from(canonicalJson(envelope.signed), 'utf8');
  let valid = 0;
  for (const signature of envelope.signatures) {
    assert(allowed.has(signature.keyid), `${label} contains an unknown signer`);
    if (!roleIds.has(signature.keyid)) continue;
    const key = keys[signature.keyid];
    assert(key, `${label} signer key is absent`);
    if (verify(null, payload, publicKeyFromMetadata(key), Buffer.from(signature.sig, 'hex'))) {
      valid += 1;
    }
  }
  assert(valid >= role.threshold, `${label} signature threshold is not met`);
}

function assertNotExpired(document, updateStart, label) {
  assert(Date.parse(document.envelope.signed.expires) > updateStart.getTime(),
    `${label} metadata is expired (possible freeze attack)`);
}

function trustedRootBinding(rootDocument) {
  return {
    version: rootDocument.envelope.signed.version,
    sha256: sha256(rootDocument.rawBytes)
  };
}

export function createTrustedState(rootDocument, versions = {}) {
  validateRoot(rootDocument);
  return {
    schema: 'deep.update-trust.client-state.v1',
    trustedRoot: trustedRootBinding(rootDocument),
    versions: {
      timestamp: versions.timestamp ?? 0,
      snapshot: versions.snapshot ?? 0,
      targets: versions.targets ?? 0,
      androidRelease: versions.androidRelease ?? 0
    }
  };
}

function validateTrustedState(state) {
  assert(state?.schema === 'deep.update-trust.client-state.v1' &&
    Number.isSafeInteger(state?.trustedRoot?.version) &&
    state.trustedRoot.version >= 1 &&
    HEX_64.test(state?.trustedRoot?.sha256 ?? '') &&
    isObject(state.versions),
  'persisted update-trust state is invalid');
  for (const name of ['timestamp', 'snapshot', 'targets', 'androidRelease']) {
    assert(Number.isSafeInteger(state.versions[name]) && state.versions[name] >= 0,
      `persisted ${name} version is invalid`);
  }
}

function updateTrustedRoot(
  initialRoot,
  candidateRoots,
  updateStart,
  persistedState,
  persistTrustedRoot
) {
  validateRoot(initialRoot);
  validateTrustedState(persistedState);
  const initialBinding = trustedRootBinding(initialRoot);
  assert(
    persistedState.trustedRoot.version === initialBinding.version &&
    persistedState.trustedRoot.sha256 === initialBinding.sha256,
    'startup trusted root does not exactly match persisted version and raw SHA-256'
  );
  let trusted = initialRoot;
  for (const candidate of candidateRoots) {
    validateRoot(candidate);
    assert(candidate.envelope.signed.version === trusted.envelope.signed.version + 1,
      'root version must advance by exactly one');
    const oldRole = trusted.envelope.signed.roles.root;
    const newRole = candidate.envelope.signed.roles.root;
    const union = [...new Set([...oldRole.keyids, ...newRole.keyids])];
    const unionKeys = {
      ...trusted.envelope.signed.keys,
      ...candidate.envelope.signed.keys
    };
    verifyRoleThreshold(
      candidate,
      oldRole,
      unionKeys,
      'new root old-root threshold',
      union
    );
    verifyRoleThreshold(
      candidate,
      newRole,
      unionKeys,
      'new root new-root threshold',
      union
    );
    trusted = candidate;
    persistTrustedRoot?.({
      ...persistedState,
      trustedRoot: trustedRootBinding(trusted)
    });
  }
  assertNotExpired(trusted, updateStart, 'root');
  return trusted;
}

function verifyTopLevel(document, type, root, updateStart) {
  validateCommonSigned(document, type);
  const role = root.envelope.signed.roles[type];
  verifyRoleThreshold(document, role, root.envelope.signed.keys, type);
  assertNotExpired(document, updateStart, type);
}

function verifyMetaBinding(document, expected, label) {
  const bytes = document.rawBytes;
  assert(Number.isSafeInteger(expected?.version) &&
    expected.version === document.envelope.signed.version,
    `${label} version does not match its parent metadata (possible mix-and-match attack)`);
  assert(Number.isSafeInteger(expected?.length) && expected.length === bytes.length,
    `${label} length does not match its parent metadata (possible mix-and-match attack)`);
  assert(HEX_64.test(expected?.hashes?.sha256 ?? '') &&
    expected.hashes.sha256 === sha256(bytes),
  `${label} hash does not match its parent metadata (possible mix-and-match attack)`);
}

function assertNoRollback(version, trustedVersion, label, strictlyNew = false) {
  assert(Number.isSafeInteger(trustedVersion) && trustedVersion >= 0,
    `${label} trusted version is invalid`);
  assert(strictlyNew ? version > trustedVersion : version >= trustedVersion,
    `${label} rollback detected`);
}

function pathMatches(pattern, targetPath) {
  if (!pattern.includes('*')) return pattern === targetPath;
  assert(pattern.endsWith('*') && pattern.indexOf('*') === pattern.length - 1,
    'only suffix-star delegation paths are supported');
  return targetPath.startsWith(pattern.slice(0, -1));
}

function verifyDelegatedTargets(
  document,
  targetsDocument,
  snapshotDocument,
  updateStart,
  trustedVersion
) {
  validateCommonSigned(document, 'targets');
  const envelope = document.envelope;
  const targetsEnvelope = targetsDocument.envelope;
  const snapshotEnvelope = snapshotDocument.envelope;
  verifyMetaBinding(document, snapshotEnvelope.signed.meta['android-release.json'],
    'android-release targets');
  assertNoRollback(envelope.signed.version, trustedVersion, 'android-release targets');
  assertNotExpired(document, updateStart, 'android-release targets');
  const delegations = targetsEnvelope.signed.delegations;
  assert(isObject(delegations) && isObject(delegations.keys) && Array.isArray(delegations.roles),
    'targets delegations are invalid');
  assert(Object.keys(targetsEnvelope.signed.targets ?? {}).length === 0,
    'top-level targets must delegate platform release paths');
  assert(delegations.roles.length === 1,
    'prototype permits exactly one platform release delegation');
  for (const [keyid, key] of Object.entries(delegations.keys)) {
    publicKeyFromMetadata(key);
    assert(sha256(Buffer.from(canonicalJson(key), 'utf8')) === keyid,
      'delegated key id does not match canonical key bytes');
  }
  const role = delegations.roles.find(item => item?.name === 'android-release');
  assert(role && Array.isArray(role.paths) && role.terminating === true,
    'android-release delegation is missing or non-terminating');
  validateRoleDefinition(role, delegations.keys, 'android-release');
  verifyRoleThreshold(document, role, delegations.keys, 'android-release targets');
  for (const targetPath of Object.keys(envelope.signed.targets ?? {})) {
    assert(targetPath.split('/').every(part => part && part !== '.' && part !== '..'),
      `delegated target path is non-canonical: ${targetPath}`);
    assert(role.paths.some(pattern => pathMatches(pattern, targetPath)),
      `delegated target path is unauthorized: ${targetPath}`);
  }
}

export function verifyUpdateBundle({
  trustedRoot,
  candidateRoots = [],
  timestamp,
  snapshot,
  targets,
  delegatedTargets,
  trustedState,
  updateStart,
  persistTrustedRoot
}) {
  const fixedStart = parseExactUtc(updateStart, 'fixed update start time');
  validateTrustedState(trustedState);
  const root = updateTrustedRoot(
    trustedRoot,
    candidateRoots,
    fixedStart,
    trustedState,
    persistTrustedRoot
  );
  const trustedVersions = trustedState.versions;

  verifyTopLevel(timestamp, 'timestamp', root, fixedStart);
  assertNoRollback(
    timestamp.envelope.signed.version,
    trustedVersions.timestamp,
    'timestamp',
    true
  );
  const snapshotBinding = timestamp.envelope.signed.meta?.['snapshot.json'];
  assert(Object.keys(timestamp.envelope.signed.meta ?? {}).length === 1 && snapshotBinding,
    'timestamp must describe only snapshot.json');
  assertNoRollback(snapshotBinding.version, trustedVersions.snapshot,
    'timestamp snapshot reference');

  verifyTopLevel(snapshot, 'snapshot', root, fixedStart);
  verifyMetaBinding(snapshot, snapshotBinding, 'snapshot');
  assertNoRollback(snapshot.envelope.signed.version, trustedVersions.snapshot, 'snapshot');
  assert(
    Object.keys(snapshot.envelope.signed.meta ?? {}).sort().join(',') ===
      'android-release.json,targets.json',
    'snapshot must describe exactly targets.json and android-release.json'
  );

  verifyTopLevel(targets, 'targets', root, fixedStart);
  verifyMetaBinding(
    targets,
    snapshot.envelope.signed.meta?.['targets.json'],
    'targets'
  );
  assertNoRollback(targets.envelope.signed.version, trustedVersions.targets, 'targets');

  verifyDelegatedTargets(
    delegatedTargets,
    targets,
    snapshot,
    fixedStart,
    trustedVersions.androidRelease
  );

  const state = {
    schema: 'deep.update-trust.client-state.v1',
    trustedRoot: trustedRootBinding(root),
    versions: {
      timestamp: timestamp.envelope.signed.version,
      snapshot: snapshot.envelope.signed.version,
      targets: targets.envelope.signed.version,
      androidRelease: delegatedTargets.envelope.signed.version
    }
  };
  return {
    root,
    state,
    delegatedTargets
  };
}

function verifyTargetBytes(targetsDocument, targetPath, bytes) {
  const description = targetsDocument.envelope.signed.targets?.[targetPath];
  assert(isObject(description), `target is not signed: ${targetPath}`);
  assert(Number.isSafeInteger(description.length) && description.length === bytes.length,
    `${targetPath} length mismatch`);
  assert(HEX_64.test(description.hashes?.sha256 ?? '') &&
    description.hashes.sha256 === sha256(bytes), `${targetPath} SHA-256 mismatch`);
  return description;
}

function parseJsonBytes(bytes, label) {
  try {
    return parseStrictJson(bytes.toString('utf8'), label);
  } catch (error) {
    if (error instanceof Error && error.message.startsWith(label)) throw error;
    fail(`${label} is not valid UTF-8 JSON`);
  }
}

export function verifySbomAndReproducibility({
  delegatedTargets,
  apkPath,
  apkBytes,
  files
}) {
  const apk = verifyTargetBytes(delegatedTargets, apkPath, apkBytes);
  const custom = apk.custom;
  assert(custom?.platform === 'android' && custom?.packageId === 'network.xpoint.deep',
    'Android package identity metadata is invalid');
  assert(/^[1-9][0-9]*$/.test(custom.versionCode ?? '') &&
    typeof custom.versionName === 'string' && custom.versionName.length > 0,
  'Android package version metadata is invalid');
  assert(HEX_64.test(custom.packageSignerSha256 ?? ''),
    'Android package signer metadata is invalid');
  assert(HEX_64.test(custom.programRevisionSha256 ?? '') &&
    /^[0-9a-f]{40}$/.test(custom.sourceCommit ?? ''),
  'Android source/program binding is invalid');

  const sbomPath = custom.sbom?.path;
  const provenancePath = custom.reproducibleBuild?.provenancePath;
  assert(typeof sbomPath === 'string' && typeof provenancePath === 'string',
    'SBOM/provenance target references are missing');
  const sbomBytes = files[sbomPath];
  const provenanceBytes = files[provenancePath];
  assert(Buffer.isBuffer(sbomBytes) && Buffer.isBuffer(provenanceBytes),
    'SBOM/provenance files are missing');
  verifyTargetBytes(delegatedTargets, sbomPath, sbomBytes);
  verifyTargetBytes(delegatedTargets, provenancePath, provenanceBytes);
  assert(custom.sbom.sha256 === sha256(sbomBytes), 'SBOM custom hash mismatch');

  const sbom = parseJsonBytes(sbomBytes, 'SBOM');
  assert(sbom.bomFormat === 'CycloneDX' && typeof sbom.specVersion === 'string' &&
    sbom.metadata?.component?.name === 'network.xpoint.deep',
  'SBOM contract is invalid');

  const provenance = parseJsonBytes(provenanceBytes, 'reproducibility provenance');
  const builders = provenance.builders;
  assert(provenance.schema === 'deep.reproducible-build.v1' &&
    provenance.sourceCommit === custom.sourceCommit &&
    provenance.programRevisionSha256 === custom.programRevisionSha256 &&
    provenance.buildDefinitionSha256 === custom.reproducibleBuild.buildDefinitionSha256 &&
    provenance.sourceDateEpoch === custom.reproducibleBuild.sourceDateEpoch &&
    provenance.sbomSha256 === sha256(sbomBytes) &&
    Number.isSafeInteger(custom.reproducibleBuild.minimumIndependentBuilders) &&
    custom.reproducibleBuild.minimumIndependentBuilders >= 2 &&
    Array.isArray(builders) &&
    builders.length >= custom.reproducibleBuild.minimumIndependentBuilders,
  'reproducibility provenance contract is invalid');
  assert(new Set(builders.map(item => item?.builderId)).size === builders.length,
    'reproducibility builders are not independent');
  assert(builders.every(item => typeof item.builderId === 'string' &&
    item.artifactSha256 === sha256(apkBytes)),
  'independent builders did not reproduce the signed APK hash');
  return { apk, sbom, provenance };
}

function normalizeSignerDigest(value) {
  return value.replace(/[^0-9A-Fa-f]/g, '').toLowerCase();
}

export function parseApkSignerDigests(output) {
  const values = [];
  const pattern = /Signer\s+#\d+\s+certificate\s+SHA-256\s+digest:\s*([0-9A-Fa-f: -]+)/g;
  for (const match of output.matchAll(pattern)) {
    const digest = normalizeSignerDigest(match[1]);
    assert(HEX_64.test(digest), 'apksigner returned an invalid certificate SHA-256');
    values.push(digest);
  }
  const unique = [...new Set(values)];
  assert(unique.length === 1, 'apksigner must report exactly one unique signing certificate');
  return unique;
}

function canonicalPinnedFile(filePath, expectedSha256, label) {
  assert(HEX_64.test(expectedSha256 ?? ''), `${label} SHA-256 is required`);
  const resolved = path.resolve(filePath);
  const info = lstatSync(resolved);
  assert(info.isFile() && !info.isSymbolicLink(),
    `${label} must be a regular non-symlink file`);
  const canonical = realpathSync(resolved);
  assert(path.normalize(canonical) === path.normalize(resolved),
    `${label} path must already be canonical and contain no links`);
  assert(sha256(readFileSync(canonical)) === expectedSha256,
    `${label} does not match trusted tool policy`);
  return canonical;
}

function canonicalTreeRelativePath(value, label) {
  assert(typeof value === 'string' && value.length > 0 && !value.includes('\\'),
    `${label} path must use canonical forward slashes`);
  const parts = value.split('/');
  assert(parts.every(part => part && part !== '.' && part !== '..'),
    `${label} path is not canonical`);
  return parts;
}

function enumeratePinnedTree(root, relative = '') {
  const records = [];
  const directory = relative
    ? path.join(root, ...relative.split('/'))
    : root;
  for (const entry of readdirSync(directory, { withFileTypes: true })
    .sort((left, right) => left.name.localeCompare(right.name))) {
    const childRelative = relative ? `${relative}/${entry.name}` : entry.name;
    canonicalTreeRelativePath(childRelative, 'runtime tree');
    const child = path.join(directory, entry.name);
    const info = lstatSync(child);
    assert(!info.isSymbolicLink(), 'runtime tree contains a link or reparse entry');
    const canonicalChild = realpathSync(child);
    assert(canonicalChild.startsWith(`${root}${path.sep}`),
      'runtime tree entry escapes its canonical root');
    if (info.isDirectory()) {
      records.push(...enumeratePinnedTree(root, childRelative));
    } else {
      assert(info.isFile(), 'runtime tree contains a non-file entry');
      records.push({
        path: childRelative.replaceAll('\\', '/'),
        length: info.size,
        sha256: sha256(readFileSync(canonicalChild))
      });
    }
  }
  return records;
}

function validatePinnedRuntimeTree({
  runtimeRootPath,
  runtimeManifestPath,
  runtimeManifestSha256,
  runtimePath,
  runtimeSha256
}) {
  const resolvedRoot = path.resolve(runtimeRootPath);
  const rootInfo = lstatSync(resolvedRoot);
  assert(rootInfo.isDirectory() && !rootInfo.isSymbolicLink(),
    'APK verifier runtime root must be a regular non-symlink directory');
  const canonicalRoot = realpathSync(resolvedRoot);
  assert(path.normalize(canonicalRoot) === path.normalize(resolvedRoot),
    'APK verifier runtime root must be canonical and contain no links');
  const canonicalManifest = canonicalPinnedFile(
    runtimeManifestPath, runtimeManifestSha256, 'APK verifier runtime manifest'
  );
  const manifest = parseStrictJson(
    readFileSync(canonicalManifest, 'utf8'), 'APK verifier runtime manifest'
  );
  assert(manifest?.schema === 'deep.apk-verifier-runtime-tree.v1' &&
    typeof manifest.entrypoint === 'string' &&
    Array.isArray(manifest.files) && manifest.files.length > 0,
  'APK verifier runtime manifest is invalid');
  const entrypointParts = canonicalTreeRelativePath(
    manifest.entrypoint, 'runtime entrypoint'
  );
  const expectedFiles = manifest.files.map((file, index) => {
    canonicalTreeRelativePath(file?.path, `runtime manifest file ${index}`);
    assert(Number.isSafeInteger(file.length) && file.length >= 0 &&
      HEX_64.test(file.sha256 ?? ''),
    `runtime manifest file ${index} is invalid`);
    return {
      path: file.path,
      length: file.length,
      sha256: file.sha256
    };
  });
  assert(new Set(expectedFiles.map(file => file.path)).size === expectedFiles.length,
    'APK verifier runtime manifest contains duplicate paths');
  const sortedExpected = [...expectedFiles].sort((left, right) =>
    left.path.localeCompare(right.path));
  const actualFiles = enumeratePinnedTree(canonicalRoot).sort((left, right) =>
    left.path.localeCompare(right.path));
  assert(JSON.stringify(actualFiles) === JSON.stringify(sortedExpected),
    'APK verifier runtime tree does not match trusted manifest');
  const manifestEntrypoint = path.join(canonicalRoot, ...entrypointParts);
  const canonicalRuntime = canonicalPinnedFile(
    runtimePath, runtimeSha256, 'APK verifier runtime'
  );
  assert(path.normalize(canonicalRuntime) === path.normalize(manifestEntrypoint),
    'APK verifier runtime entrypoint does not match trusted manifest');
  const entrypoint = sortedExpected.find(file => file.path === manifest.entrypoint);
  assert(entrypoint?.sha256 === runtimeSha256,
    'APK verifier runtime hash is not bound by the trusted manifest');
  return { canonicalRuntime, canonicalRoot, canonicalManifest };
}

function fixedVerifierInvocation(profile, runtimeArtifact, apkSnapshot) {
  const common = [
    '-cp',
    runtimeArtifact,
    APK_SIGNER_CLASS,
    'verify',
    '--verbose',
    '--print-certs',
    apkSnapshot
  ];
  if (profile === JAVA_APK_SIGNER_PROFILE) return common;
  // Test-only: Node needs the pinned fixture artifact as its program entry point.
  if (profile === NODE_FIXTURE_PROFILE) return [runtimeArtifact, ...common];
  fail('unsupported APK verifier runtime profile');
}

export function runTrustedApkSigner({
  runtimePath,
  runtimeSha256,
  runtimeRootPath,
  runtimeManifestPath,
  runtimeManifestSha256,
  runtimeArtifactPath,
  runtimeArtifactSha256,
  apkSnapshotPath,
  apkSnapshotSha256,
  profile = JAVA_APK_SIGNER_PROFILE
}) {
  const runtimePolicy = {
    runtimeRootPath,
    runtimeManifestPath,
    runtimeManifestSha256,
    runtimePath,
    runtimeSha256
  };
  const { canonicalRuntime } = validatePinnedRuntimeTree(runtimePolicy);
  const canonicalArtifact = canonicalPinnedFile(
    runtimeArtifactPath, runtimeArtifactSha256, 'APK verifier artifact'
  );
  const canonicalSnapshot = canonicalPinnedFile(
    apkSnapshotPath, apkSnapshotSha256, 'APK snapshot'
  );
  const runtimeBefore = sha256(readFileSync(canonicalRuntime));
  const artifactBefore = sha256(readFileSync(canonicalArtifact));
  const snapshotBefore = sha256(readFileSync(canonicalSnapshot));
  const args = fixedVerifierInvocation(profile, canonicalArtifact, canonicalSnapshot);
  const privateTemp = path.dirname(canonicalSnapshot);
  const result = spawnSync(canonicalRuntime, args, {
    encoding: 'utf8',
    windowsHide: true,
    shell: false,
    env: {
      LANG: 'C',
      LC_ALL: 'C',
      TMPDIR: privateTemp,
      TMP: privateTemp,
      TEMP: privateTemp
    },
    maxBuffer: 2 * 1024 * 1024
  });
  assert(sha256(readFileSync(canonicalRuntime)) === runtimeBefore,
    'APK verifier runtime changed during package verification');
  validatePinnedRuntimeTree(runtimePolicy);
  assert(sha256(readFileSync(canonicalArtifact)) === artifactBefore,
    'APK verifier artifact changed during package verification');
  assert(sha256(readFileSync(canonicalSnapshot)) === snapshotBefore,
    'APK snapshot changed during package signer verification');
  assert(result.status === 0, 'apksigner rejected the APK');
  return `${result.stdout ?? ''}\n${result.stderr ?? ''}`;
}

function createPrivateSnapshotRoot(rootPath) {
  assert(typeof rootPath === 'string' && rootPath.length > 0,
    'trusted verification temp root is required');
  const resolvedRoot = path.resolve(rootPath);
  const rootInfo = lstatSync(resolvedRoot);
  assert(rootInfo.isDirectory() && !rootInfo.isSymbolicLink(),
    'verification temp root must be a regular non-symlink directory');
  const canonicalRoot = realpathSync(resolvedRoot);
  assert(path.normalize(canonicalRoot) === path.normalize(resolvedRoot),
    'verification temp root must be canonical and contain no links');
  const directory = mkdtempSync(path.join(canonicalRoot, 'deep-apk-'));
  chmodSync(directory, 0o700);
  const createdInfo = lstatSync(directory);
  assert(createdInfo.isDirectory() && !createdInfo.isSymbolicLink() &&
    path.normalize(realpathSync(directory)) === path.normalize(directory),
  'private verification directory is unsafe');
  return directory;
}

function writePrivateSnapshot(directory, bytes) {
  const snapshot = path.join(directory, 'artifact.apk');
  let descriptor;
  try {
    descriptor = openSync(snapshot, 'wx', 0o600);
    writeFileSync(descriptor, bytes);
    fsyncSync(descriptor);
    closeSync(descriptor);
    descriptor = undefined;
    chmodSync(snapshot, 0o600);
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
  return snapshot;
}

function readApkOnceBounded(filePath, expectedLength) {
  const descriptor = openSync(filePath, 'r');
  try {
    const opened = fstatSync(descriptor);
    assert(opened.isFile() && opened.size === expectedLength,
      'APK length does not match signed target metadata');
    const bytes = Buffer.allocUnsafe(expectedLength);
    let offset = 0;
    while (offset < expectedLength) {
      const count = readSync(descriptor, bytes, offset, expectedLength - offset, null);
      assert(count > 0, 'APK changed while creating the verification snapshot');
      offset += count;
    }
    const extra = Buffer.allocUnsafe(1);
    assert(readSync(descriptor, extra, 0, 1, null) === 0,
      'APK changed while creating the verification snapshot');
    return bytes;
  } finally {
    closeSync(descriptor);
  }
}

export function verifyOfflineAndroidArtifact({
  verifiedBundle,
  apkPath,
  apkFile,
  artifactFiles,
  verifierRuntimePath,
  verifierRuntimeSha256,
  verifierRuntimeRootPath,
  verifierRuntimeManifestPath,
  verifierRuntimeManifestSha256,
  verifierArtifactPath,
  verifierArtifactSha256,
  verificationTempRoot,
  verifierProfile = JAVA_APK_SIGNER_PROFILE
}) {
  const info = lstatSync(apkFile);
  assert(info.isFile() && !info.isSymbolicLink(), 'APK must be a regular non-symlink file');
  const canonicalApk = realpathSync(apkFile);
  const target = verifiedBundle.delegatedTargets.envelope.signed.targets?.[apkPath];
  assert(target && Number.isSafeInteger(target.length) &&
    target.length >= 0 && target.length <= MAX_APK_BYTES,
  'signed APK length is missing or exceeds the 1 GiB offline verification limit');
  const before = readApkOnceBounded(canonicalApk, target.length);
  const evidence = verifySbomAndReproducibility({
    delegatedTargets: verifiedBundle.delegatedTargets,
    apkPath,
    apkBytes: before,
    files: artifactFiles
  });
  const privateDirectory = createPrivateSnapshotRoot(verificationTempRoot);
  try {
    const snapshot = writePrivateSnapshot(privateDirectory, before);
    const signerOutput = runTrustedApkSigner({
      runtimePath: verifierRuntimePath,
      runtimeSha256: verifierRuntimeSha256,
      runtimeRootPath: verifierRuntimeRootPath,
      runtimeManifestPath: verifierRuntimeManifestPath,
      runtimeManifestSha256: verifierRuntimeManifestSha256,
      runtimeArtifactPath: verifierArtifactPath,
      runtimeArtifactSha256: verifierArtifactSha256,
      apkSnapshotPath: snapshot,
      apkSnapshotSha256: sha256(before),
      profile: verifierProfile
    });
    const [observedSigner] = parseApkSignerDigests(signerOutput);
    assert(observedSigner === evidence.apk.custom.packageSignerSha256,
      'APK package signer does not match signed update metadata');
    return {
      status: 'passed',
      targetPath: apkPath,
      apkSha256: sha256(before),
      packageId: evidence.apk.custom.packageId,
      versionCode: evidence.apk.custom.versionCode,
      versionName: evidence.apk.custom.versionName,
      packageSignerSha256: observedSigner,
      verifierProfile,
      verifierRuntimeSha256,
      verifierRuntimeManifestSha256,
      verifierArtifactSha256,
      sbomSha256: evidence.apk.custom.sbom.sha256,
      independentBuilderCount: evidence.provenance.builders.length
    };
  } finally {
    rmSync(privateDirectory, { recursive: true, force: true });
  }
}

function parseCli(argv) {
  const [command, ...rest] = argv;
  const options = { candidateRoot: [] };
  for (let index = 0; index < rest.length; index += 2) {
    const name = rest[index];
    const value = rest[index + 1];
    assert(name?.startsWith('--') && value && !value.startsWith('--'), `${name} requires a value`);
    const key = name.slice(2).replace(/-([a-z])/g, (_, letter) => letter.toUpperCase());
    if (key === 'candidateRoot') options.candidateRoot.push(value);
    else options[key] = value;
  }
  return { command, options };
}

function readJson(filePath) {
  return parseStrictJson(readFileSync(filePath, 'utf8'), filePath);
}

function readMetadataDocument(filePath) {
  return parseMetadataDocument(readFileSync(filePath), filePath);
}

export function writeTrustedStateAtomic(filePath, state) {
  validateTrustedState(state);
  const target = path.resolve(filePath);
  mkdirSync(path.dirname(target), { recursive: true });
  const temporary = `${target}.${process.pid}.${Date.now()}.tmp`;
  const bytes = Buffer.from(`${JSON.stringify(state, null, 2)}\n`, 'utf8');
  let descriptor;
  try {
    descriptor = openSync(temporary, 'wx', 0o600);
    writeFileSync(descriptor, bytes);
    fsyncSync(descriptor);
    closeSync(descriptor);
    descriptor = undefined;
    renameSync(temporary, target);
    try {
      const directory = openSync(path.dirname(target), 'r');
      try {
        fsyncSync(directory);
      } finally {
        closeSync(directory);
      }
    } catch {
      // Windows does not expose fsync for directory handles. renameSync still
      // provides the same-directory atomic replacement boundary.
    }
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
    try {
      unlinkSync(temporary);
    } catch {
      // The successful rename removes the temporary path.
    }
  }
}

function safeArtifactPath(root, relativePath) {
  assert(relativePath.split('/').every(part => part && part !== '.' && part !== '..'),
    'target path is not canonical');
  const resolvedRoot = realpathSync(root);
  const candidate = path.resolve(resolvedRoot, ...relativePath.split('/'));
  assert(candidate.startsWith(`${resolvedRoot}${path.sep}`), 'target path escapes artifact root');
  const info = lstatSync(candidate);
  assert(info.isFile() && !info.isSymbolicLink(), 'target must be a regular non-symlink file');
  const canonicalCandidate = realpathSync(candidate);
  assert(canonicalCandidate.startsWith(`${resolvedRoot}${path.sep}`),
    'target canonical path escapes artifact root');
  return canonicalCandidate;
}

function runVerifyAndroid(options) {
  const required = [
    'trustedRoot', 'metadataDir', 'artifactRoot', 'target', 'javaRuntime',
    'javaRuntimeSha256', 'javaRuntimeRoot', 'javaRuntimeManifest',
    'javaRuntimeManifestSha256', 'apkSignerJar', 'apkSignerJarSha256',
    'verificationTempRoot', 'state', 'now', 'summary'
  ];
  for (const name of required) assert(options[name], `--${name} is required`);
  const metadataDir = path.resolve(options.metadataDir);
  const delegatedTargets = readMetadataDocument(
    path.join(metadataDir, 'android-release.json')
  );
  const trustedState = readJson(options.state);
  const verifiedBundle = verifyUpdateBundle({
    trustedRoot: readMetadataDocument(options.trustedRoot),
    candidateRoots: options.candidateRoot.map(readMetadataDocument),
    timestamp: readMetadataDocument(path.join(metadataDir, 'timestamp.json')),
    snapshot: readMetadataDocument(path.join(metadataDir, 'snapshot.json')),
    targets: readMetadataDocument(path.join(metadataDir, 'targets.json')),
    delegatedTargets,
    trustedState,
    updateStart: options.now,
    persistTrustedRoot: state => writeTrustedStateAtomic(options.state, state)
  });
  const apkDescription = delegatedTargets.envelope.signed.targets?.[options.target];
  assert(apkDescription, 'requested Android target is not signed');
  const sbomPath = apkDescription.custom?.sbom?.path;
  const provenancePath = apkDescription.custom?.reproducibleBuild?.provenancePath;
  const artifactFiles = {
    [sbomPath]: readFileSync(safeArtifactPath(options.artifactRoot, sbomPath)),
    [provenancePath]: readFileSync(safeArtifactPath(options.artifactRoot, provenancePath))
  };
  const result = verifyOfflineAndroidArtifact({
    verifiedBundle,
    apkPath: options.target,
    apkFile: safeArtifactPath(options.artifactRoot, options.target),
    artifactFiles,
    verifierRuntimePath: options.javaRuntime,
    verifierRuntimeSha256: options.javaRuntimeSha256.toLowerCase(),
    verifierRuntimeRootPath: options.javaRuntimeRoot,
    verifierRuntimeManifestPath: options.javaRuntimeManifest,
    verifierRuntimeManifestSha256: options.javaRuntimeManifestSha256.toLowerCase(),
    verifierArtifactPath: options.apkSignerJar,
    verifierArtifactSha256: options.apkSignerJarSha256.toLowerCase(),
    verificationTempRoot: options.verificationTempRoot,
    verifierProfile: JAVA_APK_SIGNER_PROFILE
  });
  writeTrustedStateAtomic(options.state, verifiedBundle.state);
  mkdirSync(path.dirname(path.resolve(options.summary)), { recursive: true });
  writeFileSync(options.summary, `${JSON.stringify({
    schema: 'deep.update-trust.offline-android-verification.v1',
    generatedAtUtc: new Date().toISOString(),
    trustedState: verifiedBundle.state,
    ...result
  }, null, 2)}\n`, 'utf8');
  console.log(`Offline Android update verified: ${result.apkSha256}`);
}

const isMain = process.argv[1] &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  try {
    const { command, options } = parseCli(process.argv.slice(2));
    assert(command === 'verify-android', 'supported command: verify-android');
    runVerifyAndroid(options);
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  }
}
