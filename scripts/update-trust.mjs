import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign,
  verify
} from 'node:crypto';
import { spawnSync } from 'node:child_process';
import {
  lstatSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  writeFileSync
} from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const SPEC_VERSION = '1.0.35';
const MAX_METADATA_BYTES = 1_048_576;
const HEX_64 = /^[0-9a-f]{64}$/;
const ISO_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
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

function validateCommonSigned(envelope, expectedType) {
  assert(isObject(envelope) && isObject(envelope.signed), `${expectedType} envelope is invalid`);
  metadataBytes(envelope);
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

function validateRoot(root) {
  validateCommonSigned(root, 'root');
  const signed = root.signed;
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

function verifyRoleThreshold(envelope, role, keys, label, allowedSignatureIds = role.keyids) {
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

function assertNotExpired(envelope, updateStart, label) {
  assert(Date.parse(envelope.signed.expires) > updateStart.getTime(),
    `${label} metadata is expired (possible freeze attack)`);
}

function updateTrustedRoot(initialRoot, candidateRoots, updateStart) {
  validateRoot(initialRoot);
  let trusted = initialRoot;
  for (const candidate of candidateRoots) {
    validateRoot(candidate);
    assert(candidate.signed.version === trusted.signed.version + 1,
      'root version must advance by exactly one');
    const oldRole = trusted.signed.roles.root;
    const newRole = candidate.signed.roles.root;
    const union = [...new Set([...oldRole.keyids, ...newRole.keyids])];
    const unionKeys = { ...trusted.signed.keys, ...candidate.signed.keys };
    verifyRoleThreshold(candidate, oldRole, unionKeys, 'new root under old root', union);
    verifyRoleThreshold(candidate, newRole, unionKeys, 'new root under new root', union);
    trusted = candidate;
  }
  assertNotExpired(trusted, updateStart, 'root');
  return trusted;
}

function verifyTopLevel(envelope, type, root, updateStart) {
  validateCommonSigned(envelope, type);
  const role = root.signed.roles[type];
  verifyRoleThreshold(envelope, role, root.signed.keys, type);
  assertNotExpired(envelope, updateStart, type);
}

function verifyMetaBinding(envelope, expected, label) {
  const bytes = metadataBytes(envelope);
  assert(Number.isSafeInteger(expected?.version) && expected.version === envelope.signed.version,
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

function verifyDelegatedTargets(envelope, targetsEnvelope, snapshotEnvelope, updateStart, trustedVersion) {
  validateCommonSigned(envelope, 'targets');
  verifyMetaBinding(envelope, snapshotEnvelope.signed.meta['android-release.json'],
    'android-release targets');
  assertNoRollback(envelope.signed.version, trustedVersion, 'android-release targets');
  assertNotExpired(envelope, updateStart, 'android-release targets');
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
  verifyRoleThreshold(envelope, role, delegations.keys, 'android-release targets');
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
  trustedVersions = {},
  updateStart
}) {
  const fixedStart = parseExactUtc(updateStart, 'fixed update start time');
  if (trustedVersions.root !== undefined) {
    assert(trustedVersions.root === trustedRoot.signed?.version,
      'trusted root file does not match persisted root state');
  }
  const root = updateTrustedRoot(trustedRoot, candidateRoots, fixedStart);

  verifyTopLevel(timestamp, 'timestamp', root, fixedStart);
  assertNoRollback(timestamp.signed.version, trustedVersions.timestamp ?? 0, 'timestamp', true);
  const snapshotBinding = timestamp.signed.meta?.['snapshot.json'];
  assert(Object.keys(timestamp.signed.meta ?? {}).length === 1 && snapshotBinding,
    'timestamp must describe only snapshot.json');
  assertNoRollback(snapshotBinding.version, trustedVersions.snapshot ?? 0,
    'timestamp snapshot reference');

  verifyTopLevel(snapshot, 'snapshot', root, fixedStart);
  verifyMetaBinding(snapshot, snapshotBinding, 'snapshot');
  assertNoRollback(snapshot.signed.version, trustedVersions.snapshot ?? 0, 'snapshot');
  assert(
    Object.keys(snapshot.signed.meta ?? {}).sort().join(',') ===
      'android-release.json,targets.json',
    'snapshot must describe exactly targets.json and android-release.json'
  );

  verifyTopLevel(targets, 'targets', root, fixedStart);
  verifyMetaBinding(targets, snapshot.signed.meta?.['targets.json'], 'targets');
  assertNoRollback(targets.signed.version, trustedVersions.targets ?? 0, 'targets');

  verifyDelegatedTargets(
    delegatedTargets,
    targets,
    snapshot,
    fixedStart,
    trustedVersions.androidRelease ?? 0
  );

  return {
    root,
    state: {
      root: root.signed.version,
      timestamp: timestamp.signed.version,
      snapshot: snapshot.signed.version,
      targets: targets.signed.version,
      androidRelease: delegatedTargets.signed.version
    },
    delegatedTargets
  };
}

function verifyTargetBytes(targetsEnvelope, targetPath, bytes) {
  const description = targetsEnvelope.signed.targets?.[targetPath];
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

function defaultRunApkSigner(apkSignerPath, apkPath, expectedSha256) {
  const info = lstatSync(apkSignerPath);
  assert(info.isFile() && !info.isSymbolicLink(),
    'apksigner must be a regular non-symlink file');
  const canonicalSigner = realpathSync(apkSignerPath);
  assert(HEX_64.test(expectedSha256 ?? ''), 'trusted apksigner SHA-256 is required');
  const before = readFileSync(canonicalSigner);
  assert(sha256(before) === expectedSha256, 'apksigner does not match trusted tool policy');
  let executable = canonicalSigner;
  let args = ['verify', '--verbose', '--print-certs', apkPath];
  if (process.platform === 'win32' && /\.bat$/i.test(canonicalSigner)) {
    assert(!/[&|<>()^%!"\r\n]/.test(`${canonicalSigner}${apkPath}`),
      'Windows apksigner/APK path contains unsafe command characters');
    executable = process.env.ComSpec ?? 'cmd.exe';
    args = [
      '/d',
      '/s',
      '/c',
      'call',
      canonicalSigner,
      'verify',
      '--verbose',
      '--print-certs',
      apkPath
    ];
  }
  const result = spawnSync(executable, args, {
    encoding: 'utf8',
    windowsHide: true,
    shell: false,
    maxBuffer: 2 * 1024 * 1024
  });
  assert(result.status === 0, 'apksigner rejected the APK');
  assert(sha256(readFileSync(canonicalSigner)) === expectedSha256,
    'apksigner changed during package verification');
  return `${result.stdout ?? ''}\n${result.stderr ?? ''}`;
}

export function verifyOfflineAndroidArtifact({
  verifiedBundle,
  apkPath,
  apkFile,
  artifactFiles,
  apkSignerPath,
  apkSignerSha256,
  runApkSigner = defaultRunApkSigner
}) {
  const info = lstatSync(apkFile);
  assert(info.isFile() && !info.isSymbolicLink(), 'APK must be a regular non-symlink file');
  const canonicalApk = realpathSync(apkFile);
  const before = readFileSync(canonicalApk);
  const evidence = verifySbomAndReproducibility({
    delegatedTargets: verifiedBundle.delegatedTargets,
    apkPath,
    apkBytes: before,
    files: artifactFiles
  });
  const signerOutput = runApkSigner(apkSignerPath, canonicalApk, apkSignerSha256);
  const [observedSigner] = parseApkSignerDigests(signerOutput);
  assert(observedSigner === evidence.apk.custom.packageSignerSha256,
    'APK package signer does not match signed update metadata');
  const after = readFileSync(canonicalApk);
  assert(sha256(before) === sha256(after), 'APK changed during package signer verification');
  return {
    status: 'passed',
    targetPath: apkPath,
    apkSha256: sha256(before),
    packageId: evidence.apk.custom.packageId,
    versionCode: evidence.apk.custom.versionCode,
    versionName: evidence.apk.custom.versionName,
    packageSignerSha256: observedSigner,
    apkSignerToolSha256: apkSignerSha256 ?? 'synthetic-contract-injection',
    sbomSha256: evidence.apk.custom.sbom.sha256,
    independentBuilderCount: evidence.provenance.builders.length
  };
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
    'trustedRoot', 'metadataDir', 'artifactRoot', 'target', 'apkSigner',
    'apkSignerSha256', 'now', 'summary'
  ];
  for (const name of required) assert(options[name], `--${name} is required`);
  const metadataDir = path.resolve(options.metadataDir);
  const delegatedTargets = readJson(path.join(metadataDir, 'android-release.json'));
  const verifiedBundle = verifyUpdateBundle({
    trustedRoot: readJson(options.trustedRoot),
    candidateRoots: options.candidateRoot.map(readJson),
    timestamp: readJson(path.join(metadataDir, 'timestamp.json')),
    snapshot: readJson(path.join(metadataDir, 'snapshot.json')),
    targets: readJson(path.join(metadataDir, 'targets.json')),
    delegatedTargets,
    trustedVersions: options.state ? readJson(options.state) : {},
    updateStart: options.now
  });
  const apkDescription = delegatedTargets.signed.targets?.[options.target];
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
    apkSignerPath: options.apkSigner,
    apkSignerSha256: options.apkSignerSha256.toLowerCase()
  });
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
