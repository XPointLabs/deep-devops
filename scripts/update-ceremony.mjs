import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, randomUUID, sign as cryptoSign } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import {
  lstat,
  mkdir,
  readFile,
  readdir,
  realpath,
  stat,
  writeFile
} from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  canonicalJson,
  createTrustedState,
  metadataDocumentFromEnvelope,
  parseMetadataDocument,
  sha256,
  verifySbomAndReproducibility,
  verifyUpdateBundle
} from './update-trust.mjs';

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
export const repositoryRoot = path.resolve(scriptDirectory, '..');
const fixedUpdateStart = '2030-01-01T00:00:00Z';
const onlineExpiry = '2030-01-03T00:00:00Z';
const rootExpiry = '2035-01-01T00:00:00Z';
const hex64 = /^[0-9a-f]{64}$/;

function exactKeys(value, expected) {
  return JSON.stringify(Object.keys(value ?? {}).sort()) === JSON.stringify([...expected].sort());
}

function fail(message) {
  throw new Error(message);
}

function contract(condition, message) {
  if (!condition) fail(message);
}

function looksLikePlaceholderHex(value) {
  return /^(?:([0-9a-f])\1+|([0-9a-f]{2})\2+)$/i.test(value ?? '');
}

function jsonBytes(value) {
  return Buffer.from(`${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

function canonicalBytes(value) {
  return Buffer.from(canonicalJson(value), 'utf8');
}

function targetDescription(bytes, custom = undefined) {
  return {
    length: bytes.length,
    hashes: { sha256: sha256(bytes) },
    ...(custom ? { custom } : {})
  };
}

function metadataDescription(document) {
  return {
    version: document.envelope.signed.version,
    length: document.rawBytes.length,
    hashes: { sha256: sha256(document.rawBytes) }
  };
}

class EphemeralTestHsmAdapter {
  #keys = new Map();

  createSigner(label) {
    const { privateKey, publicKey } = generateKeyPairSync('ed25519');
    const publicJwk = publicKey.export({ format: 'jwk' });
    const publicBytes = Buffer.from(publicJwk.x, 'base64url');
    contract(publicBytes.length === 32, 'ephemeral Ed25519 public key length is invalid');
    const key = {
      keytype: 'ed25519',
      scheme: 'ed25519',
      keyval: { public: publicBytes.toString('hex') }
    };
    const keyid = sha256(canonicalBytes(key));
    const keyHandle = `TEST-ONLY:${label}:${randomUUID()}`;
    this.#keys.set(keyHandle, privateKey);
    return { label, key, keyid, keyHandle, testOnly: true };
  }

  sign({ keyHandle, payload }) {
    contract(keyHandle.startsWith('TEST-ONLY:'), 'only ephemeral TEST key handles are accepted');
    const privateKey = this.#keys.get(keyHandle);
    contract(privateKey, 'unknown ephemeral TEST key handle');
    return cryptoSign(null, payload, privateKey);
  }

  destroy() {
    this.#keys.clear();
  }
}

export function signCanonicalWithAdapter(signed, signers, adapter) {
  contract(signed && typeof signed === 'object' && !Array.isArray(signed), 'signed metadata must be an object');
  contract(Array.isArray(signers) && signers.length > 0, 'metadata signers are required');
  contract(adapter && typeof adapter.sign === 'function', 'offline/HSM signer adapter is required');
  const payload = canonicalBytes(signed);
  const signatures = signers.map(signer => ({
    keyid: signer.keyid,
    sig: adapter.sign({ keyHandle: signer.keyHandle, payload }).toString('hex')
  }));
  return metadataDocumentFromEnvelope({ signatures, signed });
}

function publicKeys(signers) {
  return Object.fromEntries(signers.map(signer => [signer.keyid, signer.key]));
}

function role(signers, threshold) {
  return { keyids: signers.map(signer => signer.keyid), threshold };
}

function requestBody(input) {
  const targets = [
    [input.artifactPath, input.artifactBytes, 'application/vnd.android.package-archive'],
    [input.sbomPath, input.sbomBytes, 'application/vnd.cyclonedx+json'],
    [input.provenancePath, input.provenanceBytes, 'application/vnd.deep.test-build-evidence+json']
  ].map(([targetPath, bytes, mediaType]) => ({
    path: targetPath,
    length: bytes.length,
    sha256: sha256(bytes),
    mediaType
  })).sort((left, right) => left.path.localeCompare(right.path));
  return {
    schema: 'deep.delegated-release-request.v1',
    testOnly: true,
    productionAuthorized: false,
    requestBoundary: 'public-hashes-only',
    requestId: input.requestId,
    sourceCommit: input.sourceCommit,
    programRevisionSha256: input.programRevisionSha256,
    targets
  };
}

export function createDelegatedReleaseRequest(input) {
  const body = requestBody(input);
  const request = {
    ...body,
    requestDigest: sha256(canonicalBytes(body))
  };
  validateDelegatedReleaseRequest(request);
  return request;
}

export function validateDelegatedReleaseRequest(request) {
  contract(exactKeys(request, [
    'schema',
    'testOnly',
    'productionAuthorized',
    'requestBoundary',
    'requestId',
    'sourceCommit',
    'programRevisionSha256',
    'targets',
    'requestDigest'
  ]), 'delegated release request keys must be exact');
  contract(request.schema === 'deep.delegated-release-request.v1', 'delegated release request schema must be exact');
  contract(request.testOnly === true, 'delegated release request must be TEST-only');
  contract(request.productionAuthorized === false, 'delegated release request cannot authorize production');
  contract(request.requestBoundary === 'public-hashes-only', 'delegated release request boundary must be public hashes only');
  contract(/^[a-z0-9-]{8,64}$/.test(request.requestId ?? ''), 'delegated release request ID is invalid');
  contract(/^[0-9a-f]{40}$/.test(request.sourceCommit ?? ''), 'delegated release source commit is invalid');
  contract(hex64.test(request.programRevisionSha256 ?? ''), 'delegated release program revision is invalid');
  contract(!looksLikePlaceholderHex(request.sourceCommit), 'delegated release source commit cannot be a placeholder');
  contract(!looksLikePlaceholderHex(request.programRevisionSha256), 'delegated release program revision cannot be a placeholder');
  contract(Array.isArray(request.targets) && request.targets.length === 3, 'delegated release request must bind three targets');
  const paths = [];
  for (const target of request.targets) {
    contract(exactKeys(target, ['path', 'length', 'sha256', 'mediaType']), 'delegated target keys must be exact');
    contract(/^(?:android|sbom|provenance)\/[A-Za-z0-9._-]+$/.test(target.path ?? ''), 'delegated target path is invalid');
    contract(Number.isSafeInteger(target.length) && target.length > 0, 'delegated target length is invalid');
    contract(hex64.test(target.sha256 ?? ''), 'delegated target hash is invalid');
    contract(typeof target.mediaType === 'string' && target.mediaType.length > 8, 'delegated target media type is invalid');
    paths.push(target.path);
  }
  contract(new Set(paths).size === paths.length, 'delegated target paths must be unique');
  contract(JSON.stringify(paths) === JSON.stringify([...paths].sort()), 'delegated targets must be sorted');
  const { requestDigest, ...body } = request;
  contract(requestDigest === sha256(canonicalBytes(body)), 'delegated release request digest mismatch');
  return request;
}

export function evaluateProductionActivation(facts) {
  contract(facts?.accountableHuman === 'Mr. X', 'accountable human must be Mr. X');
  const custodians = facts.namedIndependentCustodians ?? [];
  const independentCustodyVerified = (
    custodians.length >= 3
    && new Set(custodians).size === custodians.length
    && custodians.every(name => typeof name === 'string' && name.length >= 3 && name !== 'Mr. X')
  );
  const productionHsmVerified = (
    facts.productionHsmEvidence?.verified === true
    && typeof facts.productionHsmEvidence?.attestationSha256 === 'string'
    && hex64.test(facts.productionHsmEvidence.attestationSha256)
  );
  const publicationAuthorized = false;
  const reproducibleBuildVerified = facts.reproducibleBuildEvidence?.verified === true;
  const independentSecurityReviewVerified = (
    facts.independentSecurityReview?.verified === true
    && facts.independentSecurityReview?.schema === 'deep.external-security-review-attestation.v1'
    && hex64.test(facts.independentSecurityReview?.attestationSha256 ?? '')
    && facts.independentSecurityReview?.signatureVerified === true
  );
  const blockers = [
    ...(!independentCustodyVerified ? ['named-independent-custodians-missing'] : []),
    ...(!productionHsmVerified ? ['production-hsm-attestation-missing'] : []),
    ...['production-publication-authorization-missing'],
    ...(!reproducibleBuildVerified ? ['reproducible-build-evidence-not-verified'] : []),
    ...(!independentSecurityReviewVerified ? ['independent-security-review-pending'] : [])
  ];
  return {
    accountableHuman: 'Mr. X',
    // A TEST-only dry-run is not allowed to mint production authorization.
    // A separate production command must verify the external review signature
    // and all custody/publication evidence before this can ever become READY.
    activationStatus: 'BLOCKED',
    activationRun: 'NOT-RUN',
    independentCustodyVerified,
    productionHsmVerified,
    publicationAuthorized,
    reproducibleBuildVerified,
    independentSecurityReviewVerified,
    blockers
  };
}

async function enumerateTree(root, relative = '') {
  const records = [];
  const directory = path.join(root, ...relative.split('/').filter(Boolean));
  const entries = await readdir(directory, { withFileTypes: true });
  entries.sort((left, right) => left.name.localeCompare(right.name));
  for (const entry of entries) {
    contract(!entry.isSymbolicLink(), 'mirror tree cannot contain links');
    const childRelative = relative ? `${relative}/${entry.name}` : entry.name;
    const child = path.join(root, ...childRelative.split('/'));
    if (entry.isDirectory()) {
      records.push(...await enumerateTree(root, childRelative));
    } else {
      contract(entry.isFile(), 'mirror tree may contain regular files only');
      const bytes = await readFile(child);
      records.push({ path: childRelative, length: bytes.length, sha256: sha256(bytes) });
    }
  }
  return records;
}

export async function verifyByteIdenticalTrees(leftRoot, rightRoot) {
  const left = await enumerateTree(await realpath(leftRoot));
  const right = await enumerateTree(await realpath(rightRoot));
  contract(JSON.stringify(left) === JSON.stringify(right), 'mirror trees are not byte-identical');
  for (const file of left) {
    const metadataMatch = /^metadata\/sha256\/([0-9a-f]{64})\.json$/.exec(file.path);
    const targetMatch = /^targets\/sha256\/([0-9a-f]{64})\/[A-Za-z0-9._-]+$/.exec(file.path);
    if (metadataMatch) contract(metadataMatch[1] === file.sha256, 'metadata content address mismatch');
    else if (targetMatch) contract(targetMatch[1] === file.sha256, 'target content address mismatch');
    else contract(file.path === 'release-index.json', 'mirror tree contains a non-addressed file');
  }
  return { status: 'byte-identical', files: left };
}

async function writeTree(root, entries) {
  for (const [relative, bytes] of entries) {
    const target = path.join(root, ...relative.split('/'));
    await mkdir(path.dirname(target), { recursive: true });
    await writeFile(target, bytes, { flag: 'wx' });
  }
}

function expectRejected(action) {
  let accepted = false;
  try {
    action();
    accepted = true;
  } catch {
    // Expected rejection. The explicit flag prevents this helper from
    // swallowing its own "accepted" assertion.
  }
  contract(!accepted, 'negative drill was accepted');
  return 'REJECTED-AS-REQUIRED';
}

export async function expectAsyncRejected(action) {
  let accepted = false;
  try {
    await action();
    accepted = true;
  } catch {
    // Expected rejection; assert outside the catch.
  }
  contract(!accepted, 'negative asynchronous drill was accepted');
  return 'REJECTED-AS-REQUIRED';
}

async function executionProvenance() {
  const result = spawnSync('git', ['rev-parse', 'HEAD'], {
    cwd: repositoryRoot,
    encoding: 'utf8',
    windowsHide: true
  });
  contract(result.status === 0, 'cannot bind ceremony dry-run to source commit');
  const sourceCommit = result.stdout.trim();
  contract(/^[0-9a-f]{40}$/.test(sourceCommit) && !looksLikePlaceholderHex(sourceCommit),
    'ceremony git HEAD is invalid or placeholder-like');
  const programBytes = await readFile(fileURLToPath(import.meta.url));
  const programRevisionSha256 = sha256(programBytes);
  contract(hex64.test(programRevisionSha256) && !looksLikePlaceholderHex(programRevisionSha256),
    'ceremony program revision is invalid or placeholder-like');
  return { sourceCommit, programRevisionSha256 };
}

function createCeremonyMaterial(adapter) {
  const signer = label => adapter.createSigner(label);
  const keys = Object.fromEntries([
    'root-old-a', 'root-old-b', 'root-old-c',
    'root-new-a', 'root-new-b', 'root-new-c',
    'targets-a', 'targets-b', 'targets-c',
    'android-a', 'android-b', 'android-c',
    'snapshot-primary-old', 'snapshot-primary-new', 'snapshot-primary-replacement', 'snapshot-recovery',
    'timestamp-primary-old', 'timestamp-primary-new', 'timestamp-primary-replacement', 'timestamp-recovery'
  ].map(label => [label, signer(label)]));
  const pick = labels => labels.map(label => keys[label]);

  const rootOld = pick(['root-old-a', 'root-old-b', 'root-old-c']);
  const rootNew = pick(['root-new-a', 'root-new-b', 'root-new-c']);
  const targetsKeys = pick(['targets-a', 'targets-b', 'targets-c']);
  const androidKeys = pick(['android-a', 'android-b', 'android-c']);
  const snapshotOld = pick(['snapshot-primary-old']);
  const snapshotNew = pick(['snapshot-primary-new']);
  const snapshotReplacement = pick(['snapshot-primary-replacement']);
  const snapshotRecovery = pick(['snapshot-recovery']);
  const timestampOld = pick(['timestamp-primary-old']);
  const timestampNew = pick(['timestamp-primary-new']);
  const timestampReplacement = pick(['timestamp-primary-replacement']);
  const timestampRecovery = pick(['timestamp-recovery']);

  const rootOneSigned = {
    _type: 'root',
    spec_version: '1.0.35',
    consistent_snapshot: true,
    version: 1,
    expires: rootExpiry,
    keys: publicKeys([
      ...rootOld, ...targetsKeys,
      ...snapshotOld, ...snapshotRecovery,
      ...timestampOld, ...timestampRecovery
    ]),
    roles: {
      root: role(rootOld, 2),
      targets: role(targetsKeys, 2),
      snapshot: role([...snapshotOld, ...snapshotRecovery], 1),
      timestamp: role([...timestampOld, ...timestampRecovery], 1)
    }
  };
  const rootTwoSigned = {
    ...rootOneSigned,
    version: 2,
    keys: publicKeys([
      ...rootNew, ...targetsKeys,
      ...snapshotNew, ...snapshotRecovery,
      ...timestampNew, ...timestampRecovery
    ]),
    roles: {
      root: role(rootNew, 2),
      targets: role(targetsKeys, 2),
      snapshot: role([...snapshotNew, ...snapshotRecovery], 1),
      timestamp: role([...timestampNew, ...timestampRecovery], 1)
    }
  };
  const rootOne = signCanonicalWithAdapter(rootOneSigned, rootOld.slice(0, 2), adapter);
  const rootTwo = signCanonicalWithAdapter(
    rootTwoSigned,
    [...rootOld.slice(0, 2), ...rootNew.slice(0, 2)],
    adapter
  );
  const rootThreeSigned = {
    ...rootTwoSigned,
    version: 3,
    keys: publicKeys([
      ...rootNew, ...targetsKeys,
      ...snapshotReplacement, ...snapshotRecovery,
      ...timestampReplacement, ...timestampRecovery
    ]),
    roles: {
      ...rootTwoSigned.roles,
      snapshot: role([...snapshotReplacement, ...snapshotRecovery], 1),
      timestamp: role([...timestampReplacement, ...timestampRecovery], 1)
    }
  };
  const rootThree = signCanonicalWithAdapter(rootThreeSigned, rootNew.slice(0, 2), adapter);
  const rootTwoOldOnly = signCanonicalWithAdapter(rootTwoSigned, rootOld.slice(0, 2), adapter);
  const rootTwoNewOnly = signCanonicalWithAdapter(rootTwoSigned, rootNew.slice(0, 2), adapter);
  const rootTwoInsufficient = signCanonicalWithAdapter(
    rootTwoSigned,
    [rootOld[0], rootNew[0]],
    adapter
  );
  return {
    keys,
    rootOne,
    rootTwo,
    rootThree,
    rootTwoOldOnly,
    rootTwoNewOnly,
    rootTwoInsufficient,
    targetsKeys,
    androidKeys,
    snapshotOld,
    snapshotNew,
    snapshotRecovery,
    snapshotReplacement,
    timestampOld,
    timestampNew,
    timestampRecovery,
    timestampReplacement
  };
}

function createReleaseDocuments(material, adapter, request, artifacts) {
  const targetByPath = Object.fromEntries(request.targets.map(target => [target.path, target]));
  const artifactTarget = request.targets.find(item => item.path.startsWith('android/'));
  const sbomTarget = request.targets.find(item => item.path.startsWith('sbom/'));
  const provenanceTarget = request.targets.find(item => item.path.startsWith('provenance/'));
  const buildDefinitionSha256 = sha256(Buffer.from('P02C TEST ceremony build definition', 'utf8'));
  const packageSignerSha256 = sha256(Buffer.from('P02C TEST package signer certificate', 'utf8'));
  const delegatedSigned = {
    _type: 'targets',
    spec_version: '1.0.35',
    version: 1,
    expires: onlineExpiry,
    targets: {
      [artifactTarget.path]: {
        ...targetDescription(artifacts.artifactBytes),
        custom: {
          platform: 'android',
          packageId: 'network.xpoint.deep',
          versionCode: '20002',
          versionName: '2.0.2-p02c-test',
          packageSignerSha256,
          sourceCommit: request.sourceCommit,
          programRevisionSha256: request.programRevisionSha256,
          sbom: {
            path: sbomTarget.path,
            sha256: sbomTarget.sha256,
            format: 'CycloneDX-1.6'
          },
          reproducibleBuild: {
            provenancePath: provenanceTarget.path,
            sourceDateEpoch: 1784332800,
            buildDefinitionSha256,
            minimumIndependentBuilders: 2
          }
        }
      },
      [sbomTarget.path]: targetDescription(artifacts.sbomBytes, {
        mediaType: targetByPath[sbomTarget.path].mediaType
      }),
      [provenanceTarget.path]: targetDescription(artifacts.provenanceBytes, {
        mediaType: targetByPath[provenanceTarget.path].mediaType
      })
    }
  };
  const delegatedTargets = signCanonicalWithAdapter(
    delegatedSigned,
    material.androidKeys.slice(0, 2),
    adapter
  );
  const targetsSigned = {
    _type: 'targets',
    spec_version: '1.0.35',
    version: 1,
    expires: onlineExpiry,
    targets: {},
    delegations: {
      keys: publicKeys(material.androidKeys),
      roles: [{
        name: 'android-release',
        keyids: material.androidKeys.map(item => item.keyid),
        threshold: 2,
        paths: ['android/*', 'sbom/*', 'provenance/*'],
        terminating: true
      }]
    }
  };
  const targets = signCanonicalWithAdapter(
    targetsSigned,
    material.targetsKeys.slice(0, 2),
    adapter
  );
  const snapshotSigned = {
    _type: 'snapshot',
    spec_version: '1.0.35',
    version: 1,
    expires: onlineExpiry,
    meta: {
      'targets.json': metadataDescription(targets),
      'android-release.json': metadataDescription(delegatedTargets)
    }
  };
  const snapshot = signCanonicalWithAdapter(snapshotSigned, material.snapshotNew, adapter);
  const timestampSigned = {
    _type: 'timestamp',
    spec_version: '1.0.35',
    version: 1,
    expires: onlineExpiry,
    meta: { 'snapshot.json': metadataDescription(snapshot) }
  };
  const timestamp = signCanonicalWithAdapter(timestampSigned, material.timestampNew, adapter);
  return {
    delegatedTargets,
    targets,
    snapshot,
    timestamp,
    timestampSigned,
    packageSignerSha256
  };
}

function createFixtureArtifacts(provenanceBinding) {
  const artifactBytes = Buffer.from('P02C ceremony TEST APK descriptor; never install or publish.\n', 'utf8');
  const sbomBytes = jsonBytes({
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    // Keep the public TEST fixture stable; only opaque in-memory key handles
    // and their ephemeral public keys are intentionally fresh per run.
    serialNumber: 'urn:uuid:00000000-0000-4000-8000-00000000002c',
    version: 1,
    metadata: {
      component: {
        type: 'application',
        name: 'network.xpoint.deep',
        version: '2.0.2-p02c-test'
      }
    },
    components: [],
    testOnly: true
  });
  const buildDefinitionSha256 = sha256(Buffer.from('P02C TEST ceremony build definition', 'utf8'));
  const provenanceBytes = jsonBytes({
    schema: 'deep.reproducible-build.v1',
    testOnly: true,
    independenceVerified: false,
    sourceCommit: provenanceBinding.sourceCommit,
    programRevisionSha256: provenanceBinding.programRevisionSha256,
    sourceDateEpoch: 1784332800,
    buildDefinitionSha256,
    sbomSha256: sha256(sbomBytes),
    builders: [
      { builderId: 'TEST-ONLY-builder-a', artifactSha256: sha256(artifactBytes) },
      { builderId: 'TEST-ONLY-builder-b', artifactSha256: sha256(artifactBytes) }
    ]
  });
  return { artifactBytes, sbomBytes, provenanceBytes };
}

function resignOnlineRelease(release, adapter, {
  snapshotSigner,
  timestampSigner,
  timestampVersion = 1
}) {
  const snapshot = signCanonicalWithAdapter(
    release.snapshot.envelope.signed,
    snapshotSigner,
    adapter
  );
  const timestampSigned = {
    ...release.timestampSigned,
    version: timestampVersion,
    meta: { 'snapshot.json': metadataDescription(snapshot) }
  };
  const timestamp = signCanonicalWithAdapter(timestampSigned, timestampSigner, adapter);
  return { snapshot, timestamp };
}

async function buildMirrorEntries(documents, artifacts, request) {
  const entries = [];
  const metadataIndex = {};
  for (const [name, document] of Object.entries(documents)) {
    const digest = sha256(document.rawBytes);
    const relative = `metadata/sha256/${digest}.json`;
    entries.push([relative, document.rawBytes]);
    metadataIndex[name] = { path: relative, sha256: digest, length: document.rawBytes.length };
  }
  const targetIndex = {};
  for (const target of request.targets) {
    const bytes = target.path.startsWith('android/')
      ? artifacts.artifactBytes
      : target.path.startsWith('sbom/')
        ? artifacts.sbomBytes
        : artifacts.provenanceBytes;
    const originalBasename = path.posix.basename(target.path);
    const basename = target.path.startsWith('android/')
      ? `${originalBasename}.payload.txt`
      : originalBasename;
    const relative = `targets/sha256/${target.sha256}/${basename}`;
    entries.push([relative, bytes]);
    targetIndex[target.path] = { path: relative, sha256: target.sha256, length: target.length };
  }
  const index = {
    schema: 'deep.update-ceremony.release-index.v1',
    testOnly: true,
    productionAuthorized: false,
    metadata: metadataIndex,
    targets: targetIndex
  };
  entries.push(['release-index.json', jsonBytes(index)]);
  return entries.sort(([left], [right]) => left.localeCompare(right));
}

async function readIndexedBytes(treeRoot, entry, label) {
  contract(exactKeys(entry, ['path', 'sha256', 'length']), `${label} index keys must be exact`);
  contract(typeof entry.path === 'string' && !entry.path.includes('\\') &&
    entry.path.split('/').every(part => part && part !== '.' && part !== '..'),
  `${label} index path is invalid`);
  const bytes = await readFile(path.join(treeRoot, ...entry.path.split('/')));
  contract(bytes.length === entry.length, `${label} indexed length mismatch`);
  contract(sha256(bytes) === entry.sha256, `${label} indexed SHA-256 mismatch`);
  return bytes;
}

export async function loadAndVerifyPublishedTree(treeRoot, expectedProvenance) {
  const root = await realpath(treeRoot);
  const indexBytes = await readFile(path.join(root, 'release-index.json'));
  const index = JSON.parse(indexBytes.toString('utf8'));
  contract(exactKeys(index, [
    'schema', 'testOnly', 'productionAuthorized', 'metadata', 'targets'
  ]), 'release index keys must be exact');
  contract(index.schema === 'deep.update-ceremony.release-index.v1' &&
    index.testOnly === true && index.productionAuthorized === false,
  'release index authority flags are invalid');
  const requiredMetadata = [
    'root1', 'root2', 'root3', 'timestamp', 'snapshot', 'targets', 'androidRelease'
  ];
  contract(JSON.stringify(Object.keys(index.metadata).sort()) ===
    JSON.stringify([...requiredMetadata].sort()), 'release index metadata inventory mismatch');
  const loaded = {};
  for (const name of requiredMetadata) {
    loaded[name] = parseMetadataDocument(
      await readIndexedBytes(root, index.metadata[name], `${name} metadata`),
      `${name} published metadata`
    );
  }
  const requestTargetNames = Object.keys(index.targets).sort();
  contract(requestTargetNames.length === 3, 'release index target inventory mismatch');
  const files = {};
  for (const name of requestTargetNames) {
    files[name] = await readIndexedBytes(root, index.targets[name], `${name} target`);
  }
  const verified = verifyUpdateBundle({
    trustedRoot: loaded.root1,
    candidateRoots: [loaded.root2, loaded.root3],
    timestamp: loaded.timestamp,
    snapshot: loaded.snapshot,
    targets: loaded.targets,
    delegatedTargets: loaded.androidRelease,
    trustedState: createTrustedState(loaded.root1),
    updateStart: fixedUpdateStart
  });
  const apkPath = requestTargetNames.find(name => name.startsWith('android/'));
  const sbomPath = requestTargetNames.find(name => name.startsWith('sbom/'));
  const provenancePath = requestTargetNames.find(name => name.startsWith('provenance/'));
  const artifactEvidence = verifySbomAndReproducibility({
    delegatedTargets: loaded.androidRelease,
    apkPath,
    apkBytes: files[apkPath],
    files: {
      [sbomPath]: files[sbomPath],
      [provenancePath]: files[provenancePath]
    }
  });
  contract(
    artifactEvidence.provenance.sourceCommit === expectedProvenance.sourceCommit &&
    artifactEvidence.provenance.programRevisionSha256 === expectedProvenance.programRevisionSha256,
    'published provenance does not match the executed git/program binding'
  );
  const inventory = await enumerateTree(root);
  return {
    status: 'PASSED',
    treeSha256: sha256(canonicalBytes(inventory)),
    fileCount: inventory.length,
    sourceCommit: artifactEvidence.provenance.sourceCommit,
    programRevisionSha256: artifactEvidence.provenance.programRevisionSha256,
    trustedRootVersion: verified.state.trustedRoot.version
  };
}

export async function runUpdateCeremonyDryRun({ outputRoot }) {
  const root = path.resolve(outputRoot);
  const rootInfo = await lstat(root);
  contract(rootInfo.isDirectory() && !rootInfo.isSymbolicLink(), 'dry-run output root must be a real directory');
  contract((await readdir(root)).length === 0, 'dry-run output root must start empty');
  const adapter = new EphemeralTestHsmAdapter();
  try {
    const provenanceBinding = await executionProvenance();
    const artifacts = createFixtureArtifacts(provenanceBinding);
    const request = createDelegatedReleaseRequest({
      requestId: 'p02c-test-release-request',
      sourceCommit: provenanceBinding.sourceCommit,
      programRevisionSha256: provenanceBinding.programRevisionSha256,
      artifactPath: 'android/network.xpoint.deep-2.0.2-p02c-test.apk',
      artifactBytes: artifacts.artifactBytes,
      sbomPath: 'sbom/network.xpoint.deep-2.0.2-p02c-test.cdx.json',
      sbomBytes: artifacts.sbomBytes,
      provenancePath: 'provenance/network.xpoint.deep-2.0.2-p02c-test.repro.json',
      provenanceBytes: artifacts.provenanceBytes
    });
    const material = createCeremonyMaterial(adapter);
    const release = createReleaseDocuments(material, adapter, request, artifacts);
    const rootTwoBundle = {
      trustedRoot: material.rootOne,
      candidateRoots: [material.rootTwo],
      timestamp: release.timestamp,
      snapshot: release.snapshot,
      targets: release.targets,
      delegatedTargets: release.delegatedTargets,
      trustedState: createTrustedState(material.rootOne),
      updateStart: fixedUpdateStart
    };
    const verified = verifyUpdateBundle(rootTwoBundle);
    const crossSignedAccepted = verified.state.trustedRoot.version === 2;
    contract(crossSignedAccepted, 'P02B root rotation compatibility failed');
    const rootRotationDrills = {
      crossSigned: crossSignedAccepted ? 'PASSED' : 'FAILED',
      oldOnly: expectRejected(() => verifyUpdateBundle({
        ...rootTwoBundle,
        candidateRoots: [material.rootTwoOldOnly]
      })),
      newOnly: expectRejected(() => verifyUpdateBundle({
        ...rootTwoBundle,
        candidateRoots: [material.rootTwoNewOnly]
      })),
      insufficient: expectRejected(() => verifyUpdateBundle({
        ...rootTwoBundle,
        candidateRoots: [material.rootTwoInsufficient]
      }))
    };
    const apkPath = request.targets.find(item => item.path.startsWith('android/')).path;
    const sbomPath = request.targets.find(item => item.path.startsWith('sbom/')).path;
    const provenancePath = request.targets.find(item => item.path.startsWith('provenance/')).path;
    verifySbomAndReproducibility({
      delegatedTargets: release.delegatedTargets,
      apkPath,
      apkBytes: artifacts.artifactBytes,
      files: {
        [sbomPath]: artifacts.sbomBytes,
        [provenancePath]: artifacts.provenanceBytes
      }
    });

    const recoveryOnline = resignOnlineRelease(release, adapter, {
      snapshotSigner: material.snapshotRecovery,
      timestampSigner: material.timestampRecovery,
      timestampVersion: 2
    });
    const recoveryVerified = verifyUpdateBundle({
      ...rootTwoBundle,
      trustedRoot: material.rootTwo,
      candidateRoots: [],
      trustedState: verified.state,
      snapshot: recoveryOnline.snapshot,
      timestamp: recoveryOnline.timestamp
    });
    const recoveryAccepted = (
      recoveryVerified.state.versions.timestamp === 2 &&
      recoveryVerified.state.trustedRoot.version === 2
    );
    contract(recoveryAccepted, 'sealed recovery online metadata was not accepted');
    const replacementOnline = resignOnlineRelease(release, adapter, {
      snapshotSigner: material.snapshotReplacement,
      timestampSigner: material.timestampReplacement,
      timestampVersion: 3
    });
    const replacementBundle = {
      ...rootTwoBundle,
      trustedRoot: material.rootTwo,
      candidateRoots: [material.rootThree],
      trustedState: verified.state,
      snapshot: replacementOnline.snapshot,
      timestamp: replacementOnline.timestamp
    };
    const replacementVerified = verifyUpdateBundle(replacementBundle);
    const replacementAccepted = replacementVerified.state.trustedRoot.version === 3;
    contract(replacementAccepted,
      'replacement online role root rotation failed');
    const revokedSnapshot = resignOnlineRelease(release, adapter, {
      snapshotSigner: material.snapshotNew,
      timestampSigner: material.timestampReplacement,
      timestampVersion: 3
    });
    const revokedTimestamp = resignOnlineRelease(release, adapter, {
      snapshotSigner: material.snapshotReplacement,
      timestampSigner: material.timestampNew,
      timestampVersion: 3
    });
    const revokedSnapshotPrimary = expectRejected(() => verifyUpdateBundle({
      ...replacementBundle,
      snapshot: revokedSnapshot.snapshot,
      timestamp: revokedSnapshot.timestamp
    }));
    const revokedTimestampPrimary = expectRejected(() => verifyUpdateBundle({
      ...replacementBundle,
      snapshot: revokedTimestamp.snapshot,
      timestamp: revokedTimestamp.timestamp
    }));
    const onlineRecovery = {
      policy: '1-of-2-primary-plus-sealed-recovery',
      recoveryAccepted: recoveryAccepted ? 'PASSED' : 'FAILED',
      replacementAccepted: replacementAccepted ? 'PASSED' : 'FAILED',
      oldSnapshotPrimaryRevoked: revokedSnapshotPrimary,
      oldTimestampPrimaryRevoked: revokedTimestampPrimary
    };
    const rollbackBundle = {
      ...rootTwoBundle,
      trustedState: structuredClone(rootTwoBundle.trustedState)
    };
    rollbackBundle.trustedState.versions.timestamp = 2;
    const rollback = expectRejected(() => verifyUpdateBundle(rollbackBundle));
    const frozenSigned = {
      ...release.timestampSigned,
      expires: '2029-12-31T23:59:59Z'
    };
    const frozen = signCanonicalWithAdapter(frozenSigned, material.timestampNew, adapter);
    const freeze = expectRejected(() => verifyUpdateBundle({ ...rootTwoBundle, timestamp: frozen }));

    const documents = {
      root1: material.rootOne,
      root2: material.rootTwo,
      root3: material.rootThree,
      timestamp: replacementOnline.timestamp,
      snapshot: replacementOnline.snapshot,
      targets: release.targets,
      androidRelease: release.delegatedTargets
    };
    const entries = await buildMirrorEntries(documents, artifacts, request);
    const mirrorA = path.join(root, 'mirror-a');
    const mirrorB = path.join(root, 'mirror-b');
    const offlineBundle = path.join(root, 'offline-bundle');
    await Promise.all([
      writeTree(mirrorA, entries),
      writeTree(mirrorB, entries),
      writeTree(offlineBundle, entries)
    ]);
    const mirrorEquality = await verifyByteIdenticalTrees(mirrorA, mirrorB);
    const offlineEquality = await verifyByteIdenticalTrees(mirrorA, offlineBundle);

    const addressedFile = entries.find(([relative]) => relative.startsWith('metadata/sha256/'));
    const compromisedPath = path.join(mirrorB, ...addressedFile[0].split('/'));
    const originalBytes = await readFile(compromisedPath);
    await writeFile(compromisedPath, Buffer.concat([originalBytes, Buffer.from([0])]));
    const mirrorCompromise = await expectAsyncRejected(
      () => verifyByteIdenticalTrees(mirrorA, mirrorB)
    );
    await writeFile(compromisedPath, originalBytes);
    await verifyByteIdenticalTrees(mirrorA, mirrorB);
    const publicationVerification = {
      mirrorA: await loadAndVerifyPublishedTree(mirrorA, provenanceBinding),
      mirrorB: await loadAndVerifyPublishedTree(mirrorB, provenanceBinding),
      offlineBundle: await loadAndVerifyPublishedTree(offlineBundle, provenanceBinding),
      byteIdentity: {
        mirrorTreesSha256Equal:
          mirrorEquality.files.length === offlineEquality.files.length &&
          mirrorEquality.files.every((file, index) =>
            file.sha256 === offlineEquality.files[index].sha256),
        exactTrees: 'PASSED'
      }
    };
    contract(new Set([
      publicationVerification.mirrorA.treeSha256,
      publicationVerification.mirrorB.treeSha256,
      publicationVerification.offlineBundle.treeSha256
    ]).size === 1, 'reloaded publication trees are not byte-identical');

    const activation = evaluateProductionActivation({
      accountableHuman: 'Mr. X',
      namedIndependentCustodians: [],
      productionHsmEvidence: null,
      publicationAuthorization: null,
      reproducibleBuildEvidence: null
    });
    const drills = {
      rootRotation: rootRotationDrills,
      onlineRecovery,
      mirrorCompromise,
      rollback,
      freeze
    };
    const evidenceDir = path.join(root, 'evidence');
    await mkdir(evidenceDir, { recursive: true });
    await writeFile(path.join(evidenceDir, 'delegated-release-request.json'), jsonBytes(request));
    await writeFile(path.join(evidenceDir, 'drills.json'), jsonBytes({
      schema: 'deep.update-ceremony.drills.v1',
      testOnly: true,
      ...drills
    }));
    await writeFile(path.join(evidenceDir, 'threshold-ceremony.json'), jsonBytes({
      schema: 'deep.update-ceremony.threshold-evidence.v1',
      testOnly: true,
      accountableHuman: 'Mr. X',
      rootThreshold: {
        required: material.rootOne.envelope.signed.roles.root.threshold,
        publicKeyCount: material.rootOne.envelope.signed.roles.root.keyids.length,
        signaturesObserved: material.rootOne.envelope.signatures.length
      },
      rootRotationCrossSigned: rootRotationDrills.crossSigned === 'PASSED',
      oldRootThresholdObserved: material.rootTwo.envelope.signatures.filter(signature =>
        material.rootOne.envelope.signed.roles.root.keyids.includes(signature.keyid)).length,
      newRootThresholdObserved: material.rootTwo.envelope.signatures.filter(signature =>
        material.rootTwo.envelope.signed.roles.root.keyids.includes(signature.keyid)).length,
      rootRotationNegativeDrills: rootRotationDrills,
      targetsThreshold: {
        required: material.rootTwo.envelope.signed.roles.targets.threshold,
        publicKeyCount: material.rootTwo.envelope.signed.roles.targets.keyids.length,
        signaturesObserved: release.targets.envelope.signatures.length
      },
      delegatedThreshold: {
        required: release.targets.envelope.signed.delegations.roles[0].threshold,
        publicKeyCount: release.targets.envelope.signed.delegations.roles[0].keyids.length,
        signaturesObserved: release.delegatedTargets.envelope.signatures.length
      },
      onlineRoles: {
        policy: onlineRecovery.policy,
        snapshot: {
          required: material.rootThree.envelope.signed.roles.snapshot.threshold,
          publicKeyCount: material.rootThree.envelope.signed.roles.snapshot.keyids.length
        },
        timestamp: {
          required: material.rootThree.envelope.signed.roles.timestamp.threshold,
          publicKeyCount: material.rootThree.envelope.signed.roles.timestamp.keyids.length
        },
        drills: onlineRecovery
      },
      testKeyMaterialArchived: false,
      productionHsmVerified: false,
      namedIndependentCustodians: []
    }));
    await writeFile(path.join(evidenceDir, 'publication-verification.json'), jsonBytes({
      schema: 'deep.update-ceremony.publication-verification.v1',
      testOnly: true,
      ...publicationVerification
    }));
    await writeFile(path.join(evidenceDir, 'artifact-evidence.json'), jsonBytes({
      schema: 'deep.update-ceremony.artifact-evidence.v1',
      testOnly: true,
      apkSha256: sha256(artifacts.artifactBytes),
      sbomSha256: sha256(artifacts.sbomBytes),
      provenanceSha256: sha256(artifacts.provenanceBytes),
      reproducibleBuildVerified: false,
      sourceCommit: provenanceBinding.sourceCommit,
      programRevisionSha256: provenanceBinding.programRevisionSha256,
      reason: 'two TEST builder labels are contract fixtures, not independent retained attestations'
    }));
    const summary = {
      schema: 'deep.update-ceremony.dry-run.v1',
      sourceCommitSha: provenanceBinding.sourceCommit,
      programRevisionSha256: provenanceBinding.programRevisionSha256,
      testOnly: true,
      dryRunStatus: 'PASSED',
      p02bCompatibility: 'PASSED',
      productionPublication: 'NOT-RUN',
      productionHsmVerified: activation.productionHsmVerified,
      independentCustodyVerified: activation.independentCustodyVerified,
      reproducibleBuildVerified: activation.reproducibleBuildVerified,
      activationStatus: activation.activationStatus,
      activationRun: activation.activationRun,
      blockers: activation.blockers,
      mirrors: 2,
      offlineBundle: true,
      testKeyMaterialArchived: false,
      drills
    };
    await writeFile(path.join(root, 'ceremony-summary.json'), jsonBytes(summary));
    return { summary, drills };
  } finally {
    adapter.destroy();
  }
}

function parseCli(argv) {
  const [command, ...rest] = argv;
  contract(command === 'dry-run', 'supported command: dry-run');
  contract(rest.length === 2 && rest[0] === '--output-root', 'required: --output-root <empty-directory>');
  return { outputRoot: rest[1] };
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  try {
    const result = await runUpdateCeremonyDryRun(parseCli(process.argv.slice(2)));
    console.log(`P02C ceremony dry-run: ${result.summary.dryRunStatus}; activation ${result.summary.activationStatus}/${result.summary.activationRun}`);
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  }
}
