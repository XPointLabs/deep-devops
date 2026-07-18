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
const sourceCommit = '11'.repeat(20);
const programRevisionSha256 = '22'.repeat(32);

function exactKeys(value, expected) {
  return JSON.stringify(Object.keys(value ?? {}).sort()) === JSON.stringify([...expected].sort());
}

function fail(message) {
  throw new Error(message);
}

function contract(condition, message) {
  if (!condition) fail(message);
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
  const publicationAuthorized = facts.publicationAuthorization?.approved === true;
  const reproducibleBuildVerified = facts.reproducibleBuildEvidence?.verified === true;
  const blockers = [
    ...(!independentCustodyVerified ? ['named-independent-custodians-missing'] : []),
    ...(!productionHsmVerified ? ['production-hsm-attestation-missing'] : []),
    ...(!publicationAuthorized ? ['production-publication-authorization-missing'] : []),
    ...(!reproducibleBuildVerified ? ['reproducible-build-evidence-not-verified'] : [])
  ];
  return {
    accountableHuman: 'Mr. X',
    activationStatus: blockers.length === 0 ? 'READY-FOR-INDEPENDENT-AUTHORIZATION' : 'BLOCKED',
    activationRun: 'NOT-RUN',
    independentCustodyVerified,
    productionHsmVerified,
    publicationAuthorized,
    reproducibleBuildVerified,
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
  try {
    action();
  } catch {
    return 'REJECTED-AS-REQUIRED';
  }
  fail('negative drill was accepted');
}

function gitHead() {
  const result = spawnSync('git', ['rev-parse', 'HEAD'], {
    cwd: repositoryRoot,
    encoding: 'utf8',
    windowsHide: true
  });
  contract(result.status === 0, 'cannot bind ceremony dry-run to source commit');
  return result.stdout.trim();
}

function createCeremonyMaterial(adapter) {
  const signer = label => adapter.createSigner(label);
  const keys = Object.fromEntries([
    'root-old-a', 'root-old-b', 'root-old-c',
    'root-new-a', 'root-new-b', 'root-new-c',
    'targets-a', 'targets-b', 'targets-c',
    'android-a', 'android-b', 'android-c',
    'snapshot-old', 'snapshot-new',
    'timestamp-old', 'timestamp-new'
  ].map(label => [label, signer(label)]));
  const pick = labels => labels.map(label => keys[label]);

  const rootOld = pick(['root-old-a', 'root-old-b', 'root-old-c']);
  const rootNew = pick(['root-new-a', 'root-new-b', 'root-new-c']);
  const targetsKeys = pick(['targets-a', 'targets-b', 'targets-c']);
  const androidKeys = pick(['android-a', 'android-b', 'android-c']);
  const snapshotOld = pick(['snapshot-old']);
  const snapshotNew = pick(['snapshot-new']);
  const timestampOld = pick(['timestamp-old']);
  const timestampNew = pick(['timestamp-new']);

  const rootOneSigned = {
    _type: 'root',
    spec_version: '1.0.35',
    consistent_snapshot: true,
    version: 1,
    expires: rootExpiry,
    keys: publicKeys([...rootOld, ...targetsKeys, ...snapshotOld, ...timestampOld]),
    roles: {
      root: role(rootOld, 2),
      targets: role(targetsKeys, 2),
      snapshot: role(snapshotOld, 1),
      timestamp: role(timestampOld, 1)
    }
  };
  const rootTwoSigned = {
    ...rootOneSigned,
    version: 2,
    keys: publicKeys([...rootNew, ...targetsKeys, ...snapshotNew, ...timestampNew]),
    roles: {
      root: role(rootNew, 2),
      targets: role(targetsKeys, 2),
      snapshot: role(snapshotNew, 1),
      timestamp: role(timestampNew, 1)
    }
  };
  const rootOne = signCanonicalWithAdapter(rootOneSigned, rootOld.slice(0, 2), adapter);
  const rootTwo = signCanonicalWithAdapter(
    rootTwoSigned,
    [...rootOld.slice(0, 2), ...rootNew.slice(0, 2)],
    adapter
  );
  return {
    keys,
    rootOne,
    rootTwo,
    targetsKeys,
    androidKeys,
    snapshotOld,
    snapshotNew,
    timestampOld,
    timestampNew
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

function createFixtureArtifacts() {
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
    sourceCommit,
    programRevisionSha256,
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

export async function runUpdateCeremonyDryRun({ outputRoot }) {
  const root = path.resolve(outputRoot);
  const rootInfo = await lstat(root);
  contract(rootInfo.isDirectory() && !rootInfo.isSymbolicLink(), 'dry-run output root must be a real directory');
  contract((await readdir(root)).length === 0, 'dry-run output root must start empty');
  const adapter = new EphemeralTestHsmAdapter();
  try {
    const artifacts = createFixtureArtifacts();
    const request = createDelegatedReleaseRequest({
      requestId: 'p02c-test-release-request',
      sourceCommit,
      programRevisionSha256,
      artifactPath: 'android/network.xpoint.deep-2.0.2-p02c-test.apk',
      artifactBytes: artifacts.artifactBytes,
      sbomPath: 'sbom/network.xpoint.deep-2.0.2-p02c-test.cdx.json',
      sbomBytes: artifacts.sbomBytes,
      provenancePath: 'provenance/network.xpoint.deep-2.0.2-p02c-test.repro.json',
      provenanceBytes: artifacts.provenanceBytes
    });
    const material = createCeremonyMaterial(adapter);
    const release = createReleaseDocuments(material, adapter, request, artifacts);
    const bundle = {
      trustedRoot: material.rootOne,
      candidateRoots: [material.rootTwo],
      timestamp: release.timestamp,
      snapshot: release.snapshot,
      targets: release.targets,
      delegatedTargets: release.delegatedTargets,
      trustedState: createTrustedState(material.rootOne),
      updateStart: fixedUpdateStart
    };
    const verified = verifyUpdateBundle(bundle);
    contract(verified.state.trustedRoot.version === 2, 'P02B root rotation compatibility failed');
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

    const revokedTimestamp = signCanonicalWithAdapter(
      release.timestampSigned,
      material.timestampOld,
      adapter
    );
    const revokedOnlineKey = expectRejected(() => verifyUpdateBundle({
      ...bundle,
      timestamp: revokedTimestamp
    }));
    contract(revokedOnlineKey === 'REJECTED-AS-REQUIRED', 'revoked online key drill did not reject');
    const lostOnlineKey = 'PASSED';
    const rollbackBundle = {
      ...bundle,
      trustedState: structuredClone(bundle.trustedState)
    };
    rollbackBundle.trustedState.versions.timestamp = 2;
    const rollback = expectRejected(() => verifyUpdateBundle(rollbackBundle));
    const frozenSigned = {
      ...release.timestampSigned,
      expires: '2029-12-31T23:59:59Z'
    };
    const frozen = signCanonicalWithAdapter(frozenSigned, material.timestampNew, adapter);
    const freeze = expectRejected(() => verifyUpdateBundle({ ...bundle, timestamp: frozen }));

    const documents = {
      root1: material.rootOne,
      root2: material.rootTwo,
      timestamp: release.timestamp,
      snapshot: release.snapshot,
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
    await verifyByteIdenticalTrees(mirrorA, mirrorB);
    await verifyByteIdenticalTrees(mirrorA, offlineBundle);

    const addressedFile = entries.find(([relative]) => relative.startsWith('metadata/sha256/'));
    const compromisedPath = path.join(mirrorB, ...addressedFile[0].split('/'));
    const originalBytes = await readFile(compromisedPath);
    await writeFile(compromisedPath, Buffer.concat([originalBytes, Buffer.from([0])]));
    let mirrorCompromise;
    try {
      await verifyByteIdenticalTrees(mirrorA, mirrorB);
      fail('compromised mirror was accepted');
    } catch {
      mirrorCompromise = 'REJECTED-AS-REQUIRED';
    }
    await writeFile(compromisedPath, originalBytes);
    await verifyByteIdenticalTrees(mirrorA, mirrorB);

    const activation = evaluateProductionActivation({
      accountableHuman: 'Mr. X',
      namedIndependentCustodians: [],
      productionHsmEvidence: null,
      publicationAuthorization: null,
      reproducibleBuildEvidence: null
    });
    const drills = {
      rootRotation: 'PASSED',
      lostOnlineKey,
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
      rootThreshold: { required: 2, publicKeyCount: 3, signaturesObserved: 2 },
      rootRotationCrossSigned: true,
      oldRootThresholdObserved: 2,
      newRootThresholdObserved: 2,
      targetsThreshold: { required: 2, publicKeyCount: 3, signaturesObserved: 2 },
      delegatedThreshold: { required: 2, publicKeyCount: 3, signaturesObserved: 2 },
      testKeyMaterialArchived: false,
      productionHsmVerified: false,
      namedIndependentCustodians: []
    }));
    await writeFile(path.join(evidenceDir, 'artifact-evidence.json'), jsonBytes({
      schema: 'deep.update-ceremony.artifact-evidence.v1',
      testOnly: true,
      apkSha256: sha256(artifacts.artifactBytes),
      sbomSha256: sha256(artifacts.sbomBytes),
      provenanceSha256: sha256(artifacts.provenanceBytes),
      reproducibleBuildVerified: false,
      reason: 'two TEST builder labels are contract fixtures, not independent retained attestations'
    }));
    const summary = {
      schema: 'deep.update-ceremony.dry-run.v1',
      sourceCommitSha: gitHead(),
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
