import { spawnSync } from 'node:child_process';
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync
} from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  canonicalJson,
  insecureDeterministicTestKey,
  metadataBytes,
  sha256,
  signMetadata,
  verifyOfflineAndroidArtifact,
  verifyUpdateBundle
} from './update-trust.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repositoryRoot = path.resolve(__dirname, '..');
const DEFAULT_ARTIFACT_DIR = path.join(repositoryRoot, 'artifacts', 'survival', 'P02');
const FIXED_UPDATE_START = '2030-01-01T00:00:00Z';
const GOOD_EXPIRY = '2030-01-03T00:00:00Z';
const ROOT_EXPIRY = '2035-01-01T00:00:00Z';
const EXPECTED_MANIFEST_SHA256 =
  '6527338b3e5b888a22fb2cc55323259306e9f41bff69e9554706701a86dc7824';
const EXPECTED_PROGRAM_SHA256 =
  'ca5ad9f0c9d4dfb509dedcbf8133524c15867fce5534816da21ff86a07057383';
const MANIFEST_PATH = path.join(
  repositoryRoot,
  'release',
  'manifests',
  'survival-v2.0.1-i01b.local.json'
);

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function keySet(labels) {
  return Object.fromEntries(labels.map(label => [label, insecureDeterministicTestKey(label)]));
}

function publicKeys(keys, labels) {
  return Object.fromEntries(labels.map(label => [keys[label].keyid, keys[label].key]));
}

function role(keys, labels, threshold) {
  return { keyids: labels.map(label => keys[label].keyid), threshold };
}

function metadataDescription(envelope) {
  const bytes = metadataBytes(envelope);
  return {
    version: envelope.signed.version,
    length: bytes.length,
    hashes: { sha256: sha256(bytes) }
  };
}

function targetDescription(bytes, custom) {
  const result = {
    length: bytes.length,
    hashes: { sha256: sha256(bytes) }
  };
  if (custom) result.custom = custom;
  return result;
}

function jsonBytes(value) {
  return Buffer.from(`${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

export function createUpdateTrustFixture() {
  const labels = [
    'root-a', 'root-b', 'root-c', 'root-d',
    'targets-a', 'targets-b', 'targets-c',
    'snapshot-old', 'snapshot-new',
    'timestamp-old', 'timestamp-new', 'unknown',
    'android-a', 'android-b', 'android-c'
  ];
  const keys = keySet(labels);
  const rootOneLabels = [
    'root-a', 'root-b', 'root-c',
    'targets-a', 'targets-b', 'targets-c',
    'snapshot-old', 'timestamp-old'
  ];
  const rootTwoLabels = [
    'root-b', 'root-c', 'root-d',
    'targets-a', 'targets-b', 'targets-c',
    'snapshot-new', 'timestamp-new'
  ];
  const rootOneSigned = {
    _type: 'root',
    spec_version: '1.0.35',
    consistent_snapshot: true,
    version: 1,
    expires: ROOT_EXPIRY,
    keys: publicKeys(keys, rootOneLabels),
    roles: {
      root: role(keys, ['root-a', 'root-b', 'root-c'], 2),
      targets: role(keys, ['targets-a', 'targets-b', 'targets-c'], 2),
      snapshot: role(keys, ['snapshot-old'], 1),
      timestamp: role(keys, ['timestamp-old'], 1)
    }
  };
  const rootTwoSigned = {
    ...rootOneSigned,
    version: 2,
    keys: publicKeys(keys, rootTwoLabels),
    roles: {
      root: role(keys, ['root-b', 'root-c', 'root-d'], 2),
      targets: role(keys, ['targets-a', 'targets-b', 'targets-c'], 2),
      snapshot: role(keys, ['snapshot-new'], 1),
      timestamp: role(keys, ['timestamp-new'], 1)
    }
  };
  const rootOne = signMetadata(rootOneSigned, [keys['root-a'], keys['root-b']]);
  // root-b/root-c jointly satisfy both the old and the new 2-of-3 root roles.
  const rootTwo = signMetadata(rootTwoSigned, [keys['root-b'], keys['root-c']]);

  const apkPath = 'android/network.xpoint.deep-2.0.1-i01b.apk';
  const sbomPath = 'sbom/network.xpoint.deep-2.0.1-i01b.cdx.json';
  const provenancePath = 'provenance/network.xpoint.deep-2.0.1-i01b.repro.json';
  const apkBytes = Buffer.from(
    'Deep P02 deterministic synthetic APK payload descriptor; never install or publish.\n',
    'utf8'
  );
  const buildDefinitionSha256 = sha256(
    Buffer.from('deep-client-maui/eng/build-android-play.ps1@P02-contract', 'utf8')
  );
  const packageSignerSha256 = sha256(
    Buffer.from('Deep P02 deterministic synthetic package signer certificate', 'utf8')
  );
  const sbomBytes = jsonBytes({
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    serialNumber: 'urn:uuid:00000000-0000-4000-8000-000000000002',
    version: 1,
    metadata: {
      component: {
        type: 'application',
        name: 'network.xpoint.deep',
        version: '2.0.1-i01b'
      }
    },
    components: []
  });
  const provenanceBytes = jsonBytes({
    schema: 'deep.reproducible-build.v1',
    sourceCommit: '9dc1502392ce2c1a86441df6308f2db54410eae8',
    programRevisionSha256: EXPECTED_PROGRAM_SHA256,
    sourceDateEpoch: 1784332800,
    buildDefinitionSha256,
    sbomSha256: sha256(sbomBytes),
    builders: [
      {
        builderId: 'synthetic-contract-builder-a',
        artifactSha256: sha256(apkBytes)
      },
      {
        builderId: 'synthetic-contract-builder-b',
        artifactSha256: sha256(apkBytes)
      }
    ]
  });
  const apkCustom = {
    platform: 'android',
    packageId: 'network.xpoint.deep',
    versionCode: '20001',
    versionName: '2.0.1-i01b',
    packageSignerSha256,
    sourceCommit: '9dc1502392ce2c1a86441df6308f2db54410eae8',
    programRevisionSha256: EXPECTED_PROGRAM_SHA256,
    sbom: {
      path: sbomPath,
      sha256: sha256(sbomBytes),
      format: 'CycloneDX-1.6'
    },
    reproducibleBuild: {
      provenancePath,
      sourceDateEpoch: 1784332800,
      buildDefinitionSha256,
      minimumIndependentBuilders: 2
    }
  };
  const delegatedSigned = {
    _type: 'targets',
    spec_version: '1.0.35',
    version: 1,
    expires: GOOD_EXPIRY,
    targets: {
      [apkPath]: targetDescription(apkBytes, apkCustom),
      [sbomPath]: targetDescription(sbomBytes, { mediaType: 'application/vnd.cyclonedx+json' }),
      [provenancePath]: targetDescription(provenanceBytes, {
        mediaType: 'application/vnd.deep.reproducible-build+json'
      })
    }
  };
  const delegatedTargets = signMetadata(
    delegatedSigned,
    [keys['android-a'], keys['android-b']]
  );
  const targetsSigned = {
    _type: 'targets',
    spec_version: '1.0.35',
    version: 1,
    expires: GOOD_EXPIRY,
    targets: {},
    delegations: {
      keys: publicKeys(keys, ['android-a', 'android-b', 'android-c']),
      roles: [{
        name: 'android-release',
        keyids: ['android-a', 'android-b', 'android-c'].map(label => keys[label].keyid),
        threshold: 2,
        paths: ['android/*', 'sbom/*', 'provenance/*'],
        terminating: true
      }]
    }
  };
  const targets = signMetadata(targetsSigned, [keys['targets-a'], keys['targets-b']]);

  function createBundle({
    rotatedRoot = false,
    timestampVersion = 1,
    snapshotVersion = 1,
    timestampExpiry = GOOD_EXPIRY,
    timestampSigner = rotatedRoot ? 'timestamp-new' : 'timestamp-old',
    snapshotSigner = rotatedRoot ? 'snapshot-new' : 'snapshot-old',
    snapshotOverrides = {}
  } = {}) {
    const snapshotSigned = {
      _type: 'snapshot',
      spec_version: '1.0.35',
      version: snapshotVersion,
      expires: GOOD_EXPIRY,
      meta: {
        'targets.json': metadataDescription(targets),
        'android-release.json': metadataDescription(delegatedTargets),
        ...snapshotOverrides
      }
    };
    const snapshot = signMetadata(snapshotSigned, [keys[snapshotSigner]]);
    const timestampSigned = {
      _type: 'timestamp',
      spec_version: '1.0.35',
      version: timestampVersion,
      expires: timestampExpiry,
      meta: {
        'snapshot.json': metadataDescription(snapshot)
      }
    };
    const timestamp = signMetadata(timestampSigned, [keys[timestampSigner]]);
    return {
      trustedRoot: rootOne,
      candidateRoots: rotatedRoot ? [rootTwo] : [],
      timestamp,
      snapshot,
      targets,
      delegatedTargets,
      trustedVersions: {},
      updateStart: FIXED_UPDATE_START
    };
  }

  return {
    keys,
    rootOne,
    rootTwo,
    targets,
    delegatedTargets,
    apkPath,
    sbomPath,
    provenancePath,
    apkBytes,
    sbomBytes,
    provenanceBytes,
    packageSignerSha256,
    createBundle
  };
}

function expectRejected(label, action, expectedPattern) {
  try {
    action();
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    assert(expectedPattern.test(message), `${label} rejected for unexpected reason: ${message}`);
    return {
      name: label,
      status: 'rejected-as-required',
      reason: message
    };
  }
  throw new Error(`${label} was accepted`);
}

function gitValue(args) {
  const result = spawnSync('git', args, {
    cwd: repositoryRoot,
    encoding: 'utf8',
    windowsHide: true
  });
  assert(result.status === 0, `git ${args.join(' ')} failed`);
  return result.stdout.trim();
}

function writeJson(filePath, value) {
  mkdirSync(path.dirname(filePath), { recursive: true });
  writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

function parseOptions(argv) {
  const options = { artifactDir: DEFAULT_ARTIFACT_DIR };
  for (let index = 0; index < argv.length; index += 2) {
    const name = argv[index];
    const value = argv[index + 1];
    assert(name === '--artifact-dir' && value && !value.startsWith('--'),
      'supported option: --artifact-dir <path>');
    options.artifactDir = path.resolve(value);
  }
  return options;
}

export function runUpdateTrustContracts({ artifactDir = DEFAULT_ARTIFACT_DIR } = {}) {
  const manifestBytes = readFileSync(MANIFEST_PATH);
  assert(sha256(manifestBytes) === EXPECTED_MANIFEST_SHA256,
    'pinned survival manifest SHA-256 changed');
  const manifest = JSON.parse(manifestBytes.toString('utf8'));
  assert(manifest.programRevision?.sha256 === EXPECTED_PROGRAM_SHA256,
    'pinned survival program revision changed');

  const fixture = createUpdateTrustFixture();
  const happyBundle = fixture.createBundle();
  const happy = verifyUpdateBundle(happyBundle);

  const rollbackBundle = fixture.createBundle();
  rollbackBundle.trustedVersions = { timestamp: 2 };
  const freezeBundle = fixture.createBundle({
    timestampExpiry: '2029-12-31T23:59:59Z'
  });
  const mixSnapshot = fixture.createBundle({
    snapshotOverrides: {
      'android-release.json': {
        ...metadataDescription(fixture.delegatedTargets),
        hashes: { sha256: '0'.repeat(64) }
      }
    }
  });
  // Keep a timestamp from the coherent repository, then offer a different validly
  // signed snapshot to exercise the timestamp -> snapshot hash binding.
  mixSnapshot.timestamp = happyBundle.timestamp;
  const unknownSigner = fixture.createBundle({ timestampSigner: 'unknown' });
  const negativeCases = [
    expectRejected('rollback', () => verifyUpdateBundle(rollbackBundle), /rollback/i),
    expectRejected('freeze', () => verifyUpdateBundle(freezeBundle), /freeze|expired/i),
    expectRejected('mix-and-match', () => verifyUpdateBundle(mixSnapshot), /mix-and-match|hash/i),
    expectRejected('unknown-signer', () => verifyUpdateBundle(unknownSigner), /unknown signer/i)
  ];

  const rotatedBundle = fixture.createBundle({ rotatedRoot: true });
  const rotated = verifyUpdateBundle(rotatedBundle);
  assert(rotated.state.root === 2, 'root rotation did not advance trust to root v2');
  const oldTimestampAfterRotation = fixture.createBundle({
    rotatedRoot: true,
    timestampSigner: 'timestamp-old'
  });
  const lostOnlineRejection = expectRejected(
    'revoked-online-timestamp-key',
    () => verifyUpdateBundle(oldTimestampAfterRotation),
    /unknown signer/
  );

  const sandbox = mkdtempSync(path.join(tmpdir(), 'deep-p02-'));
  try {
    const apkFile = path.join(sandbox, 'fixture.apk');
    writeFileSync(apkFile, fixture.apkBytes);
    const androidResult = verifyOfflineAndroidArtifact({
      verifiedBundle: happy,
      apkPath: fixture.apkPath,
      apkFile,
      artifactFiles: {
        [fixture.sbomPath]: fixture.sbomBytes,
        [fixture.provenancePath]: fixture.provenanceBytes
      },
      apkSignerPath: 'synthetic-test-only',
      runApkSigner: () =>
        `Signer #1 certificate SHA-256 digest: ${fixture.packageSignerSha256.toUpperCase()}`
    });
    const signerMismatch = expectRejected(
      'apk-package-signer-mismatch',
      () => verifyOfflineAndroidArtifact({
        verifiedBundle: happy,
        apkPath: fixture.apkPath,
        apkFile,
        artifactFiles: {
          [fixture.sbomPath]: fixture.sbomBytes,
          [fixture.provenancePath]: fixture.provenanceBytes
        },
        apkSignerPath: 'synthetic-test-only',
        runApkSigner: () => `Signer #1 certificate SHA-256 digest: ${'f'.repeat(64)}`
      }),
      /package signer/
    );
    negativeCases.push(signerMismatch);

    const sourceCommitSha = gitValue(['rev-parse', 'HEAD']);
    const generatedAtUtc = new Date(gitValue(['show', '-s', '--format=%cI', 'HEAD']))
      .toISOString();
    const publicMetadataDir = path.join(artifactDir, 'public-test-metadata');
    writeJson(path.join(publicMetadataDir, '1.root.json'), fixture.rootOne);
    writeJson(path.join(publicMetadataDir, '2.root.json'), fixture.rootTwo);
    writeJson(path.join(publicMetadataDir, 'timestamp.json'), rotatedBundle.timestamp);
    writeJson(path.join(publicMetadataDir, 'snapshot.json'), rotatedBundle.snapshot);
    writeJson(path.join(publicMetadataDir, 'targets.json'), fixture.targets);
    writeJson(path.join(publicMetadataDir, 'android-release.json'), fixture.delegatedTargets);
    writeJson(path.join(artifactDir, 'sbom-reproducibility-contract.json'), {
      schema: 'deep.update-trust.sbom-reproducibility.v1',
      fixtureOnly: true,
      apkTarget: fixture.apkPath,
      apkSha256: sha256(fixture.apkBytes),
      sbomTarget: fixture.sbomPath,
      sbomSha256: sha256(fixture.sbomBytes),
      provenanceTarget: fixture.provenancePath,
      provenanceSha256: sha256(fixture.provenanceBytes),
      minimumIndependentBuilders: 2,
      result: 'passed'
    });
    writeJson(path.join(artifactDir, 'root-rotation-drill.json'), {
      schema: 'deep.update-trust.root-rotation-drill.v1',
      fixtureOnly: true,
      initialRootVersion: 1,
      finalRootVersion: rotated.state.root,
      oldThreshold: 2,
      newThreshold: 2,
      result: 'passed'
    });
    writeJson(path.join(artifactDir, 'lost-online-key-drill.json'), {
      schema: 'deep.update-trust.lost-online-key-drill.v1',
      fixtureOnly: true,
      rotatedRole: 'timestamp',
      replacementAccepted: true,
      revokedSignerRejected: lostOnlineRejection.status === 'rejected-as-required',
      result: 'passed'
    });
    writeJson(path.join(artifactDir, 'offline-android-verification.json'), {
      schema: 'deep.update-trust.offline-android-verification.v1',
      fixtureOnly: true,
      packageSignerExecution: 'synthetic-output-injected-for-contract-test',
      productionContract: 'Android SDK apksigner verify --verbose --print-certs',
      ...androidResult
    });
    writeJson(path.join(artifactDir, 'negative-scenarios.json'), {
      schema: 'deep.update-trust.negative-scenarios.v1',
      fixtureOnly: true,
      cases: negativeCases
    });
    const summary = {
      schema: 'deep.update-trust.contract-summary.v1',
      generatedAtUtc,
      sourceCommitSha,
      sourceManifest: path.relative(repositoryRoot, MANIFEST_PATH).replaceAll('\\', '/'),
      sourceManifestSha256: EXPECTED_MANIFEST_SHA256,
      programRevisionSha256: EXPECTED_PROGRAM_SHA256,
      tufSpecificationVersion: '1.0.35',
      fixtureOnly: true,
      productionKeysPresent: false,
      privateTestKeyMaterialArchived: false,
      checks: {
        coherentMetadata: 'passed',
        rollback: 'rejected',
        freeze: 'rejected',
        mixAndMatch: 'rejected',
        unknownSigner: 'rejected',
        rootRotation: 'passed',
        lostOnlineKey: 'passed',
        sbomAndReproducibility: 'passed',
        offlineAndroidMetadataAndPackageSigner: 'passed'
      },
      status: 'passed'
    };
    writeJson(path.join(artifactDir, 'update-trust-summary.json'), summary);
    return summary;
  } finally {
    rmSync(sandbox, { recursive: true, force: true });
  }
}

const isMain = process.argv[1] &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  try {
    const options = parseOptions(process.argv.slice(2));
    const summary = runUpdateTrustContracts(options);
    console.log(`P02 update-trust contracts: ${summary.status}`);
  } catch (error) {
    console.error(error instanceof Error ? error.stack : String(error));
    process.exitCode = 1;
  }
}
