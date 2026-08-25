import { spawnSync } from 'node:child_process';
import {
  chmodSync,
  copyFileSync,
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
  createTrustedState,
  insecureDeterministicTestKey,
  metadataDocumentFromEnvelope,
  parseMetadataDocument,
  sha256,
  signMetadata,
  verifyOfflineAndroidArtifact,
  verifyUpdateBundle,
  writeTrustedStateAtomic
} from './update-trust.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repositoryRoot = path.resolve(__dirname, '..');
const DEFAULT_ARTIFACT_DIR = path.join(repositoryRoot, 'artifacts', 'survival', 'P02');
const FIXED_UPDATE_START = '2030-01-01T00:00:00Z';
const GOOD_EXPIRY = '2030-01-03T00:00:00Z';
const ROOT_EXPIRY = '2035-01-01T00:00:00Z';
const EXPECTED_SOURCE_BASELINE_SHA256 =
  'd1727be7885c6f46efa06dc168de3c21c7835c62437624378152822480563fca';
const EXPECTED_PROGRAM_SHA256 =
  '361c93ac16a51f2e83731548a6fcb09da7f805a9e0ba78ca5b496a896f3c2b1c';
const SOURCE_BASELINE_PATH = path.join(
  repositoryRoot,
  'release',
  'source-baseline-v1.json'
);

function fixtureVerifierArtifactBytes(signerDigest, apkSha256) {
  return Buffer.from([
    "import { readFileSync } from 'node:fs';",
    "import { createHash } from 'node:crypto';",
    "import { fileURLToPath } from 'node:url';",
    "const artifact = fileURLToPath(import.meta.url);",
    "const args = process.argv.slice(2);",
    "const snapshot = args[6];",
    "const expected = ['-cp', artifact, 'com.android.apksigner.ApkSignerTool',",
    "  'verify', '--verbose', '--print-certs', snapshot];",
    "if (args.length !== expected.length || args.some((v, i) => v !== expected[i])) process.exit(41);",
    `if (createHash('sha256').update(readFileSync(snapshot)).digest('hex') !== '${apkSha256}') process.exit(42);`,
    `console.log('Signer #1 certificate SHA-256 digest: ${signerDigest}');`,
    ''
  ].join('\n'), 'utf8');
}

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
  const bytes = envelope.rawBytes;
  return {
    version: envelope.envelope.signed.version,
    length: bytes.length,
    hashes: { sha256: sha256(bytes) }
  };
}

function signedDocument(signed, signers) {
  return metadataDocumentFromEnvelope(signMetadata(signed, signers));
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
    'root-a', 'root-b', 'root-c', 'root-d', 'root-e', 'root-f',
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
    'root-d', 'root-e', 'root-f',
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
      root: role(keys, ['root-d', 'root-e', 'root-f'], 2),
      targets: role(keys, ['targets-a', 'targets-b', 'targets-c'], 2),
      snapshot: role(keys, ['snapshot-new'], 1),
      timestamp: role(keys, ['timestamp-new'], 1)
    }
  };
  const rootOne = signedDocument(rootOneSigned, [keys['root-a'], keys['root-b']]);
  // The disjoint old/new signatures prove that each threshold is checked
  // independently over the same exact canonical root v2 bytes.
  const rootTwo = signedDocument(
    rootTwoSigned,
    [keys['root-a'], keys['root-b'], keys['root-d'], keys['root-e']]
  );

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
  const delegatedTargets = signedDocument(
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
  const targets = signedDocument(targetsSigned, [keys['targets-a'], keys['targets-b']]);

  function createBundle({
    rotatedRoot = false,
    timestampVersion = 1,
    snapshotVersion = 1,
    timestampExpiry = GOOD_EXPIRY,
    timestampSigner = rotatedRoot ? 'timestamp-new' : 'timestamp-old',
    snapshotSigner = rotatedRoot ? 'snapshot-new' : 'snapshot-old',
    snapshotOverrides = {},
    timestampSnapshotOverride,
    targetsDocument = targets,
    delegatedDocument = delegatedTargets
  } = {}) {
    const snapshotSigned = {
      _type: 'snapshot',
      spec_version: '1.0.35',
      version: snapshotVersion,
      expires: GOOD_EXPIRY,
      meta: {
        'targets.json': metadataDescription(targetsDocument),
        'android-release.json': metadataDescription(delegatedDocument),
        ...snapshotOverrides
      }
    };
    const snapshot = signedDocument(snapshotSigned, [keys[snapshotSigner]]);
    const timestampSigned = {
      _type: 'timestamp',
      spec_version: '1.0.35',
      version: timestampVersion,
      expires: timestampExpiry,
      meta: {
        'snapshot.json': timestampSnapshotOverride ?? metadataDescription(snapshot)
      }
    };
    const timestamp = signedDocument(timestampSigned, [keys[timestampSigner]]);
    return {
      trustedRoot: rootOne,
      candidateRoots: rotatedRoot ? [rootTwo] : [],
      timestamp,
      snapshot,
      targets: targetsDocument,
      delegatedTargets: delegatedDocument,
      trustedState: createTrustedState(rootOne),
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

function writeMetadata(filePath, document) {
  mkdirSync(path.dirname(filePath), { recursive: true });
  writeFileSync(filePath, document.rawBytes);
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
  const sourceBaselineBytes = readFileSync(SOURCE_BASELINE_PATH);
  assert(sha256(sourceBaselineBytes) === EXPECTED_SOURCE_BASELINE_SHA256,
    'release source baseline SHA-256 changed');
  const sourceBaseline = JSON.parse(sourceBaselineBytes.toString('utf8'));
  assert(sourceBaseline.updateTrustFixture?.programRevisionSha256 === EXPECTED_PROGRAM_SHA256,
    'release source baseline update-trust revision changed');

  const fixture = createUpdateTrustFixture();
  const happyBundle = fixture.createBundle();
  const happy = verifyUpdateBundle(happyBundle);

  const negativeCases = [];
  const freezeBundle = fixture.createBundle({
    timestampExpiry: '2029-12-31T23:59:59Z'
  });
  negativeCases.push(
    expectRejected('freeze', () => verifyUpdateBundle(freezeBundle), /freeze|expired/i)
  );
  for (const roleName of ['timestamp', 'snapshot', 'targets', 'androidRelease']) {
    const rollback = fixture.createBundle();
    rollback.trustedState.versions[roleName] = 2;
    negativeCases.push(expectRejected(
      `rollback-${roleName}`,
      () => verifyUpdateBundle(rollback),
      /rollback/i
    ));
  }
  negativeCases.push(expectRejected(
    'unknown-timestamp-signer',
    () => verifyUpdateBundle(fixture.createBundle({ timestampSigner: 'unknown' })),
    /unknown signer/i
  ));

  const rootTwoSignatures = fixture.rootTwo.envelope.signatures;
  for (const [name, signatures, expected] of [
    ['root-old-only-threshold', rootTwoSignatures.slice(0, 2), /new-root threshold/],
    ['root-new-only-threshold', rootTwoSignatures.slice(2), /old-root threshold/]
  ]) {
    const bundle = fixture.createBundle({ rotatedRoot: true });
    bundle.candidateRoots = [metadataDocumentFromEnvelope({
      ...fixture.rootTwo.envelope,
      signatures
    })];
    negativeCases.push(expectRejected(
      name,
      () => verifyUpdateBundle(bundle),
      expected
    ));
  }

  const originalRoot = fixture.rootOne.envelope.signed;
  const removedRootKey = fixture.keys['root-c'].keyid;
  const alternateRoot = signedDocument({
    ...originalRoot,
    keys: Object.fromEntries(
      Object.entries(originalRoot.keys)
        .filter(([keyid]) => keyid !== removedRootKey)
    ),
    roles: {
      ...originalRoot.roles,
      root: role(fixture.keys, ['root-a', 'root-b'], 2)
    }
  }, [fixture.keys['root-a'], fixture.keys['root-b']]);
  const alternateRootBundle = fixture.createBundle();
  alternateRootBundle.trustedRoot = alternateRoot;
  negativeCases.push(expectRejected(
    'same-version-different-root-keyset',
    () => verifyUpdateBundle(alternateRootBundle),
    /persisted version and raw SHA-256/
  ));

  for (const [name, raw] of [
    ['raw-bom', Buffer.concat([
      Buffer.from([0xEF, 0xBB, 0xBF]),
      fixture.rootOne.rawBytes
    ])],
    ['raw-whitespace', Buffer.concat([
      fixture.rootOne.rawBytes,
      Buffer.from('\n')
    ])],
    ['raw-key-order', Buffer.from(JSON.stringify({
      signed: fixture.rootOne.envelope.signed,
      signatures: fixture.rootOne.envelope.signatures
    }))],
    ['raw-number-representation', Buffer.from(
      fixture.rootOne.rawBytes.toString('utf8')
        .replace('"version":1', '"version":1e0')
    )]
  ]) {
    negativeCases.push(expectRejected(
      name,
      () => parseMetadataDocument(raw, name),
      /exact canonical POUF encoding/
    ));
  }

  for (const field of ['hash', 'length']) {
    const wrong = (document) => {
      const description = metadataDescription(document);
      if (field === 'length') description.length += 1;
      else description.hashes.sha256 = '0'.repeat(64);
      return description;
    };
    negativeCases.push(expectRejected(
      `timestamp-snapshot-${field}`,
      () => verifyUpdateBundle(fixture.createBundle({
        timestampSnapshotOverride: wrong(fixture.createBundle().snapshot)
      })),
      /mix-and-match/
    ));
    negativeCases.push(expectRejected(
      `snapshot-targets-${field}`,
      () => verifyUpdateBundle(fixture.createBundle({
        snapshotOverrides: { 'targets.json': wrong(fixture.targets) }
      })),
      /mix-and-match/
    ));
    negativeCases.push(expectRejected(
      `snapshot-delegated-${field}`,
      () => verifyUpdateBundle(fixture.createBundle({
        snapshotOverrides: {
          'android-release.json': wrong(fixture.delegatedTargets)
        }
      })),
      /mix-and-match/
    ));
  }

  const delegatedSigned = fixture.delegatedTargets.envelope.signed;
  const unauthorizedDelegation = signedDocument({
    ...delegatedSigned,
    targets: {
      ...delegatedSigned.targets,
      'windows/unauthorized.msix': delegatedSigned.targets[fixture.apkPath]
    }
  }, [fixture.keys['android-a'], fixture.keys['android-b']]);
  negativeCases.push(expectRejected(
    'unauthorized-delegated-path',
    () => verifyUpdateBundle(fixture.createBundle({
      delegatedDocument: unauthorizedDelegation
    })),
    /unauthorized/
  ));
  const unknownDelegatedSigner = signedDocument(
    delegatedSigned,
    [fixture.keys.unknown]
  );
  negativeCases.push(expectRejected(
    'unknown-delegated-signer',
    () => verifyUpdateBundle(fixture.createBundle({
      delegatedDocument: unknownDelegatedSigner
    })),
    /unknown signer/
  ));

  const rotatedBundle = fixture.createBundle({ rotatedRoot: true });
  const rotated = verifyUpdateBundle(rotatedBundle);
  assert(rotated.state.trustedRoot.version === 2,
    'root rotation did not advance trust to root v2');
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
    const statePath = path.join(sandbox, 'trusted-state.json');
    writeTrustedStateAtomic(statePath, rotatedBundle.trustedState);
    verifyUpdateBundle({
      ...rotatedBundle,
      persistTrustedRoot: state => writeTrustedStateAtomic(statePath, state)
    });
    const atomicallyPersistedState = JSON.parse(readFileSync(statePath, 'utf8'));
    assert(
      atomicallyPersistedState.trustedRoot.version === 2 &&
      atomicallyPersistedState.trustedRoot.sha256 === sha256(fixture.rootTwo.rawBytes),
      'root version/raw SHA-256 was not atomically persisted'
    );
    const apkFile = path.join(sandbox, 'fixture.apk');
    writeFileSync(apkFile, fixture.apkBytes);
    const verificationTempRoot = path.join(sandbox, 'private-temp');
    mkdirSync(verificationTempRoot, { mode: 0o700 });
    const verifierRuntimeRootPath = path.join(sandbox, 'fixture-runtime');
    mkdirSync(verifierRuntimeRootPath, { mode: 0o700 });
    const runtimeName = process.platform === 'win32' ? 'node.exe' : 'node';
    const verifierRuntimePath = path.join(verifierRuntimeRootPath, runtimeName);
    copyFileSync(process.execPath, verifierRuntimePath);
    if (process.platform !== 'win32') chmodSync(verifierRuntimePath, 0o700);
    const verifierRuntimeSha256 = sha256(readFileSync(verifierRuntimePath));
    const verifierRuntimeManifestPath = path.join(sandbox, 'fixture-runtime-manifest.json');
    const verifierRuntimeManifestBytes = Buffer.from(`${JSON.stringify({
      schema: 'deep.apk-verifier-runtime-tree.v1',
      entrypoint: runtimeName,
      files: [{
        path: runtimeName,
        length: readFileSync(verifierRuntimePath).length,
        sha256: verifierRuntimeSha256
      }]
    })}\n`, 'utf8');
    writeFileSync(verifierRuntimeManifestPath, verifierRuntimeManifestBytes);
    const verifierArtifactPath = path.join(sandbox, 'fixture-verifier.mjs');
    const verifierArtifactBytes = fixtureVerifierArtifactBytes(
      fixture.packageSignerSha256,
      sha256(fixture.apkBytes)
    );
    writeFileSync(verifierArtifactPath, verifierArtifactBytes);
    const androidResult = verifyOfflineAndroidArtifact({
      verifiedBundle: happy,
      apkPath: fixture.apkPath,
      apkFile,
      artifactFiles: {
        [fixture.sbomPath]: fixture.sbomBytes,
        [fixture.provenancePath]: fixture.provenanceBytes
      },
      verifierRuntimePath,
      verifierRuntimeSha256,
      verifierRuntimeRootPath,
      verifierRuntimeManifestPath,
      verifierRuntimeManifestSha256: sha256(verifierRuntimeManifestBytes),
      verifierArtifactPath,
      verifierArtifactSha256: sha256(verifierArtifactBytes),
      verificationTempRoot,
      verifierProfile: 'node-test-fixture-v1'
    });
    const wrongVerifierArtifactBytes = fixtureVerifierArtifactBytes(
      'f'.repeat(64),
      sha256(fixture.apkBytes)
    );
    writeFileSync(verifierArtifactPath, wrongVerifierArtifactBytes);
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
        verifierRuntimePath,
        verifierRuntimeSha256,
        verifierRuntimeRootPath,
        verifierRuntimeManifestPath,
        verifierRuntimeManifestSha256: sha256(verifierRuntimeManifestBytes),
        verifierArtifactPath,
        verifierArtifactSha256: sha256(wrongVerifierArtifactBytes),
        verificationTempRoot,
        verifierProfile: 'node-test-fixture-v1'
      }),
      /package signer/
    );
    negativeCases.push(signerMismatch);

    const sourceCommitSha = gitValue(['rev-parse', 'HEAD']);
    const generatedAtUtc = new Date(gitValue(['show', '-s', '--format=%cI', 'HEAD']))
      .toISOString();
    const publicMetadataDir = path.join(artifactDir, 'public-test-metadata');
    writeMetadata(path.join(publicMetadataDir, '1.root.json'), fixture.rootOne);
    writeMetadata(path.join(publicMetadataDir, '2.root.json'), fixture.rootTwo);
    writeMetadata(path.join(publicMetadataDir, 'timestamp.json'), rotatedBundle.timestamp);
    writeMetadata(path.join(publicMetadataDir, 'snapshot.json'), rotatedBundle.snapshot);
    writeMetadata(path.join(publicMetadataDir, 'targets.json'), fixture.targets);
    writeMetadata(
      path.join(publicMetadataDir, 'android-release.json'),
      fixture.delegatedTargets
    );
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
      finalRootVersion: rotated.state.trustedRoot.version,
      initialRootRawSha256: sha256(fixture.rootOne.rawBytes),
      finalRootRawSha256: sha256(fixture.rootTwo.rawBytes),
      oldThreshold: 2,
      newThreshold: 2,
      thresholdsVerifiedIndependently: true,
      atomicPersistedBinding: 'version-and-raw-sha256',
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
      packageSignerExecution:
        'exact-manifested-node-runtime-tree-and-pinned-fixture-artifact-enforcing-fixed-snapshot-argv',
      productionContract:
        'exact-manifested-java-runtime-tree -cp pinned-apksigner.jar com.android.apksigner.ApkSignerTool verify --verbose --print-certs protected-snapshot',
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
      sourceBaseline: path.relative(repositoryRoot, SOURCE_BASELINE_PATH).replaceAll('\\', '/'),
      sourceBaselineSha256: EXPECTED_SOURCE_BASELINE_SHA256,
      programRevisionSha256: EXPECTED_PROGRAM_SHA256,
      tufSpecificationVersion: '1.0.35',
      fixtureOnly: true,
      productionKeysPresent: false,
      privateTestKeyMaterialArchived: false,
      negativeCaseCount: negativeCases.length,
      checks: {
        coherentMetadata: 'passed',
        rollback: 'rejected',
        freeze: 'rejected',
        mixAndMatch: 'rejected',
        unknownSigner: 'rejected',
        rawCanonicalMetadata: 'passed',
        persistedRootVersionAndRawSha256: 'passed',
        parentRawHashAndLengthMatrix: 'passed',
        allRoleRollbackMatrix: 'passed',
        delegatedPathAndSignerMatrix: 'passed',
        rootRotation: 'passed',
        lostOnlineKey: 'passed',
        sbomAndReproducibility: 'passed',
        offlineAndroidMetadataAndPackageSigner: 'passed',
        apkVerifierExactRuntimeTreeAndPinnedArtifact: 'passed',
        apkSignerFixedArgvAndProtectedSnapshot: 'passed'
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
