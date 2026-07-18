import assert from 'node:assert/strict';
import {
  chmod,
  mkdtemp,
  readFile,
  realpath,
  rm,
  writeFile
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {
  canonicalJson,
  metadataDocumentFromEnvelope,
  parseApkSignerDigests,
  parseMetadataDocument,
  parseStrictJson,
  runTrustedApkSigner,
  sha256,
  signMetadata,
  verifyOfflineAndroidArtifact,
  verifyUpdateBundle,
  writeTrustedStateAtomic
} from './update-trust.mjs';
import {
  createUpdateTrustFixture,
  runUpdateTrustContracts
} from './update-trust-contracts.mjs';

function signedDocument(signed, signers) {
  return metadataDocumentFromEnvelope(signMetadata(signed, signers));
}

function meta(document) {
  return {
    version: document.envelope.signed.version,
    length: document.rawBytes.length,
    hashes: { sha256: sha256(document.rawBytes) }
  };
}

function mutateMeta(document, field) {
  const result = meta(document);
  if (field === 'length') result.length += 1;
  else result.hashes.sha256 = '0'.repeat(64);
  return result;
}

function fakeApkSignerBytes(canonicalApk, signerDigest) {
  return Buffer.from(
    process.platform === 'win32'
      ? [
          '@echo off',
          'if not "%~1"=="verify" exit /b 41',
          'if not "%~2"=="--verbose" exit /b 42',
          'if not "%~3"=="--print-certs" exit /b 43',
          `if not "%~4"=="${canonicalApk}" exit /b 44`,
          'if not "%~5"=="" exit /b 45',
          `echo Signer #1 certificate SHA-256 digest: ${signerDigest}`,
          ''
        ].join('\r\n')
      : [
          '#!/bin/sh',
          '[ "$#" -eq 4 ] || exit 40',
          '[ "$1" = "verify" ] || exit 41',
          '[ "$2" = "--verbose" ] || exit 42',
          '[ "$3" = "--print-certs" ] || exit 43',
          `[ "$4" = '${canonicalApk}' ] || exit 44`,
          `printf '%s\\n' 'Signer #1 certificate SHA-256 digest: ${signerDigest}'`,
          ''
        ].join('\n'),
    'utf8'
  );
}

async function writeFakeApkSigner(sandbox, name, canonicalApk, signerDigest) {
  assert(!canonicalApk.includes("'"), 'test path unexpectedly contains a single quote');
  const filePath = path.join(
    sandbox,
    process.platform === 'win32' ? `${name}.bat` : name
  );
  const bytes = fakeApkSignerBytes(canonicalApk, signerDigest);
  await writeFile(filePath, bytes);
  if (process.platform !== 'win32') await chmod(filePath, 0o755);
  return { filePath, sha256: sha256(bytes) };
}

test('strict JSON and canonical POUF reject duplicate, ambiguous, or non-canonical bytes', () => {
  assert.equal(
    canonicalJson({ z: [3, { b: true, a: 'x' }], a: 1 }),
    '{"a":1,"z":[3,{"a":"x","b":true}]}'
  );
  assert.throws(() => canonicalJson({ value: 1.5 }), /safe integers/);
  assert.throws(
    () => parseStrictJson('{"signed":{"version":1,"version":2}}', 'fixture'),
    /duplicate object key/
  );
  const fixture = createUpdateTrustFixture();
  const canonical = fixture.rootOne.rawBytes;
  const reordered = Buffer.from(JSON.stringify({
    signed: fixture.rootOne.envelope.signed,
    signatures: fixture.rootOne.envelope.signatures
  }));
  const numericVariant = Buffer.from(
    canonical.toString('utf8').replace('"version":1', '"version":1e0')
  );
  for (const [name, raw] of [
    ['BOM', Buffer.concat([Buffer.from([0xEF, 0xBB, 0xBF]), canonical])],
    ['whitespace', Buffer.concat([canonical, Buffer.from('\n')])],
    ['key-order', reordered],
    ['numeric-representation', numericVariant]
  ]) {
    assert.throws(
      () => parseMetadataDocument(raw, name),
      /exact canonical POUF encoding/
    );
  }
  assert.doesNotThrow(() => parseMetadataDocument(canonical, 'canonical root'));
});

test('coherent metadata and disjoint cross-signed root rotation are accepted', () => {
  const fixture = createUpdateTrustFixture();
  const baseline = verifyUpdateBundle(fixture.createBundle());
  assert.equal(baseline.state.trustedRoot.version, 1);
  assert.equal(baseline.state.trustedRoot.sha256, sha256(fixture.rootOne.rawBytes));
  assert.deepEqual(baseline.state.versions, {
    timestamp: 1,
    snapshot: 1,
    targets: 1,
    androidRelease: 1
  });
  const persisted = [];
  const rotated = verifyUpdateBundle({
    ...fixture.createBundle({ rotatedRoot: true }),
    persistTrustedRoot: state => persisted.push(structuredClone(state))
  });
  assert.equal(rotated.state.trustedRoot.version, 2);
  assert.equal(rotated.state.trustedRoot.sha256, sha256(fixture.rootTwo.rawBytes));
  assert.equal(persisted.length, 1);
  assert.deepEqual(persisted[0].trustedRoot, rotated.state.trustedRoot);
});

test('startup rejects same-version different-keyset root against persisted raw binding', () => {
  const fixture = createUpdateTrustFixture();
  const original = fixture.rootOne.envelope.signed;
  const removedKey = fixture.keys['root-c'].keyid;
  const attackerSigned = {
    ...original,
    keys: Object.fromEntries(
      Object.entries(original.keys).filter(([keyid]) => keyid !== removedKey)
    ),
    roles: {
      ...original.roles,
      root: {
        keyids: [
          fixture.keys['root-a'].keyid,
          fixture.keys['root-b'].keyid
        ],
        threshold: 2
      }
    }
  };
  const attackerRoot = signedDocument(
    attackerSigned,
    [fixture.keys['root-a'], fixture.keys['root-b']]
  );
  const bundle = fixture.createBundle();
  bundle.trustedRoot = attackerRoot;
  assert.equal(attackerRoot.envelope.signed.version, 1);
  assert.notEqual(sha256(attackerRoot.rawBytes), bundle.trustedState.trustedRoot.sha256);
  assert.throws(
    () => verifyUpdateBundle(bundle),
    /startup trusted root.*persisted version and raw SHA-256/
  );
});

test('root rotation independently requires old and new thresholds', () => {
  const fixture = createUpdateTrustFixture();
  const signatures = fixture.rootTwo.envelope.signatures;
  const oldOnly = metadataDocumentFromEnvelope({
    ...fixture.rootTwo.envelope,
    signatures: signatures.slice(0, 2)
  });
  const newOnly = metadataDocumentFromEnvelope({
    ...fixture.rootTwo.envelope,
    signatures: signatures.slice(2)
  });
  const oldOnlyBundle = fixture.createBundle({ rotatedRoot: true });
  oldOnlyBundle.candidateRoots = [oldOnly];
  assert.throws(
    () => verifyUpdateBundle(oldOnlyBundle),
    /new root new-root threshold.*not met/
  );
  const newOnlyBundle = fixture.createBundle({ rotatedRoot: true });
  newOnlyBundle.candidateRoots = [newOnly];
  assert.throws(
    () => verifyUpdateBundle(newOnlyBundle),
    /new root old-root threshold.*not met/
  );
});

test('root state is atomically persisted before a later online-role failure', async () => {
  const fixture = createUpdateTrustFixture();
  const sandbox = await mkdtemp(path.join(tmpdir(), 'deep-p02-root-state-'));
  try {
    const statePath = path.join(sandbox, 'state.json');
    const bundle = fixture.createBundle({
      rotatedRoot: true,
      timestampSigner: 'timestamp-old'
    });
    writeTrustedStateAtomic(statePath, bundle.trustedState);
    assert.throws(
      () => verifyUpdateBundle({
        ...bundle,
        persistTrustedRoot: state => writeTrustedStateAtomic(statePath, state)
      }),
      /unknown signer/
    );
    const persisted = JSON.parse(await readFile(statePath, 'utf8'));
    assert.deepEqual(persisted.trustedRoot, {
      version: 2,
      sha256: sha256(fixture.rootTwo.rawBytes)
    });
    assert.deepEqual(persisted.versions, bundle.trustedState.versions);
    assert.equal(
      (await readFile(statePath, 'utf8')).endsWith('\n'),
      true,
      'atomic state must be a complete JSON document'
    );
  } finally {
    await rm(sandbox, { recursive: true, force: true });
  }
});

test('rollback and freeze matrix rejects every metadata role', () => {
  const fixture = createUpdateTrustFixture();
  const invalidExpiry = fixture.createBundle({ timestampExpiry: '2030-02-31T00:00:00Z' });
  assert.throws(() => verifyUpdateBundle(invalidExpiry), /expiry is invalid/);
  assert.throws(
    () => verifyUpdateBundle(fixture.createBundle({
      timestampExpiry: '2029-12-31T23:59:59Z'
    })),
    /freeze|expired/i
  );
  for (const [role, expected] of [
    ['timestamp', /timestamp rollback/],
    ['snapshot', /timestamp snapshot reference rollback|snapshot rollback/],
    ['targets', /targets rollback/],
    ['androidRelease', /android-release targets rollback/]
  ]) {
    const bundle = fixture.createBundle();
    bundle.trustedState.versions[role] = 2;
    assert.throws(() => verifyUpdateBundle(bundle), expected, role);
  }
});

test('every timestamp/snapshot raw hash and length parent binding fails closed', () => {
  const fixture = createUpdateTrustFixture();
  for (const field of ['hash', 'length']) {
    assert.throws(
      () => verifyUpdateBundle(fixture.createBundle({
        timestampSnapshotOverride: mutateMeta(fixture.createBundle().snapshot, field)
      })),
      /snapshot .*parent metadata.*mix-and-match/i,
      `timestamp -> snapshot ${field}`
    );
    assert.throws(
      () => verifyUpdateBundle(fixture.createBundle({
        snapshotOverrides: {
          'targets.json': mutateMeta(fixture.targets, field)
        }
      })),
      /targets .*parent metadata.*mix-and-match/i,
      `snapshot -> targets ${field}`
    );
    assert.throws(
      () => verifyUpdateBundle(fixture.createBundle({
        snapshotOverrides: {
          'android-release.json': mutateMeta(fixture.delegatedTargets, field)
        }
      })),
      /android-release targets .*parent metadata.*mix-and-match/i,
      `snapshot -> delegated ${field}`
    );
  }
});

test('delegation rejects unauthorized paths and unknown delegated signer', () => {
  const fixture = createUpdateTrustFixture();
  const delegatedSigned = fixture.delegatedTargets.envelope.signed;
  const unauthorized = signedDocument({
    ...delegatedSigned,
    targets: {
      ...delegatedSigned.targets,
      'windows/unauthorized.msix': delegatedSigned.targets[fixture.apkPath]
    }
  }, [fixture.keys['android-a'], fixture.keys['android-b']]);
  assert.throws(
    () => verifyUpdateBundle(fixture.createBundle({ delegatedDocument: unauthorized })),
    /delegated target path is unauthorized/
  );
  const unknownSigner = signedDocument(
    delegatedSigned,
    [fixture.keys.unknown]
  );
  assert.throws(
    () => verifyUpdateBundle(fixture.createBundle({ delegatedDocument: unknownSigner })),
    /android-release targets contains an unknown signer/
  );
});

test('lost timestamp key drill accepts replacement and rejects revoked signer', () => {
  const fixture = createUpdateTrustFixture();
  assert.equal(
    verifyUpdateBundle(fixture.createBundle({ rotatedRoot: true }))
      .state.trustedRoot.version,
    2
  );
  assert.throws(
    () => verifyUpdateBundle(fixture.createBundle({
      rotatedRoot: true,
      timestampSigner: 'timestamp-old'
    })),
    /unknown signer/i
  );
});

test('offline Android verification binds bytes, evidence and exact apksigner argv/path', async () => {
  const fixture = createUpdateTrustFixture();
  const verifiedBundle = verifyUpdateBundle(fixture.createBundle());
  const sandbox = await mkdtemp(path.join(tmpdir(), 'deep-p02-apksigner-'));
  try {
    const apkFile = path.join(sandbox, 'fixture.apk');
    await writeFile(apkFile, fixture.apkBytes);
    const canonicalApk = await realpath(apkFile);
    const apkSigner = await writeFakeApkSigner(
      sandbox,
      'fixture-apksigner',
      canonicalApk,
      fixture.packageSignerSha256
    );
    const result = verifyOfflineAndroidArtifact({
      verifiedBundle,
      apkPath: fixture.apkPath,
      apkFile,
      artifactFiles: {
        [fixture.sbomPath]: fixture.sbomBytes,
        [fixture.provenancePath]: fixture.provenanceBytes
      },
      apkSignerPath: apkSigner.filePath,
      apkSignerSha256: apkSigner.sha256
    });
    assert.equal(result.status, 'passed');
    assert.equal(result.apkSignerToolSha256, apkSigner.sha256);

    assert.throws(
      () => runTrustedApkSigner(
        apkSigner.filePath,
        canonicalApk,
        apkSigner.sha256,
        ['verify', '--print-certs', canonicalApk]
      ),
      /apksigner rejected/
    );
    const wrongApk = path.join(sandbox, 'wrong.apk');
    await writeFile(wrongApk, fixture.apkBytes);
    const canonicalWrongApk = await realpath(wrongApk);
    assert.throws(
      () => runTrustedApkSigner(
        apkSigner.filePath,
        canonicalWrongApk,
        apkSigner.sha256,
        ['verify', '--verbose', '--print-certs', canonicalWrongApk]
      ),
      /apksigner rejected/
    );
    assert.throws(() => verifyOfflineAndroidArtifact({
      verifiedBundle,
      apkPath: fixture.apkPath,
      apkFile,
      artifactFiles: {
        [fixture.sbomPath]: fixture.sbomBytes,
        [fixture.provenancePath]: fixture.provenanceBytes
      },
      apkSignerPath: apkSigner.filePath,
      apkSignerSha256: '0'.repeat(64)
    }), /trusted tool policy/);
  } finally {
    await rm(sandbox, { recursive: true, force: true });
  }
});

test('SBOM, provenance, APK hash and package signer mutations reject', async () => {
  const fixture = createUpdateTrustFixture();
  const verifiedBundle = verifyUpdateBundle(fixture.createBundle());
  const sandbox = await mkdtemp(path.join(tmpdir(), 'deep-p02-artifact-'));
  try {
    const apkFile = path.join(sandbox, 'fixture.apk');
    await writeFile(apkFile, fixture.apkBytes);
    const canonicalApk = await realpath(apkFile);
    const goodSigner = await writeFakeApkSigner(
      sandbox,
      'good-apksigner',
      canonicalApk,
      fixture.packageSignerSha256
    );
    const wrongSigner = await writeFakeApkSigner(
      sandbox,
      'wrong-apksigner',
      canonicalApk,
      'f'.repeat(64)
    );
    const tamperedSbom = Buffer.from(fixture.sbomBytes);
    tamperedSbom[0] ^= 1;
    assert.throws(() => verifyOfflineAndroidArtifact({
      verifiedBundle,
      apkPath: fixture.apkPath,
      apkFile,
      artifactFiles: {
        [fixture.sbomPath]: tamperedSbom,
        [fixture.provenancePath]: fixture.provenanceBytes
      },
      apkSignerPath: goodSigner.filePath,
      apkSignerSha256: goodSigner.sha256
    }), /SHA-256 mismatch/);
    assert.throws(() => verifyOfflineAndroidArtifact({
      verifiedBundle,
      apkPath: fixture.apkPath,
      apkFile,
      artifactFiles: {
        [fixture.sbomPath]: fixture.sbomBytes,
        [fixture.provenancePath]: fixture.provenanceBytes
      },
      apkSignerPath: wrongSigner.filePath,
      apkSignerSha256: wrongSigner.sha256
    }), /package signer/);
    await writeFile(apkFile, Buffer.concat([fixture.apkBytes, Buffer.from('tampered')]));
    assert.throws(() => verifyOfflineAndroidArtifact({
      verifiedBundle,
      apkPath: fixture.apkPath,
      apkFile,
      artifactFiles: {
        [fixture.sbomPath]: fixture.sbomBytes,
        [fixture.provenancePath]: fixture.provenanceBytes
      },
      apkSignerPath: goodSigner.filePath,
      apkSignerSha256: goodSigner.sha256
    }), /length mismatch|SHA-256 mismatch/);
  } finally {
    await rm(sandbox, { recursive: true, force: true });
  }
});

test('apksigner parser rejects missing or ambiguous signer sets', () => {
  const signer = sha256(Buffer.from('signer'));
  assert.deepEqual(parseApkSignerDigests(
    `Signer #1 certificate SHA-256 digest: ${signer.toUpperCase()}`
  ), [signer]);
  assert.throws(() => parseApkSignerDigests('Verified'), /exactly one/);
  assert.throws(() => parseApkSignerDigests(
    `Signer #1 certificate SHA-256 digest: ${signer}\n` +
    `Signer #2 certificate SHA-256 digest: ${'f'.repeat(64)}`
  ), /exactly one/);
});

test('contract runner archives exact canonical public metadata and complete summaries', async () => {
  const artifactDir = await mkdtemp(path.join(tmpdir(), 'deep-p02-evidence-'));
  try {
    const summary = runUpdateTrustContracts({ artifactDir });
    assert.equal(summary.status, 'passed');
    assert.equal(summary.negativeCaseCount, 22);
    assert.equal(summary.productionKeysPresent, false);
    assert.equal(summary.privateTestKeyMaterialArchived, false);
    const rootBytes = await readFile(
      path.join(artifactDir, 'public-test-metadata', '1.root.json')
    );
    const publicRoot = parseMetadataDocument(rootBytes, 'public root');
    assert.ok(publicRoot.envelope.signed.keys);
    assert.equal(rootBytes.includes(Buffer.from('private')), false);
    const negatives = JSON.parse(await readFile(
      path.join(artifactDir, 'negative-scenarios.json'),
      'utf8'
    ));
    assert.equal(negatives.cases.length, 22);
    assert.ok(negatives.cases.every(item => item.status === 'rejected-as-required'));
  } finally {
    await rm(artifactDir, { recursive: true, force: true });
  }
});
