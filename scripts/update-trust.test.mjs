import assert from 'node:assert/strict';
import {
  chmod,
  copyFile,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  symlink,
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

function fakeVerifierArtifactBytes({
  signerDigest,
  apkSha256,
  behavior = 'normal',
  sourcePath
}) {
  return Buffer.from([
    "import { appendFileSync, readFileSync, writeFileSync } from 'node:fs';",
    "import { createHash } from 'node:crypto';",
    "import { fileURLToPath } from 'node:url';",
    "const artifact = fileURLToPath(import.meta.url);",
    "const args = process.argv.slice(2);",
    "const snapshot = args[6];",
    "const expected = ['-cp', artifact, 'com.android.apksigner.ApkSignerTool',",
    "  'verify', '--verbose', '--print-certs', snapshot];",
    "if (args.length !== expected.length || args.some((value, index) => value !== expected[index])) process.exit(41);",
    "if (!snapshot || !snapshot.endsWith('artifact.apk')) process.exit(42);",
    `const expectedHash = ${JSON.stringify(apkSha256)};`,
    "const digest = value => createHash('sha256').update(value).digest('hex');",
    "if (digest(readFileSync(snapshot)) !== expectedHash) process.exit(43);",
    behavior === 'snapshot-mutate'
      ? "appendFileSync(snapshot, Buffer.from('mutated'));"
      : '',
    behavior === 'source-aba'
      ? [
          `const source = ${JSON.stringify(sourcePath)};`,
          "const original = readFileSync(source);",
          "writeFileSync(source, Buffer.from('temporary source swap'));",
          "writeFileSync(source, original);"
        ].join('\n')
      : '',
    `console.log('Signer #1 certificate SHA-256 digest: ${signerDigest}');`,
    ''
  ].join('\n'), 'utf8');
}

async function writePinnedFixtureVerifier(sandbox, name, options) {
  const artifactPath = path.join(sandbox, `${name}.mjs`);
  const artifactBytes = fakeVerifierArtifactBytes(options);
  await writeFile(artifactPath, artifactBytes);
  const runtimeRootPath = path.join(sandbox, '.fixture-runtime');
  await mkdir(runtimeRootPath, { recursive: true, mode: 0o700 });
  const runtimeName = process.platform === 'win32' ? 'node.exe' : 'node';
  const runtimePath = path.join(runtimeRootPath, runtimeName);
  try {
    await readFile(runtimePath);
  } catch {
    await copyFile(process.execPath, runtimePath);
    if (process.platform !== 'win32') await chmod(runtimePath, 0o700);
  }
  const runtimeBytes = await readFile(runtimePath);
  const runtimeManifestPath = path.join(sandbox, '.fixture-runtime-manifest.json');
  const runtimeManifestBytes = Buffer.from(`${JSON.stringify({
    schema: 'deep.apk-verifier-runtime-tree.v1',
    entrypoint: runtimeName,
    files: [{
      path: runtimeName,
      length: runtimeBytes.length,
      sha256: sha256(runtimeBytes)
    }]
  })}\n`, 'utf8');
  await writeFile(runtimeManifestPath, runtimeManifestBytes);
  return {
    verifierRuntimePath: await realpath(runtimePath),
    verifierRuntimeSha256: sha256(runtimeBytes),
    verifierRuntimeRootPath: await realpath(runtimeRootPath),
    verifierRuntimeManifestPath: await realpath(runtimeManifestPath),
    verifierRuntimeManifestSha256: sha256(runtimeManifestBytes),
    verifierArtifactPath: await realpath(artifactPath),
    verifierArtifactSha256: sha256(artifactBytes),
    verifierProfile: 'node-test-fixture-v1'
  };
}

function verifierOptions(tool, verificationTempRoot) {
  return { ...tool, verificationTempRoot };
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

test('offline Android verification pins runtime/artifact and fixed snapshot argv', async () => {
  const fixture = createUpdateTrustFixture();
  const verifiedBundle = verifyUpdateBundle(fixture.createBundle());
  const sandbox = await mkdtemp(path.join(tmpdir(), 'deep-p02-apksigner-'));
  try {
    const apkFile = path.join(sandbox, 'fixture.apk');
    await writeFile(apkFile, fixture.apkBytes);
    const tempRoot = path.join(sandbox, 'private-temp');
    await mkdir(tempRoot, { mode: 0o700 });
    const verifier = await writePinnedFixtureVerifier(sandbox, 'fixture-verifier', {
      signerDigest: fixture.packageSignerSha256,
      apkSha256: sha256(fixture.apkBytes)
    });
    const result = verifyOfflineAndroidArtifact({
      verifiedBundle,
      apkPath: fixture.apkPath,
      apkFile,
      artifactFiles: {
        [fixture.sbomPath]: fixture.sbomBytes,
        [fixture.provenancePath]: fixture.provenanceBytes
      },
      ...verifierOptions(verifier, tempRoot)
    });
    assert.equal(result.status, 'passed');
    assert.equal(result.verifierRuntimeSha256, verifier.verifierRuntimeSha256);
    assert.equal(result.verifierArtifactSha256, verifier.verifierArtifactSha256);

    assert.throws(() => verifyOfflineAndroidArtifact({
      verifiedBundle,
      apkPath: fixture.apkPath,
      apkFile,
      artifactFiles: {
        [fixture.sbomPath]: fixture.sbomBytes,
        [fixture.provenancePath]: fixture.provenanceBytes
      },
      ...verifierOptions({
        ...verifier,
        verifierRuntimeSha256: '0'.repeat(64)
      }, tempRoot)
    }), /trusted tool policy/);
    assert.throws(() => verifyOfflineAndroidArtifact({
      verifiedBundle,
      apkPath: fixture.apkPath,
      apkFile,
      artifactFiles: {
        [fixture.sbomPath]: fixture.sbomBytes,
        [fixture.provenancePath]: fixture.provenanceBytes
      },
      ...verifierOptions({
        ...verifier,
        verifierArtifactSha256: '0'.repeat(64)
      }, tempRoot)
    }), /trusted tool policy/);
  } finally {
    await rm(sandbox, { recursive: true, force: true });
  }
});

test('offline verifier resists ambient launch, source ABA, closure and temp attacks', async t => {
  const fixture = createUpdateTrustFixture();
  const verifiedBundle = verifyUpdateBundle(fixture.createBundle());
  const sandbox = await mkdtemp(path.join(tmpdir(), 'deep-p02-adversarial-'));
  const originalComSpec = process.env.ComSpec;
  const originalPath = process.env.PATH;
  try {
    const apkFile = path.join(sandbox, 'source & argument-like --print-certs.apk');
    await writeFile(apkFile, fixture.apkBytes);
    const tempRoot = path.join(sandbox, 'private-temp');
    await mkdir(tempRoot, { mode: 0o700 });
    const base = {
      verifiedBundle,
      apkPath: fixture.apkPath,
      apkFile,
      artifactFiles: {
        [fixture.sbomPath]: fixture.sbomBytes,
        [fixture.provenancePath]: fixture.provenanceBytes
      }
    };
    const normal = await writePinnedFixtureVerifier(sandbox, 'normal-verifier', {
      signerDigest: fixture.packageSignerSha256,
      apkSha256: sha256(fixture.apkBytes)
    });

    process.env.ComSpec = path.join(sandbox, 'malicious-comspec.exe');
    process.env.PATH = path.join(sandbox, 'malicious-path');
    assert.equal(verifyOfflineAndroidArtifact({
      ...base,
      ...verifierOptions(normal, tempRoot)
    }).status, 'passed');

    const rogueRuntimeDirectory = path.join(normal.verifierRuntimeRootPath, 'lib');
    await mkdir(rogueRuntimeDirectory);
    await writeFile(path.join(rogueRuntimeDirectory, 'unmeasured-runtime-module.bin'), 'rogue');
    assert.throws(() => verifyOfflineAndroidArtifact({
      ...base,
      ...verifierOptions(normal, tempRoot)
    }), /runtime tree does not match trusted manifest/);
    await rm(rogueRuntimeDirectory, { recursive: true, force: true });

    const delimiterVerifier = await writePinnedFixtureVerifier(
      sandbox,
      `classpath${path.delimiter}injection`,
      {
        signerDigest: fixture.packageSignerSha256,
        apkSha256: sha256(fixture.apkBytes)
      }
    );
    assert.throws(() => verifyOfflineAndroidArtifact({
      ...base,
      ...verifierOptions(delimiterVerifier, tempRoot)
    }), /artifact path contains Java classpath syntax/);

    const aba = await writePinnedFixtureVerifier(sandbox, 'source-aba-verifier', {
      signerDigest: fixture.packageSignerSha256,
      apkSha256: sha256(fixture.apkBytes),
      behavior: 'source-aba',
      sourcePath: apkFile
    });
    assert.equal(verifyOfflineAndroidArtifact({
      ...base,
      ...verifierOptions(aba, tempRoot)
    }).status, 'passed');
    assert.equal(sha256(await readFile(apkFile)), sha256(fixture.apkBytes));

    const snapshotMutator = await writePinnedFixtureVerifier(sandbox, 'snapshot-mutator', {
      signerDigest: fixture.packageSignerSha256,
      apkSha256: sha256(fixture.apkBytes),
      behavior: 'snapshot-mutate'
    });
    assert.throws(() => verifyOfflineAndroidArtifact({
      ...base,
      ...verifierOptions(snapshotMutator, tempRoot)
    }), /snapshot changed/);

    await writeFile(normal.verifierArtifactPath, Buffer.from(
      (await readFile(normal.verifierArtifactPath, 'utf8'))
        .replace(fixture.packageSignerSha256, 'f'.repeat(64)),
      'utf8'
    ));
    assert.throws(() => verifyOfflineAndroidArtifact({
      ...base,
      ...verifierOptions(normal, tempRoot)
    }), /artifact does not match trusted tool policy/);

    const copiedRuntime = path.join(sandbox, path.basename(process.execPath));
    await copyFile(process.execPath, copiedRuntime);
    const copiedRuntimeHash = sha256(await readFile(copiedRuntime));
    await writeFile(copiedRuntime, Buffer.from('replaced runtime'));
    const freshArtifact = await writePinnedFixtureVerifier(sandbox, 'fresh-verifier', {
      signerDigest: fixture.packageSignerSha256,
      apkSha256: sha256(fixture.apkBytes)
    });
    assert.throws(() => verifyOfflineAndroidArtifact({
      ...base,
      ...verifierOptions({
        ...freshArtifact,
        verifierRuntimePath: copiedRuntime,
        verifierRuntimeSha256: copiedRuntimeHash
      }, tempRoot)
    }), /runtime does not match trusted tool policy/);

    const linkRoot = path.join(sandbox, 'linked-temp');
    try {
      await symlink(tempRoot, linkRoot, process.platform === 'win32' ? 'junction' : 'dir');
      assert.throws(() => verifyOfflineAndroidArtifact({
        ...base,
        ...verifierOptions(freshArtifact, linkRoot)
      }), /temp root.*(?:non-symlink|canonical)/);
    } catch (error) {
      if (error?.code === 'EPERM') t.diagnostic('symlink privilege unavailable on this host');
      else throw error;
    }
  } finally {
    if (originalComSpec === undefined) delete process.env.ComSpec;
    else process.env.ComSpec = originalComSpec;
    if (originalPath === undefined) delete process.env.PATH;
    else process.env.PATH = originalPath;
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
    const tempRoot = path.join(sandbox, 'private-temp');
    await mkdir(tempRoot, { mode: 0o700 });
    const goodSigner = await writePinnedFixtureVerifier(sandbox, 'good-verifier', {
      signerDigest: fixture.packageSignerSha256,
      apkSha256: sha256(fixture.apkBytes)
    });
    const wrongSigner = await writePinnedFixtureVerifier(sandbox, 'wrong-verifier', {
      signerDigest: 'f'.repeat(64),
      apkSha256: sha256(fixture.apkBytes)
    });
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
      ...verifierOptions(goodSigner, tempRoot)
    }), /SHA-256 mismatch/);
    assert.throws(() => verifyOfflineAndroidArtifact({
      verifiedBundle,
      apkPath: fixture.apkPath,
      apkFile,
      artifactFiles: {
        [fixture.sbomPath]: fixture.sbomBytes,
        [fixture.provenancePath]: fixture.provenanceBytes
      },
      ...verifierOptions(wrongSigner, tempRoot)
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
      ...verifierOptions(goodSigner, tempRoot)
    }), /length does not match|length mismatch|SHA-256 mismatch/);
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
