import assert from 'node:assert/strict';
import { chmod, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {
  canonicalJson,
  parseStrictJson,
  parseApkSignerDigests,
  sha256,
  verifyOfflineAndroidArtifact,
  verifyUpdateBundle
} from './update-trust.mjs';
import {
  createUpdateTrustFixture,
  runUpdateTrustContracts
} from './update-trust-contracts.mjs';

test('canonical JSON is stable and rejects ambiguous numeric values', () => {
  assert.equal(
    canonicalJson({ z: [3, { b: true, a: 'x' }], a: 1 }),
    '{"a":1,"z":[3,{"a":"x","b":true}]}'
  );
  assert.throws(() => canonicalJson({ value: 1.5 }), /safe integers/);
  assert.throws(() => canonicalJson({ value: Number.MAX_SAFE_INTEGER + 1 }), /safe integers/);
  assert.deepEqual(parseStrictJson('\uFEFF{"a":1}', 'fixture'), { a: 1 });
  assert.throws(
    () => parseStrictJson('{"signed":{"version":1,"version":2}}', 'fixture'),
    /duplicate object key/
  );
  assert.throws(() => parseStrictJson('{"a":1} trailing', 'fixture'), /trailing content/);
});

test('coherent metadata and sequential cross-signed root rotation are accepted', () => {
  const fixture = createUpdateTrustFixture();
  const baseline = verifyUpdateBundle(fixture.createBundle());
  assert.deepEqual(baseline.state, {
    root: 1,
    timestamp: 1,
    snapshot: 1,
    targets: 1,
    androidRelease: 1
  });
  const rotated = verifyUpdateBundle(fixture.createBundle({ rotatedRoot: true }));
  assert.equal(rotated.state.root, 2);
});

test('rollback and freeze metadata are rejected', () => {
  const fixture = createUpdateTrustFixture();
  const invalidExpiry = fixture.createBundle({ timestampExpiry: '2030-02-31T00:00:00Z' });
  assert.throws(() => verifyUpdateBundle(invalidExpiry), /expiry is invalid/);
  const rollback = fixture.createBundle();
  rollback.trustedVersions = { timestamp: 2 };
  assert.throws(() => verifyUpdateBundle(rollback), /rollback/i);
  assert.throws(
    () => verifyUpdateBundle(fixture.createBundle({
      timestampExpiry: '2029-12-31T23:59:59Z'
    })),
    /freeze|expired/i
  );
});

test('mix-and-match snapshot and unknown online signer are rejected', () => {
  const fixture = createUpdateTrustFixture();
  const coherent = fixture.createBundle();
  const mixed = fixture.createBundle({ snapshotVersion: 2 });
  mixed.timestamp = coherent.timestamp;
  assert.throws(() => verifyUpdateBundle(mixed), /mix-and-match|hash/i);
  assert.throws(
    () => verifyUpdateBundle(fixture.createBundle({ timestampSigner: 'unknown' })),
    /unknown signer/i
  );
});

test('root rotation requires both old and new thresholds', () => {
  const fixture = createUpdateTrustFixture();
  const staleTrustedFile = fixture.createBundle();
  staleTrustedFile.trustedVersions = { root: 2 };
  assert.throws(() => verifyUpdateBundle(staleTrustedFile), /persisted root state/);
  const bundle = fixture.createBundle({ rotatedRoot: true });
  bundle.candidateRoots = [{
    ...fixture.rootTwo,
    signatures: [fixture.rootTwo.signatures[0]]
  }];
  assert.throws(() => verifyUpdateBundle(bundle), /threshold/i);
});

test('lost timestamp key drill accepts replacement and rejects the revoked key', () => {
  const fixture = createUpdateTrustFixture();
  assert.equal(
    verifyUpdateBundle(fixture.createBundle({ rotatedRoot: true })).state.root,
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

test('offline Android verification binds target bytes, SBOM, provenance and package signer', async () => {
  const fixture = createUpdateTrustFixture();
  const verifiedBundle = verifyUpdateBundle(fixture.createBundle());
  const sandbox = await mkdtemp(path.join(tmpdir(), 'deep-p02-test-'));
  try {
    const apkFile = path.join(sandbox, 'fixture.apk');
    await writeFile(apkFile, fixture.apkBytes);
    const good = verifyOfflineAndroidArtifact({
      verifiedBundle,
      apkPath: fixture.apkPath,
      apkFile,
      artifactFiles: {
        [fixture.sbomPath]: fixture.sbomBytes,
        [fixture.provenancePath]: fixture.provenanceBytes
      },
      apkSignerPath: 'synthetic-test-only',
      runApkSigner: () =>
        `Signer #1 certificate SHA-256 digest: ${fixture.packageSignerSha256}`
    });
    assert.equal(good.status, 'passed');
    assert.equal(good.independentBuilderCount, 2);

    const apkSigner = path.join(
      sandbox,
      process.platform === 'win32' ? 'fixture-apksigner.bat' : 'fixture-apksigner'
    );
    const apkSignerBytes = Buffer.from(
      process.platform === 'win32'
        ? `@echo off\r\necho Signer #1 certificate SHA-256 digest: ${fixture.packageSignerSha256}\r\n`
        : `#!/bin/sh\nprintf '%s\\n' 'Signer #1 certificate SHA-256 digest: ${fixture.packageSignerSha256}'\n`,
      'utf8'
    );
    await writeFile(apkSigner, apkSignerBytes);
    if (process.platform !== 'win32') await chmod(apkSigner, 0o755);
    const realToolInvocation = verifyOfflineAndroidArtifact({
      verifiedBundle,
      apkPath: fixture.apkPath,
      apkFile,
      artifactFiles: {
        [fixture.sbomPath]: fixture.sbomBytes,
        [fixture.provenancePath]: fixture.provenanceBytes
      },
      apkSignerPath: apkSigner,
      apkSignerSha256: sha256(apkSignerBytes)
    });
    assert.equal(realToolInvocation.apkSignerToolSha256, sha256(apkSignerBytes));
    assert.throws(() => verifyOfflineAndroidArtifact({
      verifiedBundle,
      apkPath: fixture.apkPath,
      apkFile,
      artifactFiles: {
        [fixture.sbomPath]: fixture.sbomBytes,
        [fixture.provenancePath]: fixture.provenanceBytes
      },
      apkSignerPath: apkSigner,
      apkSignerSha256: '0'.repeat(64)
    }), /trusted tool policy/);

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
      apkSignerPath: 'synthetic-test-only',
      runApkSigner: () =>
        `Signer #1 certificate SHA-256 digest: ${fixture.packageSignerSha256}`
    }), /SHA-256 mismatch/);

    assert.throws(() => verifyOfflineAndroidArtifact({
      verifiedBundle,
      apkPath: fixture.apkPath,
      apkFile,
      artifactFiles: {
        [fixture.sbomPath]: fixture.sbomBytes,
        [fixture.provenancePath]: fixture.provenanceBytes
      },
      apkSignerPath: 'synthetic-test-only',
      runApkSigner: () => `Signer #1 certificate SHA-256 digest: ${'f'.repeat(64)}`
    }), /package signer/);
  } finally {
    await rm(sandbox, { recursive: true, force: true });
  }
});

test('apksigner parser rejects no signer and ambiguous signer sets', () => {
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

test('contract runner archives only public metadata and complete P02 summaries', async () => {
  const artifactDir = await mkdtemp(path.join(tmpdir(), 'deep-p02-evidence-'));
  try {
    const summary = runUpdateTrustContracts({ artifactDir });
    assert.equal(summary.status, 'passed');
    assert.equal(summary.productionKeysPresent, false);
    assert.equal(summary.privateTestKeyMaterialArchived, false);
    const publicRoot = JSON.parse(await readFile(
      path.join(artifactDir, 'public-test-metadata', '1.root.json'),
      'utf8'
    ));
    assert.ok(publicRoot.signed.keys);
    assert.equal(
      JSON.stringify(publicRoot).includes('private'),
      false,
      'public fixture metadata must not archive private material'
    );
    const negatives = JSON.parse(await readFile(
      path.join(artifactDir, 'negative-scenarios.json'),
      'utf8'
    ));
    assert.deepEqual(
      negatives.cases.map(item => item.name),
      [
        'rollback',
        'freeze',
        'mix-and-match',
        'unknown-signer',
        'apk-package-signer-mismatch'
      ]
    );
  } finally {
    await rm(artifactDir, { recursive: true, force: true });
  }
});
