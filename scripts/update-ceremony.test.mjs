import assert from 'node:assert/strict';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {
  createDelegatedReleaseRequest,
  evaluateProductionActivation,
  runUpdateCeremonyDryRun,
  validateDelegatedReleaseRequest,
  verifyByteIdenticalTrees
} from './update-ceremony.mjs';

async function sandbox() {
  return mkdtemp(path.join(tmpdir(), 'deep-p02c-ceremony-'));
}

async function walk(root, relative = '') {
  const output = [];
  for (const entry of await readdir(path.join(root, relative), { withFileTypes: true })) {
    const child = relative ? `${relative}/${entry.name}` : entry.name;
    if (entry.isDirectory()) output.push(...await walk(root, child));
    else output.push(child);
  }
  return output.sort();
}

test('production activation remains blocked without named independent custodians and production HSM evidence', () => {
  const status = evaluateProductionActivation({
    accountableHuman: 'Mr. X',
    namedIndependentCustodians: [],
    productionHsmEvidence: null,
    publicationAuthorization: null,
    reproducibleBuildEvidence: null
  });
  assert.equal(status.activationStatus, 'BLOCKED');
  assert.equal(status.activationRun, 'NOT-RUN');
  assert.equal(status.accountableHuman, 'Mr. X');
  assert.equal(status.productionHsmVerified, false);
  assert.equal(status.independentCustodyVerified, false);
  assert.ok(status.blockers.length >= 4);
});

test('delegated online release request is canonical public data and rejects key material or extra authority', () => {
  const request = createDelegatedReleaseRequest({
    requestId: 'test-release-request-0001',
    sourceCommit: '11'.repeat(20),
    programRevisionSha256: '22'.repeat(32),
    artifactPath: 'android/network.xpoint.deep-test.apk',
    artifactBytes: Buffer.from('test-only APK descriptor\n'),
    sbomPath: 'sbom/network.xpoint.deep-test.cdx.json',
    sbomBytes: Buffer.from('{"bomFormat":"CycloneDX"}\n'),
    provenancePath: 'provenance/network.xpoint.deep-test.json',
    provenanceBytes: Buffer.from('{"schema":"deep.test-build-evidence.v1"}\n')
  });
  assert.equal(validateDelegatedReleaseRequest(request).testOnly, true);
  assert.equal(request.productionAuthorized, false);
  assert.equal(request.requestBoundary, 'public-hashes-only');
  assert.equal(JSON.stringify(request).includes('private'), false);

  for (const mutate of [
    value => { value.privateKey = 'forbidden'; },
    value => { value.seedPhrase = 'forbidden'; },
    value => { value.productionAuthorized = true; },
    value => { value.targets[0].sha256 = '00'.repeat(32); },
    value => { value.unreviewedAuthority = true; }
  ]) {
    const candidate = structuredClone(request);
    mutate(candidate);
    assert.throws(() => validateDelegatedReleaseRequest(candidate));
  }
});

test('dry-run emits byte-identical content-addressed mirrors and offline bundle compatible with P02B', async () => {
  const root = await sandbox();
  try {
    const result = await runUpdateCeremonyDryRun({ outputRoot: root });
    assert.equal(result.summary.schema, 'deep.update-ceremony.dry-run.v1');
    assert.equal(result.summary.testOnly, true);
    assert.equal(result.summary.activationStatus, 'BLOCKED');
    assert.equal(result.summary.activationRun, 'NOT-RUN');
    assert.equal(result.summary.productionPublication, 'NOT-RUN');
    assert.equal(result.summary.productionHsmVerified, false);
    assert.equal(result.summary.independentCustodyVerified, false);
    assert.equal(result.summary.reproducibleBuildVerified, false);
    assert.equal(result.summary.p02bCompatibility, 'PASSED');

    const mirrorResult = await verifyByteIdenticalTrees(
      path.join(root, 'mirror-a'),
      path.join(root, 'mirror-b')
    );
    const offlineResult = await verifyByteIdenticalTrees(
      path.join(root, 'mirror-a'),
      path.join(root, 'offline-bundle')
    );
    assert.equal(mirrorResult.status, 'byte-identical');
    assert.equal(offlineResult.status, 'byte-identical');
    assert.ok(mirrorResult.files.every(file => (
      /^metadata\/sha256\/[0-9a-f]{64}\.json$/.test(file.path)
      || /^targets\/sha256\/[0-9a-f]{64}\/[A-Za-z0-9._-]+$/.test(file.path)
      || file.path === 'release-index.json'
    )));

    const files = await walk(root);
    assert.ok(files.length > 10);
    assert.ok(files.every(file => !/(?:private|secret|seed|pkcs8)/i.test(file)));
    const publicBytes = Buffer.concat(
      await Promise.all(files.map(file => readFile(path.join(root, ...file.split('/')))))
    ).toString('utf8');
    assert.equal(/privateKey|seedPhrase|BEGIN PRIVATE KEY/i.test(publicBytes), false);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('dry-run records required rotation, loss, compromise, rollback and freeze drills', async () => {
  const root = await sandbox();
  try {
    const { summary, drills } = await runUpdateCeremonyDryRun({ outputRoot: root });
    assert.equal(summary.dryRunStatus, 'PASSED');
    assert.deepEqual(drills, {
      rootRotation: 'PASSED',
      lostOnlineKey: 'PASSED',
      mirrorCompromise: 'REJECTED-AS-REQUIRED',
      rollback: 'REJECTED-AS-REQUIRED',
      freeze: 'REJECTED-AS-REQUIRED'
    });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
