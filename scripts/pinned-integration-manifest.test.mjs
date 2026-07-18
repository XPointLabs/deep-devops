import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFileSync, spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { appendFile, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath, pathToFileURL } from 'node:url';
import {
  assertCanonicalGitRepository,
  checkoutPinnedRepositories,
  requireZeroReviewCounts,
  validateDependencyClosure,
  validateDependencyClosureEvidence,
  validateEvidence,
  validateHandoff,
  validateManifest
} from './pinned-integration-manifest.mjs';

const acceptedRevision = {
  commit: '096b776b0946b8ce8d661312eeb231432e2c80e6',
  sha256: 'ca5ad9f0c9d4dfb509dedcbf8133524c15867fce5534816da21ff86a07057383'
};

function git(repository, args) {
  return execFileSync('git', ['-C', repository, ...args], {
    encoding: 'utf8',
    windowsHide: true
  }).trim();
}

async function writeJson(filePath, value) {
  await mkdir(path.dirname(filePath), { recursive: true });
  await writeFile(filePath, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

async function createRepository(sourceRoot, name) {
  const repository = path.join(sourceRoot, name);
  await mkdir(repository, { recursive: true });
  execFileSync('git', ['init', '-b', 'main', repository], { windowsHide: true, stdio: 'ignore' });
  git(repository, ['config', 'user.name', 'Pinned manifest test']);
  git(repository, ['config', 'user.email', 'pinned-manifest@example.invalid']);
  await writeFile(path.join(repository, 'README.md'), `${name}\n`, 'utf8');
  git(repository, ['add', 'README.md']);
  git(repository, ['commit', '-m', 'fixture']);
  const url = `https://github.com/XPointLabs/${name}.git`;
  git(repository, ['remote', 'add', 'origin', url]);
  return {
    name,
    url,
    branch: 'main',
    sha: git(repository, ['rev-parse', 'HEAD'])
  };
}

async function createFixture(t) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'deep-pinned-manifest-'));
  t.after(async () => {
    const resolved = path.resolve(root);
    if (!resolved.startsWith(path.resolve(os.tmpdir()) + path.sep)) {
      throw new Error(`unsafe fixture cleanup path: ${resolved}`);
    }
    await rm(resolved, { recursive: true, force: true, maxRetries: 3 });
  });
  const sourceRoot = path.join(root, 'sources');
  const devopsRoot = path.join(root, 'devops');
  await mkdir(sourceRoot, { recursive: true });
  await mkdir(path.join(devopsRoot, 'artifacts', 'packages', 'survival-v2.0.0'), { recursive: true });
  const repositories = [
    await createRepository(sourceRoot, 'deep-protocol'),
    await createRepository(sourceRoot, 'deep-client-maui')
  ];
  const fixture = {
    root,
    sourceRoot,
    devopsRoot,
    repositories,
    manifestPath: path.join(devopsRoot, 'release', 'manifests', 'fixture.json'),
    artifactPath: path.join(devopsRoot, 'release', 'contracts', 'fixture.json')
  };

  await writeJson(path.join(devopsRoot, 'release', 'pinned-program-revision.json'), {
    schemaVersion: '1.0.0',
    program: 'deep-survival-program',
    version: '2.0.0',
    ...acceptedRevision
  });
  await writeJson(path.join(devopsRoot, 'release', 'local-feed-policy.json'), {
    schemaVersion: '1.0.0',
    mode: 'offline-local-only',
    relativePath: 'artifacts/packages/survival-v2.0.0',
    allowNetworkRestore: false,
    allowExternalPublication: false,
    allowedUriSchemes: ['file']
  });
  await writeJson(path.join(devopsRoot, 'release', 'schemas', 'pinned-multi-repo-manifest.schema.json'), {
    $id: 'deep-pinned-multi-repo-manifest/1.0.0'
  });
  await rebuildContracts(fixture);
  return fixture;
}

async function rebuildContracts(fixture, mutate = () => {}) {
  const artifact = {
    schemaVersion: '1.0.0',
    artifactName: 'fixture-compatibility',
    version: '2.0.0',
    programRevision: acceptedRevision,
    requiredRepositories: fixture.repositories.map(({ name, sha }) => ({ name, sha })),
    compatibility: {
      protocolContract: `deep-protocol@${fixture.repositories.find(repository => repository.name === 'deep-protocol').sha}`
    }
  };
  mutate(artifact);
  await writeJson(fixture.artifactPath, artifact);
  const artifactRaw = await readFile(fixture.artifactPath);
  const artifactSha256 = createHash('sha256').update(artifactRaw).digest('hex');
  const manifest = {
    schemaVersion: '1.0.0',
    releaseId: 'fixture-v2.0.0',
    programRevision: acceptedRevision,
    packageFeed: {
      mode: 'offline-local-only',
      relativePath: 'artifacts/packages/survival-v2.0.0',
      allowNetworkRestore: false,
      allowExternalPublication: false
    },
    repositories: fixture.repositories.map(repository => ({
      ...repository,
      contractArtifact: {
        name: artifact.artifactName,
        version: artifact.version,
        relativePath: 'release/contracts/fixture.json',
        sha256: artifactSha256
      },
      programRevision: acceptedRevision,
      evidenceStatus: 'pinned'
    }))
  };
  await writeJson(fixture.manifestPath, manifest);
  return { artifact, manifest };
}

test('validates an exact-SHA manifest and immutable compatibility artifact', async t => {
  const fixture = await createFixture(t);
  const validated = await validateManifest({
    devopsRoot: fixture.devopsRoot,
    manifestPath: fixture.manifestPath
  });
  assert.equal(validated.manifest.repositories.length, 2);
  assert.equal(validated.verifiedArtifacts[0].actualSha256, validated.verifiedArtifacts[0].expectedSha256);
});

test('validates the immutable local-only I01B repository matrix', async () => {
  const validated = await validateManifest({
    manifestPath: path.join(
      path.dirname(fileURLToPath(import.meta.url)),
      '..',
      'release',
      'manifests',
      'survival-v2.0.1-i01b.local.json'
    )
  });
  assert.equal(validated.manifest.releaseId, 'deep-survival-v2.0.1-i01b-local');
  assert.equal(validated.manifest.repositories.length, 13);
  assert.equal(validated.verifiedArtifacts[0].version, '2.0.1-i01b');
});

test('retains the historical pre-carrier W0 manifest as rejected-construction evidence', async () => {
  await assert.rejects(
    validateManifest({
      manifestPath: path.join(
      path.dirname(fileURLToPath(import.meta.url)),
      '..',
      'release',
      'manifests',
      'survival-v2.0.2-w0.local.json'
      )
    }),
    /pre-carrier W0 manifest is superseded/
  );
});

test('validates detached W0 manifest from exact pinned carrier bytes and honest gate status', async () => {
  const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
  const manifestPath = path.join(
    root,
    'release',
    'manifests',
    'survival-v2.0.2-w0.detached.local.json'
  );
  const validated = await validateManifest({ manifestPath });
  assert.equal(validated.manifest.releaseId, 'deep-survival-v2.0.2-w0-detached-local');
  assert.equal(validated.manifest.repositories.length, 13);
  assert.equal(validated.verifiedArtifacts[0].version, '2.0.2-w0');
  assert.equal(
    validated.verifiedArtifacts[0].carrierCommit,
    '7e4e392b72bddf24b262609f8a2994549a08ce20'
  );
  const pins = Object.fromEntries(
    validated.manifest.repositories.map(repository => [repository.name, repository.sha])
  );
  assert.deepEqual({
    'deep-client-shared': pins['deep-client-shared'],
    'deep-client-maui': pins['deep-client-maui'],
    'deep-devops': pins['deep-devops'],
    'deep-protocol': pins['deep-protocol'],
    xnode: pins.xnode
  }, {
    'deep-client-shared': 'fb310d05a4b8bd5450695ab00569deb62aba1ff1',
    'deep-client-maui': '2d1cefd30a1e12b657288bca704aab4b10980dce',
    'deep-devops': '7e4e392b72bddf24b262609f8a2994549a08ce20',
    'deep-protocol': '8484b130a274ca7d8de574e563c83198180d7808',
    xnode: '8b19577ef00f2169116cc08da51e9592089289a9'
  });
  const contract = JSON.parse(await readFile(
    path.join(root, 'release', 'contracts', 'survival-compatibility-v2.0.2-w0.json'),
    'utf8'
  ));
  assert.equal(contract.w0Evidence.metadataProductGate.status, 'EXPECTED-RED');
  assert.equal(contract.w0Evidence.metadataProductGate.unresolvedChecks, 8);
  assert.equal(contract.w0Evidence.productionReadinessClaimed, false);
  assert.equal(contract.w0Evidence.externalPublicationAuthorized, false);
  assert.ok(contract.w0Evidence.packages.every(item => item.reviewStatus === 'GO'));
  const evidence = JSON.parse(await readFile(
    path.join(root, 'release', 'evidence', 'w0-final-manifest.json'),
    'utf8'
  ));
  assert.equal(evidence.manifest.sha256, validated.manifestSha256);
  assert.equal(
    evidence.contract.sha256,
    validated.verifiedArtifacts[0].actualSha256
  );
  assert.equal(evidence.metadataProductGate.status, 'EXPECTED-RED');
  assert.equal(evidence.productionReadinessClaimed, false);
  assert.equal(evidence.selfContainedInCarrierClaimed, false);
  assert.equal(evidence.contract.verification, 'raw-git-blob-from-pinned-carrier');
  assert.deepEqual(Object.values(evidence.workPackages), ['GO', 'GO', 'GO', 'GO', 'GO']);
});

test('validates the detached W1 contract closure and preserves the W2 dependency block', async () => {
  const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
  const validated = await validateManifest({
    manifestPath: path.join(
      root,
      'release',
      'manifests',
      'survival-v2.1.0-w1w2-gate.detached.local.json'
    )
  });
  assert.equal(
    validated.manifest.releaseId,
    'deep-survival-v2.1.0-w1w2-gate-detached-local'
  );
  assert.equal(validated.manifest.repositories.length, 13);
  assert.equal(validated.verifiedArtifacts[0].version, '2.1.0-w1w2-gate');
  assert.equal(
    validated.verifiedArtifacts[0].carrierCommit,
    '524c5796aa868fa3d057fbf7eaa13cfea2e0d19c'
  );
  assert.equal(validated.verifiedProducerArtifacts.length, 0);
});

test('strict W1 producer verification either proves all artifacts or fails closed without its source map', async () => {
  const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
  if (!process.env.DEEP_W1W2_PRODUCER_SOURCE_MAP
      || !existsSync(process.env.DEEP_W1W2_PRODUCER_SOURCE_MAP)) {
    await assert.rejects(
      validateManifest({
        manifestPath: path.join(
          root,
          'release',
          'manifests',
          'survival-v2.1.0-w1w2-gate.detached.local.json'
        ),
        verifyProducerArtifacts: true
      }),
      /producerSourceMapPath/
    );
    return;
  }
  const validated = await validateManifest({
    manifestPath: path.join(
      root,
      'release',
      'manifests',
      'survival-v2.1.0-w1w2-gate.detached.local.json'
    ),
    verifyProducerArtifacts: true,
    producerSourceMapPath: process.env.DEEP_W1W2_PRODUCER_SOURCE_MAP
  });
  assert.equal(validated.verifiedProducerArtifacts.length, 17);
  assert.deepEqual(
    [...new Set(validated.verifiedProducerArtifacts.map(artifact => artifact.workPackage))],
    ['P04', 'P05']
  );
  const evidence = JSON.parse(await readFile(
    path.join(root, 'release', 'evidence', 'w1w2-dependency-closure.json'),
    'utf8'
  ));
  assert.equal(validateDependencyClosureEvidence(evidence, validated), evidence);
  const drifted = structuredClone(evidence);
  drifted.manifest.sha256 = '00'.repeat(32);
  assert.throws(
    () => validateDependencyClosureEvidence(drifted, validated),
    /manifest identity drifted/
  );
});

test('W1/W2 dependency closure rejects authorization inflation and producer tampering', async () => {
  const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
  const contract = JSON.parse(await readFile(
    path.join(
      root,
      'release',
      'contracts',
      'survival-compatibility-v2.1.0-w1w2-gate.json'
    ),
    'utf8'
  ));
  const manifest = JSON.parse(await readFile(
    path.join(
      root,
      'release',
      'manifests',
      'survival-v2.1.0-w1w2-gate.detached.local.json'
    ),
    'utf8'
  ));

  const runtimeAuthorized = structuredClone(contract.dependencyClosure);
  runtimeAuthorized.workPackages.P05.runtimeAuthorized = true;
  await assert.rejects(
    validateDependencyClosure(runtimeAuthorized, manifest),
    /must not authorize runtime activation/
  );

  const falseW2Ready = structuredClone(contract.dependencyClosure);
  falseW2Ready.waves.W2 = 'ready';
  await assert.rejects(
    validateDependencyClosure(falseW2Ready, manifest),
    /wave status is invalid/
  );

  const networkClaim = structuredClone(contract.dependencyClosure);
  networkClaim.execution.networkUsed = true;
  await assert.rejects(
    validateDependencyClosure(networkClaim, manifest),
    /must remain offline\/local-only/
  );

  const approvedP05 = structuredClone(contract.dependencyClosure);
  approvedP05.workPackages.P05.status = 'approved';
  await assert.rejects(
    validateDependencyClosure(approvedP05, manifest),
    /proposed\/not-approved/
  );

  if (process.env.DEEP_W1W2_PRODUCER_SOURCE_MAP
      && existsSync(process.env.DEEP_W1W2_PRODUCER_SOURCE_MAP)) {
    const tamperedArtifact = structuredClone(contract.dependencyClosure);
    tamperedArtifact.workPackages.P04.artifacts[0].sha256 = '00'.repeat(32);
    await assert.rejects(
      validateDependencyClosure(tamperedArtifact, manifest, {
        verifyProducerArtifacts: true,
        producerSourceMapPath: process.env.DEEP_W1W2_PRODUCER_SOURCE_MAP
      }),
      /producer artifact identity mismatch/
    );
  }
});

test('P05 independent-review counts require the complete exact zero shape', () => {
  assert.deepEqual(
    requireZeroReviewCounts({ p0: 0, p1: 0, p2: 0, p3: 0 }, 'P05 counts'),
    { p0: 0, p1: 0, p2: 0, p3: 0 }
  );
  assert.throws(() => requireZeroReviewCounts(undefined, 'P05 counts'), /must be an object/);
  assert.throws(
    () => requireZeroReviewCounts({ p0: 0, p1: 0, p2: 0 }, 'P05 counts'),
    /missing fields/
  );
  assert.throws(
    () => requireZeroReviewCounts({ p0: 0, p1: 0, p2: 0, p3: '0' }, 'P05 counts'),
    /exact integer zero/
  );
});

test('canonical producer Git inspection rejects replace refs and grafts', async t => {
  const fixture = await createFixture(t);
  const repository = path.join(fixture.sourceRoot, 'deep-protocol');
  assert.doesNotThrow(() => assertCanonicalGitRepository(repository, 'fixture producer'));

  await appendFile(path.join(repository, 'README.md'), 'second\n', 'utf8');
  git(repository, ['add', 'README.md']);
  git(repository, ['commit', '-m', 'second fixture']);
  const second = git(repository, ['rev-parse', 'HEAD']);
  const first = git(repository, ['rev-parse', 'HEAD^']);
  git(repository, ['replace', first, second]);
  assert.throws(
    () => assertCanonicalGitRepository(repository, 'fixture producer'),
    /forbidden replace refs/
  );
  git(repository, ['replace', '-d', first]);

  const rawGraftsPath = git(repository, ['rev-parse', '--git-path', 'info/grafts']);
  const graftsPath = path.isAbsolute(rawGraftsPath)
    ? rawGraftsPath
    : path.resolve(repository, rawGraftsPath);
  await mkdir(path.dirname(graftsPath), { recursive: true });
  await writeFile(graftsPath, `${second} ${first}\n`, 'utf8');
  assert.throws(
    () => assertCanonicalGitRepository(repository, 'fixture producer'),
    /forbidden grafts/
  );
  await rm(graftsPath, { force: true });

  const rawAlternatesPath = git(repository, [
    'rev-parse',
    '--git-path',
    'objects/info/alternates'
  ]);
  const alternatesPath = path.isAbsolute(rawAlternatesPath)
    ? rawAlternatesPath
    : path.resolve(repository, rawAlternatesPath);
  await mkdir(path.dirname(alternatesPath), { recursive: true });
  await writeFile(
    alternatesPath,
    `${path.join(fixture.sourceRoot, 'deep-client-maui', '.git', 'objects')}\n`,
    'utf8'
  );
  assert.throws(
    () => assertCanonicalGitRepository(repository, 'fixture producer'),
    /forbidden object alternates/
  );
  await rm(alternatesPath, { force: true });

  const shallowRepository = path.join(fixture.root, 'shallow-producer');
  execFileSync(
    'git',
    ['clone', '--depth', '1', pathToFileURL(repository).href, shallowRepository],
    { windowsHide: true, stdio: 'ignore' }
  );
  assert.throws(
    () => assertCanonicalGitRepository(shallowRepository, 'fixture producer'),
    /complete non-shallow/
  );
});

test('dedicated W1/W2 closure gate fails closed when the producer source map is absent', () => {
  const environment = { ...process.env };
  delete environment.DEEP_W1W2_PRODUCER_SOURCE_MAP;
  const result = spawnSync(
    process.execPath,
    ['scripts/w1w2-dependency-closure-gate.mjs'],
    {
      cwd: path.join(path.dirname(fileURLToPath(import.meta.url)), '..'),
      env: environment,
      encoding: 'utf8',
      windowsHide: true
    }
  );
  assert.notEqual(result.status, 0);
  assert.match(
    `${result.stdout}\n${result.stderr}`,
    /DEEP_W1W2_PRODUCER_SOURCE_MAP is required/
  );
});

test('detached W0 manifest rejects a pre-contract carrier pin', async t => {
  const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
  const source = JSON.parse(await readFile(
    path.join(root, 'release', 'manifests', 'survival-v2.0.2-w0.detached.local.json'),
    'utf8'
  ));
  source.repositories.find(repository => repository.name === 'deep-devops').sha =
    '67cb8113e94708a4597bb98a88e00ad9ba632415';
  const sandbox = await mkdtemp(path.join(os.tmpdir(), 'deep-w0-detached-missing-'));
  t.after(() => rm(sandbox, { recursive: true, force: true }));
  const manifestPath = path.join(sandbox, 'manifest.json');
  await writeJson(manifestPath, source);
  await assert.rejects(
    validateManifest({ manifestPath }),
    /absent from pinned carrier/
  );
});

test('detached W0 manifest rejects a tampered contract digest', async t => {
  const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
  const source = JSON.parse(await readFile(
    path.join(root, 'release', 'manifests', 'survival-v2.0.2-w0.detached.local.json'),
    'utf8'
  ));
  for (const repository of source.repositories) {
    repository.contractArtifact.sha256 = '00'.repeat(32);
  }
  const sandbox = await mkdtemp(path.join(os.tmpdir(), 'deep-w0-detached-tamper-'));
  t.after(() => rm(sandbox, { recursive: true, force: true }));
  const manifestPath = path.join(sandbox, 'manifest.json');
  await writeJson(manifestPath, source);
  await assert.rejects(
    validateManifest({ manifestPath }),
    /contract artifact hash mismatch/
  );
});

test('detached W0 validation ignores a tampered working-tree contract and trusts carrier bytes', async t => {
  const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
  const sandbox = await mkdtemp(path.join(os.tmpdir(), 'deep-w0-detached-worktree-'));
  t.after(() => rm(sandbox, { recursive: true, force: true }));
  const clone = path.join(sandbox, 'devops');
  execFileSync(
    'git',
    ['clone', '--local', '--no-hardlinks', root, clone],
    { windowsHide: true, stdio: 'ignore' }
  );
  await mkdir(path.join(clone, 'artifacts', 'packages', 'survival-v2.0.0'), {
    recursive: true
  });
  await writeFile(
    path.join(clone, 'release', 'contracts', 'survival-compatibility-v2.0.2-w0.json'),
    '{"tamperedWorkingTree":true}\n',
    'utf8'
  );
  const validated = await validateManifest({
    devopsRoot: clone,
    manifestPath: path.join(
      root,
      'release',
      'manifests',
      'survival-v2.0.2-w0.detached.local.json'
    )
  });
  assert.equal(
    validated.verifiedArtifacts[0].actualSha256,
    '340a0467a5108a41676b93f05bf357e76a92405812ccb7b0e8e4700fd6d25b68'
  );
  assert.equal(
    validated.verifiedArtifacts[0].carrierCommit,
    '7e4e392b72bddf24b262609f8a2994549a08ce20'
  );
});

test('rejects a branch-only repository ref', async t => {
  const fixture = await createFixture(t);
  const manifest = JSON.parse(await readFile(fixture.manifestPath, 'utf8'));
  manifest.repositories[0].sha = 'main';
  await writeJson(fixture.manifestPath, manifest);
  await assert.rejects(
    validateManifest({ devopsRoot: fixture.devopsRoot, manifestPath: fixture.manifestPath }),
    /exact 40-hex SHA/
  );
});

test('rejects the wrong accepted program revision', async t => {
  const fixture = await createFixture(t);
  const manifest = JSON.parse(await readFile(fixture.manifestPath, 'utf8'));
  manifest.programRevision.sha256 = '0'.repeat(64);
  await writeJson(fixture.manifestPath, manifest);
  await assert.rejects(
    validateManifest({ devopsRoot: fixture.devopsRoot, manifestPath: fixture.manifestPath }),
    /does not match the accepted program revision/
  );
});

test('rejects an incorrect contract artifact hash', async t => {
  const fixture = await createFixture(t);
  const manifest = JSON.parse(await readFile(fixture.manifestPath, 'utf8'));
  for (const repository of manifest.repositories) repository.contractArtifact.sha256 = '0'.repeat(64);
  await writeJson(fixture.manifestPath, manifest);
  await assert.rejects(
    validateManifest({ devopsRoot: fixture.devopsRoot, manifestPath: fixture.manifestPath }),
    /contract artifact hash mismatch/
  );
});

test('rejects an unavailable pinned commit', async t => {
  const fixture = await createFixture(t);
  fixture.repositories[0].sha = '0'.repeat(40);
  await rebuildContracts(fixture);
  const validated = await validateManifest({
    devopsRoot: fixture.devopsRoot,
    manifestPath: fixture.manifestPath
  });
  await assert.rejects(
    checkoutPinnedRepositories(validated, {
      sourceRoot: fixture.sourceRoot,
      checkoutRoot: path.join(fixture.root, 'checkout')
    }),
    /pinned SHA is unavailable/
  );
});

test('rejects a dirty source repository before checkout', async t => {
  const fixture = await createFixture(t);
  const validated = await validateManifest({
    devopsRoot: fixture.devopsRoot,
    manifestPath: fixture.manifestPath
  });
  await appendFile(path.join(fixture.sourceRoot, 'deep-client-maui', 'README.md'), 'dirty\n', 'utf8');
  await assert.rejects(
    checkoutPinnedRepositories(validated, {
      sourceRoot: fixture.sourceRoot,
      checkoutRoot: path.join(fixture.root, 'checkout')
    }),
    /source repository is dirty/
  );
});

test('checks out every repository in isolation and reports actual SHAs', async t => {
  const fixture = await createFixture(t);
  const validated = await validateManifest({
    devopsRoot: fixture.devopsRoot,
    manifestPath: fixture.manifestPath
  });
  const result = await checkoutPinnedRepositories(validated, {
    sourceRoot: fixture.sourceRoot,
    checkoutRoot: path.join(fixture.root, 'checkout')
  });
  assert.deepEqual(
    result.repositories.map(repository => repository.actualSha),
    fixture.repositories.map(repository => repository.sha)
  );
  assert.ok(result.repositories.every(repository => repository.clean && repository.evidenceStatus === 'verified'));
});

test('artifact and handoff validators reject incomplete evidence', () => {
  assert.throws(() => validateEvidence({ schemaVersion: '1.0.0' }), /missing fields/);
  assert.throws(() => validateHandoff({
    schemaVersion: '1.0.0',
    status: 'ready-for-review',
    releaseId: 'fixture',
    evidencePath: 'evidence.json',
    blockers: [],
    rollback: {
      strategy: 'manual',
      safeToDeleteCheckoutRoot: true
    }
  }), /rollback strategy is invalid/);
});
