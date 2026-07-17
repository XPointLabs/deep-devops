import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { appendFile, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {
  checkoutPinnedRepositories,
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
