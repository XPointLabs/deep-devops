import { createHash } from 'node:crypto';
import { existsSync, statSync } from 'node:fs';
import { mkdir, readFile, readdir, stat, writeFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const devopsRoot = path.resolve(__dirname, '..');
const shaPattern = /^[0-9a-f]{40}$/;
const sha256Pattern = /^[0-9a-f]{64}$/;
const repoNamePattern = /^[A-Za-z0-9._-]+$/;

function fail(message) {
  throw new Error(message);
}

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function requireObject(value, label) {
  if (!isObject(value)) fail(`${label} must be an object`);
  return value;
}

function requireString(value, label) {
  if (typeof value !== 'string' || value.trim().length === 0) {
    fail(`${label} must be a non-empty string`);
  }
  return value;
}

function requireExactKeys(value, allowed, required, label) {
  requireObject(value, label);
  const unexpected = Object.keys(value).filter(key => !allowed.includes(key));
  const missing = required.filter(key => !(key in value));
  if (unexpected.length > 0) fail(`${label} has unexpected fields: ${unexpected.join(', ')}`);
  if (missing.length > 0) fail(`${label} is missing fields: ${missing.join(', ')}`);
}

function requireRevision(value, label) {
  requireExactKeys(value, ['commit', 'sha256'], ['commit', 'sha256'], label);
  if (!shaPattern.test(value.commit)) fail(`${label}.commit must be an exact 40-hex SHA`);
  if (!sha256Pattern.test(value.sha256)) fail(`${label}.sha256 must be a 64-hex SHA256`);
  return value;
}

function sameRevision(left, right) {
  return left.commit === right.commit && left.sha256 === right.sha256;
}

async function readJson(filePath, label = filePath) {
  let raw;
  try {
    raw = await readFile(filePath, 'utf8');
  } catch (error) {
    fail(`${label} is unavailable: ${error.message}`);
  }

  try {
    return { raw, value: JSON.parse(raw) };
  } catch (error) {
    fail(`${label} is not valid JSON: ${error.message}`);
  }
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function resolveInside(root, relativePath, label) {
  requireString(relativePath, label);
  if (path.isAbsolute(relativePath)) fail(`${label} must be relative`);
  const resolvedRoot = path.resolve(root);
  const resolved = path.resolve(resolvedRoot, relativePath);
  const prefix = `${resolvedRoot}${path.sep}`;
  if (resolved !== resolvedRoot && !resolved.startsWith(prefix)) {
    fail(`${label} escapes the repository root`);
  }
  return resolved;
}

function normalizeRemote(value) {
  return value.trim().replace(/\\/g, '/').replace(/\/$/, '').replace(/\.git$/, '').toLowerCase();
}

function canonicalGitEnvironment() {
  const environment = { ...process.env };
  const forbidden = new Set([
    'GIT_DIR',
    'GIT_WORK_TREE',
    'GIT_INDEX_FILE',
    'GIT_OBJECT_DIRECTORY',
    'GIT_ALTERNATE_OBJECT_DIRECTORIES',
    'GIT_REPLACE_REF_BASE',
    'GIT_COMMON_DIR',
    'GIT_NAMESPACE',
    'GIT_CONFIG',
    'GIT_CONFIG_COUNT',
    'GIT_CONFIG_GLOBAL',
    'GIT_CONFIG_SYSTEM'
  ]);
  for (const key of Object.keys(environment)) {
    if (forbidden.has(key)
        || key.startsWith('GIT_CONFIG_KEY_')
        || key.startsWith('GIT_CONFIG_VALUE_')) {
      delete environment[key];
    }
  }
  return {
    ...environment,
    GIT_TERMINAL_PROMPT: '0',
    GIT_ASKPASS: 'echo',
    GIT_NO_REPLACE_OBJECTS: '1',
    GIT_OPTIONAL_LOCKS: '0',
    GIT_CONFIG_NOSYSTEM: '1'
  };
}

function canonicalGitArguments(repository, args) {
  return [
    '-c',
    'core.fsmonitor=false',
    '-c',
    'core.untrackedCache=false',
    '-c',
    'core.hooksPath=',
    '-C',
    repository,
    ...args
  ];
}

function runGit(repository, args, label) {
  const result = spawnSync('git', canonicalGitArguments(repository, args), {
    encoding: 'utf8',
    env: canonicalGitEnvironment(),
    windowsHide: true
  });
  if (result.status !== 0) {
    const detail = result.stderr.trim() || result.stdout.trim() || `exit ${result.status}`;
    fail(`${label}: ${detail}`);
  }
  return result.stdout.trim();
}

function readPinnedGitBlob(repository, commit, relativePath, label) {
  if (!shaPattern.test(commit)) fail(`${label} carrier must be an exact 40-hex SHA`);
  resolveInside(repository, relativePath, `${label} path`);
  const result = spawnSync(
    'git',
    canonicalGitArguments(
      repository,
      ['show', `${commit}:${relativePath.replace(/\\/g, '/')}`]
    ),
    {
      encoding: null,
      env: canonicalGitEnvironment(),
      windowsHide: true,
      maxBuffer: 16 * 1024 * 1024
    }
  );
  if (result.status !== 0) {
    fail(`${label} is absent from pinned carrier ${commit}`);
  }
  return Buffer.from(result.stdout);
}

function runClone(source, destination) {
  const result = spawnSync('git', [
    'clone',
    '--local',
    '--no-hardlinks',
    '--no-checkout',
    source,
    destination
  ], {
    encoding: 'utf8',
    env: canonicalGitEnvironment(),
    windowsHide: true
  });
  if (result.status !== 0) {
    const detail = result.stderr.trim() || result.stdout.trim() || `exit ${result.status}`;
    fail(`isolated clone failed for ${path.basename(source)}: ${detail}`);
  }
}

async function directoryIsEmpty(directory) {
  if (!existsSync(directory)) return true;
  const directoryStat = await stat(directory);
  if (!directoryStat.isDirectory()) fail(`checkout root is not a directory: ${directory}`);
  return (await readdir(directory)).length === 0;
}

function nonEmptyFile(filePath) {
  return existsSync(filePath) && statSync(filePath).size > 0;
}

export function assertCanonicalGitRepository(repositoryPath, label = 'producer source') {
  const replaceRefs = runGit(
    repositoryPath,
    ['for-each-ref', '--format=%(refname)', 'refs/replace/'],
    `${label} replace-ref inspection failed`
  );
  if (replaceRefs.length > 0) fail(`${label} contains forbidden replace refs`);
  const shallow = runGit(
    repositoryPath,
    ['rev-parse', '--is-shallow-repository'],
    `${label} shallow-state inspection failed`
  );
  if (shallow !== 'false') fail(`${label} must be a complete non-shallow repository`);
  for (const [gitPath, description] of [
    ['info/grafts', 'grafts'],
    ['objects/info/alternates', 'object alternates']
  ]) {
    const candidate = runGit(
      repositoryPath,
      ['rev-parse', '--git-path', gitPath],
      `${label} ${description} path inspection failed`
    );
    const resolved = path.isAbsolute(candidate)
      ? candidate
      : path.resolve(repositoryPath, candidate);
    if (nonEmptyFile(resolved)) fail(`${label} contains forbidden ${description}`);
  }
}

async function readProducerSourceMap(filePath) {
  const { value } = await readJson(path.resolve(filePath), 'producer source map');
  requireExactKeys(
    value,
    ['schemaVersion', 'repositories'],
    ['schemaVersion', 'repositories'],
    'producer source map'
  );
  if (value.schemaVersion !== '1.0.0') fail('producer source map schemaVersion must be 1.0.0');
  requireObject(value.repositories, 'producer source map.repositories');
  const result = new Map();
  for (const [name, repositoryPath] of Object.entries(value.repositories)) {
    if (!repoNamePattern.test(name)) fail(`producer source map repository name is invalid: ${name}`);
    result.set(name, path.resolve(requireString(
      repositoryPath,
      `producer source map.repositories.${name}`
    )));
  }
  return result;
}

function requireBoolean(value, label) {
  if (typeof value !== 'boolean') fail(`${label} must be boolean`);
  return value;
}

function requireCommit(value, label) {
  if (!shaPattern.test(value)) fail(`${label} must be an exact 40-hex SHA`);
  return value;
}

function requireSha256(value, label) {
  if (!sha256Pattern.test(value)) fail(`${label} must be a 64-hex SHA256`);
  return value;
}

export function requireZeroReviewCounts(value, label = 'review counts') {
  requireExactKeys(value, ['p0', 'p1', 'p2', 'p3'], ['p0', 'p1', 'p2', 'p3'], label);
  if (Object.values(value).some(count => !Number.isInteger(count) || count !== 0)) {
    fail(`${label} must contain exact integer zero counts`);
  }
  return value;
}

function validateClosureExecution(value) {
  requireExactKeys(
    value,
    ['offlineLocalOnly', 'networkUsed', 'dockerUsed', 'pushPerformed', 'packagePublished', 'deployPerformed'],
    ['offlineLocalOnly', 'networkUsed', 'dockerUsed', 'pushPerformed', 'packagePublished', 'deployPerformed'],
    'dependency closure execution'
  );
  if (requireBoolean(value.offlineLocalOnly, 'dependency closure execution.offlineLocalOnly') !== true
      || requireBoolean(value.networkUsed, 'dependency closure execution.networkUsed') !== false
      || requireBoolean(value.dockerUsed, 'dependency closure execution.dockerUsed') !== false
      || requireBoolean(value.pushPerformed, 'dependency closure execution.pushPerformed') !== false
      || requireBoolean(value.packagePublished, 'dependency closure execution.packagePublished') !== false
      || requireBoolean(value.deployPerformed, 'dependency closure execution.deployPerformed') !== false) {
    fail('dependency closure execution must remain offline/local-only with no network, Docker, push, publication or deploy');
  }
}

function validateDependencyWorkPackage(item, expectedId) {
  requireExactKeys(
    item,
    [
      'id',
      'repository',
      'sourceCommit',
      'reviewedEvidenceCommit',
      'finalEvidenceCommit',
      'status',
      'runtimeAuthorized',
      'packageVersion',
      'artifacts'
    ],
    [
      'id',
      'repository',
      'sourceCommit',
      'reviewedEvidenceCommit',
      'finalEvidenceCommit',
      'status',
      'runtimeAuthorized',
      'packageVersion',
      'artifacts'
    ],
    `dependency closure ${expectedId}`
  );
  if (item.id !== expectedId) fail(`dependency closure ${expectedId}.id is invalid`);
  if (!repoNamePattern.test(item.repository)) fail(`dependency closure ${expectedId}.repository is invalid`);
  requireCommit(item.sourceCommit, `dependency closure ${expectedId}.sourceCommit`);
  requireCommit(item.reviewedEvidenceCommit, `dependency closure ${expectedId}.reviewedEvidenceCommit`);
  requireCommit(item.finalEvidenceCommit, `dependency closure ${expectedId}.finalEvidenceCommit`);
  requireString(item.status, `dependency closure ${expectedId}.status`);
  if (requireBoolean(item.runtimeAuthorized, `dependency closure ${expectedId}.runtimeAuthorized`) !== false) {
    fail(`dependency closure ${expectedId} must not authorize runtime activation`);
  }
  if (item.packageVersion !== null) {
    requireString(item.packageVersion, `dependency closure ${expectedId}.packageVersion`);
  }
  if (!Array.isArray(item.artifacts) || item.artifacts.length === 0) {
    fail(`dependency closure ${expectedId}.artifacts must be non-empty`);
  }
  const paths = new Set();
  for (const [index, artifact] of item.artifacts.entries()) {
    const label = `dependency closure ${expectedId}.artifacts[${index}]`;
    requireExactKeys(
      artifact,
      ['path', 'sha256', 'bytes', 'kind'],
      ['path', 'sha256', 'bytes', 'kind'],
      label
    );
    requireString(artifact.path, `${label}.path`);
    if (path.isAbsolute(artifact.path) || artifact.path.split(/[\\/]/).includes('..')) {
      fail(`${label}.path must be repository-relative`);
    }
    if (paths.has(artifact.path)) fail(`dependency closure ${expectedId} contains duplicate artifact path`);
    paths.add(artifact.path);
    requireSha256(artifact.sha256, `${label}.sha256`);
    if (!Number.isSafeInteger(artifact.bytes) || artifact.bytes <= 0) {
      fail(`${label}.bytes must be a positive safe integer`);
    }
    requireString(artifact.kind, `${label}.kind`);
  }
  return item;
}

export async function validateDependencyClosure(value, manifest, options = {}) {
  requireExactKeys(
    value,
    [
      'schema',
      'status',
      'accountableHuman',
      'execution',
      'waves',
      'blockedWorkPackages',
      'workPackages'
    ],
    [
      'schema',
      'status',
      'accountableHuman',
      'execution',
      'waves',
      'blockedWorkPackages',
      'workPackages'
    ],
    'dependency closure'
  );
  if (value.schema !== 'deep-survival-dependency-closure.v1') {
    fail('dependency closure schema is unsupported');
  }
  if (value.status !== 'w1-contract-closed-w2-dependency-gated-blocked') {
    fail('dependency closure status must keep W2 blocked');
  }
  if (value.accountableHuman !== 'Mr. X') fail('dependency closure accountableHuman must be Mr. X');
  validateClosureExecution(value.execution);
  requireExactKeys(value.waves, ['W1', 'W2'], ['W1', 'W2'], 'dependency closure waves');
  if (value.waves.W1 !== 'contract-closed-runtime-blocked'
      || value.waves.W2 !== 'dependency-gated-blocked') {
    fail('dependency closure wave status is invalid');
  }
  if (!Array.isArray(value.blockedWorkPackages)
      || !['P08', 'P09A', 'P09B', 'P09C'].every(id => value.blockedWorkPackages.includes(id))) {
    fail('dependency closure must block P08 and all P09 runtime packages');
  }
  requireExactKeys(value.workPackages, ['P04', 'P05'], ['P04', 'P05'], 'dependency closure workPackages');
  const p04 = validateDependencyWorkPackage(value.workPackages.P04, 'P04');
  const p05 = validateDependencyWorkPackage(value.workPackages.P05, 'P05');
  if (p04.repository !== 'deep-protocol'
      || p04.status !== 'contract-go-runtime-blocked'
      || p04.packageVersion !== '0.3.0-p04.b887fa0') {
    fail('dependency closure P04 accepted identity is invalid');
  }
  if (p05.repository !== 'xnode'
      || p05.status !== 'design-review-go-proposed-not-approved'
      || p05.packageVersion !== null) {
    fail('dependency closure P05 must remain a package-less proposed/not-approved design');
  }

  const repositories = new Map(manifest.repositories.map(repository => [repository.name, repository]));
  if (repositories.get(p04.repository)?.sha !== p04.finalEvidenceCommit
      || repositories.get(p05.repository)?.sha !== p05.finalEvidenceCommit) {
    fail('dependency closure producer evidence commits do not match repository pins');
  }

  if (!options.verifyProducerArtifacts) return [];
  const sourceMap = options.producerSources instanceof Map
    ? options.producerSources
    : await readProducerSourceMap(requireString(
      options.producerSourceMapPath,
      'producerSourceMapPath'
    ));
  const verified = [];
  for (const item of [p04, p05]) {
    const repositoryPath = sourceMap.get(item.repository);
    if (!repositoryPath || !existsSync(repositoryPath)) {
      fail(`producer source repository is unavailable: ${item.repository}`);
    }
    if (runGit(
      repositoryPath,
      ['rev-parse', '--is-inside-work-tree'],
      `${item.repository} producer source is not a Git worktree`
    ) !== 'true') {
      fail(`${item.repository} producer source is not a Git worktree`);
    }
    assertCanonicalGitRepository(repositoryPath, `${item.repository} producer source`);
    const dirty = runGit(
      repositoryPath,
      ['status', '--porcelain', '--untracked-files=normal'],
      `${item.repository} producer source status failed`
    );
    if (dirty.length > 0) fail(`producer source repository is dirty: ${item.repository}`);
    const origin = runGit(
      repositoryPath,
      ['remote', 'get-url', 'origin'],
      `${item.repository} producer source origin is unavailable`
    );
    if (normalizeRemote(origin) !== normalizeRemote(repositories.get(item.repository).url)) {
      fail(`${item.repository} producer source origin does not match manifest URL`);
    }
    for (const commit of [item.sourceCommit, item.reviewedEvidenceCommit, item.finalEvidenceCommit]) {
      runGit(
        repositoryPath,
        ['cat-file', '-e', `${commit}^{commit}`],
        `${item.repository} dependency commit is unavailable`
      );
    }
    runGit(
      repositoryPath,
      ['merge-base', '--is-ancestor', item.sourceCommit, item.reviewedEvidenceCommit],
      `${item.repository} source is not an ancestor of reviewed evidence`
    );
    runGit(
      repositoryPath,
      ['merge-base', '--is-ancestor', item.reviewedEvidenceCommit, item.finalEvidenceCommit],
      `${item.repository} reviewed evidence is not an ancestor of final evidence`
    );
    for (const artifact of item.artifacts) {
      const rawBytes = readPinnedGitBlob(
        repositoryPath,
        item.finalEvidenceCommit,
        artifact.path,
        `${item.id} producer artifact ${artifact.path}`
      );
      const actualSha256 = sha256(rawBytes);
      if (actualSha256 !== artifact.sha256 || rawBytes.length !== artifact.bytes) {
        fail(`${item.id} producer artifact identity mismatch for ${artifact.path}`);
      }
      verified.push({
        workPackage: item.id,
        repository: item.repository,
        evidenceCommit: item.finalEvidenceCommit,
        path: artifact.path,
        sha256: actualSha256,
        bytes: rawBytes.length,
        kind: artifact.kind
      });
    }

    const reportArtifact = item.artifacts.find(artifact =>
      artifact.path.endsWith('/work-package-report.json'));
    if (!reportArtifact) fail(`${item.id} work-package report artifact is missing`);
    const report = JSON.parse(readPinnedGitBlob(
      repositoryPath,
      item.finalEvidenceCommit,
      reportArtifact.path,
      `${item.id} work-package report`
    ).toString('utf8'));
    if (report.workPackage !== item.id || report.status !== item.status) {
      fail(`${item.id} work-package report status does not match dependency closure`);
    }
    if (item.id === 'P04') {
      if (report.finalSourceCommit !== item.sourceCommit
          || report.packageVersion !== item.packageVersion
          || report.independentReview?.verdict !== 'GO'
          || report.independentReview?.p0 !== 0
          || report.independentReview?.p1 !== 0
          || report.independentReview?.p2 !== 0) {
        fail('P04 work-package report does not prove the accepted contract identity');
      }
    } else if (report.secondCorrectiveDesignCommit !== item.sourceCommit
        || report.secondCorrectiveEvidenceCommit !== item.reviewedEvidenceCommit
        || report.approvedAdrSha !== 'NOT-APPROVED'
        || report.acceptance?.humanApproval !== 'pending'
        || report.independentReview?.secondCorrectiveVerdict !== 'GO'
        || report.independentReview?.allPriorFindingsClosed !== true) {
      fail('P05 work-package report does not preserve proposed/not-approved GO evidence');
    }
    if (item.id === 'P05') {
      requireZeroReviewCounts(
        report.independentReview?.secondCorrectiveCounts,
        'P05 second corrective review counts'
      );
    }
  }
  return verified;
}

export async function validateManifest(options = {}) {
  const root = path.resolve(options.devopsRoot ?? devopsRoot);
  const manifestPath = path.resolve(options.manifestPath
    ?? path.join(root, 'release', 'manifests', 'survival-v2.0.0.json'));
  const policyPath = path.resolve(options.programPolicyPath
    ?? path.join(root, 'release', 'pinned-program-revision.json'));
  const feedPolicyPath = path.resolve(options.feedPolicyPath
    ?? path.join(root, 'release', 'local-feed-policy.json'));
  const schemaPath = path.resolve(options.schemaPath
    ?? path.join(root, 'release', 'schemas', 'pinned-multi-repo-manifest.schema.json'));

  const [{ raw: manifestRaw, value: manifest }, { value: policy }, { value: feedPolicy }, { value: schema }] =
    await Promise.all([
      readJson(manifestPath, 'manifest'),
      readJson(policyPath, 'program revision policy'),
      readJson(feedPolicyPath, 'local feed policy'),
      readJson(schemaPath, 'manifest schema')
    ]);

  if (schema.$id !== 'deep-pinned-multi-repo-manifest/1.0.0') {
    fail('manifest schema id is unsupported');
  }
  requireExactKeys(
    manifest,
    ['schemaVersion', 'releaseId', 'programRevision', 'packageFeed', 'repositories'],
    ['schemaVersion', 'releaseId', 'programRevision', 'packageFeed', 'repositories'],
    'manifest'
  );
  if (manifest.schemaVersion !== '1.0.0') fail('manifest.schemaVersion must be 1.0.0');
  requireString(manifest.releaseId, 'manifest.releaseId');
  if (manifest.releaseId === 'deep-survival-v2.0.2-w0-local') {
    fail('pre-carrier W0 manifest is superseded; use the detached carrier manifest');
  }
  requireRevision(manifest.programRevision, 'manifest.programRevision');

  requireExactKeys(
    policy,
    ['schemaVersion', 'program', 'version', 'commit', 'sha256'],
    ['schemaVersion', 'program', 'version', 'commit', 'sha256'],
    'program revision policy'
  );
  requireRevision({ commit: policy.commit, sha256: policy.sha256 }, 'program revision policy');
  if (!sameRevision(manifest.programRevision, policy)) {
    fail('manifest program revision does not match the accepted program revision');
  }

  requireExactKeys(
    manifest.packageFeed,
    ['mode', 'relativePath', 'allowNetworkRestore', 'allowExternalPublication'],
    ['mode', 'relativePath', 'allowNetworkRestore', 'allowExternalPublication'],
    'manifest.packageFeed'
  );
  requireExactKeys(
    feedPolicy,
    ['schemaVersion', 'mode', 'relativePath', 'allowNetworkRestore', 'allowExternalPublication', 'allowedUriSchemes'],
    ['schemaVersion', 'mode', 'relativePath', 'allowNetworkRestore', 'allowExternalPublication', 'allowedUriSchemes'],
    'local feed policy'
  );
  if (manifest.packageFeed.mode !== 'offline-local-only'
      || manifest.packageFeed.allowNetworkRestore !== false
      || manifest.packageFeed.allowExternalPublication !== false
      || manifest.packageFeed.relativePath !== feedPolicy.relativePath
      || feedPolicy.mode !== 'offline-local-only'
      || feedPolicy.allowNetworkRestore !== false
      || feedPolicy.allowExternalPublication !== false
      || !Array.isArray(feedPolicy.allowedUriSchemes)
      || feedPolicy.allowedUriSchemes.length !== 1
      || feedPolicy.allowedUriSchemes[0] !== 'file') {
    fail('manifest package feed violates the offline/local-only feed policy');
  }
  const packageFeedPath = resolveInside(root, manifest.packageFeed.relativePath, 'manifest.packageFeed.relativePath');
  if (!existsSync(packageFeedPath)) fail(`local package feed directory is unavailable: ${packageFeedPath}`);

  if (!Array.isArray(manifest.repositories) || manifest.repositories.length === 0) {
    fail('manifest.repositories must contain at least one repository');
  }

  const repositoryNames = new Set();
  const artifacts = new Map();
  const detachedManifest = /-detached-local$/.test(manifest.releaseId);
  for (const [index, repository] of manifest.repositories.entries()) {
    const label = `manifest.repositories[${index}]`;
    requireExactKeys(
      repository,
      ['name', 'url', 'branch', 'sha', 'contractArtifact', 'programRevision', 'evidenceStatus'],
      ['name', 'url', 'branch', 'sha', 'contractArtifact', 'programRevision', 'evidenceStatus'],
      label
    );
    if (!repoNamePattern.test(repository.name)) fail(`${label}.name is invalid`);
    if (repositoryNames.has(repository.name)) fail(`duplicate repository name: ${repository.name}`);
    repositoryNames.add(repository.name);
    requireString(repository.url, `${label}.url`);
    requireString(repository.branch, `${label}.branch`);
    if (!shaPattern.test(repository.sha)) {
      fail(`${label}.sha must be an exact 40-hex SHA; floating or branch-only refs are forbidden`);
    }
    requireRevision(repository.programRevision, `${label}.programRevision`);
    if (!sameRevision(repository.programRevision, manifest.programRevision)) {
      fail(`${label}.programRevision does not match the manifest program revision`);
    }
    if (!['pinned', 'verified'].includes(repository.evidenceStatus)) {
      fail(`${label}.evidenceStatus must be pinned or verified`);
    }

    const artifact = repository.contractArtifact;
    requireExactKeys(
      artifact,
      ['name', 'version', 'relativePath', 'sha256'],
      ['name', 'version', 'relativePath', 'sha256'],
      `${label}.contractArtifact`
    );
    requireString(artifact.name, `${label}.contractArtifact.name`);
    requireString(artifact.version, `${label}.contractArtifact.version`);
    if (!sha256Pattern.test(artifact.sha256)) fail(`${label}.contractArtifact.sha256 must be a 64-hex SHA256`);
    const artifactPath = resolveInside(root, artifact.relativePath, `${label}.contractArtifact.relativePath`);
    const key = `${artifactPath}|${artifact.sha256}`;
    artifacts.set(key, { ...artifact, path: artifactPath });
  }

  const verifiedArtifacts = [];
  const verifiedProducerArtifacts = [];
  const dependencyClosures = [];
  const devopsCarrier = manifest.repositories.find(repository =>
    repository.name === 'deep-devops');
  if (detachedManifest && !devopsCarrier) {
    fail('detached manifest requires a pinned deep-devops carrier');
  }
  for (const artifact of artifacts.values()) {
    let raw;
    let rawBytes;
    let value;
    if (detachedManifest) {
      rawBytes = readPinnedGitBlob(
        root,
        devopsCarrier.sha,
        artifact.relativePath,
        `contract artifact ${artifact.relativePath}`
      );
      raw = rawBytes.toString('utf8');
      try {
        value = JSON.parse(raw);
      } catch (error) {
        fail(`contract artifact ${artifact.relativePath} from pinned carrier is not valid JSON: ${error.message}`);
      }
    } else {
      ({ raw, value } = await readJson(
        artifact.path,
        `contract artifact ${artifact.relativePath}`
      ));
      rawBytes = Buffer.from(raw, 'utf8');
    }
    const actualSha256 = sha256(rawBytes);
    if (actualSha256 !== artifact.sha256) {
      fail(`contract artifact hash mismatch for ${artifact.relativePath}: expected ${artifact.sha256}, actual ${actualSha256}`);
    }
    if (value.artifactName !== artifact.name || value.version !== artifact.version) {
      fail(`contract artifact identity mismatch for ${artifact.relativePath}`);
    }
    if (!sameRevision(requireRevision(value.programRevision, 'contract artifact programRevision'), manifest.programRevision)) {
      fail(`contract artifact program revision mismatch for ${artifact.relativePath}`);
    }
    if (!Array.isArray(value.requiredRepositories)) {
      fail(`contract artifact ${artifact.relativePath} has no requiredRepositories`);
    }
    const required = new Map(value.requiredRepositories.map(entry => [entry.name, entry.sha]));
    if (required.size !== manifest.repositories.length) {
      fail(`contract artifact ${artifact.relativePath} repository set does not match the manifest`);
    }
    for (const repository of manifest.repositories) {
      if (detachedManifest && repository.name === 'deep-devops') {
        const carrierParent = runGit(
          root,
          ['rev-parse', `${repository.sha}^`],
          'detached manifest carrier parent is unavailable'
        );
        if (required.get(repository.name) !== carrierParent) {
          fail(
            `contract artifact ${artifact.relativePath} DevOps runtime base `
            + `does not equal pinned carrier first parent`
          );
        }
        continue;
      }
      if (required.get(repository.name) !== repository.sha) {
        fail(`contract artifact ${artifact.relativePath} is incompatible with ${repository.name}@${repository.sha}`);
      }
    }
    const protocol = manifest.repositories.find(repository => repository.name === 'deep-protocol');
    if (!protocol || value.compatibility?.protocolContract !== `deep-protocol@${protocol.sha}`) {
      fail(`contract artifact ${artifact.relativePath} protocol compatibility assertion failed`);
    }
    if (value.dependencyClosure) {
      dependencyClosures.push(value.dependencyClosure);
      verifiedProducerArtifacts.push(...await validateDependencyClosure(
        value.dependencyClosure,
        manifest,
        options
      ));
    }
    verifiedArtifacts.push({
      name: artifact.name,
      version: artifact.version,
      relativePath: artifact.relativePath,
      expectedSha256: artifact.sha256,
      actualSha256,
      carrierCommit: detachedManifest ? devopsCarrier.sha : null
    });
  }

  return {
    root,
    manifestPath,
    manifestRaw,
    manifest,
    manifestSha256: sha256(manifestRaw),
    packageFeedPath,
    verifiedArtifacts,
    verifiedProducerArtifacts,
    dependencyClosure: dependencyClosures.length === 1 ? dependencyClosures[0] : null
  };
}

export function validateDependencyClosureEvidence(value, validated) {
  requireExactKeys(
    value,
    [
      'schema',
      'accountableHuman',
      'iteration',
      'status',
      'manifest',
      'contract',
      'P04',
      'P05',
      'verification',
      'claims',
      'execution',
      'independentReviewRequired'
    ],
    [
      'schema',
      'accountableHuman',
      'iteration',
      'status',
      'manifest',
      'contract',
      'P04',
      'P05',
      'verification',
      'claims',
      'execution',
      'independentReviewRequired'
    ],
    'dependency closure evidence'
  );
  if (value.schema !== 'deep.w1w2-dependency-closure-evidence.v1'
      || value.accountableHuman !== 'Mr. X'
      || value.status !== 'W1-CONTRACT-CLOSED-W2-BLOCKED') {
    fail('dependency closure evidence identity or status is invalid');
  }
  const closure = requireObject(validated.dependencyClosure, 'validated dependency closure');
  const artifact = validated.verifiedArtifacts[0];
  if (value.manifest.path !== path.relative(validated.root, validated.manifestPath).replace(/\\/g, '/')
      || value.manifest.sha256 !== validated.manifestSha256
      || value.manifest.repositoryCount !== validated.manifest.repositories.length
      || value.manifest.offlineLocalOnly !== true) {
    fail('dependency closure evidence manifest identity drifted');
  }
  if (value.contract.path !== artifact.relativePath
      || value.contract.version !== artifact.version
      || value.contract.sha256 !== artifact.actualSha256
      || value.contract.carrierCommit !== artifact.carrierCommit
      || value.contract.runtimeBaseCommit !== runGit(
        validated.root,
        ['rev-parse', `${artifact.carrierCommit}^`],
        'dependency closure evidence carrier parent is unavailable'
      )
      || value.contract.verification !== 'raw-git-blob-from-pinned-carrier') {
    fail('dependency closure evidence contract identity drifted');
  }
  for (const id of ['P04', 'P05']) {
    const expected = closure.workPackages[id];
    const actual = value[id];
    if (actual.status !== expected.status
        || actual.sourceCommit !== expected.sourceCommit
        || actual.reviewedEvidenceCommit !== expected.reviewedEvidenceCommit
        || actual.finalEvidenceCommit !== expected.finalEvidenceCommit
        || actual.runtimeAuthorized !== false) {
      fail(`dependency closure evidence ${id} identity drifted`);
    }
  }
  if (value.P04.packageVersion !== closure.workPackages.P04.packageVersion
      || value.P04.packageManifestSha256
        !== closure.workPackages.P04.artifacts.find(item => item.kind === 'package-manifest')?.sha256
      || value.P05.workPackageReportSha256
        !== closure.workPackages.P05.artifacts.find(item => item.kind === 'work-package-report')?.sha256
      || value.P05.approvedAdrSha !== 'NOT-APPROVED'
      || !closure.blockedWorkPackages.every(id => value.P05.blockedWorkPackages.includes(id))) {
    fail('dependency closure evidence package or approval pins drifted');
  }
  if (validated.verifiedProducerArtifacts.length !== 17
      || value.verification.strictProducerGitArtifacts.verified !== 17
      || value.verification.strictProducerGitArtifacts.failed !== 0
      || value.verification.strictProducerGitArtifacts.sourceMapCommitted !== false
      || value.verification.focusedManifestTests.passed !== 20
      || value.verification.focusedManifestTests.failed !== 0
      || value.verification.focusedManifestTests.skipped !== 0
      || value.verification.metadataPrivacyGateTests.passed !== 16
      || value.verification.metadataPrivacyGateTests.failed !== 0
      || value.verification.metadataPrivacyGateTests.skipped !== 0
      || value.verification.releaseGateContractCommands.passed !== 56
      || value.verification.releaseGateContractCommands.failed !== 0
      || value.verification.releaseGateContractCommands.syntheticPlaceholderEvidenceOnly !== true
      || value.verification.actualProductionReadiness.status !== 'BLOCKED'
      || value.verification.actualProductionReadiness.blockers !== 10) {
    fail('dependency closure evidence verification claims are invalid');
  }
  if (Object.values(value.claims).some(claim => claim !== false)
      || value.execution.networkUsed !== closure.execution.networkUsed
      || value.execution.dockerUsed !== closure.execution.dockerUsed
      || value.execution.pushPerformed !== closure.execution.pushPerformed
      || value.execution.packagePublished !== closure.execution.packagePublished
      || value.execution.deployPerformed !== closure.execution.deployPerformed
      || value.execution.productionCredentialsAccessed !== false
      || value.independentReviewRequired !== true) {
    fail('dependency closure evidence authorization or execution claims drifted');
  }
  return value;
}

export function verifyLocalSource(repository, sourceRoot) {
  const sourcePath = path.resolve(sourceRoot, repository.name);
  if (!existsSync(sourcePath)) fail(`source repository is unavailable: ${repository.name}`);
  const insideWorkTree = runGit(sourcePath, ['rev-parse', '--is-inside-work-tree'], `${repository.name} is not a Git worktree`);
  if (insideWorkTree !== 'true') fail(`${repository.name} is not a Git worktree`);
  const dirty = runGit(sourcePath, ['status', '--porcelain', '--untracked-files=normal'], `${repository.name} status failed`);
  if (dirty.length > 0) fail(`source repository is dirty: ${repository.name}`);
  runGit(sourcePath, ['cat-file', '-e', `${repository.sha}^{commit}`], `${repository.name} pinned SHA is unavailable`);
  const origin = runGit(sourcePath, ['remote', 'get-url', 'origin'], `${repository.name} origin is unavailable`);
  if (normalizeRemote(origin) !== normalizeRemote(repository.url)) {
    fail(`${repository.name} origin does not match manifest URL`);
  }
  return sourcePath;
}

export async function checkoutPinnedRepositories(validated, options) {
  const sourceRoot = path.resolve(requireString(options.sourceRoot, 'sourceRoot'));
  const checkoutRoot = path.resolve(requireString(options.checkoutRoot, 'checkoutRoot'));
  if (sourceRoot === checkoutRoot || checkoutRoot.startsWith(`${sourceRoot}${path.sep}`)) {
    fail('checkoutRoot must be isolated from sourceRoot');
  }
  if (!(await directoryIsEmpty(checkoutRoot))) {
    fail(`checkout root must be missing or empty: ${checkoutRoot}`);
  }

  const sources = validated.manifest.repositories.map(repository => ({
    repository,
    sourcePath: verifyLocalSource(repository, sourceRoot)
  }));
  await mkdir(checkoutRoot, { recursive: true });

  const evidenceRepositories = [];
  for (const { repository, sourcePath } of sources) {
    const destination = path.join(checkoutRoot, repository.name);
    runClone(sourcePath, destination);
    runGit(destination, ['checkout', '--detach', repository.sha], `${repository.name} exact checkout failed`);
    const actualSha = runGit(destination, ['rev-parse', 'HEAD'], `${repository.name} HEAD verification failed`);
    if (actualSha !== repository.sha) {
      fail(`${repository.name} checkout SHA mismatch: expected ${repository.sha}, actual ${actualSha}`);
    }
    const dirty = runGit(destination, ['status', '--porcelain', '--untracked-files=normal'], `${repository.name} checkout status failed`);
    if (dirty.length > 0) fail(`isolated checkout is dirty: ${repository.name}`);
    evidenceRepositories.push({
      name: repository.name,
      url: repository.url,
      informationalBranch: repository.branch,
      expectedSha: repository.sha,
      actualSha,
      checkoutPath: destination,
      clean: true,
      evidenceStatus: 'verified'
    });
  }
  return { checkoutRoot, repositories: evidenceRepositories };
}

export function validateEvidence(value) {
  requireExactKeys(
    value,
    ['schemaVersion', 'status', 'generatedAt', 'releaseId', 'programRevision', 'manifestSha256', 'contractArtifacts', 'repositories', 'packageFeed'],
    ['schemaVersion', 'status', 'generatedAt', 'releaseId', 'programRevision', 'manifestSha256', 'contractArtifacts', 'repositories', 'packageFeed'],
    'integration evidence'
  );
  if (value.schemaVersion !== '1.0.0') fail('integration evidence schemaVersion must be 1.0.0');
  if (!['ok', 'failed'].includes(value.status)) fail('integration evidence status is invalid');
  if (!Number.isFinite(Date.parse(value.generatedAt))) fail('integration evidence generatedAt is invalid');
  if (!sha256Pattern.test(value.manifestSha256)) fail('integration evidence manifestSha256 is invalid');
  requireRevision(value.programRevision, 'integration evidence programRevision');
  if (!Array.isArray(value.contractArtifacts)) fail('integration evidence contractArtifacts must be an array');
  if (!Array.isArray(value.repositories) || value.repositories.length === 0) {
    fail('integration evidence repositories must be a non-empty array');
  }
  requireObject(value.packageFeed, 'integration evidence packageFeed');
  for (const [index, artifact] of value.contractArtifacts.entries()) {
    const label = `integration evidence contractArtifacts[${index}]`;
    requireExactKeys(
      artifact,
      ['name', 'version', 'relativePath', 'expectedSha256', 'actualSha256'],
      ['name', 'version', 'relativePath', 'expectedSha256', 'actualSha256'],
      label
    );
    if (!sha256Pattern.test(artifact.expectedSha256) || !sha256Pattern.test(artifact.actualSha256)) {
      fail(`${label} contains an invalid SHA256`);
    }
    if (artifact.expectedSha256 !== artifact.actualSha256) fail(`${label} hash verification failed`);
  }
  for (const [index, repository] of value.repositories.entries()) {
    const label = `integration evidence repositories[${index}]`;
    requireExactKeys(
      repository,
      ['name', 'url', 'informationalBranch', 'expectedSha', 'actualSha', 'checkoutPath', 'clean', 'evidenceStatus'],
      ['name', 'url', 'informationalBranch', 'expectedSha', 'actualSha', 'checkoutPath', 'clean', 'evidenceStatus'],
      label
    );
    if (!repoNamePattern.test(repository.name)) fail(`${label}.name is invalid`);
    if (!shaPattern.test(repository.expectedSha) || !shaPattern.test(repository.actualSha)) {
      fail(`${label} contains an invalid commit SHA`);
    }
    if (repository.expectedSha !== repository.actualSha) fail(`${label} SHA verification failed`);
    if (repository.clean !== true || repository.evidenceStatus !== 'verified') {
      fail(`${label} is not clean verified evidence`);
    }
  }
  requireExactKeys(
    value.packageFeed,
    ['mode', 'path', 'networkRestoreAllowed', 'externalPublicationAllowed'],
    ['mode', 'path', 'networkRestoreAllowed', 'externalPublicationAllowed'],
    'integration evidence packageFeed'
  );
  if (value.packageFeed.mode !== 'offline-local-only'
      || value.packageFeed.networkRestoreAllowed !== false
      || value.packageFeed.externalPublicationAllowed !== false) {
    fail('integration evidence packageFeed violates offline/local-only policy');
  }
  return value;
}

export function validateHandoff(value) {
  requireExactKeys(
    value,
    ['schemaVersion', 'status', 'releaseId', 'evidencePath', 'blockers', 'rollback'],
    ['schemaVersion', 'status', 'releaseId', 'evidencePath', 'blockers', 'rollback'],
    'handoff'
  );
  if (value.schemaVersion !== '1.0.0') fail('handoff schemaVersion must be 1.0.0');
  if (!['ready-for-review', 'blocked'].includes(value.status)) fail('handoff status is invalid');
  requireString(value.evidencePath, 'handoff.evidencePath');
  if (!Array.isArray(value.blockers)) fail('handoff.blockers must be an array');
  requireExactKeys(
    value.rollback,
    ['strategy', 'safeToDeleteCheckoutRoot'],
    ['strategy', 'safeToDeleteCheckoutRoot'],
    'handoff.rollback'
  );
  if (value.rollback.strategy !== 'delete-isolated-checkout-root') fail('handoff rollback strategy is invalid');
  if (typeof value.rollback.safeToDeleteCheckoutRoot !== 'boolean') {
    fail('handoff.rollback.safeToDeleteCheckoutRoot must be boolean');
  }
  if (value.status === 'ready-for-review'
      && (value.blockers.length !== 0 || value.rollback.safeToDeleteCheckoutRoot !== true)) {
    fail('ready-for-review handoff must have no blockers and a safe isolated rollback');
  }
  return value;
}

function parseArguments(argv) {
  const options = {};
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === '--validate-only') {
      options.validateOnly = true;
      continue;
    }
    if (argument === '--verify-producer-artifacts') {
      options.verifyProducerArtifacts = true;
      continue;
    }
    const key = {
      '--manifest': 'manifestPath',
      '--source-root': 'sourceRoot',
      '--producer-source-map': 'producerSourceMapPath',
      '--checkout-root': 'checkoutRoot',
      '--evidence': 'evidencePath',
      '--handoff': 'handoffPath'
    }[argument];
    if (!key) fail(`unknown argument: ${argument}`);
    const value = argv[index + 1];
    if (!value || value.startsWith('--')) fail(`${argument} requires a value`);
    options[key] = value;
    index += 1;
  }
  return options;
}

export async function main(argv = process.argv.slice(2)) {
  const options = parseArguments(argv);
  const validated = await validateManifest(options);
  if (options.validateOnly) {
    console.log(`Pinned manifest valid: ${validated.manifest.releaseId} (${validated.manifest.repositories.length} repositories).`);
    return { validated };
  }
  if (!options.sourceRoot || !options.checkoutRoot) {
    fail('--source-root and --checkout-root are required unless --validate-only is used');
  }

  const checkout = await checkoutPinnedRepositories(validated, options);
  const evidencePath = path.resolve(options.evidencePath
    ?? path.join(devopsRoot, 'artifacts', 'release', 'pinned-integration-evidence.json'));
  const handoffPath = path.resolve(options.handoffPath
    ?? path.join(devopsRoot, 'artifacts', 'release', 'pinned-integration-handoff.json'));
  const generatedAt = process.env.DEEP_EVIDENCE_NOW ?? new Date().toISOString();
  const evidence = validateEvidence({
    schemaVersion: '1.0.0',
    status: 'ok',
    generatedAt,
    releaseId: validated.manifest.releaseId,
    programRevision: validated.manifest.programRevision,
    manifestSha256: validated.manifestSha256,
    contractArtifacts: validated.verifiedArtifacts,
    repositories: checkout.repositories,
    packageFeed: {
      mode: validated.manifest.packageFeed.mode,
      path: validated.packageFeedPath,
      networkRestoreAllowed: false,
      externalPublicationAllowed: false
    }
  });
  const handoff = validateHandoff({
    schemaVersion: '1.0.0',
    status: 'ready-for-review',
    releaseId: validated.manifest.releaseId,
    evidencePath,
    blockers: [],
    rollback: {
      strategy: 'delete-isolated-checkout-root',
      safeToDeleteCheckoutRoot: true
    }
  });

  await mkdir(path.dirname(evidencePath), { recursive: true });
  await mkdir(path.dirname(handoffPath), { recursive: true });
  await writeFile(evidencePath, `${JSON.stringify(evidence, null, 2)}\n`, 'utf8');
  await writeFile(handoffPath, `${JSON.stringify(handoff, null, 2)}\n`, 'utf8');
  console.log(`Pinned integration checkout verified (${checkout.repositories.length} repositories). Evidence: ${evidencePath}`);
  return { validated, checkout, evidence, handoff };
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  main().catch(error => {
    console.error(`Pinned integration manifest failed closed: ${error.message}`);
    process.exitCode = 1;
  });
}
