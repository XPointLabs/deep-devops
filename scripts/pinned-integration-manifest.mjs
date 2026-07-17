import { createHash } from 'node:crypto';
import { existsSync } from 'node:fs';
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

function runGit(repository, args, label) {
  const result = spawnSync('git', ['-C', repository, ...args], {
    encoding: 'utf8',
    env: {
      ...process.env,
      GIT_TERMINAL_PROMPT: '0',
      GIT_ASKPASS: 'echo'
    },
    windowsHide: true
  });
  if (result.status !== 0) {
    const detail = result.stderr.trim() || result.stdout.trim() || `exit ${result.status}`;
    fail(`${label}: ${detail}`);
  }
  return result.stdout.trim();
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
    env: {
      ...process.env,
      GIT_TERMINAL_PROMPT: '0',
      GIT_ASKPASS: 'echo'
    },
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
  for (const artifact of artifacts.values()) {
    const { raw, value } = await readJson(artifact.path, `contract artifact ${artifact.relativePath}`);
    const actualSha256 = sha256(raw);
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
      if (required.get(repository.name) !== repository.sha) {
        fail(`contract artifact ${artifact.relativePath} is incompatible with ${repository.name}@${repository.sha}`);
      }
    }
    const protocol = manifest.repositories.find(repository => repository.name === 'deep-protocol');
    if (!protocol || value.compatibility?.protocolContract !== `deep-protocol@${protocol.sha}`) {
      fail(`contract artifact ${artifact.relativePath} protocol compatibility assertion failed`);
    }
    verifiedArtifacts.push({
      name: artifact.name,
      version: artifact.version,
      relativePath: artifact.relativePath,
      expectedSha256: artifact.sha256,
      actualSha256
    });
  }

  return {
    root,
    manifestPath,
    manifestRaw,
    manifest,
    manifestSha256: sha256(manifestRaw),
    packageFeedPath,
    verifiedArtifacts
  };
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
    const key = {
      '--manifest': 'manifestPath',
      '--source-root': 'sourceRoot',
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
