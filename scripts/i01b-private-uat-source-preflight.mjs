import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { lstat, readFile, readdir, realpath } from 'node:fs/promises';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
export const repositoryRoot = path.resolve(scriptDirectory, '..');
export const canonicalDockerfilePath = path.join(repositoryRoot, 'docker', 'xnode-xray.Dockerfile');
const compatBuildRoots = Object.freeze([
  'docker/file-service.Dockerfile',
  'docker/push-service.Dockerfile',
  'docker/storage-service.Dockerfile',
  'tools/compat-services',
  'tools/file-service',
  'tools/push-service',
  'tools/storage-service'
]);

function samePath(left, right) {
  return process.platform === 'win32'
    ? left.toLowerCase() === right.toLowerCase()
    : left === right;
}

function runGit(context, args) {
  const result = spawnSync('git', ['-C', context, ...args], {
    encoding: 'utf8',
    windowsHide: true
  });
  if (result.error) {
    throw new Error(`git could not run: ${result.error.message}`);
  }
  if (result.status !== 0) {
    throw new Error(`git ${args.join(' ')} failed closed: ${result.stderr.trim()}`);
  }
  return result.stdout.trim();
}

async function requireCanonicalPath(input, kind) {
  assert.equal(typeof input, 'string', `${kind} path is required`);
  assert.ok(path.isAbsolute(input), `${kind} path must be absolute`);
  const resolved = path.resolve(input);
  assert.ok(samePath(input, resolved), `${kind} path must already be normalized`);
  const info = await lstat(input);
  assert.equal(info.isSymbolicLink(), false, `${kind} path must not be a symlink/reparse point`);
  const actual = await realpath(input);
  assert.ok(samePath(input, actual), `${kind} path must be its exact canonical path`);
  return { info, actual };
}

async function collectRegularFiles(root, relativeInput) {
  const absolute = path.join(root, ...relativeInput.split('/'));
  const info = await lstat(absolute);
  assert.equal(info.isSymbolicLink(), false, `compat build input ${relativeInput} must not be a symlink/reparse point`);
  if (info.isFile()) return [relativeInput];
  assert.equal(info.isDirectory(), true, `compat build input ${relativeInput} must be a regular file or directory`);
  const entries = await readdir(absolute, { withFileTypes: true });
  const files = [];
  for (const entry of entries.sort((left, right) => left.name.localeCompare(right.name))) {
    assert.equal(
      entry.isSymbolicLink(),
      false,
      `compat build input ${relativeInput}/${entry.name} must not be a symlink/reparse point`
    );
    files.push(...await collectRegularFiles(root, `${relativeInput}/${entry.name}`));
  }
  return files;
}

export async function compatBuildContentSha256(devopsRoot) {
  const files = (await Promise.all(
    compatBuildRoots.map(relative => collectRegularFiles(devopsRoot, relative))
  )).flat().sort();
  const hash = createHash('sha256');
  for (const relative of files) {
    const bytes = await readFile(path.join(devopsRoot, ...relative.split('/')));
    hash.update(Buffer.from(`${relative}\0${bytes.length}\0`, 'utf8'));
    hash.update(bytes);
    hash.update(Buffer.from('\0', 'utf8'));
  }
  return hash.digest('hex');
}

export async function preflightSource(options) {
  const expectedCommit = String(options.expectedCommit ?? '');
  const expectedDockerfileSha256 = String(options.expectedDockerfileSha256 ?? '');
  const expectedDevopsCommit = String(options.expectedDevopsCommit ?? '');
  const expectedCompatContentSha256 = String(options.expectedCompatContentSha256 ?? '');
  assert.match(expectedCommit, /^[0-9a-f]{40}$/, 'expected XNode commit must be exact lowercase SHA1');
  assert.match(expectedDevopsCommit, /^[0-9a-f]{40}$/, 'expected DevOps commit must be exact lowercase SHA1');
  assert.match(
    expectedDockerfileSha256,
    /^[0-9a-f]{64}$/,
    'expected Dockerfile SHA256 must be exact lowercase hexadecimal'
  );
  assert.match(
    expectedCompatContentSha256,
    /^[0-9a-f]{64}$/,
    'expected compat build content SHA256 must be exact lowercase hexadecimal'
  );

  const contextCheck = await requireCanonicalPath(options.xnodeContext, 'XNode context');
  assert.equal(contextCheck.info.isDirectory(), true, 'XNode context must be a directory');
  const dockerfileCheck = await requireCanonicalPath(options.dockerfile, 'Dockerfile');
  assert.equal(dockerfileCheck.info.isFile(), true, 'Dockerfile must be a regular file');

  const requiredCanonicalDockerfile = path.resolve(
    options.canonicalDockerfile ?? canonicalDockerfilePath
  );
  assert.ok(
    samePath(dockerfileCheck.actual, requiredCanonicalDockerfile),
    'Dockerfile path is not the canonical reviewed DevOps Dockerfile'
  );
  const devopsCheck = await requireCanonicalPath(options.devopsContext, 'DevOps context');
  assert.equal(devopsCheck.info.isDirectory(), true, 'DevOps context must be a directory');
  const requiredCanonicalDevopsRoot = path.resolve(options.canonicalDevopsRoot ?? repositoryRoot);
  assert.ok(
    samePath(devopsCheck.actual, requiredCanonicalDevopsRoot),
    'DevOps context is not the canonical reviewed repository root'
  );

  const gitRoot = path.resolve(runGit(contextCheck.actual, ['rev-parse', '--show-toplevel']));
  assert.ok(
    samePath(gitRoot, contextCheck.actual),
    'XNode build context must be the exact Git worktree root'
  );
  const actualCommit = runGit(contextCheck.actual, ['rev-parse', 'HEAD']).toLowerCase();
  assert.equal(actualCommit, expectedCommit, 'XNode worktree commit does not match the required commit');
  const dirty = runGit(contextCheck.actual, [
    'status',
    '--porcelain=v1',
    '--untracked-files=all'
  ]);
  assert.equal(dirty, '', 'XNode worktree must be exactly clean');

  const devopsGitRoot = path.resolve(runGit(devopsCheck.actual, ['rev-parse', '--show-toplevel']));
  assert.ok(
    samePath(devopsGitRoot, devopsCheck.actual),
    'DevOps build context must be the exact Git worktree root'
  );
  const actualDevopsCommit = runGit(devopsCheck.actual, ['rev-parse', 'HEAD']).toLowerCase();
  assert.equal(
    actualDevopsCommit,
    expectedDevopsCommit,
    'DevOps worktree commit does not match the required commit'
  );
  const devopsDirty = runGit(devopsCheck.actual, [
    'status',
    '--porcelain=v1',
    '--untracked-files=all'
  ]);
  assert.equal(devopsDirty, '', 'DevOps worktree must be exactly clean');

  const dockerfileBytes = await readFile(dockerfileCheck.actual);
  const actualDockerfileSha256 = createHash('sha256').update(dockerfileBytes).digest('hex');
  assert.equal(
    actualDockerfileSha256,
    expectedDockerfileSha256,
    'Dockerfile content does not match the required SHA256'
  );
  const actualCompatContentSha256 = await compatBuildContentSha256(devopsCheck.actual);
  assert.equal(
    actualCompatContentSha256,
    expectedCompatContentSha256,
    'compat build content does not match the required SHA256'
  );

  return {
    schemaVersion: '1.0.0',
    status: 'accepted-clean-pinned-source',
    xnodeCommit: actualCommit,
    dockerfileSha256: actualDockerfileSha256,
    devopsCommit: actualDevopsCommit,
    compatContentSha256: actualCompatContentSha256,
    clean: true,
    productionReady: false,
    uatRestartAuthorized: false
  };
}

function parse(argv) {
  const options = {};
  const mapping = {
    '--xnode-context': 'xnodeContext',
    '--expected-xnode-commit': 'expectedCommit',
    '--dockerfile': 'dockerfile',
    '--expected-dockerfile-sha256': 'expectedDockerfileSha256',
    '--devops-context': 'devopsContext',
    '--expected-devops-commit': 'expectedDevopsCommit',
    '--expected-compat-content-sha256': 'expectedCompatContentSha256'
  };
  for (let index = 0; index < argv.length; index += 2) {
    const key = mapping[argv[index]];
    const value = argv[index + 1];
    if (!key || !value || value.startsWith('--') || Object.hasOwn(options, key)) {
      throw new Error(`invalid or missing source preflight argument near ${argv[index] ?? '<end>'}`);
    }
    options[key] = value;
  }
  assert.deepEqual(
    Object.keys(options).sort(),
    Object.values(mapping).sort(),
    'all exact source preflight arguments are required'
  );
  return options;
}

export async function main(argv = process.argv.slice(2)) {
  const result = await preflightSource(parse(argv));
  console.log(JSON.stringify(result, null, 2));
  return result;
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  main().catch(error => {
    console.error(`I01B private UAT source preflight failed closed: ${error.message}`);
    process.exitCode = 1;
  });
}
