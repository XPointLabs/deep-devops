import { createHash } from 'node:crypto';
import { execFileSync, spawnSync } from 'node:child_process';
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync
} from 'node:fs';
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { pathToFileURL } from 'node:url';

function fail(message) {
  throw new Error(`P15C source export failure: ${message}`);
}

function neutralGitEnvironment() {
  const environment = { ...process.env };
  for (const name of Object.keys(environment)) {
    if (name.toUpperCase().startsWith('GIT_')) delete environment[name];
  }
  const nullFile = '/dev/null';
  environment.GIT_CONFIG_NOSYSTEM = '1';
  environment.GIT_CONFIG_GLOBAL = nullFile;
  environment.GIT_CONFIG_SYSTEM = nullFile;
  environment.GIT_ATTR_NOSYSTEM = '1';
  environment.GIT_ALLOW_PROTOCOL = 'file';
  return environment;
}

function git(root, args, options = {}) {
  return execFileSync('git', ['-C', root, ...args], {
    encoding: options.encoding ?? 'utf8',
    env: neutralGitEnvironment(),
    maxBuffer: 512 * 1024 * 1024,
    stdio: ['ignore', 'pipe', 'pipe']
  });
}

function optionalGit(root, args) {
  const result = spawnSync('git', ['-C', root, ...args], {
    encoding: 'utf8',
    env: neutralGitEnvironment(),
    stdio: ['ignore', 'pipe', 'pipe']
  });
  if (result.error || ![0, 1, 5].includes(result.status)) fail('isolated Git configuration query failed');
  return result.status === 0 ? result.stdout.trim() : '';
}

function assertOwnedDestination(destination, ownedRoot) {
  const fullRoot = resolve(ownedRoot);
  const fullDestination = resolve(destination);
  const relation = relative(fullRoot, fullDestination);
  if (!isAbsolute(fullRoot) || !relation || relation === '..' || relation.startsWith(`..${sep}`) || isAbsolute(relation)) {
    fail('destination must be a child of the owned run tree');
  }
  if (existsSync(fullDestination)) fail('destination already exists');
  return { fullRoot, fullDestination };
}

function parseTree(snapshot, sha) {
  const output = git(snapshot, ['-c', 'core.attributesFile=/dev/null', 'ls-tree', '-rz', '--full-tree', '-r', sha]);
  const entries = [];
  for (const record of output.split('\0').filter(Boolean)) {
    const match = /^(\d{6}) (\w+) ([0-9a-f]{40})\t(.+)$/.exec(record);
    if (!match) fail('tree entry is malformed');
    const [, mode, type, object, path] = match;
    if (!['100644', '100755'].includes(mode) || type !== 'blob') {
      fail(`special Git mode is prohibited for ${path}`);
    }
    if (path.includes('\\') || path.startsWith('/') || path.split('/').some(part => !part || part === '.' || part === '..' || part.toLowerCase() === '.git')) {
      fail('tree entry path is unsafe');
    }
    entries.push({ mode, object, path });
  }
  return entries;
}

function readBlobs(snapshot, entries) {
  const input = `${entries.map(entry => entry.object).join('\n')}\n`;
  const result = spawnSync('git', ['-C', snapshot, 'cat-file', '--batch'], {
    input,
    encoding: null,
    env: neutralGitEnvironment(),
    maxBuffer: 1024 * 1024 * 1024,
    stdio: ['pipe', 'pipe', 'pipe']
  });
  if (result.error || result.status !== 0) fail('isolated blob export failed');
  const output = result.stdout;
  let offset = 0;
  return entries.map(entry => {
    const newline = output.indexOf(10, offset);
    if (newline < 0) fail('blob batch header is missing');
    const header = output.subarray(offset, newline).toString('ascii');
    const match = /^([0-9a-f]{40}) blob (\d+)$/.exec(header);
    if (!match || match[1] !== entry.object) fail('blob batch identity differs from the tree');
    const size = Number(match[2]);
    const start = newline + 1;
    const end = start + size;
    if (!Number.isSafeInteger(size) || end >= output.length || output[end] !== 10) fail('blob batch length is invalid');
    offset = end + 1;
    return output.subarray(start, end);
  });
}

function gitBlobId(bytes) {
  return createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex');
}

function verifyDestination(destination, entries) {
  const observed = [];
  const visit = directory => {
    for (const item of readdirSync(directory, { withFileTypes: true })) {
      const full = join(directory, item.name);
      const stat = lstatSync(full);
      if (stat.isSymbolicLink()) fail('export contains a symlink or reparse point');
      if (stat.isDirectory()) visit(full);
      else if (stat.isFile()) observed.push(relative(destination, full).split(sep).join('/'));
      else fail('export contains a special filesystem entry');
    }
  };
  visit(destination);
  const expectedPaths = entries.map(entry => entry.path).sort();
  observed.sort();
  if (JSON.stringify(observed) !== JSON.stringify(expectedPaths)) fail('exported entry inventory differs from the commit tree');
  for (const entry of entries) {
    const bytes = readFileSync(join(destination, ...entry.path.split('/')));
    if (gitBlobId(bytes) !== entry.object) fail(`exported content differs for ${entry.path}`);
  }
}

export function exportExactCommit({ source, sha, tree, destination, ownedRoot }) {
  if (!/^[0-9a-f]{40}$/.test(sha ?? '') || !/^[0-9a-f]{40}$/.test(tree ?? '')) fail('commit pin is malformed');
  const { fullRoot, fullDestination } = assertOwnedDestination(destination, ownedRoot);
  const snapshot = mkdtempSync(join(fullRoot, '.git-snapshot-'));
  try {
    execFileSync('git', [
      '-c', 'protocol.file.allow=always',
      'clone', '--quiet', '--no-local', '--no-hardlinks', '--no-checkout',
      resolve(source), snapshot
    ], { env: neutralGitEnvironment(), stdio: ['ignore', 'pipe', 'pipe'] });
    optionalGit(snapshot, ['remote', 'remove', 'origin']);
    if (git(snapshot, ['rev-parse', `${sha}^{commit}`]).trim() !== sha) fail('isolated snapshot lacks the exact commit');
    if (git(snapshot, ['rev-parse', `${sha}^{tree}`]).trim() !== tree) fail('isolated snapshot tree differs from the pin');
    const gitDir = git(snapshot, ['rev-parse', '--absolute-git-dir']).trim();
    for (const special of [join(gitDir, 'objects', 'info', 'alternates'), join(gitDir, 'info', 'attributes'), join(gitDir, 'info', 'grafts')]) {
      if (existsSync(special)) fail('isolated snapshot contains prohibited special metadata');
    }
    if (optionalGit(snapshot, ['config', '--get', 'core.attributesFile'])) fail('isolated snapshot contains core.attributesFile');
    const entries = parseTree(snapshot, sha);
    const blobs = readBlobs(snapshot, entries);
    mkdirSync(fullDestination);
    entries.forEach((entry, index) => {
      const output = join(fullDestination, ...entry.path.split('/'));
      mkdirSync(dirname(output), { recursive: true });
      writeFileSync(output, blobs[index], { flag: 'wx' });
      if (process.platform !== 'win32' && entry.mode === '100755') chmodSync(output, 0o755);
    });
    verifyDestination(fullDestination, entries);
    return { sha, tree, entries: entries.length };
  } catch (error) {
    if (existsSync(fullDestination)) rmSync(fullDestination, { recursive: true, force: true });
    throw error;
  } finally {
    rmSync(snapshot, { recursive: true, force: true });
  }
}

function main() {
  const [command, source, sha, tree, destination, ownedRoot] = process.argv.slice(2);
  if (command !== 'export' || !ownedRoot) fail('command is invalid');
  process.stdout.write(`${JSON.stringify(exportExactCommit({ source, sha, tree, destination, ownedRoot }))}\n`);
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  try { main(); } catch (error) { console.error(error.message); process.exitCode = 1; }
}
