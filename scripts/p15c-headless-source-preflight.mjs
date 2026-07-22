import { execFileSync, spawnSync } from 'node:child_process';
import { lstatSync, realpathSync, readFileSync } from 'node:fs';
import { dirname, join, normalize, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

function fail(message) { throw new Error(`P15C source preflight failure: ${message}`); }
function normalized(value) { return normalize(resolve(value)).replace(/[\\/]+$/, '').toLowerCase(); }

export function validateSourceRecord(value) {
  if (normalized(value.expectedPath) !== normalized(value.canonicalPath) || normalized(value.gitRoot) !== normalized(value.canonicalPath)) fail('source path is not the canonical Git root');
  if (value.sha !== value.expectedSha || !/^[0-9a-f]{40}$/.test(value.sha ?? '')) fail('source SHA does not match');
  if (value.tree !== value.expectedTree || !/^[0-9a-f]{40}$/.test(value.tree ?? '')) fail('source tree does not match');
  if (value.dirty) fail('source tree is dirty');
  if (value.reparse) fail('source path contains a symlink or reparse point');
  if (value.shallow) fail('shallow repository is prohibited');
  if ((value.replaceRefs ?? []).length) fail('replace refs are prohibited');
  if ((value.alternates ?? []).length) fail('object alternates are prohibited');
  if (value.grafts) fail('grafts are prohibited');
  if ((value.indexFlags ?? []).length) fail('skip-worktree, assume-unchanged or nonstandard index flags are prohibited');
  if (value.trackedContentMatches !== true) fail('tracked worktree content differs from the exact index');
  if (value.sparse) fail('sparse checkout or sparse index is prohibited');
  if ((value.ambientGitOverrides ?? []).length) fail('ambient GIT_* overrides are prohibited');
  return true;
}

export function validateImageLock(value) {
  if (value.reference !== value.expectedReference || !/^[a-z0-9./_-]+@sha256:[0-9a-f]{64}$/.test(value.reference ?? '')) fail('image reference is not the exact digest lock');
  if (!/^sha256:[0-9a-f]{64}$/.test(value.id ?? '') || !Array.isArray(value.repoDigests) || !value.repoDigests.includes(value.reference)) fail('exact local RepoDigest is missing');
  if (value.os !== 'linux' || value.architecture !== 'arm64') fail('image must be Linux ARM64');
  return true;
}

export function validateSdkInventory(output) {
  const versions = String(output).trim().split(/\r?\n/).filter(Boolean);
  if (versions.length !== 1 || versions[0] !== '10.0.301') fail('SDK inventory must contain exactly 10.0.301');
  return true;
}

export function validateDotnetRuntimeInventory(output) {
  const versions = String(output).trim().split(/\r?\n/).filter(Boolean).sort();
  const expected = ['Microsoft.AspNetCore.App 10.0.10', 'Microsoft.NETCore.App 10.0.10'];
  if (versions.length !== 2 || !versions.every((value, index) => value === expected[index])) fail('ASP.NET runtime inventory must be exactly 10.0.10');
  return true;
}

export function validateNodeInventory(output) {
  if (String(output).trim() !== 'v24.16.0') fail('Node inventory must be exactly 24.16.0');
  return true;
}

const acceptedPins = Object.freeze({
  xnode: Object.freeze({
    path: 'C:\\W\\deep-survival\\wave09\\xnode-p15c-source',
    sha: 'cd9d20a8ec8346d171d4cd070dde170aa5f471d7',
    tree: 'e27c1d7c2517bd9d1bcdfbacda8c68c57a2ced59'
  }),
  e2e: Object.freeze({ path: 'C:\\Work\\DeepSession\\XPointLabs\\deep-tests-e2e', sha: 'da24f530f187dbd81258905bc28feedce0eb23eb', tree: '566ee86cd01ec5a32d3ad60d1c9eac9183328c1f' }),
  registry: Object.freeze({ path: 'C:\\Work\\DeepSession\\XPointLabs\\deep-registry-api', sha: 'fb7ebac6404e7a53241af08bb2f80d8a81022be8', tree: 'be7a44e68933fa0773e81f6ad898feebd752a67a' }),
  staking: Object.freeze({ path: 'C:\\Work\\DeepSession\\XPointLabs\\xpoint-staking-backend', sha: 'c4638486d1f658f3cda2b5060eb3709e255d7288', tree: 'a0dafebbd380425e5b4c5e86bdb3138bf77fa3e0' }),
  contracts: Object.freeze({ path: 'C:\\Work\\DeepSession\\XPointLabs\\xpoint-staking-contracts', sha: 'd5063212b491b4c7bd649a3ab367491dfed9909f', tree: '89f506e9c1c33cce0e1ad928b72602aa533b012c' })
});
const prohibitedCarrierShas = new Set(['2a21902ff5a613242180fdd75233991da896f879']);
const exactManifestNames = Object.freeze(['DevOps', 'XNode', 'E2E', 'Registry', 'Staking', 'Contracts']);

export function validateSourcePinTable(pins) {
  const names = Object.keys(acceptedPins);
  if (!Array.isArray(pins) || pins.length !== names.length || pins.some((pin, index) => pin?.name !== names[index])) fail('source pin table must contain the exact canonical source set');
  for (const pin of pins) {
    const expected = acceptedPins[pin?.name];
    if (!expected || prohibitedCarrierShas.has(pin.sha) || normalized(pin.path) !== normalized(expected.path) || pin.sha !== expected.sha || pin.tree !== expected.tree) fail(`exact accepted source pin is invalid for ${pin?.name ?? 'unknown'}`);
  }
  return true;
}

function git(root, args) { return execFileSync('git', ['-C', root, ...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim(); }
function gitOptional(root, args) {
  const result = spawnSync('git', ['-C', root, ...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  if (result.status === 1) return '';
  if (result.error || result.status !== 0) fail('optional Git query failed');
  return result.stdout.trim();
}

function hasReparseComponent(path) {
  let current = resolve(path);
  while (true) {
    if (lstatSync(current).isSymbolicLink()) return true;
    const parent = dirname(current);
    if (parent === current) return false;
    current = parent;
  }
}

export function inspectSource({ path, sha, tree }) {
  const ambientGitOverrides = Object.keys(process.env).filter(name => name.toUpperCase().startsWith('GIT_') && String(process.env[name] ?? '').trim()).sort();
  const canonicalPath = realpathSync.native(path);
  const gitRoot = git(canonicalPath, ['rev-parse', '--show-toplevel']);
  const gitDirRaw = git(canonicalPath, ['rev-parse', '--git-dir']);
  const gitDir = resolve(canonicalPath, gitDirRaw);
  const commonDirRaw = git(canonicalPath, ['rev-parse', '--git-common-dir']);
  const commonDir = resolve(canonicalPath, commonDirRaw);
  const alternatesPaths = [...new Set([join(commonDir, 'objects', 'info', 'alternates'), join(gitDir, 'objects', 'info', 'alternates')])];
  const graftsPaths = [...new Set([join(commonDir, 'info', 'grafts'), join(gitDir, 'info', 'grafts')])];
  let alternates = [];
  for (const alternatesPath of alternatesPaths) { try { alternates.push(...readFileSync(alternatesPath, 'utf8').split(/\r?\n/).filter(Boolean)); } catch {} }
  const indexFlags = git(canonicalPath, ['ls-files', '-v']).split(/\r?\n/).filter(line => /^[a-zS]/.test(line));
  const diffFiles = spawnSync('git', ['-C', canonicalPath, 'diff-files', '--quiet', '--ignore-submodules=none', '--'], { stdio: 'ignore' });
  if (diffFiles.error || ![0, 1].includes(diffFiles.status)) fail('tracked content comparison failed');
  const sparse = gitOptional(canonicalPath, ['config', '--bool', 'core.sparseCheckout']) === 'true'
    || gitOptional(canonicalPath, ['config', '--bool', 'index.sparse']) === 'true';
  const record = {
    expectedPath: path,
    canonicalPath,
    gitRoot,
    sha: git(canonicalPath, ['rev-parse', 'HEAD']),
    tree: git(canonicalPath, ['rev-parse', 'HEAD^{tree}']),
    expectedSha: sha,
    expectedTree: tree,
    dirty: git(canonicalPath, ['status', '--porcelain=v1', '--untracked-files=all']) !== '',
    reparse: hasReparseComponent(canonicalPath),
    shallow: git(canonicalPath, ['rev-parse', '--is-shallow-repository']) === 'true',
    replaceRefs: git(canonicalPath, ['replace', '-l']).split(/\r?\n/).filter(Boolean),
    alternates,
    grafts: graftsPaths.some(graftsPath => { try { return lstatSync(graftsPath).isFile(); } catch { return false; } }),
    indexFlags,
    trackedContentMatches: diffFiles.status === 0,
    sparse,
    ambientGitOverrides
  };
  validateSourceRecord(record);
  return { sha: record.sha, tree: record.tree };
}

async function main() {
  const [command, manifestPath] = process.argv.slice(2);
  if (command !== 'check-sources' || !manifestPath) fail('command is invalid');
  const inputs = JSON.parse(readFileSync(manifestPath, 'utf8'));
  if (!inputs || typeof inputs !== 'object' || Array.isArray(inputs) || Object.keys(inputs).join(',') !== 'sources' || !Array.isArray(inputs.sources) || inputs.sources.length !== exactManifestNames.length) fail('source manifest envelope is invalid');
  if (!inputs.sources.every((source, index) => source?.name === exactManifestNames[index] && Object.keys(source).sort().join(',') === 'name,path,sha,tree')) fail('source manifest must contain the exact ordered six-source set');
  validateSourcePinTable(inputs.sources.slice(1).map(source => ({ name: source.name.toLowerCase() === 'xnode' ? 'xnode' : source.name.toLowerCase(), path: source.path, sha: source.sha, tree: source.tree })));
  for (const source of inputs.sources ?? []) inspectSource(source);
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) main().catch(error => { console.error(error.message); process.exitCode = 1; });
