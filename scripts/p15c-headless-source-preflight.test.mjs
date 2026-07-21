import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { inspectSource, validateDotnetRuntimeInventory, validateImageLock, validateNodeInventory, validateSdkInventory, validateSourcePinTable, validateSourceRecord } from './p15c-headless-source-preflight.mjs';

const sha = 'a'.repeat(40);
const tree = 'b'.repeat(40);
const digest = `sha256:${'c'.repeat(64)}`;

test('source record requires canonical clean exact non-shallow Git root', () => {
  const valid = { expectedPath: 'C:\\source', canonicalPath: 'C:\\source', gitRoot: 'C:\\source', sha, tree, expectedSha: sha, expectedTree: tree, dirty: false, reparse: false, shallow: false, replaceRefs: [], alternates: [], grafts: false };
  assert.equal(validateSourceRecord(valid), true);
  for (const patch of [{ dirty: true }, { reparse: true }, { shallow: true }, { replaceRefs: ['x'] }, { alternates: ['x'] }, { grafts: true }, { sha: 'd'.repeat(40) }, { tree: 'd'.repeat(40) }, { gitRoot: 'C:\\other' }, { expectedPath: 'C:\\carrier' }]) {
    assert.throws(() => validateSourceRecord({ ...valid, ...patch }));
  }
});

test('runtime and Node inventories are exact accepted versions', () => {
  assert.equal(validateDotnetRuntimeInventory('Microsoft.AspNetCore.App 10.0.10\nMicrosoft.NETCore.App 10.0.10\n'), true);
  assert.throws(() => validateDotnetRuntimeInventory('Microsoft.AspNetCore.App 10.0.9\nMicrosoft.NETCore.App 10.0.10\n'));
  assert.equal(validateNodeInventory('v24.16.0\n'), true);
  assert.throws(() => validateNodeInventory('v24.15.0\n'));
});

test('exact source pin table rejects the known P14C2 evidence carrier even if self-consistent', () => {
  const carrier = '2a21902ff5a613242180fdd75233991da896f879';
  const pins = [
    { name: 'xnode', path: 'C:\\W\\deep-survival\\wave09\\xnode-p15c-source', sha: 'cd9d20a8ec8346d171d4cd070dde170aa5f471d7', tree: 'e27c1d7c2517bd9d1bcdfbacda8c68c57a2ced59' },
    { name: 'e2e', path: 'C:\\Work\\DeepSession\\XPointLabs\\deep-tests-e2e', sha: 'da24f530f187dbd81258905bc28feedce0eb23eb', tree: '566ee86cd01ec5a32d3ad60d1c9eac9183328c1f' },
    { name: 'registry', path: 'C:\\Work\\DeepSession\\XPointLabs\\deep-registry-api', sha: 'fb7ebac6404e7a53241af08bb2f80d8a81022be8', tree: 'be7a44e68933fa0773e81f6ad898feebd752a67a' },
    { name: 'staking', path: 'C:\\Work\\DeepSession\\XPointLabs\\xpoint-staking-backend', sha: 'c4638486d1f658f3cda2b5060eb3709e255d7288', tree: 'a0dafebbd380425e5b4c5e86bdb3138bf77fa3e0' },
    { name: 'contracts', path: 'C:\\Work\\DeepSession\\XPointLabs\\xpoint-staking-contracts', sha: 'd5063212b491b4c7bd649a3ab367491dfed9909f', tree: '89f506e9c1c33cce0e1ad928b72602aa533b012c' }
  ];
  assert.equal(validateSourcePinTable(pins), true);
  assert.throws(() => validateSourcePinTable([{ ...pins[0], sha: carrier }]));
  assert.throws(() => validateSourcePinTable([{ ...pins[0], path: 'C:\\carrier' }]));
  assert.throws(() => validateSourcePinTable([{ ...pins[0], tree: 'f'.repeat(40) }]));
  for (const pin of pins.slice(1)) {
    assert.throws(() => validateSourcePinTable([{ ...pin, sha: 'f'.repeat(40) }]));
    assert.throws(() => validateSourcePinTable([{ ...pin, path: `${pin.path}-other` }]));
  }
});

test('inspectSource checks common-dir alternates and grafts for linked worktrees', () => {
  const root = mkdtempSync(join(tmpdir(), 'p15c-linked-'));
  const main = join(root, 'main');
  const linked = join(root, 'linked');
  try {
    mkdirSync(main);
    execFileSync('git', ['init', main]);
    execFileSync('git', ['-C', main, 'config', 'user.email', 'p15c@example.invalid']);
    execFileSync('git', ['-C', main, 'config', 'user.name', 'P15C Test']);
    writeFileSync(join(main, 'source.txt'), 'exact source\n');
    execFileSync('git', ['-C', main, 'add', 'source.txt']);
    execFileSync('git', ['-C', main, 'commit', '-m', 'source']);
    execFileSync('git', ['-C', main, 'worktree', 'add', '--detach', linked, 'HEAD']);
    const sha = execFileSync('git', ['-C', linked, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
    const tree = execFileSync('git', ['-C', linked, 'rev-parse', 'HEAD^{tree}'], { encoding: 'utf8' }).trim();
    assert.deepEqual(inspectSource({ path: linked, sha, tree }), { sha, tree });
    const common = execFileSync('git', ['-C', linked, 'rev-parse', '--git-common-dir'], { encoding: 'utf8' }).trim();
    const commonPath = common.match(/^[A-Za-z]:[\\/]/) ? common : join(linked, common);
    const objectInfo = join(commonPath, 'objects', 'info');
    mkdirSync(objectInfo, { recursive: true });
    writeFileSync(join(objectInfo, 'alternates'), join(root, 'foreign-objects'));
    assert.throws(() => inspectSource({ path: linked, sha, tree }));
    rmSync(join(objectInfo, 'alternates'));
    writeFileSync(join(commonPath, 'info', 'grafts'), `${sha} ${'0'.repeat(40)}\n`);
    assert.throws(() => inspectSource({ path: linked, sha, tree }));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('image lock requires local exact RepoDigest on Linux ARM64', () => {
  const reference = `node@${digest}`;
  const valid = { reference, expectedReference: reference, id: digest, repoDigests: [reference], os: 'linux', architecture: 'arm64' };
  assert.equal(validateImageLock(valid), true);
  assert.throws(() => validateImageLock({ ...valid, id: '' }));
  assert.throws(() => validateImageLock({ ...valid, architecture: 'amd64' }));
  assert.throws(() => validateImageLock({ ...valid, reference: 'node:latest' }));
});

test('SDK inventory is exactly 10.0.301', () => {
  assert.equal(validateSdkInventory('10.0.301\n'), true);
  assert.throws(() => validateSdkInventory('10.0.100\n'));
  assert.throws(() => validateSdkInventory('10.0.301\n10.0.400\n'));
});
