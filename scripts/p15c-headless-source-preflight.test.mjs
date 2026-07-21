import assert from 'node:assert/strict';
import test from 'node:test';

import { validateDotnetRuntimeInventory, validateImageLock, validateNodeInventory, validateSdkInventory, validateSourcePinTable, validateSourceRecord } from './p15c-headless-source-preflight.mjs';

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
  const pins = [{ name: 'xnode', path: 'C:\\xnode', sha: 'cd9d20a8ec8346d171d4cd070dde170aa5f471d7', tree: 'e27c1d7c2517bd9d1bcdfbacda8c68c57a2ced59' }];
  assert.equal(validateSourcePinTable(pins), true);
  assert.throws(() => validateSourcePinTable([{ ...pins[0], sha: carrier }]));
  assert.throws(() => validateSourcePinTable([{ ...pins[0], path: 'C:\\carrier' }]));
  assert.throws(() => validateSourcePinTable([{ ...pins[0], tree: 'f'.repeat(40) }]));
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
