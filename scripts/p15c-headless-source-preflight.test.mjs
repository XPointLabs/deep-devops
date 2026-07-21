import assert from 'node:assert/strict';
import test from 'node:test';

import { validateImageLock, validateSdkInventory, validateSourceRecord } from './p15c-headless-source-preflight.mjs';

const sha = 'a'.repeat(40);
const tree = 'b'.repeat(40);
const digest = `sha256:${'c'.repeat(64)}`;

test('source record requires canonical clean exact non-shallow Git root', () => {
  const valid = { expectedPath: 'C:\\source', canonicalPath: 'C:\\source', gitRoot: 'C:\\source', sha, tree, expectedSha: sha, expectedTree: tree, dirty: false, reparse: false, shallow: false, replaceRefs: [], alternates: [], grafts: false };
  assert.equal(validateSourceRecord(valid), true);
  for (const patch of [{ dirty: true }, { reparse: true }, { shallow: true }, { replaceRefs: ['x'] }, { alternates: ['x'] }, { sha: 'd'.repeat(40) }, { gitRoot: 'C:\\other' }]) {
    assert.throws(() => validateSourceRecord({ ...valid, ...patch }));
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
