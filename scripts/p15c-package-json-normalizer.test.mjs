import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { normalizePackageJson } from './p15c-package-json-normalizer.mjs';

async function withTempFile(bytes, action) {
  const root = await mkdtemp(join(tmpdir(), 'p15c-package-json-'));
  const path = join(root, 'package.json');
  try {
    await writeFile(path, bytes);
    await action(path);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

test('tracked UTF-8 BOM is removed without rewriting package JSON', async () => {
  const json = Buffer.from('{"name":"contracts","private":true}\r\n');
  await withTempFile(Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), json]), async path => {
    assert.equal(await normalizePackageJson(path), true);
    assert.deepEqual(await readFile(path), json);
  });
});

test('BOM-free package JSON bytes remain untouched', async () => {
  const json = Buffer.from('{ "name": "contracts" }\n');
  await withTempFile(json, async path => {
    assert.equal(await normalizePackageJson(path), false);
    assert.deepEqual(await readFile(path), json);
  });
});

test('malformed or non-UTF-8 package JSON fails closed without mutation', async () => {
  for (const bytes of [Buffer.from('{'), Buffer.from([0xef, 0xbb, 0xbf, 0xff])]) {
    await withTempFile(bytes, async path => {
      await assert.rejects(() => normalizePackageJson(path));
      assert.deepEqual(await readFile(path), bytes);
    });
  }
});
