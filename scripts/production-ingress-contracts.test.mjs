import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import test from 'node:test';

test('production ingress static security contract passes', () => {
  const script = path.join(import.meta.dirname, 'production-ingress-contracts.mjs');
  const result = spawnSync(process.execPath, [script], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr || result.stdout);
  const summary = JSON.parse(result.stdout);
  assert.equal(summary.status, 'ok');
  assert.ok(summary.checked >= 13);
});
