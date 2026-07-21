import assert from 'node:assert/strict';
import test from 'node:test';

import { canonicalJson, sanitizeEvidence } from './p15c-evidence-sanitizer.mjs';

test('bounded evidence allows only aggregated headless results', () => {
  const value = { schema: 'deep-p15c-headless-evidence.v1', evidenceClass: 'headless-harness', productRuntime: false, result: 'pass', gates: { source: 'pass', images: 'pass', contracts: 'pass', runtime: 'pass', e2e: 'pass', cleanup: 'pass' }, counts: { services: 11, tests: 12 } };
  assert.deepEqual(sanitizeEvidence(value), value);
  assert.equal(canonicalJson(value).endsWith('\n'), true);
});

test('evidence rejects paths, endpoints, Docker ids, keys and payload identifiers recursively', () => {
  for (const value of [
    { path: 'C:\\secret' },
    { endpoint: 'http://127.0.0.1:1' },
    { containerId: 'a'.repeat(64) },
    { privateKey: 'x' },
    { payloadId: 'x' },
    { rawResponse: { ok: true } },
    { environmentDump: { SAFE: 'still forbidden raw environment' } },
    { rawLogs: ['container output'] },
    { resourceIds: ['abc'] },
    { nested: { mnemonic: 'x' } }
  ]) assert.throws(() => sanitizeEvidence(value));
});
