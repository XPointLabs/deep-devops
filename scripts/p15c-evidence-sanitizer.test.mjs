import assert from 'node:assert/strict';
import test from 'node:test';

import { parseEvidenceJson, canonicalJson, sanitizeEvidence } from './p15c-evidence-sanitizer.mjs';

const validEvidence = () => ({
  schema: 'deep-p15c-headless-evidence.v1',
  evidenceClass: 'headless-harness',
  productRuntime: false,
  result: 'pass',
  gates: { source: 'pass', images: 'pass', contracts: 'pass', runtime: 'pass', e2e: 'pass', cleanup: 'pass' },
  counts: { services: 11, xnodes: 3, localContracts: 4 }
});

test('bounded evidence allows only aggregated headless results', () => {
  const value = validEvidence();
  assert.deepEqual(sanitizeEvidence(value), value);
  assert.equal(canonicalJson(value).endsWith('\n'), true);
});

test('evidence schema is an exact allowlist with exact counts and no positive product claims', () => {
  const valid = validEvidence();
  for (const mutation of [
    value => { value.productionReady = true; },
    value => { value.deviceE2E = 'GO'; },
    value => { value.profileActivation = true; },
    value => { value.claim = 'PRODUCT-RUNTIME-GO'; },
    value => { value.claim = 'VLESS-GO'; },
    value => { value.gates.extra = 'pass'; },
    value => { value.gates.runtime = 'skip'; },
    value => { value.counts.tests = 39; },
    value => { value.counts.services = 12; },
    value => { value.counts.xnodes = 2; },
    value => { value.counts.localContracts = 5; }
  ]) {
    const candidate = structuredClone(valid);
    mutation(candidate);
    assert.throws(() => sanitizeEvidence(candidate));
  }
});

test('raw evidence parser rejects duplicate object keys before JSON normalization', () => {
  const raw = JSON.stringify(validEvidence()).replace('"result":"pass"', '"result":"pass","result":"pass"');
  assert.throws(() => parseEvidenceJson(raw), /duplicate/i);
  assert.deepEqual(parseEvidenceJson(JSON.stringify(validEvidence())), validEvidence());
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
