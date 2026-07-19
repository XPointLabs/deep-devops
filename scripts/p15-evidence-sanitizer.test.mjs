import assert from 'node:assert/strict';
import test from 'node:test';

async function sanitizer() {
  return import('./p15-evidence-sanitizer.mjs');
}

const safeEvidence = {
  schema: 'deep-p15-compat-lab-evidence.v1',
  evidenceClass: 'compatibility-lab',
  productRuntime: false,
  clock: '2026-07-20T00:00:00.000Z',
  source: {
    sha: '1c01e24e24647a46b4f37622f3934dc2cc1284ef',
    tree: 'f608ecf9a53d1ce2c99d9c71bdebe4e95b2ebea2'
  },
  image: {
    baseDigest: 'sha256:242549cd46785b480c832479a730f4f2a20865d61ea2e404fdb2a5c3d3b73ecf',
    baseImageId: 'sha256:242549cd46785b480c832479a730f4f2a20865d61ea2e404fdb2a5c3d3b73ecf',
    contextSha256: `sha256:${'6'.repeat(64)}`,
    architecture: 'arm64'
  },
  scenarios: {
    'source-lock': 'pass',
    'image-lock': 'pass',
    'empty-start': 'pass',
    'health-identity': 'pass',
    operations: 'pass',
    'restart-persistence': 'pass',
    'network-fault-recovery': 'pass',
    'privacy-scan': 'pass',
    cleanup: 'pass'
  },
  counts: {
    services: 4,
    probes: 4,
    restarts: 4,
    networkFaults: 1,
    residualResources: 0,
    residualImages: 0
  },
  durationBoundsMs: {
    health: 30_000,
    operation: 5_000,
    networkFailure: 5_000
  },
  result: 'pass'
};

test('allowlisted evidence is canonical and accepted', async () => {
  const { sanitizeEvidence, canonicalJson } = await sanitizer();
  const first = sanitizeEvidence(structuredClone(safeEvidence));
  const second = sanitizeEvidence(structuredClone(safeEvidence));
  assert.deepEqual(first, safeEvidence);
  assert.equal(canonicalJson(first), canonicalJson(second));
});

test('private keys, seeds, tokens and bearer values are hard failures', async () => {
  const { sanitizeEvidence } = await sanitizer();
  for (const [field, value] of [
    ['privateKey', '1'.repeat(64)],
    ['seed', '2'.repeat(64)],
    ['token', 'device-token-value'],
    ['authorization', 'Bearer example-secret-value']
  ]) {
    assert.throws(
      () => sanitizeEvidence({ ...safeEvidence, [field]: value }),
      /privacy|secret|forbidden/i
    );
  }
});

test('public keys, Session, mailbox and capability identifiers are hard failures', async () => {
  const { sanitizeEvidence } = await sanitizer();
  for (const [field, value] of [
    ['publicKey', '3'.repeat(64)],
    ['sessionId', `05${'4'.repeat(64)}`],
    ['mailboxId', 'mailbox-example'],
    ['capabilityId', 'capability-example']
  ]) {
    assert.throws(
      () => sanitizeEvidence({ ...safeEvidence, [field]: value }),
      /privacy|identifier|forbidden/i
    );
  }
});

test('URLs, machine paths and container IDs are hard failures', async () => {
  const { sanitizeEvidence } = await sanitizer();
  for (const [field, value] of [
    ['endpoint', 'https://example.invalid/private'],
    ['path', 'C:\\Users\\operator\\private'],
    ['containerId', 'a'.repeat(64)]
  ]) {
    assert.throws(
      () => sanitizeEvidence({ ...safeEvidence, [field]: value }),
      /privacy|path|identifier|forbidden/i
    );
  }
});

test('raw responses, environment dumps and payload/message hashes are hard failures', async () => {
  const { sanitizeEvidence } = await sanitizer();
  for (const [field, value] of [
    ['rawResponse', '{"ok":true}'],
    ['environment', { PATH: '/private' }],
    ['payloadHash', 'b'.repeat(64)],
    ['messageSha256', 'c'.repeat(64)]
  ]) {
    assert.throws(
      () => sanitizeEvidence({ ...safeEvidence, [field]: value }),
      /privacy|raw|environment|hash|forbidden/i
    );
  }
});

test('privacy and secret findings can never be warnings', async () => {
  const { sanitizeEvidence } = await sanitizer();
  assert.throws(() => sanitizeEvidence({
    ...safeEvidence,
    findings: [{ severity: 'warning', rule: 'secret' }]
  }), /finding|warning|forbidden/i);
});
