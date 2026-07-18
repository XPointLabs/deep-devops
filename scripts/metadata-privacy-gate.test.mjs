import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {
  featureFlag,
  inspectMetadataText,
  lintMetricText,
  metadataSafeProfile,
  renderMetadataSafeTopology,
  repositoryRoot,
  runGate,
  scanSelectedPaths,
  validateBreakGlassReceipt,
  validateMetadataSafeTopology,
  validateRetentionPolicy,
  validateXrayGeneratorSource
} from './metadata-privacy-gate.mjs';

const syntheticSession = `05${'11'.repeat(32)}`;
const syntheticPushToken = 'synthetic-push-provider-token-p01b';
const syntheticMailbox = 'synthetic-mailbox-capability-p01b';

async function fixtureRoot() {
  return mkdtemp(path.join(tmpdir(), 'deep-p01b-metadata-'));
}

async function loadPolicy() {
  return validateRetentionPolicy(JSON.parse(await readFile(
    path.join(repositoryRoot, 'config', 'metadata-safe', 'retention-policy.v1.json'),
    'utf8'
  )));
}

function validReceipt(policy) {
  return {
    schema: 'deep-metadata-break-glass-receipt.v1',
    humanOwner: 'Mr. X',
    status: 'closed',
    reasonCode: 'incident-response',
    openedAt: '2030-01-01T00:00:00.000Z',
    closedAt: '2030-01-01T00:15:00.000Z',
    accessRevoked: true,
    rawExportDeleted: true,
    deletionVerified: true,
    operationalLogKeyRef: policy.keySeparation.operationalLogKeyRef,
    evidenceKeyRef: policy.keySeparation.evidenceKeyRef,
    containsRawIdentifiers: false,
    evidence: {
      ticketId: 'synthetic-ticket-reference',
      deletionCheckId: 'synthetic-deletion-check-reference'
    }
  };
}

test('retention policy inventories every metadata domain and separates log keys', async () => {
  const policy = await loadPolicy();
  assert.equal(policy.components.length, 7);
  assert.notEqual(
    policy.keySeparation.operationalLogKeyRef,
    policy.keySeparation.evidenceKeyRef
  );
  assert.equal(policy.components.find(item => item.component === 'provider-push').retentionHours, null);
});

test('metadata scanner rejects synthetic ingress, mailbox, push and correlation joins without echoing values', () => {
  const seeded = [
    'client_ip=198.51.100.77',
    `path=/subscriptions/${syntheticSession}`,
    `push_token=${syntheticPushToken}`,
    `mailbox_capability=${syntheticMailbox}`,
    'correlation_id=synthetic-correlation-p01b'
  ].join('\n');
  const findings = inspectMetadataText(seeded, 'synthetic-seeded.log');
  const rules = new Set(findings.map(item => item.ruleId));
  for (const expected of [
    'source-ip-field',
    'raw-session-identifier',
    'sensitive-request-target',
    'raw-push-handle',
    'raw-mailbox-capability',
    'stable-cross-domain-correlation'
  ]) {
    assert.ok(rules.has(expected), `missing ${expected}`);
  }
  assert.ok(!JSON.stringify(findings).includes(syntheticSession));
  assert.ok(!JSON.stringify(findings).includes(syntheticPushToken));
  assert.ok(!JSON.stringify(findings).includes(syntheticMailbox));
});

test('metric lint rejects identifier and path labels while preserving aggregate operational labels', () => {
  const clean = 'deep_requests_total{service="storage",operation="store",status_code="503",error_class="unavailable"} 1\n';
  assert.deepEqual(lintMetricText(clean), []);

  const seeded = [
    `deep_requests_total{service="storage",session_id="${syntheticSession}"} 1`,
    `deep_requests_total{service="push",push_token="${syntheticPushToken}"} 1`,
    'deep_requests_total{service="router",client_ip="198.51.100.77"} 1',
    'deep_requests_total{service="router",path="/storage/retrieve"} 1'
  ].join('\n');
  const findings = lintMetricText(seeded, 'synthetic-metrics.prom');
  assert.ok(findings.some(item => item.ruleId === 'metric-sensitive-label-name'));
  assert.ok(findings.some(item => item.ruleId === 'metric-label-not-allowlisted'));
  assert.ok(findings.some(item => item.ruleId === 'raw-session-identifier'));

  const jsonFindings = lintMetricText(
    '{"metric":"deep_requests_total","labels":{"mailbox_id":"synthetic-mailbox-label"}}',
    'synthetic-metrics.json'
  );
  assert.ok(jsonFindings.some(item => item.ruleId === 'metric-sensitive-label-name'));
});

test('selected artifact scanner is clean by default and deliberately seeded leaks fail', async () => {
  const root = await fixtureRoot();
  try {
    const clean = path.join(root, 'clean.json');
    await writeFile(clean, '{"service":"storage","status":"unavailable","error_class":"upstream"}\n');
    assert.deepEqual((await scanSelectedPaths([clean])).findings, []);

    const seeded = path.join(root, 'seeded.log');
    await writeFile(
      seeded,
      `source_ip=198.51.100.77 path=/inbox/${syntheticSession} push_token=${syntheticPushToken}\n`
    );
    assert.ok((await scanSelectedPaths([seeded])).findings.length >= 3);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('break-glass receipt requires closure, deletion verification and separate key references', async () => {
  const policy = await loadPolicy();
  assert.equal(validateBreakGlassReceipt(validReceipt(policy), policy).status, 'closed');

  for (const mutate of [
    receipt => { receipt.status = 'open'; },
    receipt => { receipt.deletionVerified = false; },
    receipt => { receipt.rawExportDeleted = false; },
    receipt => { receipt.evidenceKeyRef = receipt.operationalLogKeyRef; },
    receipt => { receipt.closedAt = '2030-01-01T02:00:00.000Z'; },
    receipt => { receipt.containsRawIdentifiers = true; }
  ]) {
    const receipt = validReceipt(policy);
    mutate(receipt);
    assert.throws(() => validateBreakGlassReceipt(receipt, policy));
  }
});

test('metadata-safe compose profile is exact, bounded and keeps operational warnings visible', () => {
  const topology = validateMetadataSafeTopology(renderMetadataSafeTopology());
  assert.equal(topology.services['xnode-1'].logging.options['max-file'], '2');
  assert.equal(
    topology.services['xnode-1'].environment.Logging__LogLevel__Default,
    'Warning'
  );
});

test('metadata-safe topology rejects profile, retention and operational visibility mutations', () => {
  const topology = renderMetadataSafeTopology();
  for (const mutate of [
    value => { value.services.storage.environment.DEEP_INFRA_PRIVACY_PROFILE = 'default'; },
    value => { value.services.push.logging.options['max-file'] = '20'; },
    value => { value.services.calls.logging.driver = 'json-file'; },
    value => { value.services['xnode-1'].environment.Logging__LogLevel__Default = 'Information'; },
    value => { delete value.services.file.labels['io.deep.infrastructure-privacy-profile']; }
  ]) {
    const candidate = structuredClone(topology);
    mutate(candidate);
    assert.throws(() => validateMetadataSafeTopology(candidate));
  }
});

test('Xray contract keeps warning/error visibility but has no access sink', async () => {
  const xnodeDir = path.resolve(repositoryRoot, '..', 'xnode');
  const source = await readFile(
    path.join(xnodeDir, 'src', 'XNode.Transport.Vless', 'XrayConfigGenerator.cs'),
    'utf8'
  );
  assert.equal(validateXrayGeneratorSource(source), true);
  assert.throws(() => validateXrayGeneratorSource(source.replace(
    '["loglevel"] = "warning"',
    '["loglevel"] = "info", ["access"] = "/var/log/xray/access.log"'
  )));
});

test('strict gate rejects absent or wrong profile before inspecting evidence', async () => {
  const previous = process.env[featureFlag];
  try {
    delete process.env[featureFlag];
    await assert.rejects(() => runGate({}), /must be exact metadata-safe-v1/);
    process.env[featureFlag] = 'default';
    await assert.rejects(() => runGate({}), /must be exact metadata-safe-v1/);
  } finally {
    if (previous === undefined) delete process.env[featureFlag];
    else process.env[featureFlag] = previous;
  }
});

test('strict gate binds P01, pinned XNode, compose profile and clean selected evidence', async () => {
  const root = await fixtureRoot();
  const previous = process.env[featureFlag];
  try {
    const artifact = path.join(root, 'evidence.json');
    const metrics = path.join(root, 'metrics.prom');
    await writeFile(artifact, '{"service":"router","status":"degraded","error_class":"upstream"}\n');
    await writeFile(metrics, 'deep_requests_total{service="router",status_code="503"} 1\n');
    process.env[featureFlag] = metadataSafeProfile;
    const summary = await runGate({
      artifactPaths: [artifact],
      metricPaths: [metrics],
      xnodeDir: path.resolve(repositoryRoot, '..', 'xnode'),
      clientExpectationsPath: path.resolve(
        repositoryRoot,
        '..',
        'deep-client-shared',
        'tests',
        'Deep.Client.Shared.Tests',
        'Fixtures',
        'metadata-expectations.v1.json'
      )
    });
    assert.equal(summary.status, 'ok');
    assert.equal(summary.findingCount, 0);
    assert.equal(summary.topologyServices, 7);
    assert.equal(summary.providerDeletionGuaranteed, false);
    assert.equal(summary.productionReady, false);
  } finally {
    if (previous === undefined) delete process.env[featureFlag];
    else process.env[featureFlag] = previous;
    await rm(root, { recursive: true, force: true });
  }
});

test('strict gate returns failed summary for deliberately seeded cross-domain evidence', async () => {
  const root = await fixtureRoot();
  const previous = process.env[featureFlag];
  try {
    const artifact = path.join(root, 'seeded.log');
    const metrics = path.join(root, 'clean.prom');
    await writeFile(
      artifact,
      `client_ip=198.51.100.77 path=/mailbox/${syntheticSession} push_token=${syntheticPushToken}\n`
    );
    await writeFile(metrics, 'deep_requests_total{service="router",status_code="503"} 1\n');
    process.env[featureFlag] = metadataSafeProfile;
    const summary = await runGate({
      artifactPaths: [artifact],
      metricPaths: [metrics],
      xnodeDir: path.resolve(repositoryRoot, '..', 'xnode'),
      clientExpectationsPath: path.resolve(
        repositoryRoot,
        '..',
        'deep-client-shared',
        'tests',
        'Deep.Client.Shared.Tests',
        'Fixtures',
        'metadata-expectations.v1.json'
      )
    });
    assert.equal(summary.status, 'failed');
    assert.ok(summary.findingCount >= 4);
    assert.ok(!JSON.stringify(summary).includes(syntheticSession));
    assert.ok(!JSON.stringify(summary).includes(syntheticPushToken));
  } finally {
    if (previous === undefined) delete process.env[featureFlag];
    else process.env[featureFlag] = previous;
    await rm(root, { recursive: true, force: true });
  }
});
