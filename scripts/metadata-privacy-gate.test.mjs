import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdir, mkdtemp, readFile, rm, utimes, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {
  featureFlag,
  createLocalRetentionReceipt,
  inspectMetadataText,
  lintMetricText,
  metadataSafeProfile,
  renderMetadataSafeTopology,
  repositoryRoot,
  runGate,
  scanSelectedPaths,
  validateBreakGlassReceipt,
  validateLocalRetentionReceipt,
  validateMetadataSafeTopology,
  validateRetentionPolicy,
  validateXrayGeneratorSource
} from './metadata-privacy-gate.mjs';

const syntheticSession = `05${'11'.repeat(32)}`;
const syntheticPushToken = 'synthetic-push-provider-token-p01b';
const syntheticMailbox = 'synthetic-mailbox-capability-p01b';
const syntheticSensitiveFilename = `private-${syntheticSession}.json`;

async function fixtureRoot() {
  return mkdtemp(path.join(tmpdir(), 'deep-p01b-metadata-'));
}

async function loadPolicy() {
  return validateRetentionPolicy(JSON.parse(await readFile(
    path.join(repositoryRoot, 'config', 'metadata-safe', 'retention-policy.v1.json'),
    'utf8'
  )));
}

function pinnedGateInputs() {
  return {
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
  };
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
  const duplicate = structuredClone(policy);
  duplicate.components.push(structuredClone(duplicate.components[0]));
  assert.throws(() => validateRetentionPolicy(duplicate));
  const unbounded = structuredClone(policy);
  unbounded.components.find(item => item.component === 'xnode-operational').retentionHours = 876000;
  assert.throws(() => validateRetentionPolicy(unbounded));
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
    assert.deepEqual((await scanSelectedPaths([clean], { expectedFiles: 1 })).findings, []);

    const seeded = path.join(root, 'seeded.log');
    await writeFile(
      seeded,
      `source_ip=198.51.100.77 path=/inbox/${syntheticSession} push_token=${syntheticPushToken}\n`
    );
    assert.ok((await scanSelectedPaths([seeded], { expectedFiles: 1 })).findings.length >= 3);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('selection contract rejects empty, unsupported, binary, malformed and count-mismatched inputs', async () => {
  const root = await fixtureRoot();
  try {
    const empty = path.join(root, 'empty');
    await mkdir(empty);
    await assert.rejects(
      () => scanSelectedPaths([empty], { expectedFiles: 1 }),
      /selection root 1 failed closed/
    );

    const unsupported = path.join(root, 'opaque.bin');
    await writeFile(unsupported, Buffer.from([0, 1, 2, 3]));
    await assert.rejects(
      () => scanSelectedPaths([unsupported], { expectedFiles: 1 }),
      /selection root 1 failed closed/
    );

    const binaryText = path.join(root, 'binary.log');
    await writeFile(binaryText, Buffer.from([1, 2, 3]));
    await assert.rejects(
      () => scanSelectedPaths([binaryText], { expectedFiles: 1 }),
      /selection root 1 failed closed/
    );

    const malformed = path.join(root, 'malformed.json');
    await writeFile(malformed, '{"nested":');
    await assert.rejects(
      () => scanSelectedPaths([malformed], { expectedFiles: 1 }),
      /selection root 1 failed closed/
    );

    const clean = path.join(root, 'clean.log');
    await writeFile(clean, 'service=router status=degraded\n');
    await assert.rejects(
      () => scanSelectedPaths([clean], { expectedFiles: 2 }),
      /selected file count/
    );
    await assert.rejects(() => scanSelectedPaths([clean]), /expected file count/);
    await assert.rejects(
      () => scanSelectedPaths([clean, clean], { expectedFiles: 2 }),
      /selection root 2 failed closed/
    );
    const overlap = path.join(root, 'overlap');
    await mkdir(overlap);
    const contained = path.join(overlap, 'contained.log');
    await writeFile(contained, 'service=router status=degraded\n');
    await assert.rejects(
      () => scanSelectedPaths([overlap, contained], { expectedFiles: 2 }),
      /selection root 2 failed closed/
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('structured JSON and JSONL recursively reject quoted nested IPv6 and cross-domain fields', async () => {
  const root = await fixtureRoot();
  try {
    const seededJson = path.join(root, syntheticSensitiveFilename);
    const document = {
      records: [
        { source: { ip: '2001:db8::77' } },
        { request: { uri: `/mailbox/${syntheticSession}` } },
        { session: { id: syntheticSession } },
        { mailbox: { capability: syntheticMailbox } },
        { push: { token: syntheticPushToken } },
        { trace: { id: 'synthetic-trace-identifier-p01b' } }
      ]
    };
    await writeFile(seededJson, `${JSON.stringify(document)}\n`);
    const result = await scanSelectedPaths([seededJson], { expectedFiles: 1 });
    const rules = new Set(result.findings.map(item => item.ruleId));
    for (const expected of [
      'source-ip-field',
      'sensitive-request-target',
      'raw-session-identifier',
      'raw-mailbox-capability',
      'raw-push-handle',
      'stable-cross-domain-correlation'
    ]) {
      assert.ok(rules.has(expected), `missing structured ${expected}`);
    }
    const serialized = JSON.stringify(result);
    for (const raw of [
      syntheticSensitiveFilename,
      syntheticSession,
      syntheticMailbox,
      syntheticPushToken,
      '2001:db8::77',
      'synthetic-trace-identifier-p01b'
    ]) {
      assert.ok(!serialized.includes(raw), `serialized result echoed ${raw}`);
    }
    assert.ok(result.findings.every(item => item.inputId === 'input-1'));
    assert.ok(result.findings.every(item => !Object.hasOwn(item, 'path')));
    assert.ok(result.findings.every(item => !Object.hasOwn(item, 'pathHash')));

    const jsonl = path.join(root, 'events.jsonl');
    await writeFile(jsonl, [
      JSON.stringify({ service: 'router', status: 'degraded' }),
      JSON.stringify({ remote_address: '2001:db8::99' })
    ].join('\n'));
    const jsonlResult = await scanSelectedPaths([jsonl], { expectedFiles: 1 });
    assert.ok(jsonlResult.findings.some(item => item.ruleId === 'source-ip-field'));
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

test('local wall-clock retention receipt binds exact archive set and observed mtimes', async () => {
  const root = await fixtureRoot();
  const policy = await loadPolicy();
  try {
    const archive = path.join(root, syntheticSensitiveFilename);
    await writeFile(archive, 'warning: aggregate service unavailable\n');
    const recent = new Date('2030-01-01T11:30:00.000Z');
    await utimes(archive, recent, recent);
    const receipt = await createLocalRetentionReceipt(
      root,
      '2030-01-01T12:00:00.000Z',
      policy
    );
    const observation = await validateLocalRetentionReceipt(receipt, root, policy, {
      verificationNow: Date.parse('2030-01-01T12:02:00.000Z')
    });
    assert.equal(observation.expiredArchiveCount, 0);
    assert.ok(!JSON.stringify(receipt).includes(syntheticSensitiveFilename));

    const wrongHash = structuredClone(receipt);
    wrongHash.archiveSetSha256 = '00'.repeat(32);
    await assert.rejects(() => validateLocalRetentionReceipt(wrongHash, root, policy, {
      verificationNow: Date.parse('2030-01-01T12:02:00.000Z')
    }));

    await writeFile(path.join(root, 'second.log'), 'warning: aggregate retry\n');
    await assert.rejects(() => validateLocalRetentionReceipt(receipt, root, policy, {
      verificationNow: Date.parse('2030-01-01T12:02:00.000Z')
    }));

    await rm(path.join(root, 'second.log'));
    const old = new Date('2029-12-30T00:00:00.000Z');
    await utimes(archive, old, old);
    const expired = await createLocalRetentionReceipt(
      root,
      '2030-01-01T12:00:00.000Z',
      policy
    );
    await assert.rejects(
      () => validateLocalRetentionReceipt(expired, root, policy, {
        verificationNow: Date.parse('2030-01-01T12:02:00.000Z')
      }),
      /expired archives/
    );
    const staleClock = await createLocalRetentionReceipt(
      root,
      '2029-12-30T00:00:00.000Z',
      policy
    );
    await assert.rejects(
      () => validateLocalRetentionReceipt(staleClock, root, policy, {
        verificationNow: Date.parse('2030-01-01T12:02:00.000Z')
      }),
      /must be fresh/
    );
    const future = new Date('2030-01-01T12:30:00.000Z');
    await utimes(archive, future, future);
    const futureReceipt = await createLocalRetentionReceipt(
      root,
      '2030-01-01T12:00:00.000Z',
      policy
    );
    await assert.rejects(
      () => validateLocalRetentionReceipt(futureReceipt, root, policy, {
        verificationNow: Date.parse('2030-01-01T12:02:00.000Z')
      }),
      /ahead of the observation clock/
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('metadata-safe compose profile is exact, bounded and keeps operational warnings visible', () => {
  const topology = validateMetadataSafeTopology(renderMetadataSafeTopology());
  assert.equal(topology.services['xnode-1'].logging.options['max-file'], '2');
  assert.equal(topology.networks['i01b-private-uat'].internal, true);
  assert.equal(topology.services['xnode-1'].environment.Vless__InboundListenPort, '8443');
  assert.equal(Object.hasOwn(topology.services['xnode-1'], 'cap_add'), false);
  assert.equal(
    topology.services['xnode-1'].environment.Logging__LogLevel__Default,
    'Warning'
  );
});

test('metadata-safe topology rejects privilege, host escape, public listener and topology mutations', () => {
  const topology = renderMetadataSafeTopology();
  for (const mutate of [
    value => { value.services.storage.environment.DEEP_INFRA_PRIVACY_PROFILE = 'default'; },
    value => { value.services.push.logging.options['max-file'] = '20'; },
    value => { value.services.calls.logging.driver = 'json-file'; },
    value => { value.services['xnode-1'].environment.Logging__LogLevel__Default = 'Information'; },
    value => { delete value.services.file.labels['io.deep.infrastructure-privacy-profile']; },
    value => { value.services.calls.network_mode = 'host'; },
    value => { value.services.calls.pid = 'host'; },
    value => { value.services.calls.ipc = 'host'; },
    value => { value.services.calls.privileged = true; },
    value => { value.services.calls.devices = ['/dev/kvm']; },
    value => { value.services.calls.cap_add = ['SYS_ADMIN']; },
    value => { value.services['xnode-1'].cap_add = ['NET_BIND_SERVICE']; },
    value => { value.services.push.cap_drop = []; },
    value => { value.services.file.security_opt.push('seccomp:unconfined'); },
    value => { value.services.storage.extra_hosts = ['host.docker.internal:host-gateway']; },
    value => { value.services.calls.ports[0].host_ip = '0.0.0.0'; },
    value => { delete value.services.file.ports[0].host_ip; },
    value => { value.services.push.ports.push({ mode: 'ingress', host_ip: '127.0.0.1', target: 443, published: '29443', protocol: 'tcp' }); },
    value => { value.services.calls.expose = ['8081']; },
    value => { value.services['xnode-1'].environment.Vless__InboundListenPort = '443'; },
    value => { value.services['xnode-1'].environment.Unreviewed__ListenPort = '9000'; },
    value => { value.services.storage.networks.default = null; },
    value => { value.networks['i01b-private-uat'].internal = false; },
    value => { value.networks.default = { driver: 'bridge' }; },
    value => { value.services.eighth = structuredClone(value.services.calls); },
    value => { value.services.calls.volumes.push({ type: 'bind', source: '/var/run/docker.sock', target: '/var/run/docker.sock' }); },
    value => { value.services.file.volumes[0].source = 'i01b-private-uat-push-state'; },
    value => { value.volumes['i01b-private-uat-calls-state'].external = true; },
    value => { value.services['xnode-2'].secrets[0].source = 'i01b-private-uat-node-1-ed25519'; },
    value => { value.services.storage.secrets = [{ source: 'i01b-private-uat-node-1-ed25519' }]; },
    value => { value.secrets['i01b-private-uat-node-1-ed25519'].file = '/var/run/docker.sock'; },
    value => { value.services.calls.build.network = 'host'; },
    value => { value.services.calls.build.context = 'C:\\'; },
    value => { value.services.calls.build.dockerfile = 'unreviewed.Dockerfile'; },
    value => { value.services.calls.build.args.NODE_IMAGE = 'node:latest'; },
    value => { value.services['xnode-1'].build.args.XRAY_SHA256 = '00'.repeat(32); },
    value => { value.services.calls.environment.ASPNETCORE_HTTP_PORTS = '9000'; },
    value => { value.services.calls.environment.HOST = '0.0.0.0'; },
    value => { value.services['xnode-1'].environment.Runtime__AllowPublicPeerEndpoints = 'true'; },
    value => { value.services['xnode-1'].environment.Runtime__RequireSignedRelayContacts = 'false'; },
    value => { value.services['xnode-1'].environment.Vless__MockProcess = 'true'; }
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
      expectedArtifactFiles: 1,
      expectedMetricFiles: 1,
      ...pinnedGateInputs()
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
      expectedArtifactFiles: 1,
      expectedMetricFiles: 1,
      ...pinnedGateInputs()
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

test('CLI uses exit 1 for leaks, exit 2 for harness failures and never echoes logical paths', async () => {
  const root = await fixtureRoot();
  try {
    const artifact = path.join(root, syntheticSensitiveFilename);
    const metrics = path.join(root, 'metrics.prom');
    const summary = path.join(root, 'summary.json');
    await writeFile(artifact, JSON.stringify({
      source_ip: '2001:db8::123',
      push_token: syntheticPushToken
    }));
    await writeFile(metrics, 'deep_requests_total{service="router",status_code="503"} 1\n');
    const pinned = pinnedGateInputs();
    const baseArgs = [
      path.join(repositoryRoot, 'scripts', 'metadata-privacy-gate.mjs'),
      '--artifacts', artifact,
      '--metrics', metrics,
      '--expected-artifact-files', '1',
      '--expected-metric-files', '1',
      '--xnode-dir', pinned.xnodeDir,
      '--client-expectations', pinned.clientExpectationsPath,
      '--summary', summary
    ];
    const leakRun = spawnSync(process.execPath, baseArgs, {
      cwd: repositoryRoot,
      env: { ...process.env, [featureFlag]: metadataSafeProfile },
      encoding: 'utf8',
      windowsHide: true
    });
    assert.equal(leakRun.status, 1);
    const serializedLeakOutput = [
      leakRun.stdout,
      leakRun.stderr,
      await readFile(summary, 'utf8')
    ].join('\n');
    for (const raw of [
      artifact,
      syntheticSensitiveFilename,
      syntheticPushToken,
      '2001:db8::123'
    ]) {
      assert.ok(!serializedLeakOutput.includes(raw), `CLI leak output echoed ${raw}`);
    }

    const empty = path.join(root, 'empty-root');
    await mkdir(empty);
    const harnessRun = spawnSync(process.execPath, baseArgs.map(value => (
      value === artifact ? empty : value
    )), {
      cwd: repositoryRoot,
      env: { ...process.env, [featureFlag]: metadataSafeProfile },
      encoding: 'utf8',
      windowsHide: true
    });
    assert.equal(harnessRun.status, 2);
    assert.ok(!`${harnessRun.stdout}\n${harnessRun.stderr}`.includes(empty));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
