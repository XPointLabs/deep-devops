import { access, mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { addGeneratedAtFreshnessCheck, addLocalEvidencePathCheck, addNoPlaceholderUrlCheck } from './release-evidence-guards.mjs';
import { requiredCiRuns } from './release-ci-lanes.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const devopsRoot = path.resolve(__dirname, '..');
const workspaceRoot = path.resolve(devopsRoot, '..');
const artifactRoot = process.env.DEEP_RELEASE_ARTIFACT_ROOT
  ? path.resolve(process.env.DEEP_RELEASE_ARTIFACT_ROOT)
  : path.join(devopsRoot, 'artifacts');
const outputDir = path.join(artifactRoot, 'release');
const outputPath = path.join(outputDir, 'release-evidence-summary.json');

const args = new Set(process.argv.slice(2));
const requireAttachedCi = args.has('--require-attached-ci') || process.env.DEEP_RELEASE_REQUIRE_ATTACHED_CI === 'true';
const requireRollbackDrill = args.has('--require-rollback-drill') || process.env.DEEP_RELEASE_REQUIRE_ROLLBACK_DRILL === 'true';
const requireStagingProviderCanary = args.has('--require-staging-provider-canary') || process.env.DEEP_RELEASE_REQUIRE_STAGING_PROVIDER_CANARY === 'true';

const checks = [];
let releaseCandidate = null;

function addCheck(name, passed, details = {}) {
  checks.push({ name, passed: Boolean(passed), ...details });
}

function get(value, pathExpression) {
  return pathExpression.split('.').reduce((current, key) => current?.[key], value);
}

async function fileExists(filePath) {
  try {
    await access(filePath);
    return true;
  } catch {
    return false;
  }
}

async function readJson(label, filePath, required = true) {
  const absolutePath = path.resolve(filePath);
  if (!await fileExists(absolutePath)) {
    addCheck(required ? `${label}:exists` : `${label}:optional-missing`, !required, { path: absolutePath });
    return null;
  }

  try {
    const raw = await readFile(absolutePath, 'utf8');
    const parsed = JSON.parse(raw.replace(/^\uFEFF/, ''));
    addCheck(`${label}:exists`, true, { path: absolutePath });
    return parsed;
  } catch (error) {
    addCheck(`${label}:parse`, false, { path: absolutePath, error: error.message });
    return null;
  }
}

function checkPositiveDelta(label, artifact, pathExpression) {
  const value = get(artifact, pathExpression);
  addCheck(label, typeof value === 'number' && value > 0, {
    observed: value,
    target: '> 0',
    source: pathExpression
  });
}

function checkNoErrors(label, serviceStats) {
  const errors = serviceStats?.stats?.errors;
  addCheck(label, errors === 0, { observed: errors, target: 0 });
}

function checkNonEmptyArray(label, value) {
  addCheck(label, Array.isArray(value) && value.length > 0, {
    observed: Array.isArray(value) ? value.length : null,
    target: '> 0'
  });
}

function hasText(value) {
  return typeof value === 'string' && value.trim().length > 0;
}

function asArray(value) {
  return Array.isArray(value) ? value : [];
}

function normalizeWorkflow(value) {
  return hasText(value) ? value.replaceAll('\\', '/').toLowerCase() : '';
}

function repositoryMatches(value, expectedName) {
  if (!hasText(value)) {
    return false;
  }

  const normalized = value.toLowerCase();
  return normalized === expectedName || normalized.endsWith(`/${expectedName}`);
}

function workflowMatches(value, expectedFile) {
  const workflow = normalizeWorkflow(value);
  return workflow === expectedFile || workflow.endsWith(`/${expectedFile}`);
}

function successfulConclusion(value) {
  return value === 'success' || value === 'passed' || value === 'ok';
}

function fullCommitSha(value) {
  return /^[a-f0-9]{40}$/i.test(String(value ?? ''));
}

function positiveInteger(value) {
  const number = Number(value);
  return Number.isInteger(number) && number > 0;
}

function localOrPlaceholderHost(host) {
  if (!hasText(host)) {
    return true;
  }

  const normalized = host.toLowerCase();
  return normalized === 'localhost'
    || normalized.startsWith('127.')
    || normalized === 'host.docker.internal'
    || normalized.endsWith('.invalid');
}

function artifactsForRun(manifest, run) {
  const runArtifacts = asArray(run?.artifacts);
  const manifestArtifacts = asArray(manifest?.artifacts).filter(artifact => {
    if (!hasText(run?.name) && !hasText(run?.lane)) {
      return false;
    }

    return artifact.run === run?.name || artifact.run === run?.lane || artifact.lane === run?.lane || artifact.lane === run?.name;
  });

  return [...runArtifacts, ...manifestArtifacts];
}

function validateAttachedCiRun(manifest, requiredRun) {
  const runs = asArray(manifest?.runs);
  const candidates = runs.filter(run => {
    const laneMatches = run.name === requiredRun.name || run.lane === requiredRun.name;
    const repoAndWorkflowMatch = repositoryMatches(run.repository, requiredRun.repository)
      && workflowMatches(run.workflow, requiredRun.workflow);
    const runArtifacts = artifactsForRun(manifest, run);
    const hasRequiredArtifact = requiredRun.artifacts.some(name => runArtifacts.some(artifact => artifact.name === name));
    return laneMatches || (repoAndWorkflowMatch && hasRequiredArtifact);
  });
  const run = candidates[0];
  const prefix = `attached-ci:${requiredRun.name}`;

  addCheck(`${prefix}:run-present`, Boolean(run), {
    expectedRepository: requiredRun.repository,
    expectedWorkflow: requiredRun.workflow,
    expectedArtifacts: requiredRun.artifacts
  });

  if (!run) {
    return;
  }

  addCheck(`${prefix}:repository`, repositoryMatches(run.repository, requiredRun.repository), {
    observed: run.repository,
    expected: requiredRun.repository
  });
  addCheck(`${prefix}:workflow`, workflowMatches(run.workflow, requiredRun.workflow), {
    observed: run.workflow,
    expected: requiredRun.workflow
  });
  addCheck(`${prefix}:conclusion-success`, successfulConclusion(run.conclusion ?? run.result ?? run.status), {
    observed: run.conclusion ?? run.result ?? run.status
  });
  addCheck(`${prefix}:head-sha-present`, hasText(run.headSha ?? run.commit ?? run.sha), {
    observed: run.headSha ?? run.commit ?? run.sha ?? null
  });
  addCheck(`${prefix}:head-sha-full`, fullCommitSha(run.headSha ?? run.commit ?? run.sha), {
    observed: run.headSha ?? run.commit ?? run.sha ?? null
  });
  addCheck(`${prefix}:run-attempt-present`, positiveInteger(run.runAttempt ?? run.attempt), {
    observed: run.runAttempt ?? run.attempt ?? null
  });
  addCheck(`${prefix}:run-reference-present`, hasText(run.htmlUrl ?? run.url) || hasText(String(run.runId ?? '')) || hasText(String(run.runNumber ?? '')), {
    runId: run.runId,
    runNumber: run.runNumber,
    htmlUrl: run.htmlUrl,
    url: run.url
  });

  const runArtifacts = artifactsForRun(manifest, run);
  for (const artifactName of requiredRun.artifacts) {
    const artifact = runArtifacts.find(entry => entry.name === artifactName);
    addCheck(`${prefix}:artifact:${artifactName}`, Boolean(artifact && (hasText(artifact.url) || hasText(artifact.path) || hasText(String(artifact.id ?? '')))), {
      url: artifact?.url,
      path: artifact?.path,
      id: artifact?.id
    });
  }
}

const runtimeGate = await readJson('runtime-gate', path.join(artifactRoot, 'runtime.gate.json'));
if (runtimeGate) {
  addCheck('runtime-gate:no-hard-failures', Array.isArray(runtimeGate.failedHard) && runtimeGate.failedHard.length === 0, {
    failedHard: runtimeGate.failedHard ?? null
  });
  addCheck('runtime-gate:no-soft-failures', Array.isArray(runtimeGate.failedSoft) && runtimeGate.failedSoft.length === 0, {
    failedSoft: runtimeGate.failedSoft ?? null
  });
  addCheck('runtime-gate:router-no-mock-required', runtimeGate.requireRouterNoMock === true, {
    observed: runtimeGate.requireRouterNoMock
  });
  addCheck('runtime-gate:router-not-mocked', runtimeGate.routerTransportMocked === false, {
    observed: runtimeGate.routerTransportMocked,
    mode: runtimeGate.routerTransportMode
  });
  addCheck('runtime-gate:push-provider-canary-required', runtimeGate.requirePushProviderCanary === true, {
    observed: runtimeGate.requirePushProviderCanary
  });
  addCheck('runtime-gate:push-provider-canary-delivered', runtimeGate.pushProviderCanaryDelivered === true, {
    observed: runtimeGate.pushProviderCanaryDelivered,
    status: runtimeGate.pushProviderCanaryStatus
  });
}

const loadSmoke = await readJson('backend-load-smoke', path.join(artifactRoot, 'test-results', 'backend-load-smoke.json'));
if (loadSmoke) {
  checkPositiveDelta('load:storage-store-delta', loadSmoke, 'statsDelta.storage.storageStore');
  checkPositiveDelta('load:storage-retrieve-delta', loadSmoke, 'statsDelta.storage.storageRetrieve');
  checkPositiveDelta('load:file-upload-delta', loadSmoke, 'statsDelta.file.fileUpload');
  checkPositiveDelta('load:file-download-delta', loadSmoke, 'statsDelta.file.fileDownload');
  checkPositiveDelta('load:file-info-delta', loadSmoke, 'statsDelta.file.fileInfo');
  checkPositiveDelta('load:file-extend-delta', loadSmoke, 'statsDelta.file.fileExtend');
  checkPositiveDelta('load:avatar-upload-delta', loadSmoke, 'statsDelta.file.avatarUpload');
  checkPositiveDelta('load:avatar-download-delta', loadSmoke, 'statsDelta.file.avatarDownload');
  checkPositiveDelta('load:avatar-info-delta', loadSmoke, 'statsDelta.file.avatarInfo');
  checkPositiveDelta('load:push-subscribe-delta', loadSmoke, 'statsDelta.push.pushSubscribe');
  checkPositiveDelta('load:push-unsubscribe-delta', loadSmoke, 'statsDelta.push.pushUnsubscribe');
  checkPositiveDelta('load:push-notifications-queued-delta', loadSmoke, 'statsDelta.push.pushNotificationsQueued');
  checkNoErrors('load:storage-errors-zero', loadSmoke.statsAfter?.storage);
  checkNoErrors('load:file-errors-zero', loadSmoke.statsAfter?.file);
  checkNoErrors('load:push-errors-zero', loadSmoke.statsAfter?.push);
}

const restartSmoke = await readJson('backend-restart-smoke', path.join(artifactRoot, 'test-results', 'backend-restart-smoke.json'));
if (restartSmoke) {
  addCheck('restart:status-ok', restartSmoke.status === 'ok', { observed: restartSmoke.status });
  checkNonEmptyArray('restart:retrieved-after-restart', restartSmoke.retrievedAfterRestart?.messages);
  checkNonEmptyArray('restart:retrieved-final', restartSmoke.retrievedFinal?.messages);
  addCheck('restart:file-info-preserved', restartSmoke.fileInfoAfterRestart?.size === restartSmoke.fileInfoBeforeRestart?.size, {
    before: restartSmoke.fileInfoBeforeRestart?.size,
    after: restartSmoke.fileInfoAfterRestart?.size
  });
  addCheck('restart:avatar-info-preserved', restartSmoke.avatarInfoAfterRestart?.fileId === restartSmoke.avatarInfoBeforeRestart?.fileId, {
    before: restartSmoke.avatarInfoBeforeRestart?.fileId,
    after: restartSmoke.avatarInfoAfterRestart?.fileId
  });
  checkNonEmptyArray('restart:push-deliveries-preserved', restartSmoke.subscriptionsAfterRestart?.deliveries);
  checkNoErrors('restart:storage-errors-zero', restartSmoke.statsAfterRehearsal?.storage);
  checkNoErrors('restart:file-errors-zero', restartSmoke.statsAfterRehearsal?.file);
  checkNoErrors('restart:push-errors-zero', restartSmoke.statsAfterRehearsal?.push);
  addCheck('restart:registry-call-signal-accepted', restartSmoke.callRegistry?.authenticatedSignalAcceptedBeforeRestart === true, {
    observed: restartSmoke.callRegistry?.authenticatedSignalAcceptedBeforeRestart
  });
  addCheck('restart:registry-restarted', restartSmoke.callRegistry?.registryRestarted === true, {
    observed: restartSmoke.callRegistry?.registryRestarted
  });
  addCheck('restart:registry-call-inbox-durable',
    restartSmoke.callRegistry?.authenticatedInboxRetrievedAfterRestart === true
      && restartSmoke.callRegistry?.exactSignalCountAfterRestart === 1,
    { observed: restartSmoke.callRegistry ?? null });
}

const physicalCall = await readJson('physical-call', path.join(artifactRoot, 'test-results', 'mau2-call-result.json'));
if (physicalCall) {
  addCheck('physical-call:schema', physicalCall.schema === 'deep.physical-mau2-phase.v1', {
    observed: physicalCall.schema
  });
  addCheck('physical-call:phase', physicalCall.phase === 'Call', { observed: physicalCall.phase });
  addCheck('physical-call:status-passed', physicalCall.status === 'passed', { observed: physicalCall.status });
  for (const field of [
    'outgoingOfferStarted',
    'incomingRingingObserved',
    'incomingAnswerAccepted',
    'selectedIceCandidatePairObserved',
    'bidirectionalAudioRtpObserved',
    'microphoneMuteApplied',
    'microphoneRestoreApplied',
    'remoteHangupObserved',
    'authenticatedMau2EnvironmentValidated',
    'productionPackageUntouched'
  ]) {
    addCheck(`physical-call:${field}`, physicalCall[field] === true, {
      observed: physicalCall[field]
    });
  }
}

const pushCanary = await readJson('push-provider-canary', path.join(artifactRoot, 'test-results', 'push-provider-canary.json'));
if (pushCanary) {
  addCheck('push-canary:status-ok', pushCanary.status === 'ok', { observed: pushCanary.status });
  addCheck('push-canary:provider-delivered', pushCanary.provider?.status === 'delivered', {
    observed: pushCanary.provider?.status,
    attempts: pushCanary.provider?.attempts
  });
  addCheck('push-canary:provider-url-configured', pushCanary.provider?.hasConfiguredUrl === true, {
    observed: pushCanary.provider?.hasConfiguredUrl
  });
  addCheck('push-canary:no-provider-failures', (pushCanary.statsAfterDelivery?.inventory?.pushProviderFailed ?? 0) === 0, {
    observed: pushCanary.statsAfterDelivery?.inventory?.pushProviderFailed
  });
  if (requireStagingProviderCanary) {
    const releaseLane = pushCanary.providerEvidence?.releaseLane ?? pushCanary.releaseLane;
    const providerHost = pushCanary.providerEvidence?.providerHost;
    addCheck('push-canary:staging-lane', hasText(releaseLane) && !['local', 'dev', 'test'].includes(String(releaseLane).toLowerCase()), {
      observed: releaseLane ?? null
    });
    addCheck('push-canary:credential-token-from-env', pushCanary.providerEvidence?.tokenSource === 'env' || pushCanary.tokenSource === 'env', {
      observed: pushCanary.providerEvidence?.tokenSource ?? pushCanary.tokenSource ?? null
    });
    addCheck('push-canary:provider-auth-configured', pushCanary.providerEvidence?.providerAuthConfigured === true, {
      observed: pushCanary.providerEvidence?.providerAuthConfigured ?? null
    });
    addCheck('push-canary:provider-host-staging-like', hasText(providerHost) && !localOrPlaceholderHost(providerHost), {
      observed: providerHost ?? null
    });
    addCheck('push-canary:provider-url-source-recorded', hasText(pushCanary.providerEvidence?.providerUrlSource), {
      observed: pushCanary.providerEvidence?.providerUrlSource ?? null
    });
  }
}

const multiNode = await readJson('multi-node-topology', path.join(artifactRoot, 'test-results', 'multi-node-topology.json'));
if (multiNode) {
  addCheck('multi-node:status-ok', multiNode.status === 'ok', { observed: multiNode.status });
  addCheck('multi-node:three-routers', Array.isArray(multiNode.routers) && multiNode.routers.length >= 3, {
    observed: multiNode.routers?.length,
    target: '>= 3'
  });
  addCheck('multi-node:routers-no-mock', Array.isArray(multiNode.routers) && multiNode.routers.every(router => router.transportMocked === false), {
    mockedRouters: multiNode.routers?.filter(router => router.transportMocked !== false).map(router => router.routerId) ?? null
  });
  addCheck('multi-node:xray-running', Array.isArray(multiNode.routers) && multiNode.routers.every(router => router.xrayRunning === true && router.xrayDegraded === false), {
    degradedRouters: multiNode.routers?.filter(router => router.xrayRunning !== true || router.xrayDegraded !== false).map(router => router.routerId) ?? null
  });
  addCheck('multi-node:registry-node-count', (multiNode.registryRuntime?.totalNodes ?? multiNode.registryNodeCount ?? 0) >= 3, {
    observed: multiNode.registryRuntime?.totalNodes ?? multiNode.registryNodeCount,
    target: '>= 3'
  });
  addCheck('multi-node:no-reconciliation-issues', Array.isArray(multiNode.reconciliationIssues) && multiNode.reconciliationIssues.length === 0, {
    observed: multiNode.reconciliationIssues?.length
  });
  addCheck('multi-node:three-distinct-hops', multiNode.selectedPath?.distinctHops >= 3, {
    observed: multiNode.selectedPath?.distinctHops,
    hops: multiNode.selectedPath?.hops
  });
}

const registryRecovery = await readJson('registry-recovery', path.join(artifactRoot, 'test-results', 'registry-recovery.json'));
if (registryRecovery) {
  const requiredRegistryRecoveryTests = [
    'NodeRegistry_PersistsAndReloadsFromSnapshot',
    'NodeRegistry_RecoversFromCorruptedStateFile',
    'RuntimeEndpoint_ReturnsRegistryStats',
    'NodeRegistry_ReconciliationJob_TracksLastReportAndRuns'
  ];
  const passedTests = asArray(registryRecovery.passedTests);
  addCheck('registry-recovery:status-ok', registryRecovery.status === 'ok', { observed: registryRecovery.status });
  addCheck('registry-recovery:exit-code-zero', registryRecovery.exitCode === 0, { observed: registryRecovery.exitCode });
  for (const testName of requiredRegistryRecoveryTests) {
    addCheck(`registry-recovery:test:${testName}`, passedTests.includes(testName), {
      observed: passedTests.includes(testName)
    });
  }
  addCheck('registry-recovery:snapshot-persistence', registryRecovery.coverage?.snapshotPersistenceReload === true, {
    observed: registryRecovery.coverage?.snapshotPersistenceReload
  });
  addCheck('registry-recovery:corrupt-state-quarantine', registryRecovery.coverage?.corruptedSnapshotQuarantine === true, {
    observed: registryRecovery.coverage?.corruptedSnapshotQuarantine
  });
  addCheck('registry-recovery:runtime-counters', registryRecovery.coverage?.runtimeRecoveryCounters === true, {
    observed: registryRecovery.coverage?.runtimeRecoveryCounters
  });
  addCheck('registry-recovery:reconciliation-job-status', registryRecovery.coverage?.reconciliationJobStatus === true, {
    observed: registryRecovery.coverage?.reconciliationJobStatus
  });
}

const securityGate = await readJson('security-gate', path.join(artifactRoot, 'security', 'security-gate-summary.json'));
if (securityGate) {
  addCheck('security:status-ok', securityGate.status === 'ok', { observed: securityGate.status });
  addCheck('security:secret-findings-zero', securityGate.secretFindings === 0, { observed: securityGate.secretFindings });
  addCheck('security:dependency-failures-zero', securityGate.dependencyFailures === 0, { observed: securityGate.dependencyFailures });
  addCheck('security:sbom-nonempty', securityGate.sbomComponents > 0, { observed: securityGate.sbomComponents });
}

const observabilityGate = await readJson('observability-gate', path.join(artifactRoot, 'observability', 'observability-gate-summary.json'));
if (observabilityGate) {
  addCheck('observability:status-ok', observabilityGate.status === 'ok', { observed: observabilityGate.status });
  addCheck('observability:no-failed-checks', Array.isArray(observabilityGate.failedChecks) && observabilityGate.failedChecks.length === 0, {
    observed: observabilityGate.failedChecks?.length ?? null
  });
  addCheck('observability:alert-rules-present', Array.isArray(observabilityGate.alertRules) && observabilityGate.alertRules.length >= 4, {
    observed: observabilityGate.alertRules?.length ?? null,
    target: '>= 4'
  });
}

const sessionInfraGuard = await readJson('session-infra-guard', path.join(artifactRoot, 'release', 'session-infra-guard-summary.json'));
if (sessionInfraGuard) {
  addCheck('session-infra:status-ok', sessionInfraGuard.status === 'ok', { observed: sessionInfraGuard.status });
  addCheck('session-infra:no-failed-checks', asArray(sessionInfraGuard.failedChecks).length === 0, {
    observed: asArray(sessionInfraGuard.failedChecks).length
  });
  addCheck('session-infra:no-forbidden-hosts', asArray(sessionInfraGuard.findings).length === 0, {
    observed: asArray(sessionInfraGuard.findings).length
  });
  addCheck('session-infra:scanned-files-present', Number(sessionInfraGuard.scannedFileCount ?? 0) > 0, {
    observed: sessionInfraGuard.scannedFileCount ?? null
  });
  addGeneratedAtFreshnessCheck(addCheck, 'session-infra', sessionInfraGuard);
}

const routerC3Path = process.env.XNODE_C3_ARTIFACT
  ? path.resolve(process.env.XNODE_C3_ARTIFACT)
  : path.join(workspaceRoot, 'xnode', 'artifacts', 'test-results', 'c3', 'latest.json');
const routerC3 = await readJson('router-c3', routerC3Path);
if (routerC3) {
  addCheck('router-c3:slo-baseline-passed', routerC3.sloBaseline?.passed === true, {
    observed: routerC3.sloBaseline?.passed
  });
  addCheck('router-c3:soak-success-rate', routerC3.soak?.successRate >= 0.99, {
    observed: routerC3.soak?.successRate,
    target: '>= 0.99'
  });
  addCheck('router-c3:chaos-success-rate', routerC3.chaos?.successRate >= 0.55, {
    observed: routerC3.chaos?.successRate,
    target: '>= 0.55'
  });
  addCheck('router-c3:load-success-rate', routerC3.load?.successRate >= 0.99, {
    observed: routerC3.load?.successRate,
    target: '>= 0.99'
  });
  addCheck('router-c3:path-select-p95', routerC3.load?.latencyP95Ms <= 15, {
    observed: routerC3.load?.latencyP95Ms,
    target: '<= 15 ms'
  });
  addCheck('router-c3:restart-storm-degraded', routerC3.restartStorm?.degraded === true, {
    observed: routerC3.restartStorm?.degraded,
    mode: routerC3.restartStorm?.mode
  });
}

const attachedCiManifestPath = process.env.DEEP_ATTACHED_CI_MANIFEST
  ? path.resolve(process.env.DEEP_ATTACHED_CI_MANIFEST)
  : path.join(artifactRoot, 'release', 'attached-ci-artifacts.json');
const attachedCiManifest = await readJson('attached-ci-artifacts', attachedCiManifestPath, requireAttachedCi);
if (attachedCiManifest) {
  releaseCandidate = hasText(attachedCiManifest.releaseCandidate)
    ? attachedCiManifest.releaseCandidate.trim()
    : null;
  addNoPlaceholderUrlCheck(addCheck, 'attached-ci-artifacts', attachedCiManifest);
  addLocalEvidencePathCheck(addCheck, 'attached-ci-artifacts', attachedCiManifest, { baseDir: artifactRoot });
  addCheck('attached-ci:generated-at-present', hasText(attachedCiManifest.generatedAt), {
    observed: attachedCiManifest.generatedAt ?? null
  });
  addGeneratedAtFreshnessCheck(addCheck, 'attached-ci', attachedCiManifest);
  addCheck('attached-ci:release-candidate-present', hasText(attachedCiManifest.releaseCandidate), {
    observed: attachedCiManifest.releaseCandidate ?? null
  });
  addCheck('attached-ci:runs-present', Array.isArray(attachedCiManifest.runs) && attachedCiManifest.runs.length > 0, {
    observed: attachedCiManifest.runs?.length ?? null
  });
  for (const run of requiredCiRuns) {
    validateAttachedCiRun(attachedCiManifest, run);
  }
} else if (!requireAttachedCi) {
  addCheck('attached-ci:not-required-for-local-preflight', true, {
    note: 'Set DEEP_RELEASE_REQUIRE_ATTACHED_CI=true or pass --require-attached-ci for release sign-off.'
  });
}

const rollbackArtifactPath = process.env.DEEP_ROLLBACK_DRILL_ARTIFACT
  ? path.resolve(process.env.DEEP_ROLLBACK_DRILL_ARTIFACT)
  : path.join(artifactRoot, 'test-results', 'rollback-drill.json');
const rollbackArtifact = await readJson('rollback-drill', rollbackArtifactPath, requireRollbackDrill);
if (rollbackArtifact) {
  addCheck('rollback:status-ok', rollbackArtifact.status === 'ok', { observed: rollbackArtifact.status });
  addCheck('rollback:post-smoke-green', rollbackArtifact.postRollbackSmoke?.status === 'ok' || rollbackArtifact.postRollbackSmoke?.passed === true, {
    observed: rollbackArtifact.postRollbackSmoke?.status ?? rollbackArtifact.postRollbackSmoke?.passed
  });
  addCheck('rollback:mttr-budget', typeof rollbackArtifact.mttrSeconds === 'number' && rollbackArtifact.mttrSeconds <= 3600, {
    observed: rollbackArtifact.mttrSeconds,
    target: '<= 3600 seconds'
  });
} else if (!requireRollbackDrill) {
  addCheck('rollback:not-required-for-local-preflight', true, {
    note: 'Set DEEP_RELEASE_REQUIRE_ROLLBACK_DRILL=true or pass --require-rollback-drill for release sign-off.'
  });
}

const failed = checks.filter(check => !check.passed);
const summary = {
  status: failed.length === 0 ? 'ok' : 'failed',
  generatedAt: new Date().toISOString(),
  workspaceRoot,
  artifactRoot,
  releaseCandidate,
  requireAttachedCi,
  requireRollbackDrill,
  requireStagingProviderCanary,
  checks,
  failedChecks: failed.map(check => check.name),
  residualReleaseSignoff: {
    attachedCiArtifactsRequired: !requireAttachedCi,
    rollbackDrillRequired: !requireRollbackDrill,
    stagingProviderCanaryRequired: !requireStagingProviderCanary,
    externalHumanSignoffRequired: true
  }
};

await mkdir(outputDir, { recursive: true });
await writeFile(outputPath, JSON.stringify(summary, null, 2));

if (failed.length > 0) {
  console.error(`Release evidence gate failed (${failed.length} checks). Summary: ${outputPath}`);
  for (const check of failed) {
    console.error(`- ${check.name}`);
  }
  process.exit(1);
}

console.log(`Release evidence gate passed (${checks.length} checks). Summary: ${outputPath}`);
