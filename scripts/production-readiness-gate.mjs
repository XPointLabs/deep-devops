import { access, mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { addGeneratedAtFreshnessCheck, addLocalEvidencePathCheck, addNoPlaceholderUrlCheck } from './release-evidence-guards.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const devopsRoot = path.resolve(__dirname, '..');
const workspaceRoot = path.resolve(devopsRoot, '..');
const artifactRoot = process.env.DEEP_RELEASE_ARTIFACT_ROOT
  ? path.resolve(process.env.DEEP_RELEASE_ARTIFACT_ROOT)
  : path.join(devopsRoot, 'artifacts');
const outputDir = path.join(artifactRoot, 'release');
const outputPath = path.join(outputDir, 'production-readiness-summary.json');

const checks = [];

function addCheck(name, passed, details = {}) {
  checks.push({ name, passed: Boolean(passed), ...details });
}

function hasText(value) {
  return typeof value === 'string' && value.trim().length > 0;
}

function asArray(value) {
  return Array.isArray(value) ? value : [];
}

function normalizedText(value) {
  return hasText(value) ? value.trim() : null;
}

function successful(value) {
  return value === 'ok' || value === 'passed' || value === 'success' || value === 'approved';
}

function hasEvidenceReference(value) {
  if (!value || typeof value !== 'object') {
    return false;
  }

  return hasText(value.url) || hasText(value.path) || hasText(String(value.id ?? ''));
}

function artifactLikeReference(value) {
  if (hasEvidenceReference(value)) {
    return true;
  }

  return asArray(value?.artifacts).some(hasEvidenceReference)
    || asArray(value?.evidence).some(hasEvidenceReference)
    || hasEvidenceReference(value?.evidence);
}

async function fileExists(filePath) {
  try {
    await access(filePath);
    return true;
  } catch {
    return false;
  }
}

async function readJson(label, filePath) {
  const absolutePath = path.resolve(filePath);
  if (!await fileExists(absolutePath)) {
    addCheck(`${label}:exists`, false, { path: absolutePath });
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

function validateStrictReleaseEvidence(releaseEvidence) {
  if (!releaseEvidence) {
    return;
  }

  addCheck('release-evidence:status-ok', releaseEvidence.status === 'ok', { observed: releaseEvidence.status });
  addGeneratedAtFreshnessCheck(addCheck, 'release-evidence', releaseEvidence);
  addCheck('release-evidence:no-failed-checks', asArray(releaseEvidence.failedChecks).length === 0, {
    observed: asArray(releaseEvidence.failedChecks).length
  });
  addCheck('release-evidence:release-candidate-present', hasText(releaseEvidence.releaseCandidate), {
    observed: releaseEvidence.releaseCandidate ?? null
  });
  addCheck('release-evidence:attached-ci-required', releaseEvidence.requireAttachedCi === true, {
    observed: releaseEvidence.requireAttachedCi
  });
  addCheck('release-evidence:rollback-required', releaseEvidence.requireRollbackDrill === true, {
    observed: releaseEvidence.requireRollbackDrill
  });
  addCheck('release-evidence:staging-provider-required', releaseEvidence.requireStagingProviderCanary === true, {
    observed: releaseEvidence.requireStagingProviderCanary
  });
}

function validateReleaseArtifactBundle(bundleSummary) {
  if (!bundleSummary) {
    return;
  }

  addCheck('release-artifact-bundle:status-ok', bundleSummary.status === 'ok', { observed: bundleSummary.status ?? null });
  addCheck('release-artifact-bundle:no-failed-checks', asArray(bundleSummary.failedChecks).length === 0, {
    observed: asArray(bundleSummary.failedChecks).length
  });
  addCheck('release-artifact-bundle:generated-at-present', hasText(bundleSummary.generatedAt), {
    observed: bundleSummary.generatedAt ?? null
  });
  addGeneratedAtFreshnessCheck(addCheck, 'release-artifact-bundle', bundleSummary);
  addCheck('release-artifact-bundle:release-candidate-present', hasText(bundleSummary.expectedReleaseCandidate), {
    observed: bundleSummary.expectedReleaseCandidate ?? null
  });

  const artifacts = asArray(bundleSummary.artifacts);
  for (const artifactId of [
    'runtime-gate',
    'backend-load-smoke',
    'backend-restart-smoke',
    'physical-call',
    'push-provider-canary',
    'multi-node-topology',
    'rollback-drill',
    'security-gate-summary',
    'observability-gate-summary',
    'session-infra-guard-summary',
    'router-c3-latest',
    'attached-ci-artifacts',
    'attached-ci-manifest-summary',
    'client-device-acceptance',
    'ops-deployment-evidence',
    'security-audit-signoff',
    'ga-decision'
  ]) {
    const artifact = artifacts.find(entry => entry?.id === artifactId);
    addCheck(`release-artifact-bundle:artifact:${artifactId}:present`, Boolean(artifact), {
      observed: Boolean(artifact)
    });
    if (artifact) {
      addCheck(`release-artifact-bundle:artifact:${artifactId}:exists`, artifact.exists === true, {
        path: artifact.path ?? null,
        observed: artifact.exists ?? null
      });
      addCheck(`release-artifact-bundle:artifact:${artifactId}:parseable`, !hasText(artifact.parseError), {
        path: artifact.path ?? null,
        parseError: artifact.parseError ?? null
      });
    }
  }
}

function validateReleaseCandidateConsistency(releaseEvidence, manifests) {
  if (!releaseEvidence) {
    return;
  }

  const expected = normalizedText(releaseEvidence.releaseCandidate);
  if (!expected) {
    return;
  }

  for (const [label, manifest] of Object.entries(manifests)) {
    if (!manifest) {
      continue;
    }

    const observed = normalizedText(manifest.releaseCandidate ?? manifest.expectedReleaseCandidate);
    addCheck(`release-candidate:${label}:matches`, observed === expected, {
      observed,
      expected
    });
  }
}

function validateSummaryReleaseCandidateConsistency(summariesByLabel, manifestsByLabel) {
  for (const [label, summary] of Object.entries(summariesByLabel)) {
    const manifest = manifestsByLabel[label];
    if (!summary || !manifest) {
      continue;
    }

    const summaryCandidate = normalizedText(summary.releaseCandidate);
    const manifestCandidate = normalizedText(manifest.releaseCandidate);
    addCheck(`release-candidate:${label}:summary-matches-manifest`, summaryCandidate === manifestCandidate, {
      observed: summaryCandidate,
      expected: manifestCandidate
    });
  }
}

function validateVerifierSummary(label, summary, expectedInputPath) {
  if (!summary) {
    return;
  }

  addCheck(`${label}:status-ok`, summary.status === 'ok', { observed: summary.status ?? null });
  addCheck(`${label}:no-failed-checks`, asArray(summary.failedChecks).length === 0, {
    observed: asArray(summary.failedChecks).length
  });
  addCheck(`${label}:generated-at-present`, hasText(summary.generatedAt), {
    observed: summary.generatedAt ?? null
  });
  addGeneratedAtFreshnessCheck(addCheck, label, summary);
  if (summary.status === 'ok') {
    addCheck(`${label}:release-candidate-present`, hasText(summary.releaseCandidate), {
      observed: summary.releaseCandidate ?? null
    });
  }
  addCheck(`${label}:input-path-present`, hasText(summary.inputPath), {
    observed: summary.inputPath ?? null
  });
  if (hasText(summary.inputPath)) {
    addCheck(`${label}:input-path-default-artifact`, path.resolve(summary.inputPath) === path.resolve(expectedInputPath), {
      observed: path.resolve(summary.inputPath),
      expected: path.resolve(expectedInputPath)
    });
  }
}

function validateClientDeviceAcceptance(clientEvidence) {
  if (!clientEvidence) {
    return;
  }

  addCheck('client-acceptance:status-ok', successful(clientEvidence.status), { observed: clientEvidence.status });

  const platforms = asArray(clientEvidence.platforms);
  const requiredPlatforms = ['android', 'ios', 'windows'];
  for (const platformName of requiredPlatforms) {
    const platform = platforms.find(entry => String(entry.name ?? entry.platform).toLowerCase() === platformName);
    addCheck(`client-acceptance:platform:${platformName}:present`, Boolean(platform), { observed: Boolean(platform) });
    if (!platform) {
      continue;
    }

    addCheck(`client-acceptance:platform:${platformName}:passed`, successful(platform.status ?? platform.result), {
      observed: platform.status ?? platform.result
    });
    addCheck(`client-acceptance:platform:${platformName}:not-build-only`, !['build-only', 'synthetic', 'unit-only'].includes(String(platform.evidenceType ?? '').toLowerCase()), {
      observed: platform.evidenceType ?? null
    });
    addCheck(`client-acceptance:platform:${platformName}:artifact`, artifactLikeReference(platform), {
      evidenceType: platform.evidenceType ?? null
    });
  }

  const scenarios = asArray(clientEvidence.scenarios);
  const requiredScenarios = [
    'onboarding-recovery',
    'one-to-one-messaging',
    'offline-retrieval',
    'groups-lifecycle',
    'attachments',
    'avatars-profile-image',
    'push-lifecycle',
    'release-no-stub-no-mock-guards'
  ];
  for (const scenarioName of requiredScenarios) {
    const scenario = scenarios.find(entry => String(entry.name ?? entry.scenario).toLowerCase() === scenarioName);
    addCheck(`client-acceptance:scenario:${scenarioName}:present`, Boolean(scenario), { observed: Boolean(scenario) });
    if (!scenario) {
      continue;
    }

    addCheck(`client-acceptance:scenario:${scenarioName}:passed`, successful(scenario.status ?? scenario.result), {
      observed: scenario.status ?? scenario.result
    });
    addCheck(`client-acceptance:scenario:${scenarioName}:all-platforms`, requiredPlatforms.every(platform => asArray(scenario.platforms).map(String).map(value => value.toLowerCase()).includes(platform)), {
      observed: scenario.platforms ?? null,
      required: requiredPlatforms
    });
    addCheck(`client-acceptance:scenario:${scenarioName}:artifact`, artifactLikeReference(scenario), {
      observed: Boolean(artifactLikeReference(scenario))
    });
  }
}

function validateOpsDeployment(opsEvidence) {
  if (!opsEvidence) {
    return;
  }

  addCheck('ops-deployment:status-ok', successful(opsEvidence.status), { observed: opsEvidence.status });
  addCheck('ops-deployment:environment-staging-or-production', ['staging', 'production'].includes(String(opsEvidence.environment ?? '').toLowerCase()), {
    observed: opsEvidence.environment ?? null
  });
  addCheck('ops-deployment:dashboards-deployed', opsEvidence.dashboards?.deployed === true, {
    observed: opsEvidence.dashboards?.deployed ?? null
  });
  addCheck('ops-deployment:dashboard-reference', hasText(opsEvidence.dashboards?.url) || hasText(opsEvidence.dashboards?.uid), {
    uid: opsEvidence.dashboards?.uid,
    url: opsEvidence.dashboards?.url
  });
  addCheck('ops-deployment:alert-routes-tested', opsEvidence.alerts?.routesTested === true, {
    observed: opsEvidence.alerts?.routesTested ?? null
  });
  addCheck('ops-deployment:alert-test-artifact', artifactLikeReference(opsEvidence.alerts), {
    observed: Boolean(artifactLikeReference(opsEvidence.alerts))
  });
  addCheck('ops-deployment:post-deploy-verification-ok', successful(opsEvidence.postDeployVerification?.status), {
    observed: opsEvidence.postDeployVerification?.status ?? null
  });
  addCheck('ops-deployment:post-deploy-artifact', artifactLikeReference(opsEvidence.postDeployVerification), {
    observed: Boolean(artifactLikeReference(opsEvidence.postDeployVerification))
  });
}

function validateSecurityAudit(securityAudit) {
  if (!securityAudit) {
    return;
  }

  addCheck('security-audit:status-approved', successful(securityAudit.status), { observed: securityAudit.status });
  addCheck('security-audit:external-audit-closed-or-accepted', ['closed', 'accepted', 'not_required'].includes(String(securityAudit.externalAudit?.status ?? '').toLowerCase()), {
    observed: securityAudit.externalAudit?.status ?? null
  });
  addCheck('security-audit:critical-findings-zero', Number(securityAudit.openFindings?.critical ?? 0) === 0, {
    observed: securityAudit.openFindings?.critical ?? null
  });
  addCheck('security-audit:high-findings-zero-or-accepted', Number(securityAudit.openFindings?.high ?? 0) === 0 || securityAudit.highFindingException?.approved === true, {
    highFindings: securityAudit.openFindings?.high ?? null,
    exceptionApproved: securityAudit.highFindingException?.approved ?? false
  });
  addCheck('security-audit:artifact', artifactLikeReference(securityAudit.externalAudit ?? securityAudit), {
    observed: Boolean(artifactLikeReference(securityAudit.externalAudit ?? securityAudit))
  });
}

function validateGaDecision(gaDecision) {
  if (!gaDecision) {
    return;
  }

  addCheck('ga-decision:decision-go', String(gaDecision.decision ?? '').toLowerCase() === 'go', {
    observed: gaDecision.decision ?? null
  });
  addCheck('ga-decision:meeting-minutes-artifact', artifactLikeReference(gaDecision.meetingMinutes ?? gaDecision), {
    observed: Boolean(artifactLikeReference(gaDecision.meetingMinutes ?? gaDecision))
  });
  addCheck('ga-decision:release-blockers-closed-or-accepted', asArray(gaDecision.releaseBlockers).every(blocker => ['closed', 'accepted'].includes(String(blocker.status ?? '').toLowerCase())), {
    blockers: asArray(gaDecision.releaseBlockers).map(blocker => ({ id: blocker.id, status: blocker.status }))
  });
  const approvals = asArray(gaDecision.approvals);
  for (const role of ['engineering', 'security', 'ops']) {
    const approval = approvals.find(entry => String(entry.role ?? '').toLowerCase() === role);
    addCheck(`ga-decision:approval:${role}`, successful(approval?.status), {
      observed: approval?.status ?? null,
      approver: approval?.approver ?? null
    });
  }

  const stabilization = gaDecision.stabilizationPlan;
  addCheck('ga-decision:stabilization-plan-present', Boolean(stabilization), { observed: Boolean(stabilization) });
  if (stabilization) {
    for (const milestone of ['day30', 'day60', 'day90']) {
      addCheck(`ga-decision:stabilization:${milestone}:owner`, hasText(stabilization[milestone]?.owner), {
        observed: stabilization[milestone]?.owner ?? null
      });
      addCheck(`ga-decision:stabilization:${milestone}:objective`, hasText(stabilization[milestone]?.objective), {
        observed: stabilization[milestone]?.objective ?? null
      });
    }
  }

  addCheck('ga-decision:post-ga-backlog-present', asArray(gaDecision.postGaBacklog).length > 0, {
    observed: asArray(gaDecision.postGaBacklog).length
  });
}

const releaseEvidence = await readJson('release-evidence', path.join(artifactRoot, 'release', 'release-evidence-summary.json'));
validateStrictReleaseEvidence(releaseEvidence);

const releaseArtifactBundle = await readJson('release-artifact-bundle', path.join(artifactRoot, 'release', 'release-artifact-bundle-summary.json'));
validateReleaseArtifactBundle(releaseArtifactBundle);

const clientDeviceAcceptancePath = path.join(artifactRoot, 'release', 'client-device-acceptance.json');
const clientDeviceAcceptanceSummary = await readJson('client-device-acceptance-summary', path.join(artifactRoot, 'release', 'client-device-acceptance-summary.json'));
validateVerifierSummary('client-device-acceptance-summary', clientDeviceAcceptanceSummary, clientDeviceAcceptancePath);
const clientDeviceAcceptance = await readJson('client-device-acceptance', clientDeviceAcceptancePath);
validateClientDeviceAcceptance(clientDeviceAcceptance);
addNoPlaceholderUrlCheck(addCheck, 'client-device-acceptance', clientDeviceAcceptance);
addLocalEvidencePathCheck(addCheck, 'client-device-acceptance', clientDeviceAcceptance, { baseDir: artifactRoot });
addGeneratedAtFreshnessCheck(addCheck, 'client-device-acceptance', clientDeviceAcceptance);

const opsDeploymentPath = path.join(artifactRoot, 'release', 'ops-deployment-evidence.json');
const opsDeploymentSummary = await readJson('ops-deployment-evidence-summary', path.join(artifactRoot, 'release', 'ops-deployment-evidence-summary.json'));
validateVerifierSummary('ops-deployment-evidence-summary', opsDeploymentSummary, opsDeploymentPath);
const opsDeployment = await readJson('ops-deployment-evidence', opsDeploymentPath);
validateOpsDeployment(opsDeployment);
addNoPlaceholderUrlCheck(addCheck, 'ops-deployment-evidence', opsDeployment);
addLocalEvidencePathCheck(addCheck, 'ops-deployment-evidence', opsDeployment, { baseDir: artifactRoot });
addGeneratedAtFreshnessCheck(addCheck, 'ops-deployment-evidence', opsDeployment);

const securityAuditPath = path.join(artifactRoot, 'release', 'security-audit-signoff.json');
const securityAuditSummary = await readJson('security-audit-signoff-summary', path.join(artifactRoot, 'release', 'security-audit-signoff-summary.json'));
validateVerifierSummary('security-audit-signoff-summary', securityAuditSummary, securityAuditPath);
const securityAudit = await readJson('security-audit-signoff', securityAuditPath);
validateSecurityAudit(securityAudit);
addNoPlaceholderUrlCheck(addCheck, 'security-audit-signoff', securityAudit);
addLocalEvidencePathCheck(addCheck, 'security-audit-signoff', securityAudit, { baseDir: artifactRoot });
addGeneratedAtFreshnessCheck(addCheck, 'security-audit-signoff', securityAudit);

const gaDecisionPath = path.join(artifactRoot, 'release', 'ga-decision.json');
const gaDecisionSummary = await readJson('ga-decision-summary', path.join(artifactRoot, 'release', 'ga-decision-summary.json'));
validateVerifierSummary('ga-decision-summary', gaDecisionSummary, gaDecisionPath);
const gaDecision = await readJson('ga-decision', gaDecisionPath);
validateGaDecision(gaDecision);
addNoPlaceholderUrlCheck(addCheck, 'ga-decision', gaDecision);
addLocalEvidencePathCheck(addCheck, 'ga-decision', gaDecision, { baseDir: artifactRoot });
addGeneratedAtFreshnessCheck(addCheck, 'ga-decision', gaDecision);

validateReleaseCandidateConsistency(releaseEvidence, {
  'release-artifact-bundle': releaseArtifactBundle,
  'client-device-acceptance': clientDeviceAcceptance,
  'ops-deployment-evidence': opsDeployment,
  'security-audit-signoff': securityAudit,
  'ga-decision': gaDecision
});
validateSummaryReleaseCandidateConsistency(
  {
    'client-device-acceptance': clientDeviceAcceptanceSummary,
    'ops-deployment-evidence': opsDeploymentSummary,
    'security-audit-signoff': securityAuditSummary,
    'ga-decision': gaDecisionSummary
  },
  {
    'client-device-acceptance': clientDeviceAcceptance,
    'ops-deployment-evidence': opsDeployment,
    'security-audit-signoff': securityAudit,
    'ga-decision': gaDecision
  }
);

const failed = checks.filter(check => !check.passed);
const summary = {
  status: failed.length === 0 ? 'ok' : 'failed',
  generatedAt: new Date().toISOString(),
  workspaceRoot,
  artifactRoot,
  releaseCandidate: normalizedText(releaseEvidence?.releaseCandidate ?? releaseArtifactBundle?.expectedReleaseCandidate),
  checks,
  failedChecks: failed.map(check => check.name),
  requiredEvidence: [
    'artifacts/release/release-evidence-summary.json from strict release gate',
    'artifacts/release/release-artifact-bundle-summary.json from raw bundle preflight',
    'artifacts/release/client-device-acceptance.json plus client-device-acceptance-summary.json',
    'artifacts/release/ops-deployment-evidence.json plus ops-deployment-evidence-summary.json',
    'artifacts/release/security-audit-signoff.json plus security-audit-signoff-summary.json',
    'artifacts/release/ga-decision.json plus ga-decision-summary.json'
  ]
};

await mkdir(outputDir, { recursive: true });
await writeFile(outputPath, `${JSON.stringify(summary, null, 2)}\n`, 'utf8');

if (failed.length > 0) {
  console.error(`Production readiness gate failed (${failed.length} checks). Summary: ${outputPath}`);
  for (const check of failed) {
    console.error(`- ${check.name}`);
  }
  process.exit(1);
}

console.log(`Production readiness gate passed (${checks.length} checks). Summary: ${outputPath}`);
