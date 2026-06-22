import { access, mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { addGeneratedAtFreshnessCheck, addLocalEvidencePathCheck, addNoPlaceholderUrlCheck } from './release-evidence-guards.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const devopsRoot = path.resolve(__dirname, '..');
const artifactRoot = process.env.DEEP_RELEASE_ARTIFACT_ROOT
  ? path.resolve(process.env.DEEP_RELEASE_ARTIFACT_ROOT)
  : path.join(devopsRoot, 'artifacts');
const inputPath = process.env.DEEP_OPS_DEPLOYMENT_EVIDENCE
  ? path.resolve(process.env.DEEP_OPS_DEPLOYMENT_EVIDENCE)
  : path.join(artifactRoot, 'release', 'ops-deployment-evidence.json');
const outputDir = path.join(artifactRoot, 'release');
const outputPath = path.join(outputDir, 'ops-deployment-evidence-summary.json');

const checks = [];

function addCheck(name, passed, details = {}) {
  checks.push({ name, passed: Boolean(passed), ...details });
}

function asArray(value) {
  return Array.isArray(value) ? value : [];
}

function hasText(value) {
  return typeof value === 'string' && value.trim().length > 0;
}

function normalizedText(value) {
  return hasText(value) ? value.trim() : null;
}

function successful(value) {
  return ['ok', 'passed', 'success', 'approved'].includes(String(value ?? '').toLowerCase());
}

function hasEvidenceReference(value) {
  return Boolean(value && typeof value === 'object' && (hasText(value.url) || hasText(value.path) || hasText(String(value.id ?? ''))));
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
  if (!await fileExists(filePath)) {
    addCheck(`${label}:exists`, false, { path: filePath });
    return null;
  }

  try {
    const raw = await readFile(filePath, 'utf8');
    const parsed = JSON.parse(raw.replace(/^\uFEFF/, ''));
    addCheck(`${label}:exists`, true, { path: filePath });
    return parsed;
  } catch (error) {
    addCheck(`${label}:parse`, false, { path: filePath, error: error.message });
    return null;
  }
}

function validateManifest(manifest) {
  if (!manifest) {
    return;
  }

  addCheck('manifest:status-ok', successful(manifest.status), { observed: manifest.status ?? null });
  addCheck('manifest:generated-at-present', hasText(manifest.generatedAt), { observed: manifest.generatedAt ?? null });
  addGeneratedAtFreshnessCheck(addCheck, 'manifest', manifest);
  addCheck('manifest:release-candidate-present', hasText(manifest.releaseCandidate), { observed: manifest.releaseCandidate ?? null });
  addCheck('manifest:environment-staging-or-production', ['staging', 'production'].includes(String(manifest.environment ?? '').toLowerCase()), {
    observed: manifest.environment ?? null
  });
  addCheck('manifest:deployment-reference', artifactLikeReference(manifest.deployment ?? manifest), {
    observed: Boolean(artifactLikeReference(manifest.deployment ?? manifest))
  });

  const dashboards = manifest.dashboards ?? {};
  addCheck('dashboards:deployed', dashboards.deployed === true, { observed: dashboards.deployed ?? null });
  addCheck('dashboards:reference', hasText(dashboards.url) || hasText(dashboards.uid), { url: dashboards.url, uid: dashboards.uid });
  addCheck('dashboards:release-health-panel', asArray(dashboards.panels).includes('Deep Messenger Release Health') || asArray(dashboards.panels).length >= 1, {
    observed: dashboards.panels ?? null
  });
  addCheck('dashboards:artifact', artifactLikeReference(dashboards), { observed: Boolean(artifactLikeReference(dashboards)) });

  const alerts = manifest.alerts ?? {};
  addCheck('alerts:routes-tested', alerts.routesTested === true, { observed: alerts.routesTested ?? null });
  addCheck('alerts:critical-route-tested', asArray(alerts.testedRoutes).includes('critical-release-pager'), {
    observed: alerts.testedRoutes ?? null
  });
  addCheck('alerts:warning-route-tested', asArray(alerts.testedRoutes).includes('warning-release-watch'), {
    observed: alerts.testedRoutes ?? null
  });
  addCheck('alerts:artifact', artifactLikeReference(alerts), { observed: Boolean(artifactLikeReference(alerts)) });

  const postDeploy = manifest.postDeployVerification ?? {};
  addCheck('post-deploy:status-ok', successful(postDeploy.status), { observed: postDeploy.status ?? null });
  addCheck('post-deploy:runtime-health-ok', postDeploy.runtimeHealth?.status === 'ok' || postDeploy.runtimeHealth?.passed === true, {
    observed: postDeploy.runtimeHealth?.status ?? postDeploy.runtimeHealth?.passed ?? null
  });
  addCheck('post-deploy:release-gate-reference', artifactLikeReference(postDeploy.releaseGate ?? postDeploy), {
    observed: Boolean(artifactLikeReference(postDeploy.releaseGate ?? postDeploy))
  });
  addCheck('post-deploy:artifact', artifactLikeReference(postDeploy), { observed: Boolean(artifactLikeReference(postDeploy)) });

  const recovery = manifest.recovery ?? {};
  addCheck('recovery:backup-location', hasText(recovery.backupLocation), { observed: recovery.backupLocation ?? null });
  addCheck('recovery:rollback-artifact', artifactLikeReference(recovery.rollbackDrill ?? recovery), {
    observed: Boolean(artifactLikeReference(recovery.rollbackDrill ?? recovery))
  });
}

const manifest = await readJson('ops-deployment-evidence', inputPath);
validateManifest(manifest);
addNoPlaceholderUrlCheck(addCheck, 'manifest', manifest);
addLocalEvidencePathCheck(addCheck, 'manifest', manifest, { baseDir: artifactRoot });

const failed = checks.filter(check => !check.passed);
const summary = {
  status: failed.length === 0 ? 'ok' : 'failed',
  generatedAt: new Date().toISOString(),
  inputPath,
  releaseCandidate: normalizedText(manifest?.releaseCandidate),
  checks,
  failedChecks: failed.map(check => check.name)
};

await mkdir(outputDir, { recursive: true });
await writeFile(outputPath, `${JSON.stringify(summary, null, 2)}\n`, 'utf8');

if (failed.length > 0) {
  console.error(`Ops deployment evidence gate failed (${failed.length} checks). Summary: ${outputPath}`);
  for (const check of failed) {
    console.error(`- ${check.name}`);
  }
  process.exit(1);
}

console.log(`Ops deployment evidence gate passed (${checks.length} checks). Summary: ${outputPath}`);
