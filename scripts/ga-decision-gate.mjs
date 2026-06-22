import { access, mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { addGeneratedAtFreshnessCheck, addLocalEvidencePathCheck, addNoPlaceholderUrlCheck } from './release-evidence-guards.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const devopsRoot = path.resolve(__dirname, '..');
const artifactRoot = process.env.DEEP_RELEASE_ARTIFACT_ROOT
  ? path.resolve(process.env.DEEP_RELEASE_ARTIFACT_ROOT)
  : path.join(devopsRoot, 'artifacts');
const inputPath = process.env.DEEP_GA_DECISION
  ? path.resolve(process.env.DEEP_GA_DECISION)
  : path.join(artifactRoot, 'release', 'ga-decision.json');
const outputDir = path.join(artifactRoot, 'release');
const outputPath = path.join(outputDir, 'ga-decision-summary.json');

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

  addCheck('decision:go', String(manifest.decision ?? '').toLowerCase() === 'go', { observed: manifest.decision ?? null });
  addCheck('decision:generated-at-present', hasText(manifest.generatedAt), { observed: manifest.generatedAt ?? null });
  addGeneratedAtFreshnessCheck(addCheck, 'decision', manifest);
  addCheck('decision:release-candidate-present', hasText(manifest.releaseCandidate), { observed: manifest.releaseCandidate ?? null });
  addCheck('decision:meeting-minutes-artifact', artifactLikeReference(manifest.meetingMinutes ?? manifest), {
    observed: Boolean(artifactLikeReference(manifest.meetingMinutes ?? manifest))
  });

  const blockers = asArray(manifest.releaseBlockers);
  addCheck('blockers:present', blockers.length > 0, { observed: blockers.length });
  addCheck('blockers:closed-or-accepted', blockers.every(blocker => ['closed', 'accepted'].includes(String(blocker.status ?? '').toLowerCase())), {
    observed: blockers.map(blocker => ({ id: blocker.id, status: blocker.status }))
  });

  const approvals = asArray(manifest.approvals);
  for (const role of ['engineering', 'security', 'ops']) {
    const approval = approvals.find(entry => String(entry.role ?? '').toLowerCase() === role);
    addCheck(`approval:${role}:approved`, successful(approval?.status), {
      status: approval?.status ?? null,
      approver: approval?.approver ?? null
    });
    addCheck(`approval:${role}:artifact-or-timestamp`, hasText(approval?.approvedAt) || artifactLikeReference(approval), {
      approvedAt: approval?.approvedAt ?? null
    });
  }

  const stabilization = manifest.stabilizationPlan;
  addCheck('stabilization:present', Boolean(stabilization), { observed: Boolean(stabilization) });
  if (stabilization) {
    for (const milestone of ['day30', 'day60', 'day90']) {
      addCheck(`stabilization:${milestone}:owner`, hasText(stabilization[milestone]?.owner), {
        observed: stabilization[milestone]?.owner ?? null
      });
      addCheck(`stabilization:${milestone}:objective`, hasText(stabilization[milestone]?.objective), {
        observed: stabilization[milestone]?.objective ?? null
      });
    }
  }

  addCheck('post-ga-backlog:present', asArray(manifest.postGaBacklog).length > 0, {
    observed: asArray(manifest.postGaBacklog).length
  });
  addCheck('post-ga-backlog:vpn-deferred', asArray(manifest.postGaBacklog).some(item => String(item.scope ?? item.title ?? '').toLowerCase().includes('vpn')), {
    observed: asArray(manifest.postGaBacklog).map(item => item.scope ?? item.title ?? item.id)
  });
}

const manifest = await readJson('ga-decision', inputPath);
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
  console.error(`GA decision gate failed (${failed.length} checks). Summary: ${outputPath}`);
  for (const check of failed) {
    console.error(`- ${check.name}`);
  }
  process.exit(1);
}

console.log(`GA decision gate passed (${checks.length} checks). Summary: ${outputPath}`);
