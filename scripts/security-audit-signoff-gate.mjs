import { access, mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { addGeneratedAtFreshnessCheck, addLocalEvidencePathCheck, addNoPlaceholderUrlCheck } from './release-evidence-guards.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const devopsRoot = path.resolve(__dirname, '..');
const artifactRoot = process.env.DEEP_RELEASE_ARTIFACT_ROOT
  ? path.resolve(process.env.DEEP_RELEASE_ARTIFACT_ROOT)
  : path.join(devopsRoot, 'artifacts');
const inputPath = process.env.DEEP_SECURITY_AUDIT_SIGNOFF
  ? path.resolve(process.env.DEEP_SECURITY_AUDIT_SIGNOFF)
  : path.join(artifactRoot, 'release', 'security-audit-signoff.json');
const outputDir = path.join(artifactRoot, 'release');
const outputPath = path.join(outputDir, 'security-audit-signoff-summary.json');

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

  addCheck('manifest:status-approved', successful(manifest.status), { observed: manifest.status ?? null });
  addCheck('manifest:generated-at-present', hasText(manifest.generatedAt), { observed: manifest.generatedAt ?? null });
  addGeneratedAtFreshnessCheck(addCheck, 'manifest', manifest);
  addCheck('manifest:release-candidate-present', hasText(manifest.releaseCandidate), { observed: manifest.releaseCandidate ?? null });
  addCheck('manifest:security-approver-present', hasText(manifest.approver?.name) || hasText(manifest.approver?.id), {
    approver: manifest.approver ?? null
  });

  const externalAudit = manifest.externalAudit ?? {};
  addCheck('external-audit:status-closed-or-accepted', ['closed', 'accepted', 'not_required'].includes(String(externalAudit.status ?? '').toLowerCase()), {
    observed: externalAudit.status ?? null
  });
  addCheck('external-audit:artifact', artifactLikeReference(externalAudit), { observed: Boolean(artifactLikeReference(externalAudit)) });

  const findings = manifest.openFindings ?? {};
  addCheck('findings:critical-zero', Number(findings.critical ?? 0) === 0, { observed: findings.critical ?? null });
  addCheck('findings:high-zero-or-exception', Number(findings.high ?? 0) === 0 || manifest.highFindingException?.approved === true, {
    highFindings: findings.high ?? null,
    exceptionApproved: manifest.highFindingException?.approved ?? false
  });
  if (Number(findings.high ?? 0) > 0) {
    addCheck('findings:high-exception-owner', hasText(manifest.highFindingException?.owner), {
      observed: manifest.highFindingException?.owner ?? null
    });
    addCheck('findings:high-exception-review-date', hasText(manifest.highFindingException?.reviewDate), {
      observed: manifest.highFindingException?.reviewDate ?? null
    });
  }

  const releaseGate = manifest.securityGate ?? {};
  addCheck('security-gate:status-ok', successful(releaseGate.status), { observed: releaseGate.status ?? null });
  addCheck('security-gate:artifact', artifactLikeReference(releaseGate), { observed: Boolean(artifactLikeReference(releaseGate)) });
  addCheck('sbom:attested', manifest.sbom?.attested === true, { observed: manifest.sbom?.attested ?? null });
  addCheck('sbom:artifact', artifactLikeReference(manifest.sbom), { observed: Boolean(artifactLikeReference(manifest.sbom)) });
}

const manifest = await readJson('security-audit-signoff', inputPath);
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
  console.error(`Security audit sign-off gate failed (${failed.length} checks). Summary: ${outputPath}`);
  for (const check of failed) {
    console.error(`- ${check.name}`);
  }
  process.exit(1);
}

console.log(`Security audit sign-off gate passed (${checks.length} checks). Summary: ${outputPath}`);
