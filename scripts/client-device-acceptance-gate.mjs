import { access, mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { addGeneratedAtFreshnessCheck, addLocalEvidencePathCheck, addNoPlaceholderUrlCheck } from './release-evidence-guards.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const devopsRoot = path.resolve(__dirname, '..');
const artifactRoot = process.env.DEEP_RELEASE_ARTIFACT_ROOT
  ? path.resolve(process.env.DEEP_RELEASE_ARTIFACT_ROOT)
  : path.join(devopsRoot, 'artifacts');
const inputPath = process.env.DEEP_CLIENT_DEVICE_ACCEPTANCE
  ? path.resolve(process.env.DEEP_CLIENT_DEVICE_ACCEPTANCE)
  : path.join(artifactRoot, 'release', 'client-device-acceptance.json');
const outputDir = path.join(artifactRoot, 'release');
const outputPath = path.join(outputDir, 'client-device-acceptance-summary.json');

const requiredPlatforms = ['android', 'ios', 'windows'];
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

function forbiddenEvidenceType(value) {
  return ['build-only', 'synthetic', 'unit-only', 'local-only'].includes(String(value ?? '').toLowerCase());
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
  addCheck('manifest:release-candidate-present', hasText(manifest.releaseCandidate), {
    observed: manifest.releaseCandidate ?? null
  });
  addCheck('manifest:deep-stack-reference', artifactLikeReference(manifest.deepSessionStack ?? manifest.stackEvidence), {
    observed: Boolean(artifactLikeReference(manifest.deepSessionStack ?? manifest.stackEvidence))
  });

  const platforms = asArray(manifest.platforms);
  for (const platformName of requiredPlatforms) {
    const platform = platforms.find(entry => String(entry.name ?? entry.platform ?? '').toLowerCase() === platformName);
    addCheck(`platform:${platformName}:present`, Boolean(platform), { observed: Boolean(platform) });
    if (!platform) {
      continue;
    }

    addCheck(`platform:${platformName}:passed`, successful(platform.status ?? platform.result), {
      observed: platform.status ?? platform.result ?? null
    });
    addCheck(`platform:${platformName}:device-evidence-type`, !forbiddenEvidenceType(platform.evidenceType), {
      observed: platform.evidenceType ?? null
    });
    addCheck(`platform:${platformName}:device-or-lab-id`, hasText(platform.deviceId) || hasText(platform.deviceLabRunId), {
      deviceId: platform.deviceId ?? null,
      deviceLabRunId: platform.deviceLabRunId ?? null
    });
    addCheck(`platform:${platformName}:artifact`, artifactLikeReference(platform), {
      observed: Boolean(artifactLikeReference(platform))
    });
  }

  const scenarios = asArray(manifest.scenarios);
  for (const scenarioName of requiredScenarios) {
    const scenario = scenarios.find(entry => String(entry.name ?? entry.scenario ?? '').toLowerCase() === scenarioName);
    addCheck(`scenario:${scenarioName}:present`, Boolean(scenario), { observed: Boolean(scenario) });
    if (!scenario) {
      continue;
    }

    const scenarioPlatforms = asArray(scenario.platforms).map(value => String(value).toLowerCase());
    addCheck(`scenario:${scenarioName}:passed`, successful(scenario.status ?? scenario.result), {
      observed: scenario.status ?? scenario.result ?? null
    });
    addCheck(`scenario:${scenarioName}:all-platforms`, requiredPlatforms.every(platform => scenarioPlatforms.includes(platform)), {
      observed: scenario.platforms ?? null,
      required: requiredPlatforms
    });
    addCheck(`scenario:${scenarioName}:not-build-only`, !forbiddenEvidenceType(scenario.evidenceType), {
      observed: scenario.evidenceType ?? null
    });
    addCheck(`scenario:${scenarioName}:artifact`, artifactLikeReference(scenario), {
      observed: Boolean(artifactLikeReference(scenario))
    });
  }

  const releaseGuards = manifest.releaseGuards ?? {};
  addCheck('release-guards:no-stub-transport', releaseGuards.noStubTransport === true, {
    observed: releaseGuards.noStubTransport ?? null
  });
  addCheck('release-guards:no-session-endpoints', releaseGuards.noSessionEndpoints === true, {
    observed: releaseGuards.noSessionEndpoints ?? null
  });
  addCheck('release-guards:deep-file-url-required', releaseGuards.deepSessionFileUrlRequired === true, {
    observed: releaseGuards.deepSessionFileUrlRequired ?? null
  });
  addCheck('release-guards:deep-push-url-required', releaseGuards.deepSessionPushUrlRequired === true, {
    observed: releaseGuards.deepSessionPushUrlRequired ?? null
  });
}

const manifest = await readJson('client-device-acceptance', inputPath);
validateManifest(manifest);
addNoPlaceholderUrlCheck(addCheck, 'manifest', manifest);
addLocalEvidencePathCheck(addCheck, 'manifest', manifest, { baseDir: artifactRoot });

const failed = checks.filter(check => !check.passed);
const summary = {
  status: failed.length === 0 ? 'ok' : 'failed',
  generatedAt: new Date().toISOString(),
  inputPath,
  releaseCandidate: normalizedText(manifest?.releaseCandidate),
  requiredPlatforms,
  requiredScenarios,
  checks,
  failedChecks: failed.map(check => check.name)
};

await mkdir(outputDir, { recursive: true });
await writeFile(outputPath, `${JSON.stringify(summary, null, 2)}\n`, 'utf8');

if (failed.length > 0) {
  console.error(`Client device acceptance gate failed (${failed.length} checks). Summary: ${outputPath}`);
  for (const check of failed) {
    console.error(`- ${check.name}`);
  }
  process.exit(1);
}

console.log(`Client device acceptance gate passed (${checks.length} checks). Summary: ${outputPath}`);
