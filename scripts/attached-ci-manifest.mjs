import { access, mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { addGeneratedAtFreshnessCheck, addLocalEvidencePathCheck, addNoPlaceholderUrlCheck } from './release-evidence-guards.mjs';
import { requiredCiRuns } from './release-ci-lanes.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const devopsRoot = path.resolve(__dirname, '..');
const artifactRoot = process.env.DEEP_RELEASE_ARTIFACT_ROOT
  ? path.resolve(process.env.DEEP_RELEASE_ARTIFACT_ROOT)
  : path.join(devopsRoot, 'artifacts');
const releaseDir = path.join(artifactRoot, 'release');

const inputPath = argValue('--input')
  ? path.resolve(argValue('--input'))
  : process.env.DEEP_ATTACHED_CI_SOURCE
    ? path.resolve(process.env.DEEP_ATTACHED_CI_SOURCE)
    : path.join(releaseDir, 'attached-ci-source.json');
const outputPath = argValue('--output')
  ? path.resolve(argValue('--output'))
  : process.env.DEEP_ATTACHED_CI_MANIFEST
    ? path.resolve(process.env.DEEP_ATTACHED_CI_MANIFEST)
    : path.join(releaseDir, 'attached-ci-artifacts.json');
const summaryPath = argValue('--summary')
  ? path.resolve(argValue('--summary'))
  : path.join(releaseDir, 'attached-ci-manifest-summary.json');
const expectedReleaseCandidate = argValue('--release-candidate')
  ?? process.env.DEEP_RELEASE_CANDIDATE
  ?? null;

const requiredRuns = requiredCiRuns;

const checks = [];

function argValue(name) {
  const index = process.argv.indexOf(name);
  if (index >= 0 && index + 1 < process.argv.length) {
    const value = process.argv[index + 1];
    return value.startsWith('--') ? null : value;
  }

  const prefix = `${name}=`;
  const inline = process.argv.find(value => value.startsWith(prefix));
  return inline ? inline.slice(prefix.length) : null;
}

function addCheck(name, passed, details = {}) {
  checks.push({ name, passed: Boolean(passed), ...details });
}

function generatedAtNow() {
  const raw = process.env.DEEP_EVIDENCE_NOW;
  if (hasText(raw)) {
    const parsed = new Date(raw);
    if (!Number.isNaN(parsed.getTime())) {
      return parsed.toISOString();
    }
  }

  return new Date().toISOString();
}

function hasText(value) {
  return typeof value === 'string' && value.trim().length > 0;
}

function normalizedText(value) {
  return hasText(value) ? value.trim() : null;
}

function asArray(value) {
  return Array.isArray(value) ? value : [];
}

function successfulConclusion(value) {
  return ['success', 'passed', 'ok'].includes(String(value ?? '').toLowerCase());
}

function fullCommitSha(value) {
  return /^[a-f0-9]{40}$/i.test(String(value ?? ''));
}

function positiveInteger(value) {
  const number = Number(value);
  return Number.isInteger(number) && number > 0;
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

function artifactReferencePresent(artifact) {
  return Boolean(artifact && (hasText(artifact.url) || hasText(artifact.path) || hasText(String(artifact.id ?? ''))));
}

async function fileExists(filePath) {
  try {
    await access(filePath);
    return true;
  } catch {
    return false;
  }
}

async function readJson(filePath) {
  if (!await fileExists(filePath)) {
    addCheck('input:exists', false, { path: filePath });
    return null;
  }

  try {
    const raw = await readFile(filePath, 'utf8');
    addCheck('input:exists', true, { path: filePath });
    return JSON.parse(raw.replace(/^\uFEFF/, ''));
  } catch (error) {
    addCheck('input:parse', false, { path: filePath, error: error.message });
    return null;
  }
}

function rawRunsFromSource(source) {
  const laneRuns = source?.lanes && typeof source.lanes === 'object'
    ? Object.entries(source.lanes).map(([lane, value]) => ({ lane, name: lane, ...value }))
    : [];
  return [...asArray(source?.runs), ...laneRuns];
}

function artifactsForRun(source, run) {
  const runArtifacts = asArray(run?.artifacts);
  const sourceArtifacts = asArray(source?.artifacts).filter(artifact => {
    if (!hasText(run?.name) && !hasText(run?.lane)) {
      return false;
    }

    return artifact.run === run?.name
      || artifact.run === run?.lane
      || artifact.lane === run?.lane
      || artifact.lane === run?.name;
  });

  return [...runArtifacts, ...sourceArtifacts].map(artifact => ({
    name: artifact.name,
    id: artifact.id,
    url: artifact.url,
    path: artifact.path
  })).filter(artifact => hasText(artifact.name));
}

function runField(run, ...names) {
  for (const name of names) {
    const value = run?.[name];
    if (value !== undefined && value !== null) {
      return value;
    }
  }
  return null;
}

function selectRun(source, requiredRun) {
  const runs = rawRunsFromSource(source);
  const candidates = runs.filter(run => {
    const laneMatches = run.name === requiredRun.name || run.lane === requiredRun.name;
    const repoAndWorkflowMatch = repositoryMatches(run.repository, requiredRun.repository)
      && workflowMatches(run.workflow, requiredRun.workflow);
    const hasRequiredArtifact = requiredRun.artifacts.some(name => artifactsForRun(source, run).some(artifact => artifact.name === name));
    return laneMatches || (repoAndWorkflowMatch && hasRequiredArtifact);
  });

  return candidates[0] ?? null;
}

function normalizeRun(source, requiredRun, run) {
  const artifacts = artifactsForRun(source, run);
  return {
    name: requiredRun.name,
    repository: runField(run, 'repository', 'repo') ?? '',
    workflow: runField(run, 'workflow', 'workflowName', 'workflowFileName') ?? '',
    runId: runField(run, 'runId', 'databaseId', 'id') ?? null,
    runNumber: runField(run, 'runNumber', 'number') ?? null,
    runAttempt: runField(run, 'runAttempt', 'attempt') ?? null,
    headSha: runField(run, 'headSha', 'head_sha', 'commit', 'sha') ?? null,
    conclusion: runField(run, 'conclusion', 'result', 'status') ?? null,
    htmlUrl: runField(run, 'htmlUrl', 'url') ?? null,
    artifacts
  };
}

function validateRun(requiredRun, run) {
  const prefix = `lane:${requiredRun.name}`;
  addCheck(`${prefix}:present`, Boolean(run), {
    expectedRepository: requiredRun.repository,
    expectedWorkflow: requiredRun.workflow,
    expectedArtifacts: requiredRun.artifacts
  });
  if (!run) {
    return null;
  }

  addCheck(`${prefix}:repository`, repositoryMatches(run.repository, requiredRun.repository), {
    observed: run.repository,
    expected: requiredRun.repository
  });
  addCheck(`${prefix}:workflow`, workflowMatches(run.workflow, requiredRun.workflow), {
    observed: run.workflow,
    expected: requiredRun.workflow
  });
  addCheck(`${prefix}:conclusion-success`, successfulConclusion(run.conclusion), {
    observed: run.conclusion
  });
  addCheck(`${prefix}:head-sha-full`, fullCommitSha(run.headSha), {
    observed: run.headSha
  });
  addCheck(`${prefix}:run-attempt-present`, positiveInteger(run.runAttempt), {
    observed: run.runAttempt
  });
  addCheck(`${prefix}:run-reference-present`, hasText(run.htmlUrl) || hasText(String(run.runId ?? '')) || hasText(String(run.runNumber ?? '')), {
    runId: run.runId,
    runNumber: run.runNumber,
    htmlUrl: run.htmlUrl
  });

  for (const artifactName of requiredRun.artifacts) {
    const artifact = run.artifacts.find(entry => entry.name === artifactName);
    addCheck(`${prefix}:artifact:${artifactName}`, artifactReferencePresent(artifact), {
      url: artifact?.url,
      path: artifact?.path,
      id: artifact?.id
    });
  }

  return run;
}

const source = await readJson(inputPath);
const sourceReleaseCandidate = normalizedText(source?.releaseCandidate);
const releaseCandidate = normalizedText(expectedReleaseCandidate) ?? sourceReleaseCandidate;
addCheck('release-candidate:present', hasText(releaseCandidate), {
  observed: releaseCandidate
});
if (hasText(expectedReleaseCandidate) && hasText(sourceReleaseCandidate)) {
  addCheck('release-candidate:matches-input', normalizedText(expectedReleaseCandidate) === sourceReleaseCandidate, {
    expected: normalizedText(expectedReleaseCandidate),
    observed: sourceReleaseCandidate
  });
}

const normalizedRuns = [];
if (source) {
  for (const requiredRun of requiredRuns) {
    const selectedRun = selectRun(source, requiredRun);
    const normalizedRun = selectedRun ? normalizeRun(source, requiredRun, selectedRun) : null;
    const validatedRun = validateRun(requiredRun, normalizedRun);
    if (validatedRun) {
      normalizedRuns.push(validatedRun);
    }
  }
}

const manifest = {
  generatedAt: generatedAtNow(),
  releaseCandidate,
  runs: normalizedRuns
};

addNoPlaceholderUrlCheck(addCheck, 'attached-ci-artifacts', manifest);
addLocalEvidencePathCheck(addCheck, 'attached-ci-artifacts', manifest, { baseDir: artifactRoot });
addGeneratedAtFreshnessCheck(addCheck, 'attached-ci-artifacts', manifest);

const failed = checks.filter(check => !check.passed);
const summary = {
  status: failed.length === 0 ? 'ok' : 'failed',
  generatedAt: new Date().toISOString(),
  inputPath,
  outputPath,
  releaseCandidate,
  requiredRuns,
  checks,
  failedChecks: failed.map(check => check.name)
};

await mkdir(path.dirname(summaryPath), { recursive: true });
await writeFile(summaryPath, `${JSON.stringify(summary, null, 2)}\n`, 'utf8');

if (failed.length > 0) {
  console.error(`Attached CI manifest generation failed (${failed.length} checks). Summary: ${summaryPath}`);
  for (const check of failed) {
    console.error(`- ${check.name}`);
  }
  process.exit(1);
}

await mkdir(path.dirname(outputPath), { recursive: true });
await writeFile(outputPath, `${JSON.stringify(manifest, null, 2)}\n`, 'utf8');
console.log(`Attached CI manifest generated (${normalizedRuns.length} runs). Manifest: ${outputPath}`);
