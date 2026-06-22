import { appendFile, mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { postReadinessCiRuns, releasePrerequisiteCiRuns } from './release-ci-lanes.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const devopsRoot = path.resolve(__dirname, '..');
const artifactRoot = process.env.DEEP_RELEASE_ARTIFACT_ROOT
  ? path.resolve(process.env.DEEP_RELEASE_ARTIFACT_ROOT)
  : path.join(devopsRoot, 'artifacts');
const releaseDir = path.join(artifactRoot, 'release');

const owner = argValue('--owner')
  ?? process.env.DEEP_GITHUB_OWNER
  ?? process.env.GITHUB_REPOSITORY_OWNER
  ?? 'XPointLabs';
const branch = argValue('--branch') ?? process.env.DEEP_GITHUB_BRANCH ?? 'master';
const releaseCandidate = argValue('--release-candidate')
  ?? process.env.DEEP_RELEASE_CANDIDATE
  ?? null;
const outputPath = argValue('--output')
  ? path.resolve(argValue('--output'))
  : path.join(releaseDir, 'attached-ci-source.json');
const summaryPath = argValue('--summary')
  ? path.resolve(argValue('--summary'))
  : path.join(releaseDir, 'attached-ci-source-summary.json');
const maxRuns = Number(argValue('--max-runs') ?? process.env.DEEP_ATTACHED_CI_MAX_RUNS ?? 30);
const requireSuccess = process.argv.includes('--require-success');
const includeProductionReadiness = process.argv.includes('--include-production-readiness')
  || process.env.DEEP_ATTACHED_CI_INCLUDE_PRODUCTION_READINESS === 'true';
const ciRunsToCollect = includeProductionReadiness ? postReadinessCiRuns : releasePrerequisiteCiRuns;
const token = process.env.DEEP_GITHUB_TOKEN
  ?? process.env.GH_TOKEN
  ?? process.env.GITHUB_TOKEN
  ?? null;

const checks = [];
const errors = [];

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

function hasText(value) {
  return typeof value === 'string' && value.trim().length > 0;
}

function positiveInteger(value) {
  return Number.isInteger(value) && value > 0;
}

function artifactHtmlUrl(repository, runId, artifactId) {
  return `https://github.com/${owner}/${repository}/actions/runs/${runId}/artifacts/${artifactId}`;
}

function outputKey(value) {
  return String(value ?? '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '');
}

async function writeGithubOutputs(runs) {
  if (!hasText(process.env.GITHUB_OUTPUT)) {
    return;
  }

  const lines = [];
  for (const run of runs) {
    const key = outputKey(run.name);
    if (!key) {
      continue;
    }

    lines.push(`${key}_run_id=${run.runId}`);
    lines.push(`${key}_repository=${run.repository}`);
    lines.push(`${key}_conclusion=${run.conclusion}`);
  }

  if (lines.length > 0) {
    await appendFile(process.env.GITHUB_OUTPUT, `${lines.join('\n')}\n`, 'utf8');
  }
}

function apiUrl(urlPath, query = {}) {
  const url = new URL(`https://api.github.com${urlPath}`);
  for (const [key, value] of Object.entries(query)) {
    if (value !== undefined && value !== null && value !== '') {
      url.searchParams.set(key, String(value));
    }
  }
  return url;
}

async function githubJson(url) {
  const response = await fetch(url, {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28'
    }
  });

  const text = await response.text();
  let parsed = null;
  if (text.length > 0) {
    try {
      parsed = JSON.parse(text);
    } catch {
      parsed = { message: text.slice(0, 500) };
    }
  }

  if (!response.ok) {
    throw new Error(`${response.status} ${response.statusText}: ${parsed?.message ?? 'GitHub API request failed'}`);
  }

  return parsed;
}

async function workflowRuns(requiredRun) {
  const url = apiUrl(
    `/repos/${owner}/${requiredRun.repository}/actions/workflows/${encodeURIComponent(requiredRun.workflow)}/runs`,
    {
      branch,
      status: 'completed',
      per_page: positiveInteger(maxRuns) ? maxRuns : 30
    }
  );
  const response = await githubJson(url);
  return Array.isArray(response?.workflow_runs) ? response.workflow_runs : [];
}

async function runArtifacts(requiredRun, run) {
  const url = apiUrl(`/repos/${owner}/${requiredRun.repository}/actions/runs/${run.id}/artifacts`, {
    per_page: 100
  });
  const response = await githubJson(url);
  return Array.isArray(response?.artifacts) ? response.artifacts : [];
}

async function collectLane(requiredRun) {
  const runs = await workflowRuns(requiredRun);
  addCheck(`lane:${requiredRun.name}:runs-present`, runs.length > 0, {
    repository: `${owner}/${requiredRun.repository}`,
    workflow: requiredRun.workflow,
    branch,
    observed: runs.length
  });

  for (const run of runs) {
    if (requireSuccess && run.conclusion !== 'success') {
      continue;
    }

    const artifacts = await runArtifacts(requiredRun, run);
    const matchingArtifacts = requiredRun.artifacts
      .map(name => artifacts.find(artifact => artifact.name === name))
      .filter(Boolean);
    const hasAllArtifacts = matchingArtifacts.length === requiredRun.artifacts.length;
    if (!hasAllArtifacts) {
      continue;
    }

    addCheck(`lane:${requiredRun.name}:selected`, true, {
      runId: run.id,
      conclusion: run.conclusion,
      artifactNames: matchingArtifacts.map(artifact => artifact.name)
    });

    return {
      name: requiredRun.name,
      repository: `${owner}/${requiredRun.repository}`,
      workflow: requiredRun.workflow,
      runId: run.id,
      runNumber: run.run_number,
      runAttempt: run.run_attempt,
      headSha: run.head_sha,
      conclusion: run.conclusion,
      htmlUrl: run.html_url,
      artifacts: matchingArtifacts.map(artifact => ({
        name: artifact.name,
        id: artifact.id,
        url: artifactHtmlUrl(requiredRun.repository, run.id, artifact.id)
      }))
    };
  }

  addCheck(`lane:${requiredRun.name}:selected`, false, {
    repository: `${owner}/${requiredRun.repository}`,
    workflow: requiredRun.workflow,
    branch,
    requiredArtifacts: requiredRun.artifacts,
    requireSuccess
  });
  return null;
}

addCheck('github-token:present', hasText(token), {
  env: hasText(token) ? 'provided' : 'missing'
});
addCheck('release-candidate:present', hasText(releaseCandidate), {
  observed: releaseCandidate
});
addCheck('owner:present', hasText(owner), { observed: owner });
addCheck('branch:present', hasText(branch), { observed: branch });

const collectedRuns = [];
if (hasText(token) && hasText(owner) && hasText(branch)) {
  for (const requiredRun of ciRunsToCollect) {
    try {
      const run = await collectLane(requiredRun);
      if (run) {
        collectedRuns.push(run);
      }
    } catch (error) {
      errors.push({
        lane: requiredRun.name,
        repository: `${owner}/${requiredRun.repository}`,
        workflow: requiredRun.workflow,
        error: error.message
      });
      addCheck(`lane:${requiredRun.name}:api`, false, {
        repository: `${owner}/${requiredRun.repository}`,
        workflow: requiredRun.workflow,
        error: error.message
      });
    }
  }
}

const source = {
  generatedAt: new Date().toISOString(),
  releaseCandidate,
  owner,
  branch,
  includeProductionReadiness,
  runs: collectedRuns
};

const nonSuccessRuns = collectedRuns.filter(run => run.conclusion !== 'success');
for (const run of nonSuccessRuns) {
  addCheck(`lane:${run.name}:conclusion-success`, false, {
    observed: run.conclusion,
    note: 'attached-ci-manifest.mjs will keep this lane release-blocking until a green run is collected.'
  });
}

const failed = checks.filter(check => !check.passed);
const blockingFailed = failed.filter(check => {
  if (check.name.endsWith(':conclusion-success')) {
    return requireSuccess;
  }
  return true;
});
const summary = {
  status: blockingFailed.length === 0 ? 'ok' : 'failed',
  generatedAt: new Date().toISOString(),
  outputPath,
  releaseCandidate,
  owner,
  branch,
  requireSuccess,
  includeProductionReadiness,
  requiredRuns: ciRunsToCollect,
  collectedRuns: collectedRuns.map(run => ({
    name: run.name,
    repository: run.repository,
    workflow: run.workflow,
    runId: run.runId,
    conclusion: run.conclusion,
    artifacts: run.artifacts.map(artifact => artifact.name)
  })),
  nonSuccessRuns: nonSuccessRuns.map(run => run.name),
  errors,
  checks,
  failedChecks: failed.map(check => check.name),
  blockingFailedChecks: blockingFailed.map(check => check.name)
};

await mkdir(path.dirname(outputPath), { recursive: true });
await mkdir(path.dirname(summaryPath), { recursive: true });
await writeFile(outputPath, `${JSON.stringify(source, null, 2)}\n`, 'utf8');
await writeFile(summaryPath, `${JSON.stringify(summary, null, 2)}\n`, 'utf8');
await writeGithubOutputs(collectedRuns);

if (blockingFailed.length > 0) {
  console.error(`Attached CI source collection failed (${blockingFailed.length} blocking checks). Summary: ${summaryPath}`);
  for (const check of blockingFailed) {
    console.error(`- ${check.name}`);
  }
  process.exit(1);
}

console.log(`Attached CI source collected (${collectedRuns.length} runs). Source: ${outputPath}. Summary: ${summaryPath}`);
if (nonSuccessRuns.length > 0) {
  console.error(`Non-success CI lanes collected: ${nonSuccessRuns.map(run => run.name).join(', ')}`);
}
