import { readFile, readdir } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repositoryRoot = path.resolve(__dirname, '..');
const workflowRoot = path.join(repositoryRoot, '.github', 'workflows');
const requiredLaneEvidence = new Map([
  ['p6-release-evidence.yml', [
    'release-artifact-hydration-summary.json',
    'mau2-call-result.json',
    'client-device-acceptance.json',
    'client-device-acceptance-summary.json',
    'ops-deployment-evidence.json',
    'ops-deployment-evidence-summary.json',
    'security-audit-signoff.json',
    'security-audit-signoff-summary.json',
    'ga-decision.json',
    'ga-decision-summary.json'
  ]],
  ['integration.yml', [
    'runtime.gate.json',
    'runtime.snapshot.json',
    'compose.topology.redacted.json',
    'security/secret-scan-summary.json',
    'test-results/multi-node-topology.json'
  ]],
  ['nightly-full-e2e.yml', [
    'runtime.gate.json',
    'runtime.snapshot.json',
    'compose.topology.redacted.json',
    'security/secret-scan-summary.json',
    'test-results/backend-load-smoke.json',
    'test-results/backend-restart-smoke.json'
  ]],
  ['production-readiness.yml', [
    'production-readiness-status.json',
    'production-readiness-checklist.json'
  ]],
  ['release-secret-preflight.yml', ['release-secret-preflight-summary.json']],
  ['supporting-release-evidence.yml', [
    'supporting-release-evidence-summary.json',
    'test-results/push-provider-canary.json',
    'test-results/rollback-drill.json',
    'test-results/registry-recovery.json',
    'observability/observability-gate-summary.json'
  ]]
]);

function unquote(value) {
  const trimmed = value.trim();
  if ((trimmed.startsWith('"') && trimmed.endsWith('"'))
    || (trimmed.startsWith("'") && trimmed.endsWith("'"))) {
    return trimmed.slice(1, -1);
  }
  return trimmed;
}

function scalar(lines, index, value, keyIndent) {
  const marker = value.trim();
  if (marker !== '|' && marker !== '>' && !marker.startsWith('|') && !marker.startsWith('>')) {
    return { value: unquote(value), end: index };
  }
  const parts = [];
  let cursor = index + 1;
  for (; cursor < lines.length; cursor += 1) {
    const line = lines[cursor];
    if (!line.trim()) {
      parts.push('');
      continue;
    }
    const indent = line.match(/^ */)[0].length;
    if (indent <= keyIndent) break;
    parts.push(line.slice(Math.min(line.length, keyIndent + 2)));
  }
  return { value: parts.join('\n'), end: cursor - 1 };
}

// This is a deliberately constrained Actions YAML parser. It parses the jobs/steps
// graph and step mappings instead of searching raw text, so comments and unrelated
// scalar values cannot satisfy a publication contract.
export function parseWorkflowGraph(content) {
  const lines = content.replace(/\r/g, '').split('\n');
  const jobs = [];
  let inJobs = false;
  let job;
  let step;
  let inSteps = false;
  let inWith = false;

  for (let index = 0; index < lines.length; index += 1) {
    const raw = lines[index];
    if (!raw.trim() || raw.trimStart().startsWith('#')) continue;
    const indent = raw.match(/^ */)[0].length;
    const text = raw.slice(indent);
    if (indent === 0) {
      inJobs = text === 'jobs:';
      job = undefined;
      step = undefined;
      inSteps = false;
      continue;
    }
    if (!inJobs) continue;
    const jobMatch = indent === 2 ? text.match(/^([A-Za-z0-9_-]+):(?:\s+#.*)?$/) : null;
    if (jobMatch) {
      job = { id: jobMatch[1], steps: [] };
      jobs.push(job);
      step = undefined;
      inSteps = false;
      continue;
    }
    if (!job) continue;
    if (indent === 4 && text === 'steps:') {
      inSteps = true;
      continue;
    }
    if (!inSteps) continue;
    if (indent === 6 && text.startsWith('- ')) {
      step = { line: index + 1, with: {} };
      job.steps.push(step);
      inWith = false;
      const inline = text.slice(2).match(/^([A-Za-z0-9_-]+):\s*(.*)$/);
      if (inline) step[inline[1]] = unquote(inline[2]);
      continue;
    }
    if (!step || indent < 8) continue;
    if (indent === 8) {
      const field = text.match(/^([A-Za-z0-9_-]+):\s*(.*)$/);
      if (!field) continue;
      inWith = field[1] === 'with';
      if (inWith) continue;
      const parsed = scalar(lines, index, field[2], indent);
      step[field[1]] = parsed.value;
      index = parsed.end;
      continue;
    }
    if (inWith && indent === 10) {
      const field = text.match(/^([A-Za-z0-9_-]+):\s*(.*)$/);
      if (!field) continue;
      const parsed = scalar(lines, index, field[2], indent);
      step.with[field[1]] = parsed.value;
      index = parsed.end;
    }
  }
  return { jobs };
}

function quotedArgument(command, name) {
  const match = command?.match(new RegExp(`(?:^|\\s)--${name}\\s+"([^"]+)"`));
  return match?.[1] ?? null;
}

function requiredArguments(command) {
  return [...(command ?? '').matchAll(/(?:^|\s)--require\s+("[^"]+"|'[^']+'|[^\s]+)/g)]
    .map(match => unquote(match[1]));
}

function executableText(command) {
  return (command ?? '').split('\n')
    .map(line => line.replace(/^\s*#.*$/, '').replace(/\s+#.*$/, ''))
    .join('\n');
}

function invokes(command, scriptName) {
  const executable = executableText(command);
  return new RegExp(
    `(?:^|\\n)\\s*node\\s+[^\\n]*scripts/${scriptName.replaceAll('.', '\\.')}(?:\\s|$)`
  ).test(executable);
}

function fail(failures, workflow, job, step, message) {
  failures.push(`${workflow}:${step.line} [${job.id}]: ${message}`);
}

export async function validateWorkflows(options = {}) {
  const failures = [];
  let uploadCount = 0;
  const root = options.workflowRoot ?? workflowRoot;
  const names = (await readdir(root))
    .filter(item => item.endsWith('.yml') || item.endsWith('.yaml'))
    .sort();
  for (const name of names) {
    const graph = parseWorkflowGraph(await readFile(path.join(root, name), 'utf8'));
    const workflowCommands = graph.jobs.flatMap(item =>
      item.steps.map(candidate => executableText(candidate.run)));
    for (const job of graph.jobs) {
      for (let index = 0; index < job.steps.length; index += 1) {
        const upload = job.steps[index];
        if (upload.uses !== 'actions/upload-artifact@v4') continue;
        uploadCount += 1;
        const preceding = job.steps.slice(0, index);
        const prepare = preceding.findLast(candidate =>
          invokes(candidate.run, 'artifact-upload-manifest.mjs'));
        const gate = preceding.findLast(candidate =>
          invokes(candidate.run, 'artifact-upload-gate.mjs'));
        if (!prepare?.id || !gate?.id || preceding.indexOf(prepare) >= preceding.indexOf(gate)) {
          fail(failures, name, job, upload, 'upload lacks an ordered manifest preparation and fail-closed gate');
          continue;
        }
        if (!upload.id) fail(failures, name, job, upload, 'upload step requires an id for digest binding');
        if (!upload.if?.includes(`steps.${prepare.id}.outcome == 'success'`)) {
          fail(failures, name, job, upload, 'upload condition is not bound to preparation success');
        }
        if (!upload.if?.includes(`steps.${gate.id}.outcome == 'success'`)) {
          fail(failures, name, job, upload, 'upload condition is not bound to gate success');
        }
        const bundlePath = quotedArgument(gate.run, 'bundle');
        const uploadPath = upload.with.path;
        if (!bundlePath || uploadPath !== bundlePath || /[*?\n]/.test(uploadPath ?? '')) {
          fail(failures, name, job, upload, 'upload must select exactly the single sealed bundle emitted by the gate');
        }
        const download = job.steps.slice(index + 1).find(candidate =>
          candidate.uses === 'actions/download-artifact@v4');
        const verify = job.steps.slice(index + 1).find(candidate =>
          invokes(candidate.run, 'sealed-evidence-bundle.mjs'));
        if (!download || download.with.name !== upload.with.name || !download.with.path) {
          fail(failures, name, job, upload, 'upload lacks a same-name round-trip download');
        }
        if (!verify
          || !verify.run.includes(`steps.${gate.id}.outputs.bundle_sha256`)
          || !verify.run.includes(`steps.${upload.id}.outputs.artifact-id`)
          || !verify.run.includes(`steps.${upload.id}.outputs.artifact-digest`)) {
          fail(failures, name, job, upload, 'round-trip verifier is not bound to bundle SHA, artifact id, and artifact digest');
        }
        if (download && verify && bundlePath) {
          const downloadedBundle = quotedArgument(verify.run, 'bundle');
          const expected = `${download.with.path}/${path.posix.basename(bundlePath)}`;
          if (downloadedBundle !== expected) {
            fail(failures, name, job, upload, 'round-trip verifier does not read the exact downloaded sealed bundle');
          }
        }
      }
    }
    for (const requiredPath of requiredLaneEvidence.get(name) ?? []) {
      const preparers = workflowCommands.filter(command =>
        invokes(command, 'artifact-upload-manifest.mjs')
        && requiredArguments(command).includes(requiredPath));
      const gates = workflowCommands.filter(command =>
        invokes(command, 'artifact-upload-gate.mjs')
        && requiredArguments(command).includes(requiredPath));
      if (preparers.length !== 1 || gates.length !== 1) {
        failures.push(
          `${name}: required lane evidence must be semantically bound once during preparation and once during gating: ${requiredPath}`
        );
      }
    }
  }
  if (uploadCount === 0) failures.push('no artifact uploads were found');
  return { uploadCount, failures };
}

export async function main() {
  const result = await validateWorkflows();
  if (result.failures.length > 0) {
    for (const failure of result.failures) console.error(failure);
    throw new Error(`${result.failures.length} artifact upload contract violation(s)`);
  }
  console.log(`Artifact upload contracts passed (${result.uploadCount} sealed round-trip uploads).`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  main().catch(error => {
    console.error(`Artifact upload contract validation failed: ${error.message}`);
    process.exitCode = 1;
  });
}
