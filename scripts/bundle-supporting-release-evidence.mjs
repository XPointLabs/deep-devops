import { access, copyFile, mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scan as scanSecrets } from './secret-scan.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const devopsRoot = path.resolve(__dirname, '..');
const defaultArtifactRoot = process.env.DEEP_RELEASE_ARTIFACT_ROOT
  ? path.resolve(process.env.DEEP_RELEASE_ARTIFACT_ROOT)
  : path.join(devopsRoot, 'artifacts');

const sourceRoot = argValue('--source-root')
  ? path.resolve(argValue('--source-root'))
  : defaultArtifactRoot;
const outputDir = argValue('--output-dir')
  ? path.resolve(argValue('--output-dir'))
  : path.join(defaultArtifactRoot, 'supporting-release-evidence');
const summaryPath = argValue('--summary')
  ? path.resolve(argValue('--summary'))
  : path.join(outputDir, 'supporting-release-evidence-summary.json');
const requireAll = process.argv.includes('--require-all');

const supportingArtifacts = [
  {
    id: 'push-provider-canary',
    source: path.join(sourceRoot, 'test-results', 'push-provider-canary.json'),
    target: path.join(outputDir, 'test-results', 'push-provider-canary.json')
  },
  {
    id: 'rollback-drill',
    source: path.join(sourceRoot, 'test-results', 'rollback-drill.json'),
    target: path.join(outputDir, 'test-results', 'rollback-drill.json')
  },
  {
    id: 'registry-recovery',
    source: path.join(sourceRoot, 'test-results', 'registry-recovery.json'),
    target: path.join(outputDir, 'test-results', 'registry-recovery.json')
  },
  {
    id: 'observability-gate-summary',
    source: path.join(sourceRoot, 'observability', 'observability-gate-summary.json'),
    target: path.join(outputDir, 'observability', 'observability-gate-summary.json')
  },
  {
    id: 'client-device-acceptance',
    source: path.join(sourceRoot, 'release', 'client-device-acceptance.json'),
    target: path.join(outputDir, 'release', 'client-device-acceptance.json')
  },
  {
    id: 'ops-deployment-evidence',
    source: path.join(sourceRoot, 'release', 'ops-deployment-evidence.json'),
    target: path.join(outputDir, 'release', 'ops-deployment-evidence.json')
  },
  {
    id: 'security-audit-signoff',
    source: path.join(sourceRoot, 'release', 'security-audit-signoff.json'),
    target: path.join(outputDir, 'release', 'security-audit-signoff.json')
  },
  {
    id: 'ga-decision',
    source: path.join(sourceRoot, 'release', 'ga-decision.json'),
    target: path.join(outputDir, 'release', 'ga-decision.json')
  }
];

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

async function fileExists(filePath) {
  try {
    await access(filePath);
    return true;
  } catch {
    return false;
  }
}

const sourceSecretScan = await scanSecrets({
  root: devopsRoot,
  includeTracked: false,
  artifactRoots: [],
  paths: supportingArtifacts.map(artifact => artifact.source)
});
addCheck('bundle:source-secret-scan', sourceSecretScan.status === 'ok', {
  scannedFiles: sourceSecretScan.scannedFiles,
  findingCount: sourceSecretScan.findingCount,
  findings: sourceSecretScan.findings
});

const copiedArtifacts = [];
for (const artifact of supportingArtifacts) {
  const exists = await fileExists(artifact.source);
  addCheck(`${artifact.id}:source-exists`, exists || !requireAll, {
    source: artifact.source,
    optional: !requireAll && !exists
  });

  if (!exists) {
    copiedArtifacts.push({
      id: artifact.id,
      source: artifact.source,
      target: artifact.target,
      copied: false
    });
    continue;
  }

  await mkdir(path.dirname(artifact.target), { recursive: true });
  await copyFile(artifact.source, artifact.target);
  addCheck(`${artifact.id}:copied`, await fileExists(artifact.target), {
    source: artifact.source,
    target: artifact.target
  });

  copiedArtifacts.push({
    id: artifact.id,
    source: artifact.source,
    target: artifact.target,
    copied: true
  });
}

const copiedCount = copiedArtifacts.filter(artifact => artifact.copied).length;
addCheck('bundle:copied-at-least-one', copiedCount > 0, {
  observed: copiedCount,
  target: '> 0'
});

if (requireAll) {
  addCheck('bundle:all-required-present', copiedCount === supportingArtifacts.length, {
    observed: copiedCount,
    expected: supportingArtifacts.length
  });
}

const outputSecretScan = await scanSecrets({
  root: devopsRoot,
  includeTracked: false,
  artifactRoots: [outputDir]
});
addCheck('bundle:output-secret-scan', outputSecretScan.status === 'ok', {
  scannedFiles: outputSecretScan.scannedFiles,
  findingCount: outputSecretScan.findingCount,
  findings: outputSecretScan.findings
});

const failedChecks = checks.filter(check => !check.passed).map(check => check.name);
const summary = {
  status: failedChecks.length === 0 ? 'ok' : 'failed',
  generatedAt: new Date().toISOString(),
  sourceRoot,
  outputDir,
  requireAll,
  copiedArtifacts,
  checks,
  failedChecks
};

await mkdir(path.dirname(summaryPath), { recursive: true });
await writeFile(summaryPath, `${JSON.stringify(summary, null, 2)}\n`, 'utf8');

if (failedChecks.length > 0) {
  console.error(`Supporting release evidence bundle failed (${failedChecks.length} checks). Summary: ${summaryPath}`);
  for (const failedCheck of failedChecks) {
    console.error(`- ${failedCheck}`);
  }
  process.exit(1);
}

console.log(`Supporting release evidence bundle passed (${copiedCount} artifacts). Summary: ${summaryPath}`);
