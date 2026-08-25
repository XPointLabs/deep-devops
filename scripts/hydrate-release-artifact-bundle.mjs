import { access, copyFile, mkdir, readdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const devopsRoot = path.resolve(__dirname, '..');
const artifactRoot = process.env.DEEP_RELEASE_ARTIFACT_ROOT
  ? path.resolve(process.env.DEEP_RELEASE_ARTIFACT_ROOT)
  : path.join(devopsRoot, 'artifacts');
const inputDir = argValue('--input-dir')
  ? path.resolve(argValue('--input-dir'))
  : path.join(artifactRoot, 'hydrated');
const outputPath = argValue('--summary')
  ? path.resolve(argValue('--summary'))
  : path.join(artifactRoot, 'release', 'release-artifact-hydration-summary.json');
const allowMissing = process.argv.includes('--allow-missing');

const artifactMappings = [
  {
    id: 'runtime-gate',
    fileName: 'runtime.gate.json',
    target: path.join(artifactRoot, 'runtime.gate.json')
  },
  {
    id: 'backend-load-smoke',
    fileName: 'backend-load-smoke.json',
    target: path.join(artifactRoot, 'test-results', 'backend-load-smoke.json')
  },
  {
    id: 'backend-restart-smoke',
    fileName: 'backend-restart-smoke.json',
    target: path.join(artifactRoot, 'test-results', 'backend-restart-smoke.json')
  },
  {
    id: 'physical-call',
    fileName: 'mau2-call-result.json',
    target: path.join(artifactRoot, 'test-results', 'mau2-call-result.json')
  },
  {
    id: 'push-provider-canary',
    fileName: 'push-provider-canary.json',
    target: path.join(artifactRoot, 'test-results', 'push-provider-canary.json')
  },
  {
    id: 'multi-node-topology',
    fileName: 'multi-node-topology.json',
    target: path.join(artifactRoot, 'test-results', 'multi-node-topology.json')
  },
  {
    id: 'registry-recovery',
    fileName: 'registry-recovery.json',
    target: path.join(artifactRoot, 'test-results', 'registry-recovery.json')
  },
  {
    id: 'rollback-drill',
    fileName: 'rollback-drill.json',
    target: path.join(artifactRoot, 'test-results', 'rollback-drill.json')
  },
  {
    id: 'security-gate-summary',
    fileName: 'security-gate-summary.json',
    target: path.join(artifactRoot, 'security', 'security-gate-summary.json')
  },
  {
    id: 'observability-gate-summary',
    fileName: 'observability-gate-summary.json',
    target: path.join(artifactRoot, 'observability', 'observability-gate-summary.json')
  },
  {
    id: 'client-device-acceptance',
    fileName: 'client-device-acceptance.json',
    target: path.join(artifactRoot, 'release', 'client-device-acceptance.json'),
    preferPathIncludes: ['/release/']
  },
  {
    id: 'ops-deployment-evidence',
    fileName: 'ops-deployment-evidence.json',
    target: path.join(artifactRoot, 'release', 'ops-deployment-evidence.json'),
    preferPathIncludes: ['/release/']
  },
  {
    id: 'security-audit-signoff',
    fileName: 'security-audit-signoff.json',
    target: path.join(artifactRoot, 'release', 'security-audit-signoff.json'),
    preferPathIncludes: ['/release/']
  },
  {
    id: 'ga-decision',
    fileName: 'ga-decision.json',
    target: path.join(artifactRoot, 'release', 'ga-decision.json'),
    preferPathIncludes: ['/release/']
  },
  {
    id: 'router-c3-latest',
    fileName: 'latest.json',
    alternateFileNames: ['router-c3-latest.json'],
    target: path.join(artifactRoot, 'router-c3-latest.json'),
    preferPathIncludes: ['xnode-c3', 'c3']
  }
];

const checks = [];
const onlyArtifactIds = [...new Set(argValues('--only').flatMap(value => value.split(',')).map(value => value.trim()).filter(Boolean))];
const knownArtifactIds = new Set(artifactMappings.map(mapping => mapping.id));
const unknownOnlyArtifactIds = onlyArtifactIds.filter(id => !knownArtifactIds.has(id));
const selectedArtifactMappings = onlyArtifactIds.length > 0
  ? artifactMappings.filter(mapping => onlyArtifactIds.includes(mapping.id))
  : artifactMappings;

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

function argValues(name) {
  const values = [];
  for (let index = 0; index < process.argv.length; index += 1) {
    const value = process.argv[index];
    if (value === name && index + 1 < process.argv.length && !process.argv[index + 1].startsWith('--')) {
      values.push(process.argv[index + 1]);
    } else if (value.startsWith(`${name}=`)) {
      values.push(value.slice(name.length + 1));
    }
  }

  return values;
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

async function* walkFiles(directory) {
  let entries = [];
  try {
    entries = await readdir(directory, { withFileTypes: true });
  } catch {
    return;
  }

  for (const entry of entries) {
    const entryPath = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      yield* walkFiles(entryPath);
    } else if (entry.isFile()) {
      yield entryPath;
    }
  }
}

function normalizedPath(filePath) {
  return filePath.replaceAll('\\', '/').toLowerCase();
}

function candidateScore(filePath, mapping) {
  const normalized = normalizedPath(filePath);
  let score = 0;
  for (const part of mapping.preferPathIncludes ?? []) {
    if (normalized.includes(String(part).toLowerCase())) {
      score += 10;
    }
  }
  if (normalized.includes(`/${mapping.fileName.toLowerCase()}`)) {
    score += 1;
  }
  return score;
}

function selectCandidate(candidates, mapping) {
  const pathDepth = filePath => normalizedPath(filePath).split('/').length;
  return candidates
    .map(filePath => ({ filePath, score: candidateScore(filePath, mapping) }))
    .sort((left, right) => right.score - left.score || pathDepth(left.filePath) - pathDepth(right.filePath) || left.filePath.localeCompare(right.filePath))[0]?.filePath ?? null;
}

const inputExists = await fileExists(inputDir);
addCheck('input-dir:exists', inputExists, { path: inputDir });

const discoveredFiles = [];
if (inputExists) {
  for await (const filePath of walkFiles(inputDir)) {
    discoveredFiles.push(filePath);
  }
}

const hydratedArtifacts = [];
for (const artifactId of unknownOnlyArtifactIds) {
  addCheck(`only:${artifactId}:known`, false, {
    requestedArtifactIds: onlyArtifactIds,
    knownArtifactIds: [...knownArtifactIds]
  });
}

for (const mapping of selectedArtifactMappings) {
  const expectedFileNames = [mapping.fileName, ...(mapping.alternateFileNames ?? [])];
  const candidates = discoveredFiles.filter(filePath => expectedFileNames.includes(path.basename(filePath)));
  const sourcePath = selectCandidate(candidates, mapping);
  addCheck(`${mapping.id}:source-found`, Boolean(sourcePath), {
    fileNames: expectedFileNames,
    candidates: candidates.map(candidate => path.relative(inputDir, candidate))
  });

  if (!sourcePath) {
    hydratedArtifacts.push({
      id: mapping.id,
      sourcePath: null,
      targetPath: mapping.target,
      hydrated: false
    });
    continue;
  }

  await mkdir(path.dirname(mapping.target), { recursive: true });
  await copyFile(sourcePath, mapping.target);
  addCheck(`${mapping.id}:copied`, await fileExists(mapping.target), {
    sourcePath,
    targetPath: mapping.target
  });
  hydratedArtifacts.push({
    id: mapping.id,
    sourcePath,
    targetPath: mapping.target,
    hydrated: true
  });
}

const failed = checks.filter(check => !check.passed);
const summary = {
  status: failed.length === 0 ? 'ok' : 'failed',
  generatedAt: new Date().toISOString(),
  artifactRoot,
  inputDir,
  allowMissing,
  requestedArtifactIds: onlyArtifactIds,
  selectedArtifactIds: selectedArtifactMappings.map(mapping => mapping.id),
  discoveredFileCount: discoveredFiles.length,
  hydratedArtifacts,
  checks,
  failedChecks: failed.map(check => check.name)
};

await mkdir(path.dirname(outputPath), { recursive: true });
await writeFile(outputPath, `${JSON.stringify(summary, null, 2)}\n`, 'utf8');

if (failed.length > 0) {
  console.error(`Release artifact hydration failed (${failed.length} checks). Summary: ${outputPath}`);
  for (const check of failed) {
    console.error(`- ${check.name}`);
  }
  if (!allowMissing) {
    process.exit(1);
  }
} else {
  console.log(`Release artifact hydration passed (${hydratedArtifacts.length} artifacts). Summary: ${outputPath}`);
}
