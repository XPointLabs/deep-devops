import { mkdir, writeFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const devopsRoot = path.resolve(__dirname, '..');
const workspaceRoot = path.resolve(devopsRoot, '..');
const artifactRoot = process.env.DEEP_RELEASE_ARTIFACT_ROOT
  ? path.resolve(process.env.DEEP_RELEASE_ARTIFACT_ROOT)
  : path.join(devopsRoot, 'artifacts');
const outputPath = argValue('--output')
  ? path.resolve(argValue('--output'))
  : path.join(artifactRoot, 'test-results', 'registry-recovery.json');
const resultsDir = argValue('--results-dir')
  ? path.resolve(argValue('--results-dir'))
  : path.join(artifactRoot, 'test-results', 'registry-recovery');
const registryRoot = process.env.DEEP_REGISTRY_REPO
  ? path.resolve(process.env.DEEP_REGISTRY_REPO)
  : path.join(workspaceRoot, 'deep-registry-api');
const solutionPath = path.join(registryRoot, 'Deep.Registry.Api.slnx');

const requiredTests = [
  'NodeRegistry_PersistsAndReloadsFromSnapshot',
  'NodeRegistry_RecoversFromCorruptedStateFile',
  'RuntimeEndpoint_ReturnsRegistryStats',
  'NodeRegistry_ReconciliationJob_TracksLastReportAndRuns'
];

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

function outputSnippet(value) {
  const normalized = String(value ?? '').trim();
  return normalized.length <= 4000 ? normalized : `${normalized.slice(0, 4000)}...`;
}

await mkdir(resultsDir, { recursive: true });
await mkdir(path.dirname(outputPath), { recursive: true });

const filter = requiredTests.map(testName => `FullyQualifiedName~${testName}`).join('|');
const commandArgs = [
  'test',
  solutionPath,
  '--configuration',
  'Release',
  '--filter',
  filter,
  '--logger',
  'trx;LogFileName=registry-recovery.trx',
  '--results-directory',
  resultsDir
];

const result = spawnSync('dotnet', commandArgs, {
  cwd: registryRoot,
  env: process.env,
  encoding: 'utf8'
});

const passed = result.status === 0;
const summary = {
  status: passed ? 'ok' : 'failed',
  generatedAt: new Date().toISOString(),
  workspaceRoot,
  registryRoot,
  solutionPath,
  command: ['dotnet', ...commandArgs].join(' '),
  exitCode: result.status,
  requiredTests,
  passedTests: passed ? requiredTests : [],
  coverage: {
    snapshotPersistenceReload: passed,
    corruptedSnapshotQuarantine: passed,
    runtimeRecoveryCounters: passed,
    reconciliationJobStatus: passed
  },
  artifacts: {
    trx: path.join(resultsDir, 'registry-recovery.trx')
  },
  stdout: outputSnippet(result.stdout),
  stderr: outputSnippet(result.stderr)
};

await writeFile(outputPath, `${JSON.stringify(summary, null, 2)}\n`, 'utf8');

if (!passed) {
  console.error(`Registry recovery drill failed. Summary: ${outputPath}`);
  process.exit(result.status ?? 1);
}

console.log(`Registry recovery drill passed. Summary: ${outputPath}`);
