import assert from 'node:assert/strict';
import { mkdirSync, rmSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  repositoryRoot,
  runUpdateCeremonyDryRun
} from './update-ceremony.mjs';

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const defaultArtifactDir = path.join(
  repositoryRoot,
  'artifacts',
  'survival',
  'P02C'
);

function parseOptions(argv) {
  const options = { artifactDir: defaultArtifactDir };
  for (let index = 0; index < argv.length; index += 2) {
    const name = argv[index];
    const value = argv[index + 1];
    assert.equal(name, '--artifact-dir');
    assert.ok(value && !value.startsWith('--'), '--artifact-dir requires a value');
    options.artifactDir = path.resolve(value);
  }
  return options;
}

function assertSafeArtifactDirectory(candidate) {
  const artifactsRoot = path.resolve(repositoryRoot, 'artifacts');
  const relative = path.relative(artifactsRoot, candidate);
  assert.ok(
    relative
      && !relative.startsWith(`..${path.sep}`)
      && !path.isAbsolute(relative),
    'P02C dry-run artifact directory must remain below repository artifacts'
  );
}

export async function runUpdateCeremonyContracts({ artifactDir = defaultArtifactDir } = {}) {
  const resolved = path.resolve(artifactDir);
  assertSafeArtifactDirectory(resolved);
  rmSync(resolved, { recursive: true, force: true });
  mkdirSync(resolved, { recursive: true });
  return runUpdateCeremonyDryRun({ outputRoot: resolved });
}

const isMain = process.argv[1]
  && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  try {
    const result = await runUpdateCeremonyContracts(parseOptions(process.argv.slice(2)));
    console.log(
      `P02C update ceremony: ${result.summary.dryRunStatus}; `
      + `activation ${result.summary.activationStatus}/${result.summary.activationRun}`
    );
  } catch (error) {
    console.error(error instanceof Error ? error.stack : String(error));
    process.exitCode = 1;
  }
}
