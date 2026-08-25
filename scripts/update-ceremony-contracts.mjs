import assert from 'node:assert/strict';
import { existsSync, lstatSync, mkdirSync, realpathSync, rmSync } from 'node:fs';
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
  'generated',
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
  const segments = relative.split(path.sep);
  assert.ok(
    relative
      && !relative.startsWith(`..${path.sep}`)
      && !path.isAbsolute(relative)
      && segments.includes('generated'),
    'P02C generated output must remain in a distinct repository artifacts/**/generated subdirectory'
  );
  const historicalEvidenceRoot = path.resolve(repositoryRoot, 'artifacts', 'survival');
  const historicalRelative = path.relative(historicalEvidenceRoot, candidate);
  assert.ok(
    path.isAbsolute(historicalRelative)
      || historicalRelative === '..'
      || historicalRelative.startsWith(`..${path.sep}`),
    'generated output cannot enter the historical survival evidence namespace'
  );
  let existingAncestor = candidate;
  while (!existsSync(existingAncestor)) {
    const parent = path.dirname(existingAncestor);
    assert.notEqual(parent, existingAncestor, 'cannot resolve generated output ancestor');
    existingAncestor = parent;
  }
  assert.ok(!lstatSync(existingAncestor).isSymbolicLink(),
    'P02C generated output cannot traverse a symbolic-link ancestor');
  const realArtifactsRoot = realpathSync(artifactsRoot);
  const realAncestor = realpathSync(existingAncestor);
  const realRelative = path.relative(realArtifactsRoot, realAncestor);
  assert.ok(
    !path.isAbsolute(realRelative)
      && realRelative !== '..'
      && !realRelative.startsWith(`..${path.sep}`),
    'P02C generated output ancestor escapes the real repository artifacts root'
  );
}

export async function runUpdateCeremonyContracts({ artifactDir = defaultArtifactDir } = {}) {
  const resolved = path.resolve(artifactDir);
  assertSafeArtifactDirectory(resolved);
  // Only the narrowly guarded ignored generated directory is replaceable.
  rmSync(resolved, { recursive: true, force: true });
  mkdirSync(resolved, { recursive: true });
  assertSafeArtifactDirectory(realpathSync(resolved));
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
