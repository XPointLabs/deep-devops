import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { mkdir, mkdtemp, rm, readFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const powershell = process.env.DEEP_PWSH ?? 'pwsh';

test('test container output and collector use the same selected run root', async () => {
  const compose = await readFile(path.join(root, 'docker-compose.yml'), 'utf8');
  const script = await readFile(path.join(root, 'scripts/test-env.ps1'), 'utf8');
  assert.ok(compose.includes('${DEEP_TEST_ENV_ARTIFACT_ROOT:-${DEEP_DEVOPS_DIR:-.}/artifacts}:/artifacts'));
  assert.ok(script.includes("SetEnvironmentVariable('DEEP_TEST_ENV_ARTIFACT_ROOT', $ArtifactDir, 'Process')"));
  assert.match(script, /collect-artifacts\.ps1.*-ArtifactDir \$ArtifactDir/);
});

function rejects(candidate, expected) {
  const result = spawnSync(powershell, ['-NoProfile', '-File',
    path.join(root, 'scripts/test-env.ps1'), '-RunArtifactDirectory', candidate],
  { cwd: root, windowsHide: true, encoding: 'utf8', timeout: 15000 });
  assert.ifError(result.error);
  assert.equal(result.status, 1);
  assert.match(result.stderr, expected);
  assert.doesNotMatch(result.stdout, /docker|Test environment evidence directory/i);
}

test('relative evidence path rejects before secrets or Docker', () => {
  rejects('artifacts/rehearsals/smoke/test', /absolute fresh path/);
});

test('shared artifact root and an existing child cannot be a new run', async () => {
  await mkdir(path.join(root, 'artifacts'), { recursive: true });
  rejects(path.join(root, 'artifacts'), /new child of artifacts/);
  const existing = await mkdtemp(path.join(root, 'artifacts', 'scope-negative-'));
  try { rejects(existing, /new child of artifacts/); }
  finally { await rm(existing, { recursive: true }); }
});

test('outside and traversal paths reject without creating directories', () => {
  const outside = path.join(os.tmpdir(), `deep-evidence-negative-${randomUUID()}`);
  rejects(outside, /new child of artifacts/);
  assert.equal(existsSync(outside), false);
  rejects(path.join(root, 'artifacts', '..', 'outside'), /new child of artifacts/);
});
