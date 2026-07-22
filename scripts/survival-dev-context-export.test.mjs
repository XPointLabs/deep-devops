import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { exportDevelopmentContext } from './survival-dev-context-export.mjs';

function git(root, ...args) {
  return execFileSync('git', ['-C', root, ...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
}

function fixture() {
  const root = mkdtempSync(path.join(os.tmpdir(), 'survival-dev-context-'));
  const source = path.join(root, 'source');
  const owned = path.join(root, 'owned');
  mkdirSync(path.join(source, 'src', 'App'), { recursive: true });
  mkdirSync(owned);
  git(root, 'init', '--quiet', source);
  writeFileSync(path.join(source, '.gitignore'), '.env*\n');
  writeFileSync(path.join(source, 'src', 'App', 'App.csproj'), '<Project />\n');
  writeFileSync(path.join(source, 'src', 'App', 'Program.cs'), 'class Program {}\n');
  writeFileSync(path.join(source, 'README.md'), 'not needed in the build context\n');
  return { root, source, owned };
}

test('exports only the development build allowlist, including untracked source', () => {
  const item = fixture();
  try {
    writeFileSync(path.join(item.source, '.env.local'), 'must-not-be-read-or-copied');
    const destination = path.join(item.owned, 'xnode');
    const result = exportDevelopmentContext({ kind: 'dotnet', source: item.source, destination, ownedRoot: item.owned });
    assert.equal(result.fileCount, 2);
    assert.ok(existsSync(path.join(destination, 'src', 'App', 'App.csproj')));
    assert.ok(existsSync(path.join(destination, 'src', 'App', 'Program.cs')));
    assert.equal(existsSync(path.join(destination, '.env.local')), false);
    assert.equal(existsSync(path.join(destination, 'README.md')), false);
  } finally {
    rmSync(item.root, { recursive: true, force: true });
  }
});

test('fails closed on selected secret-like paths without disclosing their names', () => {
  const item = fixture();
  try {
    writeFileSync(path.join(item.source, 'src', 'App', 'production.pem'), 'sensitive fixture');
    const destination = path.join(item.owned, 'xnode');
    assert.throws(
      () => exportDevelopmentContext({ kind: 'dotnet', source: item.source, destination, ownedRoot: item.owned }),
      error => /prohibited source entries detected/i.test(error.message) && !/production\.pem/i.test(error.message)
    );
    assert.equal(existsSync(destination), false);
  } finally {
    rmSync(item.root, { recursive: true, force: true });
  }
});
