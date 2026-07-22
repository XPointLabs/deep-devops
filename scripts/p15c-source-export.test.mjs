import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { exportExactCommit } from './p15c-source-export.mjs';

function repository() {
  const root = mkdtempSync(join(tmpdir(), 'p15c-export-'));
  execFileSync('git', ['init', root]);
  execFileSync('git', ['-C', root, 'config', 'user.email', 'p15c@example.invalid']);
  execFileSync('git', ['-C', root, 'config', 'user.name', 'P15C Test']);
  writeFileSync(join(root, 'kept.txt'), 'kept\n');
  writeFileSync(join(root, 'also-kept.txt'), 'also kept\n');
  execFileSync('git', ['-C', root, 'add', '.']);
  execFileSync('git', ['-C', root, 'commit', '-m', 'source']);
  return {
    root,
    sha: execFileSync('git', ['-C', root, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim(),
    tree: execFileSync('git', ['-C', root, 'rev-parse', 'HEAD^{tree}'], { encoding: 'utf8' }).trim()
  };
}

test('isolated export ignores a post-preflight info/attributes export-ignore race', () => {
  const source = repository();
  const owned = mkdtempSync(join(tmpdir(), 'p15c-export-owned-'));
  const destination = join(owned, 'context');
  try {
    mkdirSync(join(source.root, '.git', 'info'), { recursive: true });
    writeFileSync(join(source.root, '.git', 'info', 'attributes'), 'kept.txt export-ignore\n');
    const poisonedTar = join(owned, 'poisoned.tar');
    execFileSync('git', ['-C', source.root, 'archive', '--format=tar', `--output=${poisonedTar}`, source.sha]);
    const poisonedList = execFileSync('tar', ['-tf', poisonedTar], { encoding: 'utf8' });
    assert.doesNotMatch(poisonedList, /kept\.txt/);

    const result = exportExactCommit({ source: source.root, sha: source.sha, tree: source.tree, destination, ownedRoot: owned });
    assert.deepEqual(result, { sha: source.sha, tree: source.tree, entries: 2 });
    assert.equal(readFileSync(join(destination, 'kept.txt'), 'utf8'), 'kept\n');
    assert.equal(readFileSync(join(destination, 'also-kept.txt'), 'utf8'), 'also kept\n');
    assert.equal(existsSync(join(destination, '.git')), false);
  } finally {
    rmSync(source.root, { recursive: true, force: true });
    rmSync(owned, { recursive: true, force: true });
  }
});

test('isolated export rejects symlinks, gitlinks, and destinations outside its owned root', () => {
  const source = repository();
  const owned = mkdtempSync(join(tmpdir(), 'p15c-export-owned-'));
  try {
    assert.throws(() => exportExactCommit({ source: source.root, sha: source.sha, tree: source.tree, destination: join(owned, '..', 'escaped'), ownedRoot: owned }));
    execFileSync('git', ['-C', source.root, 'update-index', '--add', '--cacheinfo', '120000', execFileSync('git', ['-C', source.root, 'hash-object', '-w', '--stdin'], { input: 'kept.txt\n', encoding: 'utf8' }).trim(), 'link']);
    execFileSync('git', ['-C', source.root, 'commit', '-m', 'special']);
    const specialSha = execFileSync('git', ['-C', source.root, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
    const specialTree = execFileSync('git', ['-C', source.root, 'rev-parse', 'HEAD^{tree}'], { encoding: 'utf8' }).trim();
    assert.throws(() => exportExactCommit({ source: source.root, sha: specialSha, tree: specialTree, destination: join(owned, 'special'), ownedRoot: owned }), /special|mode|symlink/i);
  } finally {
    rmSync(source.root, { recursive: true, force: true });
    rmSync(owned, { recursive: true, force: true });
  }
});
