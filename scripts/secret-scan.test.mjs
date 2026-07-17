import assert from 'node:assert/strict';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { spawnSync } from 'node:child_process';
import { scan } from './secret-scan.mjs';

async function fixture() {
  const root = await mkdtemp(path.join(os.tmpdir(), 'deep-secret-scan-'));
  spawnSync('git', ['init', '--quiet'], { cwd: root, windowsHide: true });
  await mkdir(path.join(root, 'artifacts'), { recursive: true });
  return root;
}

async function remove(root) {
  await rm(root, { recursive: true, force: true });
}

test('accepts placeholders and records only repository-relative paths', async () => {
  const root = await fixture();
  try {
    await writeFile(path.join(root, 'safe.env'), [
      'UAT_DEPLOYER_MNEMONIC=__REQUIRED_SECRET_NOT_COMMITTED__',
      'Node__Ed25519PrivateKey=${UAT_NODE_PRIVATE_KEY}',
      'TOKEN_FILE=/run/secrets/provider_token',
      ''
    ].join('\n'));
    spawnSync('git', ['add', 'safe.env'], { cwd: root, windowsHide: true });
    const result = await scan({ root, artifactRoots: [path.join(root, 'artifacts')] });
    assert.equal(result.status, 'ok');
    assert.deepEqual(result.findings, []);
  } finally {
    await remove(root);
  }
});

test('detects a synthetic mnemonic without returning its value', async () => {
  const root = await fixture();
  try {
    const words = Array.from({ length: 12 }, (_, index) => `word${String.fromCharCode(97 + index)}`);
    const canary = `MNEMONIC=${words.join(' ')}`;
    await writeFile(path.join(root, 'tracked.env'), `${canary}\n`);
    spawnSync('git', ['add', 'tracked.env'], { cwd: root, windowsHide: true });
    const result = await scan({ root, artifactRoots: [path.join(root, 'artifacts')] });
    assert.equal(result.status, 'failed');
    assert.ok(result.findings.some(finding => finding.ruleId === 'mnemonic-shape'));
    assert.ok(!JSON.stringify(result).includes(words.join(' ')));
    assert.ok(result.findings.every(finding => !path.isAbsolute(finding.path)));
  } finally {
    await remove(root);
  }
});

test('detects a synthetic private scalar and a forbidden raw artifact', async () => {
  const root = await fixture();
  try {
    const privateScalar = Array.from({ length: 64 }, (_, index) => (index % 16).toString(16)).join('');
    await writeFile(path.join(root, 'tracked.yml'), `BlsPrivateKey: ${privateScalar}\n`);
    await writeFile(path.join(root, 'artifacts', 'compose.resolved.yml'), 'services: {}\n');
    spawnSync('git', ['add', 'tracked.yml'], { cwd: root, windowsHide: true });
    const result = await scan({ root, artifactRoots: [path.join(root, 'artifacts')] });
    assert.equal(result.status, 'failed');
    assert.ok(result.findings.some(finding => finding.ruleId === 'private-hex-context'));
    assert.ok(result.findings.some(finding => finding.ruleId === 'forbidden-raw-artifact'));
    assert.ok(!JSON.stringify(result).includes(privateScalar));
  } finally {
    await remove(root);
  }
});

test('fails closed for an oversized text artifact', async () => {
  const root = await fixture();
  try {
    await writeFile(path.join(root, 'artifacts', 'oversized.txt'), Buffer.alloc(8 * 1024 * 1024 + 1, 65));
    const result = await scan({
      root,
      includeTracked: false,
      artifactRoots: [path.join(root, 'artifacts')]
    });
    assert.equal(result.status, 'failed');
    assert.equal(result.findings[0].ruleId, 'unscannable-large-file');
  } finally {
    await remove(root);
  }
});
