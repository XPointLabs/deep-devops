import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { spawnSync } from 'node:child_process';
import { scan } from './secret-scan.mjs';
import { prepareUpload } from './artifact-upload-manifest.mjs';

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

test('confirmed bypass: rejects symlink or reparse content inside an upload root', async () => {
  const root = await fixture();
  const outside = await mkdtemp(path.join(os.tmpdir(), 'deep-secret-outside-'));
  try {
    const keyName = ['api', 'key'].join('_');
    await writeFile(path.join(outside, 'hidden.txt'), `${keyName}: HiddenCanary123456789\n`);
    await symlink(outside, path.join(root, 'artifacts', 'linked'), 'junction');
    await assert.rejects(
      scan({ root, includeTracked: false, artifactRoots: [path.join(root, 'artifacts')] }),
      /symlink\/reparse/
    );
  } finally {
    await remove(root);
    await remove(outside);
  }
});

test('confirmed bypass: blocks unknown binary rather than silently skipping it', async () => {
  const root = await fixture();
  try {
    await writeFile(path.join(root, 'artifacts', 'opaque.bin'), Buffer.from([0, 1, 2, 3, 4]));
    const result = await scan({ root, includeTracked: false, artifactRoots: [path.join(root, 'artifacts')] });
    assert.ok(result.findings.some(item => item.ruleId === 'unknown-binary-file'));
  } finally {
    await remove(root);
  }
});

test('confirmed bypass: scans credential assignments in JSON and punctuation variants without values in results', async () => {
  const root = await fixture();
  try {
    const canary = 'Canary-1234567890-Value';
    await writeFile(path.join(root, 'artifacts', 'evidence.json'), JSON.stringify({
      'api-key': canary,
      nested: { client_secret: canary }
    }, null, 2));
    await writeFile(path.join(root, 'artifacts', 'evidence.yml'), `auth.token => ${canary}\n`);
    const result = await scan({ root, includeTracked: false, artifactRoots: [path.join(root, 'artifacts')] });
    assert.equal(result.status, 'failed');
    assert.ok(result.findings.filter(item => item.ruleId === 'sensitive-assignment').length >= 3);
    assert.ok(!JSON.stringify(result).includes(canary));
  } finally {
    await remove(root);
  }
});

test('confirmed bypass: scans relative archive entry names and redacts a sensitive filename', async () => {
  const root = await fixture();
  try {
    const archive = storedZip('password=Canary123456789.txt', Buffer.from('safe\n'));
    await writeFile(path.join(root, 'artifacts', 'names.zip'), archive);
    const result = await scan({ root, includeTracked: false, artifactRoots: [path.join(root, 'artifacts')] });
    assert.equal(result.status, 'failed');
    assert.ok(result.findings.some(item => item.ruleId === 'sensitive-filename'));
    assert.ok(result.findings.some(item => item.path === '<redacted-sensitive-filename>'));
  } finally {
    await remove(root);
  }
});

test('blocks normalized secret-shaped artifact filenames including Unicode punctuation variants', async () => {
  const root = await fixture();
  try {
    const names = [
      'wallet-mnemonic.txt',
      'private＿key.json',
      'service.credentials.yaml',
      'backup-keystore.txt',
      'state-database.json',
      '.env.production'
    ];
    for (const [index, name] of names.entries()) {
      const artifactRoot = path.join(root, `artifact-case-${index}`);
      await mkdir(artifactRoot);
      await writeFile(path.join(artifactRoot, name), 'safe synthetic content\n');
      const result = await scan({ root, includeTracked: false, artifactRoots: [artifactRoot] });
      assert.equal(result.status, 'failed');
      assert.ok(result.findings.some(item => item.ruleId === 'sensitive-filename'));
      assert.ok(result.findings.every(item => item.path === '<redacted-sensitive-filename>'));
    }
  } finally {
    await remove(root);
  }
});

test('placeholder matching is exact and rejects literals with a REDACTED prefix', async () => {
  const root = await fixture();
  try {
    const canary = 'REDACTED-but-still-a-literal';
    await writeFile(path.join(root, 'artifacts', 'evidence.json'), JSON.stringify({ password: canary }));
    const result = await scan({ root, includeTracked: false, artifactRoots: [path.join(root, 'artifacts')] });
    assert.equal(result.status, 'failed');
    assert.ok(result.findings.some(item => item.ruleId === 'sensitive-assignment'));
    assert.ok(!JSON.stringify(result).includes(canary));
  } finally {
    await remove(root);
  }
});

test('recursively inspects ZIP text entries and rejects malformed archives', async () => {
  const root = await fixture();
  try {
    const canary = 'ArchiveCanary123456789';
    await writeFile(
      path.join(root, 'artifacts', 'evidence.zip'),
      storedZip('nested/config.env', Buffer.from(`PASSWORD=${canary}\n`))
    );
    let result = await scan({ root, includeTracked: false, artifactRoots: [path.join(root, 'artifacts')] });
    assert.ok(result.findings.some(item => item.path.includes('nested/config.env')));
    assert.ok(!JSON.stringify(result).includes(canary));
    await writeFile(path.join(root, 'artifacts', 'evidence.zip'), Buffer.from('PK\x03\x04broken'));
    await assert.rejects(
      scan({ root, includeTracked: false, artifactRoots: [path.join(root, 'artifacts')] }),
      /truncated ZIP/
    );
  } finally {
    await remove(root);
  }
});

test('manifest scan verifies exact staged files and blocks opaque executable binaries', async () => {
  const root = await fixture();
  try {
    const source = path.join(root, 'source');
    const staging = path.join(root, 'staged');
    const manifestPath = path.join(root, 'upload-manifest.json');
    await mkdir(source);
    await writeFile(path.join(source, 'evidence.json'), '{"status":"ok"}\n');
    const manifest = await prepareUpload({ roots: [source], staging, manifest: manifestPath });
    assert.equal(manifest.fileCount, 1);
    const result = await scan({ root, manifest: manifestPath, stagingRoot: staging });
    assert.equal(result.status, 'ok');
    await writeFile(path.join(staging, 'evidence.json'), '{"status":"changed"}\n');
    await assert.rejects(scan({ root, manifest: manifestPath, stagingRoot: staging }), /changed after manifest/);

    await writeFile(path.join(source, 'blocked.exe'), Buffer.from([0, 1, 2, 3]));
    await assert.rejects(
      prepareUpload({ roots: [source], staging, manifest: manifestPath }),
      /opaque executable binaries are blocked/
    );
  } finally {
    await remove(root);
  }
});

test('manifest policy fields cannot be mutated to bypass unknown-binary inspection', async () => {
  const root = await fixture();
  try {
    const source = path.join(root, 'source');
    const staging = path.join(root, 'staged');
    const manifestPath = path.join(root, 'upload-manifest.json');
    await mkdir(source);
    await writeFile(path.join(source, 'payload.bin'), Buffer.from([0, 1, 2, 3, 4]));
    await prepareUpload({ roots: [source], staging, manifest: manifestPath });
    const original = JSON.parse(await readFile(manifestPath, 'utf8'));
    const mutations = [
      entry => { entry.handling = 'hash-only'; },
      entry => { entry.approvedOpaqueSignedBinary = true; },
      entry => { entry.extension = '.txt'; },
      entry => { entry.mediaType = 'text/plain'; },
      entry => { entry.untrustedPolicyOverride = true; }
    ];
    for (const mutate of mutations) {
      const document = structuredClone(original);
      mutate(document.files[0]);
      await writeFile(manifestPath, `${JSON.stringify(document, null, 2)}\n`);
      await assert.rejects(
        scan({ root, manifest: manifestPath, stagingRoot: staging }),
        /unsupported or missing fields|inspect-only policy/
      );
    }
  } finally {
    await remove(root);
  }
});

function storedZip(name, content) {
  const nameBuffer = Buffer.from(name);
  const header = Buffer.alloc(30);
  header.writeUInt32LE(0x04034b50, 0);
  header.writeUInt16LE(20, 4);
  header.writeUInt16LE(0, 6);
  header.writeUInt16LE(0, 8);
  header.writeUInt32LE(content.length, 18);
  header.writeUInt32LE(content.length, 22);
  header.writeUInt16LE(nameBuffer.length, 26);
  return Buffer.concat([header, nameBuffer, content]);
}
