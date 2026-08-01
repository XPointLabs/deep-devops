import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { spawnSync } from 'node:child_process';
import { deflateRawSync } from 'node:zlib';
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

test('top-level evidence volume does not consume the nested archive expansion budget', async () => {
  const root = await fixture();
  try {
    for (let index = 0; index < 6; index += 1) {
      await writeFile(
        path.join(root, 'artifacts', `large-safe-evidence-${index}.txt`),
        Buffer.alloc(6 * 1024 * 1024, 65)
      );
    }
    const result = await scan({ root, includeTracked: false, artifactRoots: [path.join(root, 'artifacts')] });
    assert.equal(result.archiveEntriesInspected, 0);
    assert.equal(result.findings.filter(item => item.ruleId === 'unscannable-large-file').length, 0);
  } finally {
    await remove(root);
  }
});

test('default artifact traversal skips generated package/build caches but explicit paths remain fail closed', async () => {
  const root = await fixture();
  try {
    const buildCache = path.join(root, 'artifacts', 'build-contexts');
    await mkdir(buildCache, { recursive: true });
    const cacheArchive = path.join(buildCache, 'cached-package.zip');
    await writeFile(cacheArchive, storedZip('safe.txt', Buffer.from('safe\n')));
    await writeFile(path.join(root, 'artifacts', 'evidence.json'), '{"status":"ok"}\n');

    const defaultResult = await scan({
      root,
      includeTracked: false,
      artifactRoots: [path.join(root, 'artifacts')]
    });
    assert.equal(defaultResult.status, 'ok');
    assert.equal(defaultResult.scannedFiles, 1);

    const explicitResult = await scan({
      root,
      includeTracked: false,
      artifactRoots: [],
      paths: [cacheArchive]
    });
    assert.equal(explicitResult.status, 'failed');
    assert.ok(explicitResult.findings.some(item => item.ruleId === 'forbidden-archive-artifact'));
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
    assert.ok(!JSON.stringify(result).includes('password=Canary123456789.txt'));
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

test('environment placeholders with literal defaults, nesting, or Unicode punctuation are never safe', async () => {
  const root = await fixture();
  try {
    const variable = ['PASS', 'WORD'].join('');
    const start = name => ['$', '{', name].join('');
    const cases = [
      `${start(variable)}:-LiteralCanary123}`,
      `${start(variable)}:-${start(`OTHER_${variable}`)}}`,
      `${start(variable)}：-UnicodeCanary123}`,
      `${start(variable)}-Canary123}`
    ];
    await writeFile(
      path.join(root, 'artifacts', 'placeholder-cases.yml'),
      cases.map(value => `password: ${value}`).join('\n')
    );
    const result = await scan({ root, includeTracked: false, artifactRoots: [path.join(root, 'artifacts')] });
    assert.equal(result.status, 'failed');
    assert.ok(result.findings.filter(item => item.ruleId === 'sensitive-assignment').length >= cases.length);
    assert.ok(cases.every(value => !JSON.stringify(result).includes(value)));
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
    assert.ok(result.findings.some(item => item.path.includes('entry-0')));
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

test('ZIP and TAR entry names are secret-scanned without publishing the literal name', async () => {
  const root = await fixture();
  try {
    const token = ['ghp', Array.from({ length: 32 }, () => 'A').join('')].join('_');
    for (const [extension, archive] of [
      ['zip', storedZip(`${token}.txt`, Buffer.from('safe\n'))],
      ['tar', storedTar(`${token}.txt`, Buffer.from('safe\n'))]
    ]) {
      const artifactRoot = path.join(root, `entry-name-${extension}`);
      await mkdir(artifactRoot);
      await writeFile(path.join(artifactRoot, `case.${extension}`), archive);
      const result = await scan({ root, includeTracked: false, artifactRoots: [artifactRoot] });
      assert.equal(result.status, 'failed');
      assert.ok(result.findings.some(item => item.ruleId === 'known-provider-token'));
      assert.ok(!JSON.stringify(result).includes(token));
    }
  } finally {
    await remove(root);
  }
});

test('Lead ZIP repro rejects valid EOCD followed by unparsed credential bytes', async () => {
  const root = await fixture();
  try {
    const archive = Buffer.concat([
      storedZip('safe.txt', Buffer.from('safe\n')),
      Buffer.from('PASSWORD=ArchiveCanary123\n')
    ]);
    await writeFile(path.join(root, 'artifacts', 'trailing.zip'), archive);
    await assert.rejects(
      scan({ root, includeTracked: false, artifactRoots: [path.join(root, 'artifacts')] }),
      /EOCD is missing or trailing bytes/
    );
  } finally {
    await remove(root);
  }
});

test('ZIP comments are scanned without returning credential values', async () => {
  const root = await fixture();
  try {
    const canary = 'ArchiveCommentCanary123';
    await writeFile(
      path.join(root, 'artifacts', 'comments.zip'),
      storedZip('safe.txt', Buffer.from('safe\n'), {
        centralComment: `password=${canary}`,
        archiveComment: `api_key=${canary}`
      })
    );
    const result = await scan({ root, includeTracked: false, artifactRoots: [path.join(root, 'artifacts')] });
    assert.equal(result.status, 'failed');
    assert.ok(result.findings.some(item => item.ruleId === 'sensitive-assignment'));
    assert.ok(!JSON.stringify(result).includes(canary));
  } finally {
    await remove(root);
  }
});

test('ZIP central-only, ZIP64, encrypted, and mismatched forms fail closed', async () => {
  const root = await fixture();
  try {
    const valid = storedZip('safe.txt', Buffer.from('safe\n'));
    const centralOffset = valid.indexOf(Buffer.from([0x50, 0x4b, 0x01, 0x02]));
    const centralOnly = Buffer.from(valid.subarray(centralOffset));
    const centralOnlyEocd = centralOnly.indexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]));
    centralOnly.writeUInt32LE(0, centralOnlyEocd + 16);

    const zip64 = Buffer.from(valid);
    const zip64Eocd = zip64.indexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]));
    zip64.writeUInt16LE(0xffff, zip64Eocd + 8);
    zip64.writeUInt16LE(0xffff, zip64Eocd + 10);

    const encrypted = Buffer.from(valid);
    encrypted.writeUInt16LE(1, 6);
    encrypted.writeUInt16LE(1, centralOffset + 8);

    const mismatched = Buffer.from(valid);
    mismatched[30] ^= 1;

    for (const [index, archive] of [centralOnly, zip64, encrypted, mismatched].entries()) {
      const artifactRoot = path.join(root, `zip-negative-${index}`);
      await mkdir(artifactRoot);
      await writeFile(path.join(artifactRoot, 'case.zip'), archive);
      await assert.rejects(
        scan({ root, includeTracked: false, artifactRoots: [artifactRoot] }),
        /ZIP/
      );
    }
  } finally {
    await remove(root);
  }
});

test('Lead TAR repro rejects nonzero bytes after valid end blocks and invalid checksums', async () => {
  const root = await fixture();
  try {
    const valid = storedTar('safe.txt', Buffer.from('safe\n'));
    const trailingBlock = Buffer.alloc(512);
    Buffer.from('PASSWORD=TarCanary123').copy(trailingBlock);
    const trailing = Buffer.concat([valid, trailingBlock]);
    const invalidChecksum = Buffer.from(valid);
    invalidChecksum[0] ^= 1;
    for (const [index, archive] of [trailing, invalidChecksum].entries()) {
      const artifactRoot = path.join(root, `tar-negative-${index}`);
      await mkdir(artifactRoot);
      await writeFile(path.join(artifactRoot, 'case.tar'), archive);
      await assert.rejects(
        scan({ root, includeTracked: false, artifactRoots: [artifactRoot] }),
        /TAR/
      );
    }
  } finally {
    await remove(root);
  }
});

test('all archive artifacts and disguised archive magic are blocked, including GZIP FNAME metadata', async () => {
  const root = await fixture();
  try {
    const token = ['AKIA', Array.from({ length: 16 }, () => 'A').join('')].join('');
    const content = Buffer.from('safe\n');
    const gzipHeader = Buffer.from([0x1f, 0x8b, 8, 8, 0, 0, 0, 0, 0, 255]);
    const trailer = Buffer.alloc(8);
    trailer.writeUInt32LE(crc32(content), 0);
    trailer.writeUInt32LE(content.length, 4);
    const gzip = Buffer.concat([
      gzipHeader,
      Buffer.from(`${token}.txt\0`),
      deflateRawSync(content),
      trailer
    ]);
    const cases = [
      ['safe.zip', storedZip('safe.txt', content)],
      ['safe.tar', storedTar('safe.txt', content)],
      ['safe.gz', gzip],
      ['disguised.bin', storedZip('safe.txt', content)]
    ];
    for (const [name, archive] of cases) {
      const artifactRoot = path.join(root, name.replace('.', '-'));
      await mkdir(artifactRoot);
      await writeFile(path.join(artifactRoot, name), archive);
      const result = await scan({ root, includeTracked: false, artifactRoots: [artifactRoot] });
      assert.equal(result.status, 'failed');
      assert.ok(result.findings.some(item => item.ruleId === 'forbidden-archive-artifact'));
      assert.ok(!JSON.stringify(result).includes(token));
    }
  } finally {
    await remove(root);
  }
});

test('tracked archives are blocked before ignored TAR linkname metadata can hide a token', async () => {
  const root = await fixture();
  try {
    const token = ['AKIA', Array.from({ length: 16 }, () => 'B').join('')].join('');
    const archive = storedTar('safe.txt', Buffer.from('safe\n'));
    archive.fill(0, 157, 257);
    Buffer.from(token).copy(archive, 157);
    archive.fill(0x20, 148, 156);
    let checksum = 0;
    for (let index = 0; index < 512; index += 1) checksum += archive[index];
    const checksumText = checksum.toString(8).padStart(6, '0');
    archive.write(checksumText, 148, 'ascii');
    archive[154] = 0;
    archive[155] = 0x20;
    await writeFile(path.join(root, 'fixture.tar'), archive);
    spawnSync('git', ['add', 'fixture.tar'], { cwd: root, windowsHide: true });
    const result = await scan({ root, artifactRoots: [] });
    assert.equal(result.status, 'failed');
    assert.ok(result.findings.some(item => item.ruleId === 'forbidden-archive-artifact'));
    assert.ok(!JSON.stringify(result).includes(token));
    await writeFile(path.join(root, 'fixture.tar'), storedTar('safe.txt', Buffer.from('safe\n')));
    const benign = await scan({ root, artifactRoots: [] });
    assert.equal(benign.status, 'failed');
    assert.ok(benign.findings.some(item => item.ruleId === 'forbidden-archive-artifact'));
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

function storedZip(name, content, options = {}) {
  const nameBuffer = Buffer.from(name);
  const checksum = crc32(content);
  const local = Buffer.alloc(30);
  local.writeUInt32LE(0x04034b50, 0);
  local.writeUInt16LE(20, 4);
  local.writeUInt16LE(0x800, 6);
  local.writeUInt16LE(0, 8);
  local.writeUInt32LE(checksum, 14);
  local.writeUInt32LE(content.length, 18);
  local.writeUInt32LE(content.length, 22);
  local.writeUInt16LE(nameBuffer.length, 26);
  const localRegion = Buffer.concat([local, nameBuffer, content]);

  const centralComment = Buffer.from(options.centralComment ?? '');
  const central = Buffer.alloc(46);
  central.writeUInt32LE(0x02014b50, 0);
  central.writeUInt16LE(20, 4);
  central.writeUInt16LE(20, 6);
  central.writeUInt16LE(0x800, 8);
  central.writeUInt16LE(0, 10);
  central.writeUInt32LE(checksum, 16);
  central.writeUInt32LE(content.length, 20);
  central.writeUInt32LE(content.length, 24);
  central.writeUInt16LE(nameBuffer.length, 28);
  central.writeUInt16LE(centralComment.length, 32);
  const centralRegion = Buffer.concat([central, nameBuffer, centralComment]);

  const archiveComment = Buffer.from(options.archiveComment ?? '');
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(1, 8);
  eocd.writeUInt16LE(1, 10);
  eocd.writeUInt32LE(centralRegion.length, 12);
  eocd.writeUInt32LE(localRegion.length, 16);
  eocd.writeUInt16LE(archiveComment.length, 20);
  return Buffer.concat([localRegion, centralRegion, eocd, archiveComment]);
}

function storedTar(name, content) {
  const header = Buffer.alloc(512);
  Buffer.from(name).copy(header, 0, 0, 100);
  Buffer.from('0000600\0').copy(header, 100);
  Buffer.from('0000000\0').copy(header, 108);
  Buffer.from('0000000\0').copy(header, 116);
  Buffer.from(`${content.length.toString(8).padStart(11, '0')}\0`).copy(header, 124);
  Buffer.from('00000000000\0').copy(header, 136);
  Buffer.from('        ').copy(header, 148);
  header[156] = 48;
  Buffer.from('ustar\0').copy(header, 257);
  Buffer.from('00').copy(header, 263);
  let checksum = 0;
  for (const byte of header) checksum += byte;
  Buffer.from(`${checksum.toString(8).padStart(6, '0')}\0 `).copy(header, 148);
  const padding = Buffer.alloc(Math.ceil(content.length / 512) * 512 - content.length);
  return Buffer.concat([header, content, padding, Buffer.alloc(1024)]);
}

function crc32(buffer) {
  let value = 0xffffffff;
  for (const byte of buffer) {
    value ^= byte;
    for (let bit = 0; bit < 8; bit += 1) {
      value = (value >>> 1) ^ ((value & 1) ? 0xedb88320 : 0);
    }
  }
  return (value ^ 0xffffffff) >>> 0;
}
