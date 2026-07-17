import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { prepareUpload } from './artifact-upload-manifest.mjs';
import { gate } from './artifact-upload-gate.mjs';

async function fixture() {
  const root = await mkdtemp(path.join(os.tmpdir(), 'deep-upload-gate-'));
  const source = path.join(root, 'source');
  const stagingRoot = path.join(root, 'staging');
  const manifest = path.join(root, 'manifest.json');
  const summary = path.join(root, 'summary.json');
  await mkdir(source);
  await writeFile(path.join(source, 'evidence.json'), '{"status":"ok"}\n');
  const requiredFiles = ['evidence.json'];
  await prepareUpload({ roots: [source], requiredFiles, staging: stagingRoot, manifest });
  return { root, stagingRoot, manifest, summary, requiredFiles };
}

test('passes only with a fresh result bound to the exact selected manifest', async () => {
  const item = await fixture();
  try {
    const result = await gate(item);
    assert.equal(result.status, 'ok');
    assert.equal(result.manifestedFiles, 1);
  } finally {
    await rm(item.root, { recursive: true, force: true });
  }
});

test('scanner nonzero/crash prevents upload', async () => {
  const item = await fixture();
  try {
    const scannerPath = path.join(item.root, 'crash.mjs');
    await writeFile(scannerPath, 'process.exitCode = 7;\n');
    await assert.rejects(gate({ ...item, scannerPath }), /crashed or returned nonzero/);
  } finally {
    await rm(item.root, { recursive: true, force: true });
  }
});

test('scanner success without a fresh result prevents upload', async () => {
  const item = await fixture();
  try {
    const scannerPath = path.join(item.root, 'missing-result.mjs');
    await writeFile(scannerPath, 'process.exitCode = 0;\n');
    await assert.rejects(gate({ ...item, scannerPath }), /result is missing or unreadable/);
  } finally {
    await rm(item.root, { recursive: true, force: true });
  }
});

test('scanner timeout prevents upload', async () => {
  const item = await fixture();
  try {
    const scannerPath = path.join(item.root, 'timeout.mjs');
    await writeFile(scannerPath, 'setInterval(() => {}, 1000);\n');
    await assert.rejects(gate({ ...item, scannerPath, timeoutMs: 100 }), /timed out/);
  } finally {
    await rm(item.root, { recursive: true, force: true });
  }
});

test('empty upload roots and missing required lane evidence fail closed', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'deep-upload-empty-'));
  try {
    const source = path.join(root, 'source');
    await mkdir(source);
    await assert.rejects(
      prepareUpload({
        roots: [source],
        staging: path.join(root, 'staging'),
        manifest: path.join(root, 'manifest.json')
      }),
      /upload selection is empty/
    );
    await writeFile(path.join(source, 'present.json'), '{"status":"ok"}\n');
    await assert.rejects(
      prepareUpload({
        roots: [source],
        requiredFiles: ['required-lane-evidence.json'],
        staging: path.join(root, 'staging'),
        manifest: path.join(root, 'manifest.json')
      }),
      /required artifact is missing/
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('gate invocation independently binds the required lane evidence contract', async () => {
  const item = await fixture();
  try {
    const document = JSON.parse(await readFile(item.manifest, 'utf8'));
    document.requiredFiles = [];
    await writeFile(item.manifest, `${JSON.stringify(document, null, 2)}\n`);
    await assert.rejects(
      gate(item),
      /required-file contract differs/
    );
  } finally {
    await rm(item.root, { recursive: true, force: true });
  }
});

test('manifest mutation while scanner runs fails closed', async () => {
  const item = await fixture();
  try {
    const scannerPath = path.join(item.root, 'mutate-manifest.mjs');
    await writeFile(scannerPath, [
      "import { appendFile, readFile, writeFile } from 'node:fs/promises';",
      "import { createHash } from 'node:crypto';",
      "const value = name => process.argv[process.argv.indexOf(name) + 1];",
      "const manifest = value('--manifest');",
      "const summary = value('--summary');",
      "const raw = await readFile(manifest);",
      "await appendFile(manifest, ' ');",
      "await writeFile(summary, JSON.stringify({",
      "schemaVersion:'2.0.0',status:'ok',findingCount:0,scannedFiles:1,",
      "selectedManifestSha256:createHash('sha256').update(raw).digest('hex')",
      "}));"
    ].join('\n'));
    await assert.rejects(
      gate({ ...item, scannerPath }),
      /manifest changed while the scanner was running/
    );
  } finally {
    await rm(item.root, { recursive: true, force: true });
  }
});

test('staged file mutation while scanner runs fails closed', async () => {
  const item = await fixture();
  try {
    const scannerPath = path.join(item.root, 'mutate-staging.mjs');
    const stagedFile = path.join(item.stagingRoot, 'evidence.json');
    await writeFile(scannerPath, [
      "import { readFile, writeFile } from 'node:fs/promises';",
      "import { createHash } from 'node:crypto';",
      "const value = name => process.argv[process.argv.indexOf(name) + 1];",
      "const manifest = value('--manifest');",
      "const summary = value('--summary');",
      `await writeFile(${JSON.stringify(stagedFile)}, '{"status":"mutated"}\\n');`,
      "const raw = await readFile(manifest);",
      "await writeFile(summary, JSON.stringify({",
      "schemaVersion:'2.0.0',status:'ok',findingCount:0,scannedFiles:1,",
      "selectedManifestSha256:createHash('sha256').update(raw).digest('hex')",
      "}));"
    ].join('\n'));
    await assert.rejects(
      gate({ ...item, scannerPath }),
      /changed after manifest preparation/
    );
  } finally {
    await rm(item.root, { recursive: true, force: true });
  }
});
