import assert from 'node:assert/strict';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
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
  await prepareUpload({ roots: [source], staging: stagingRoot, manifest });
  return { root, stagingRoot, manifest, summary };
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
