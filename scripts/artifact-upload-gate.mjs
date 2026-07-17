import { createHash } from 'node:crypto';
import { readFile, rm } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const scannerPath = path.join(__dirname, 'secret-scan.mjs');

function parse(argv) {
  const options = {};
  for (let index = 0; index < argv.length; index += 2) {
    const name = argv[index];
    const value = argv[index + 1];
    if (!value || value.startsWith('--')) throw new Error(`${name} requires a value`);
    if (name === '--manifest') options.manifest = value;
    else if (name === '--staging-root') options.stagingRoot = value;
    else if (name === '--summary') options.summary = value;
    else if (name === '--timeout-ms') options.timeoutMs = Number(value);
    else throw new Error(`unknown argument: ${name}`);
  }
  if (!options.manifest || !options.stagingRoot || !options.summary) {
    throw new Error('manifest, staging root, and fresh summary path are required');
  }
  return options;
}

export async function gate(options) {
  const manifestPath = path.resolve(options.manifest);
  const stagingRoot = path.resolve(options.stagingRoot);
  const summaryPath = path.resolve(options.summary);
  await rm(summaryPath, { force: true });
  const selectedScanner = options.scannerPath ?? process.env.DEEP_SECRET_SCANNER_PATH ?? scannerPath;
  const result = spawnSync(process.execPath, [
    selectedScanner,
    '--manifest', manifestPath,
    '--staging-root', stagingRoot,
    '--summary', summaryPath
  ], {
    cwd: path.resolve(__dirname, '..'),
    encoding: 'utf8',
    windowsHide: true,
    timeout: options.timeoutMs ?? 120_000
  });
  if (result.error?.code === 'ETIMEDOUT') throw new Error('secret scanner timed out');
  if (result.error || result.status !== 0) throw new Error('secret scanner crashed or returned nonzero');
  let summary;
  try {
    summary = JSON.parse(await readFile(summaryPath, 'utf8'));
  } catch {
    throw new Error('secret scanner result is missing or unreadable');
  }
  const manifestRaw = await readFile(manifestPath);
  const manifest = JSON.parse(manifestRaw.toString('utf8'));
  const digest = createHash('sha256').update(manifestRaw).digest('hex');
  if (summary.status !== 'ok'
    || summary.findingCount !== 0
    || summary.scannedFiles !== manifest.fileCount
    || summary.selectedManifestSha256 !== digest) {
    throw new Error('secret scanner result does not prove the selected upload manifest');
  }
  return {
    status: 'ok',
    manifestedFiles: manifest.fileCount,
    manifestSha256: digest
  };
}

export async function main(argv = process.argv.slice(2)) {
  const result = await gate(parse(argv));
  console.log(`Artifact upload gate passed (${result.manifestedFiles} exact files).`);
  return result;
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  main().catch(error => {
    console.error(`Artifact upload gate failed closed: ${error.message}`);
    process.exitCode = 1;
  });
}
