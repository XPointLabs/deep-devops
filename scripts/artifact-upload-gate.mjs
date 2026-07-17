import { createHash } from 'node:crypto';
import { readFile, rm } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import {
  validatePreparedManifest,
  verifyPreparedStaging
} from './artifact-upload-manifest.mjs';
import {
  sealEvidenceBundle,
  writeGithubOutputs
} from './sealed-evidence-bundle.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const scannerPath = path.join(__dirname, 'secret-scan.mjs');

function parse(argv) {
  const options = { requiredFiles: [] };
  for (let index = 0; index < argv.length; index += 2) {
    const name = argv[index];
    const value = argv[index + 1];
    if (!value || value.startsWith('--')) throw new Error(`${name} requires a value`);
    if (name === '--manifest') options.manifest = value;
    else if (name === '--staging-root') options.stagingRoot = value;
    else if (name === '--summary') options.summary = value;
    else if (name === '--bundle') options.bundle = value;
    else if (name === '--require') options.requiredFiles.push(value);
    else if (name === '--timeout-ms') options.timeoutMs = Number(value);
    else throw new Error(`unknown argument: ${name}`);
  }
  if (!options.manifest || !options.stagingRoot || !options.summary || !options.bundle) {
    throw new Error('manifest, staging root, fresh summary, and sealed bundle paths are required');
  }
  return options;
}

export async function gate(options) {
  const manifestPath = path.resolve(options.manifest);
  const stagingRoot = path.resolve(options.stagingRoot);
  const summaryPath = path.resolve(options.summary);
  await rm(summaryPath, { force: true });
  const initialManifestRaw = await readFile(manifestPath);
  const initialManifest = JSON.parse(initialManifestRaw.toString('utf8'));
  validatePreparedManifest(initialManifest);
  const externallyRequiredFiles = [...new Set((options.requiredFiles ?? [])
    .map(value => String(value).normalize('NFKC').replaceAll('\\', '/')))].sort();
  if (JSON.stringify(initialManifest.requiredFiles) !== JSON.stringify(externallyRequiredFiles)) {
    throw new Error('upload manifest required-file contract differs from the gate invocation');
  }
  await verifyPreparedStaging(initialManifest, stagingRoot);
  const initialDigest = createHash('sha256').update(initialManifestRaw).digest('hex');
  const selectedScanner = options.scannerPath ?? scannerPath;
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
  const finalManifestRaw = await readFile(manifestPath);
  const finalDigest = createHash('sha256').update(finalManifestRaw).digest('hex');
  if (finalDigest !== initialDigest || !finalManifestRaw.equals(initialManifestRaw)) {
    throw new Error('upload manifest changed while the scanner was running');
  }
  const finalManifest = JSON.parse(finalManifestRaw.toString('utf8'));
  validatePreparedManifest(finalManifest);
  await verifyPreparedStaging(finalManifest, stagingRoot);
  if (summary.schemaVersion !== '2.0.0'
    || summary.status !== 'ok'
    || summary.findingCount !== 0
    || summary.scannedFiles !== finalManifest.fileCount
    || summary.selectedManifestSha256 !== initialDigest) {
    throw new Error('secret scanner result does not prove the selected upload manifest');
  }
  const sealed = await sealEvidenceBundle({
    manifestPath,
    stagingRoot,
    scanSummaryPath: summaryPath,
    bundlePath: path.resolve(options.bundle)
  });
  const response = {
    status: 'ok',
    manifestedFiles: finalManifest.fileCount,
    manifestSha256: initialDigest,
    bundlePath: path.resolve(options.bundle),
    bundleSha256: sealed.sha256,
    bundleSize: sealed.size,
    productionReady: false,
    trustedArtifactPublication: false
  };
  await writeGithubOutputs({
    bundlePath: response.bundlePath,
    sha256: response.bundleSha256,
    size: response.bundleSize
  });
  return response;
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
