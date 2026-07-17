import { createHash } from 'node:crypto';
import { appendFile, mkdir, readFile, writeFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import {
  validatePreparedManifest,
  verifyPreparedStaging
} from './artifact-upload-manifest.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repositoryRoot = path.resolve(__dirname, '..');

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function gitValue(args) {
  const result = spawnSync('git', args, {
    cwd: repositoryRoot,
    encoding: 'utf8',
    windowsHide: true
  });
  if (result.status !== 0 || !result.stdout.trim()) throw new Error('unable to bind sealed evidence to Git');
  return result.stdout.trim();
}

function parse(argv) {
  const options = {};
  for (let index = 0; index < argv.length; index += 1) {
    const name = argv[index];
    const value = argv[index + 1];
    if (!value || value.startsWith('--')) throw new Error(`${name} requires a value`);
    if (name === '--bundle') options.bundle = value;
    else if (name === '--expected-sha256') options.expectedSha256 = value;
    else if (name === '--actions-artifact-id') options.actionsArtifactId = value;
    else if (name === '--actions-artifact-digest') options.actionsArtifactDigest = value;
    else if (name === '--receipt') options.receipt = value;
    else if (name === '--extract-dir') options.extractDir = value;
    else if (name === '--expected-source-run-id') options.expectedSourceRunId = value;
    else throw new Error(`unknown argument: ${name}`);
    index += 1;
  }
  if (!options.bundle
    || (!options.extractDir && !options.expectedSha256)
    || (options.extractDir && !options.expectedSourceRunId)) {
    throw new Error('round-trip verification requires bundle/SHA; extraction requires bundle/destination/source run');
  }
  return options;
}

export async function sealEvidenceBundle({
  manifestPath,
  stagingRoot,
  scanSummaryPath,
  bundlePath
}) {
  const manifestRaw = await readFile(manifestPath);
  const manifest = JSON.parse(manifestRaw.toString('utf8'));
  validatePreparedManifest(manifest);
  await verifyPreparedStaging(manifest, stagingRoot);
  const scanSummaryRaw = await readFile(scanSummaryPath);
  const scanSummary = JSON.parse(scanSummaryRaw.toString('utf8'));
  const manifestSha256 = sha256(manifestRaw);
  if (scanSummary.schemaVersion !== '2.0.0'
    || scanSummary.status !== 'ok'
    || scanSummary.findingCount !== 0
    || scanSummary.scannedFiles !== manifest.fileCount
    || scanSummary.selectedManifestSha256 !== manifestSha256) {
    throw new Error('scan summary cannot seal the selected manifest');
  }
  const payload = [];
  for (const entry of manifest.files) {
    const bytes = await readFile(path.resolve(stagingRoot, ...entry.path.split('/')));
    payload.push({
      path: entry.path,
      size: entry.size,
      sha256: entry.sha256,
      mediaType: entry.mediaType,
      contentBase64: bytes.toString('base64')
    });
  }
  const sourceCommit = gitValue(['rev-parse', 'HEAD']);
  const sourceTree = gitValue(['rev-parse', 'HEAD^{tree}']);
  const generatedAt = process.env.DEEP_EVIDENCE_NOW ?? new Date().toISOString();
  const bundle = {
    schemaVersion: 'deep-sealed-evidence-v1',
    status: 'sealed-untrusted-pending-ci-roundtrip',
    productionReady: false,
    trustedArtifactPublication: false,
    generatedAt,
    source: {
      commit: sourceCommit,
      tree: sourceTree,
      runId: process.env.GITHUB_RUN_ID ?? 'local-not-ci',
      runAttempt: process.env.GITHUB_RUN_ATTEMPT ?? 'local-not-ci'
    },
    manifestSha256,
    scanSummarySha256: sha256(scanSummaryRaw),
    manifestRawBase64: manifestRaw.toString('base64'),
    scanSummaryRawBase64: scanSummaryRaw.toString('base64'),
    manifest,
    scanSummary,
    requiredEvidenceValidation: {
      status: 'passed',
      requiredFiles: manifest.requiredFiles,
      requiredFileCount: manifest.requiredFiles.length,
      missingFiles: [],
      ...manifest.requiredEvidenceValidation
    },
    payload
  };
  bundle.selfSealSha256 = sha256(Buffer.from(JSON.stringify(bundle)));
  const bytes = Buffer.from(`${JSON.stringify(bundle, null, 2)}\n`);
  await mkdir(path.dirname(bundlePath), { recursive: true });
  await writeFile(bundlePath, bytes);
  return { bundle, sha256: sha256(bytes), size: bytes.length };
}

export async function verifySealedEvidenceBundle(options) {
  if (options.expectedSha256 && !/^[0-9a-f]{64}$/i.test(options.expectedSha256)) {
    throw new Error('expected bundle SHA256 is invalid');
  }
  const raw = await readFile(path.resolve(options.bundle));
  const actualBundleSha256 = sha256(raw);
  if (options.expectedSha256 && actualBundleSha256 !== options.expectedSha256.toLowerCase()) {
    throw new Error('sealed evidence bundle SHA256 mismatch');
  }
  const bundle = JSON.parse(raw.toString('utf8'));
  const selfSealDocument = { ...bundle };
  delete selfSealDocument.selfSealSha256;
  const generatedAt = Date.parse(bundle.generatedAt);
  const age = Date.now() - generatedAt;
  if (bundle.schemaVersion !== 'deep-sealed-evidence-v1'
    || bundle.productionReady !== false
    || bundle.trustedArtifactPublication !== false
    || bundle.requiredEvidenceValidation?.status !== 'passed'
    || bundle.requiredEvidenceValidation?.missingFiles?.length !== 0
    || bundle.requiredEvidenceValidation?.skippedChecks !== 0
    || bundle.payload?.length !== bundle.manifest?.fileCount
    || !Number.isFinite(generatedAt)
    || age < -5 * 60 * 1000
    || age > 24 * 60 * 60 * 1000
    || !/^[0-9a-f]{40}$/i.test(bundle.source?.commit ?? '')
    || !/^[0-9a-f]{40}$/i.test(bundle.source?.tree ?? '')
    || typeof bundle.source?.runId !== 'string'
    || bundle.source.runId.length === 0
    || !/^[0-9a-f]{64}$/i.test(bundle.selfSealSha256 ?? '')
    || sha256(Buffer.from(JSON.stringify(selfSealDocument))) !== bundle.selfSealSha256) {
    throw new Error('sealed evidence bundle schema/status is invalid');
  }
  const manifestRaw = Buffer.from(bundle.manifestRawBase64 ?? '', 'base64');
  const scanSummaryRaw = Buffer.from(bundle.scanSummaryRawBase64 ?? '', 'base64');
  let rawManifestDocument;
  let rawScanSummaryDocument;
  try {
    rawManifestDocument = JSON.parse(manifestRaw.toString('utf8'));
    rawScanSummaryDocument = JSON.parse(scanSummaryRaw.toString('utf8'));
  } catch {
    throw new Error('sealed evidence embeds unreadable raw manifest or scan summary');
  }
  if (sha256(manifestRaw) !== bundle.manifestSha256
    || sha256(scanSummaryRaw) !== bundle.scanSummarySha256
    || JSON.stringify(rawManifestDocument) !== JSON.stringify(bundle.manifest)
    || JSON.stringify(rawScanSummaryDocument) !== JSON.stringify(bundle.scanSummary)) {
    throw new Error('embedded manifest digest mismatch');
  }
  validatePreparedManifest(bundle.manifest, {
    expectedSourceRunId: options.expectedSourceRunId
  });
  if (JSON.stringify(bundle.source) !== JSON.stringify(bundle.manifest.requiredEvidenceValidation.source)) {
    throw new Error('sealed bundle and manifest source bindings differ');
  }
  const seen = new Set();
  for (const entry of bundle.payload) {
    const manifestEntry = bundle.manifest.files.find(item => item.path === entry.path);
    const bytes = Buffer.from(entry.contentBase64, 'base64');
    if (!manifestEntry
      || seen.has(entry.path)
      || entry.size !== bytes.length
      || entry.sha256 !== sha256(bytes)
      || entry.sha256 !== manifestEntry.sha256
      || entry.mediaType !== manifestEntry.mediaType) {
      throw new Error('sealed evidence payload does not match embedded manifest');
    }
    seen.add(entry.path);
  }
  if (options.actionsArtifactId && !/^[0-9]+$/.test(options.actionsArtifactId)) {
    throw new Error('Actions artifact id is invalid');
  }
  if (options.actionsArtifactDigest && !/^(?:sha256:)?[0-9a-f]{64}$/i.test(options.actionsArtifactDigest)) {
    throw new Error('Actions artifact digest is invalid');
  }
  const receipt = {
    schemaVersion: 'deep-sealed-evidence-roundtrip-v1',
    status: 'roundtrip-verified-actions-archive-digest-not-locally-reproducible',
    productionReady: false,
    trustedArtifactPublication: false,
    bundleSha256: actualBundleSha256,
    sourceCommit: bundle.source.commit,
    sourceTree: bundle.source.tree,
    runId: bundle.source.runId,
    actionsArtifactId: options.actionsArtifactId ?? null,
    actionsArtifactDigest: options.actionsArtifactDigest ?? null,
    payloadFilesVerified: seen.size
  };
  if (options.receipt) {
    await mkdir(path.dirname(path.resolve(options.receipt)), { recursive: true });
    await writeFile(path.resolve(options.receipt), `${JSON.stringify(receipt, null, 2)}\n`);
  }
  return receipt;
}

export async function extractSealedEvidenceBundle(options) {
  if (!/^[0-9]+$/.test(String(options.expectedSourceRunId ?? ''))) {
    throw new Error('expected source run id must be a GitHub Actions run id');
  }
  const receipt = await verifySealedEvidenceBundle({
    bundle: options.bundle,
    expectedSha256: options.expectedSha256,
    expectedSourceRunId: options.expectedSourceRunId
  });
  const bundle = JSON.parse(await readFile(path.resolve(options.bundle), 'utf8'));
  if (String(bundle.source.runId) !== String(options.expectedSourceRunId)) {
    throw new Error('sealed evidence source run does not match the requested Actions run');
  }
  const destination = path.resolve(options.extractDir);
  await mkdir(destination);
  for (const entry of bundle.payload) {
    const target = path.resolve(destination, ...entry.path.split('/'));
    const relative = path.relative(destination, target);
    if (relative.startsWith('..') || path.isAbsolute(relative)) {
      throw new Error('sealed evidence extraction path escapes destination');
    }
    await mkdir(path.dirname(target), { recursive: true });
    await writeFile(target, Buffer.from(entry.contentBase64, 'base64'), { flag: 'wx' });
  }
  return { ...receipt, extractedTo: destination };
}

export async function writeGithubOutputs(result) {
  if (!process.env.GITHUB_OUTPUT) return;
  await appendFile(process.env.GITHUB_OUTPUT, [
    `bundle_path=${result.bundlePath}`,
    `bundle_sha256=${result.sha256}`,
    `bundle_size=${result.size}`,
    ''
  ].join('\n'));
}

export async function main(argv = process.argv.slice(2)) {
  const options = parse(argv);
  const result = options.extractDir
    ? await extractSealedEvidenceBundle(options)
    : await verifySealedEvidenceBundle(options);
  console.log(
    `Sealed evidence ${options.extractDir ? 'extracted' : 'round-trip verified'} (${result.payloadFilesVerified} files); publication remains untrusted pending CI digest semantics acceptance.`
  );
  return result;
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  main().catch(error => {
    console.error(`Sealed evidence verification failed closed: ${error.message}`);
    process.exitCode = 1;
  });
}
