import { createHash } from 'node:crypto';
import {
  copyFile,
  lstat,
  mkdir,
  readFile,
  readdir,
  realpath,
  rm,
  stat,
  writeFile
} from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repositoryRoot = path.resolve(__dirname, '..');
const DEFAULT_MAX_FILE_BYTES = 64 * 1024 * 1024;
const forbiddenExtensions = new Set([
  '.bmp', '.gif', '.heic', '.jpeg', '.jpg', '.log', '.png', '.tif', '.tiff', '.webp'
]);
const opaqueExtensions = new Set(['.dll', '.dylib', '.exe', '.node', '.so', '.wasm']);
const mediaTypes = new Map([
  ['.json', 'application/json'],
  ['.md', 'text/markdown'],
  ['.txt', 'text/plain'],
  ['.trx', 'application/xml'],
  ['.xml', 'application/xml'],
  ['.yaml', 'application/yaml'],
  ['.yml', 'application/yaml'],
  ['.zip', 'application/zip'],
  ['.gz', 'application/gzip'],
  ['.tar', 'application/x-tar'],
  ['.apk', 'application/vnd.android.package-archive'],
  ['.aab', 'application/x-authorware-bin'],
  ['.msix', 'application/vnd.ms-appx']
]);

function toPosix(value) {
  return value.split(path.sep).join('/');
}

function inside(root, target) {
  const relative = path.relative(root, target);
  return relative === '' || (!relative.startsWith('..') && !path.isAbsolute(relative));
}

async function assertRegularNoReparse(root, target) {
  const rootReal = await realpath(root);
  let current = path.resolve(target);
  if (!inside(path.resolve(root), current)) throw new Error('artifact path escapes upload root');
  while (inside(path.resolve(root), current)) {
    const info = await lstat(current);
    if (info.isSymbolicLink()) throw new Error('artifact upload roots cannot contain symlink/reparse points');
    if (current === path.resolve(root)) break;
    current = path.dirname(current);
  }
  const targetReal = await realpath(target);
  if (!inside(rootReal, targetReal)) throw new Error('artifact resolves outside upload root');
  const info = await stat(target);
  if (!info.isFile()) throw new Error('artifact manifest entries must be regular files');
  return info;
}

async function walk(root) {
  const files = [];
  const pending = [root];
  while (pending.length > 0) {
    const current = pending.pop();
    const currentInfo = await lstat(current);
    if (currentInfo.isSymbolicLink()) throw new Error('artifact upload roots cannot contain symlink/reparse points');
    for (const entry of await readdir(current, { withFileTypes: true })) {
      const full = path.join(current, entry.name);
      if (entry.isSymbolicLink()) throw new Error('artifact upload roots cannot contain symlink/reparse points');
      if (entry.isDirectory()) pending.push(full);
      else if (entry.isFile()) files.push(full);
      else throw new Error('artifact upload roots may contain only directories and regular files');
    }
  }
  return files.sort();
}

function sha256(buffer) {
  return createHash('sha256').update(buffer).digest('hex');
}

function mediaTypeFor(filePath) {
  return mediaTypes.get(path.extname(filePath).toLowerCase()) ?? 'application/octet-stream';
}

function parse(argv) {
  const options = { roots: [], files: [], opaqueApprovalManifest: null };
  for (let index = 0; index < argv.length; index += 1) {
    const name = argv[index];
    const value = argv[index + 1];
    if (!value || value.startsWith('--')) throw new Error(`${name} requires a value`);
    if (name === '--root') options.roots.push(value);
    else if (name === '--file') options.files.push(value);
    else if (name === '--staging') options.staging = value;
    else if (name === '--manifest') options.manifest = value;
    else if (name === '--opaque-approvals') options.opaqueApprovalManifest = value;
    else if (name === '--max-file-bytes') options.maxFileBytes = Number(value);
    else throw new Error(`unknown argument: ${name}`);
    index += 1;
  }
  if (options.roots.length === 0 && options.files.length === 0) {
    throw new Error('at least one --root or --file is required');
  }
  if (!options.staging) throw new Error('--staging is required');
  if (!options.manifest) throw new Error('--manifest is required');
  return options;
}

async function loadOpaqueApprovals(filePath) {
  if (!filePath) return new Map();
  const document = JSON.parse(await readFile(path.resolve(filePath), 'utf8'));
  if (document.schemaVersion !== '1.0.0' || !Array.isArray(document.files)) {
    throw new Error('opaque approval manifest has an unsupported schema');
  }
  const approvals = new Map();
  for (const entry of document.files) {
    if (!entry || entry.approvedOpaqueSignedBinary !== true || entry.handling !== 'hash-only') {
      throw new Error('opaque approval must explicitly select signed hash-only handling');
    }
    if (!Number.isSafeInteger(entry.size) || !/^[0-9a-f]{64}$/i.test(entry.sha256 ?? '')) {
      throw new Error('opaque approval requires exact size and SHA256');
    }
    approvals.set(toPosix(entry.path), entry);
  }
  return approvals;
}

export async function prepareUpload(options) {
  const roots = (options.roots ?? []).map(item => path.resolve(item));
  const explicitFiles = (options.files ?? []).map(item => path.resolve(item));
  const staging = path.resolve(options.staging);
  const manifestPath = path.resolve(options.manifest);
  const maxFileBytes = options.maxFileBytes ?? DEFAULT_MAX_FILE_BYTES;
  const approvals = await loadOpaqueApprovals(options.opaqueApprovalManifest);
  const discovered = [];
  for (const [rootIndex, root] of roots.entries()) {
    const rootInfo = await lstat(root);
    if (rootInfo.isSymbolicLink() || !rootInfo.isDirectory()) {
      throw new Error('each upload root must be a canonical directory without reparse points');
    }
    for (const filePath of await walk(root)) {
      const relative = toPosix(path.relative(root, filePath));
      discovered.push({ root, rootIndex, filePath, relative });
    }
  }
  for (const [fileIndex, filePath] of explicitFiles.entries()) {
    const parent = path.dirname(filePath);
    await assertRegularNoReparse(parent, filePath);
    discovered.push({
      root: parent,
      rootIndex: roots.length + fileIndex,
      filePath,
      relative: path.basename(filePath),
      explicit: true
    });
  }

  await rm(staging, { recursive: true, force: true });
  await mkdir(staging, { recursive: true });
  const entries = [];
  const seen = new Set();
  for (const item of discovered) {
    const info = await assertRegularNoReparse(item.root, item.filePath);
    if (info.size > maxFileBytes) throw new Error('artifact exceeds upload size policy');
    const extension = path.extname(item.relative).toLowerCase();
    if (forbiddenExtensions.has(extension)) {
      throw new Error('raw UI bitmaps and arbitrary logs are not uploadable');
    }
    const stagedRelative = roots.length + explicitFiles.length === 1
      ? item.relative
      : `${item.rootIndex}/${item.relative}`;
    if (seen.has(stagedRelative)) throw new Error('duplicate staged artifact path');
    seen.add(stagedRelative);
    const buffer = await readFile(item.filePath);
    const digest = sha256(buffer);
    const mediaType = mediaTypeFor(item.filePath);
    let handling = 'inspect';
    let approvedOpaqueSignedBinary = false;
    if (opaqueExtensions.has(extension)) {
      const approval = approvals.get(item.relative);
      if (!approval
        || approval.size !== info.size
        || approval.sha256.toLowerCase() !== digest
        || approval.extension !== extension
        || approval.mediaType !== mediaType) {
        throw new Error('opaque binary lacks an exact signed-binary approval');
      }
      handling = 'hash-only';
      approvedOpaqueSignedBinary = true;
    }
    const stagedPath = path.join(staging, ...stagedRelative.split('/'));
    await mkdir(path.dirname(stagedPath), { recursive: true });
    await copyFile(item.filePath, stagedPath);
    entries.push({
      path: stagedRelative,
      size: info.size,
      sha256: digest,
      extension,
      mediaType,
      handling,
      approvedOpaqueSignedBinary
    });
  }
  entries.sort((left, right) => left.path.localeCompare(right.path));
  const manifest = {
    schemaVersion: '1.0.0',
    status: 'prepared',
    fileCount: entries.length,
    totalBytes: entries.reduce((sum, entry) => sum + entry.size, 0),
    stagingRoot: toPosix(path.relative(repositoryRoot, staging)),
    files: entries
  };
  await mkdir(path.dirname(manifestPath), { recursive: true });
  await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, 'utf8');
  return manifest;
}

export async function main(argv = process.argv.slice(2)) {
  const options = parse(argv);
  const manifest = await prepareUpload(options);
  console.log(`Prepared ${manifest.fileCount} explicitly manifested artifact file(s).`);
  return manifest;
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  main().catch(error => {
    console.error(`Artifact upload preparation failed closed: ${error.message}`);
    process.exitCode = 1;
  });
}
