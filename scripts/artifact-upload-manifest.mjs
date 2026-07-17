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
const MANIFEST_SCHEMA_VERSION = '1.1.0';
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

function exactKeys(value, expected, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    throw new Error(`${label} contains unsupported or missing fields`);
  }
}

function normalizeRequiredPath(value) {
  const normalized = String(value).normalize('NFKC').replaceAll('\\', '/');
  if (!normalized
    || normalized.startsWith('/')
    || /^[A-Za-z]:/.test(normalized)
    || normalized.split('/').some(part => part === '' || part === '.' || part === '..')) {
    throw new Error('required artifact paths must be canonical relative paths');
  }
  return normalized;
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
  const options = { roots: [], files: [], requiredFiles: [] };
  for (let index = 0; index < argv.length; index += 1) {
    const name = argv[index];
    const value = argv[index + 1];
    if (!value || value.startsWith('--')) throw new Error(`${name} requires a value`);
    if (name === '--root') options.roots.push(value);
    else if (name === '--file') options.files.push(value);
    else if (name === '--require') options.requiredFiles.push(value);
    else if (name === '--staging') options.staging = value;
    else if (name === '--manifest') options.manifest = value;
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

export function validatePreparedManifest(document) {
  exactKeys(document, [
    'schemaVersion',
    'status',
    'fileCount',
    'totalBytes',
    'stagingRoot',
    'requiredFiles',
    'files'
  ], 'upload manifest');
  if (document.schemaVersion !== MANIFEST_SCHEMA_VERSION
    || document.status !== 'prepared'
    || !Number.isSafeInteger(document.fileCount)
    || document.fileCount <= 0
    || !Number.isSafeInteger(document.totalBytes)
    || document.totalBytes < 0
    || typeof document.stagingRoot !== 'string'
    || !Array.isArray(document.requiredFiles)
    || !Array.isArray(document.files)
    || document.files.length !== document.fileCount) {
    throw new Error('upload manifest has an unsupported schema or empty/inconsistent content');
  }
  const requiredFiles = document.requiredFiles.map(normalizeRequiredPath);
  if (new Set(requiredFiles).size !== requiredFiles.length) {
    throw new Error('upload manifest required paths must be unique');
  }
  let totalBytes = 0;
  const paths = new Set();
  for (const entry of document.files) {
    exactKeys(entry, [
      'path',
      'size',
      'sha256',
      'extension',
      'mediaType',
      'handling',
      'approvedOpaqueSignedBinary'
    ], 'upload manifest entry');
    const entryPath = normalizeRequiredPath(entry.path);
    if (entryPath !== entry.path || paths.has(entryPath)) {
      throw new Error('upload manifest paths must be canonical and unique');
    }
    paths.add(entryPath);
    if (!Number.isSafeInteger(entry.size)
      || entry.size < 0
      || !/^[0-9a-f]{64}$/.test(entry.sha256 ?? '')
      || entry.extension !== path.posix.extname(entry.path).toLowerCase()
      || entry.mediaType !== mediaTypeFor(entry.path)
      || entry.handling !== 'inspect'
      || entry.approvedOpaqueSignedBinary !== false) {
      throw new Error('upload manifest entry violates the inspect-only policy');
    }
    totalBytes += entry.size;
    if (!Number.isSafeInteger(totalBytes)) throw new Error('upload manifest total size overflow');
  }
  if (totalBytes !== document.totalBytes) throw new Error('upload manifest total byte count mismatch');
  for (const required of requiredFiles) {
    if (!paths.has(required)) throw new Error(`required artifact is missing from upload manifest: ${required}`);
  }
  return document;
}

export async function verifyPreparedStaging(document, stagingRoot) {
  validatePreparedManifest(document);
  const resolvedRoot = path.resolve(stagingRoot);
  const rootInfo = await lstat(resolvedRoot);
  if (rootInfo.isSymbolicLink() || !rootInfo.isDirectory()) {
    throw new Error('staging root must be a canonical directory');
  }
  const realRoot = await realpath(resolvedRoot);
  const discovered = await walk(resolvedRoot);
  if (discovered.length !== document.fileCount) {
    throw new Error('staging root contains unmanifested or missing files');
  }
  const expectedPaths = new Set(document.files.map(entry => entry.path));
  for (const filePath of discovered) {
    const relative = toPosix(path.relative(resolvedRoot, filePath));
    if (!expectedPaths.has(relative)) throw new Error('staging root contains an unmanifested file');
  }
  for (const entry of document.files) {
    const filePath = path.resolve(resolvedRoot, ...entry.path.split('/'));
    if (!inside(resolvedRoot, filePath)) throw new Error('upload manifest path escapes staging root');
    const info = await lstat(filePath);
    if (info.isSymbolicLink() || !info.isFile()) throw new Error('manifested artifact is not a regular file');
    if (!inside(realRoot, await realpath(filePath))) {
      throw new Error('manifested artifact resolves outside staging root');
    }
    const buffer = await readFile(filePath);
    if (buffer.length !== entry.size || sha256(buffer) !== entry.sha256) {
      throw new Error('manifested artifact changed after manifest preparation');
    }
  }
}

export async function prepareUpload(options) {
  const roots = (options.roots ?? []).map(item => path.resolve(item));
  const explicitFiles = (options.files ?? []).map(item => path.resolve(item));
  const staging = path.resolve(options.staging);
  const manifestPath = path.resolve(options.manifest);
  const maxFileBytes = options.maxFileBytes ?? DEFAULT_MAX_FILE_BYTES;
  const requiredFiles = [...new Set((options.requiredFiles ?? []).map(normalizeRequiredPath))].sort();
  if (requiredFiles.length > 0 && (roots.length !== 1 || explicitFiles.length !== 0)) {
    throw new Error('required artifact contracts currently require exactly one upload root');
  }
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
  if (discovered.length === 0) {
    throw new Error('upload selection is empty');
  }
  const discoveredRelative = new Set(discovered.map(item => item.relative));
  for (const required of requiredFiles) {
    if (!discoveredRelative.has(required)) {
      throw new Error(`required artifact is missing from upload selection: ${required}`);
    }
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
    if (opaqueExtensions.has(extension)) {
      throw new Error('opaque executable binaries are blocked until cryptographic approval verification exists');
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
      handling: 'inspect',
      approvedOpaqueSignedBinary: false
    });
  }
  entries.sort((left, right) => left.path.localeCompare(right.path));
  const manifest = {
    schemaVersion: MANIFEST_SCHEMA_VERSION,
    status: 'prepared',
    fileCount: entries.length,
    totalBytes: entries.reduce((sum, entry) => sum + entry.size, 0),
    stagingRoot: toPosix(path.relative(repositoryRoot, staging)),
    requiredFiles,
    files: entries
  };
  validatePreparedManifest(manifest);
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
