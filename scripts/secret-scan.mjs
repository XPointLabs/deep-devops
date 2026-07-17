import { createHash } from 'node:crypto';
import { existsSync } from 'node:fs';
import {
  lstat,
  mkdir,
  readFile,
  readdir,
  realpath,
  stat,
  writeFile
} from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { gunzipSync, inflateRawSync } from 'node:zlib';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const repositoryRoot = path.resolve(__dirname, '..');
const PROGRAM_REVISION_SHA = 'ca5ad9f0c9d4dfb509dedcbf8133524c15867fce5534816da21ff86a07057383';
const MAX_FILE_BYTES = 8 * 1024 * 1024;
const MAX_ARCHIVE_DEPTH = 3;
const MAX_ARCHIVE_ENTRIES = 2048;
const MAX_ARCHIVE_EXPANDED_BYTES = 32 * 1024 * 1024;
const MAX_ENTRY_BYTES = 8 * 1024 * 1024;
const forbiddenArtifactNames = new Set([
  'compose.log', 'compose.resolved.yml', 'compose.resolved.yaml',
  'docker-compose.resolved.yml', 'docker-compose.resolved.yaml'
]);
const forbiddenUploadExtensions = new Set([
  '.bmp', '.gif', '.heic', '.jpeg', '.jpg', '.log', '.png', '.tif', '.tiff', '.webp'
]);
const archiveExtensions = new Set(['.zip', '.apk', '.aab', '.msix', '.tar', '.gz']);
const ignoredDirectoryNames = new Set(['.git', 'node_modules', 'bin', 'obj']);
const textExtensions = new Set([
  '.conf', '.cs', '.cmd', '.dockerfile', '.env', '.example', '.html', '.js',
  '.json', '.md', '.mjs', '.ps1', '.sh', '.trx', '.txt', '.xml', '.yaml', '.yml'
]);
const assignmentName = '(?:mnemonic|seed(?:[_. -]?phrase)?|private[_. -]?(?:key|seed|scalar)|'
  + 'bls[_. -]?private(?:[_. -]?(?:key|scalar))?|ed25519[_. -]?private(?:[_. -]?(?:key|seed))?|'
  + 'password|passwd|secret|client[_. -]?secret|api[_. -]?key|auth[_. -]?token|'
  + 'access[_. -]?token|bearer[_. -]?token)';

const directRules = [
  { id: 'private-key-block', regex: /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/gi },
  { id: 'known-provider-token', regex: /\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|AKIA[0-9A-Z]{16})\b/g },
  { id: 'jwt', regex: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g },
  { id: 'credential-in-url', regex: /\b(?:https?|wss?):\/\/[^/\s:@]+:[^/\s@]{8,}@/gi },
  { id: 'sensitive-interpolation-hex-default', regex: /\$\{[^}\r\n]*:-([0-9a-f]{64})\}/gi, capture: 1 },
  {
    id: 'mnemonic-shape',
    regex: /\b(?:mnemonic|seed(?:[_. -]?phrase)?)\b[^=\r\n:]{0,40}(?:=|:|=>)\s*["'`]?\s*((?:[a-z]{3,12}\s+){11,23}[a-z]{3,12})\b/gi,
    capture: 1
  },
  {
    id: 'private-hex-context',
    regex: new RegExp(`\\b${assignmentName}\\b[^\\r\\n]{0,120}\\b([0-9a-f]{64})\\b`, 'gi'),
    capture: 1
  }
];
const assignmentRegex = new RegExp(
  `(?:^|[,\\{;])[\t ]*(?:export[\t ]+)?["']?(${assignmentName})["']?[\t ]*(?:=|:|=>)[\t ]*(?:["'\`])?([^\\r\\n"',};#]+)`,
  'gim'
);
const sensitiveFilenameRegex = new RegExp(`${assignmentName}\\s*(?:=|:|=>)\\s*[^/\\\\:]+`, 'i');

function toPosix(value) {
  return value.split(path.sep).join('/');
}

function inside(root, target) {
  const relative = path.relative(root, target);
  return relative === '' || (!relative.startsWith('..') && !path.isAbsolute(relative));
}

function logicalPath(root, filePath, externalRoots = []) {
  if (inside(root, filePath)) return toPosix(path.relative(root, filePath) || '.');
  for (const [index, externalRoot] of externalRoots.entries()) {
    if (inside(externalRoot, filePath)) {
      const relative = path.relative(externalRoot, filePath);
      return `external-artifacts/${index}${relative ? `/${toPosix(relative)}` : ''}`;
    }
  }
  throw new Error('scan target escapes the selected roots');
}

function safeDisplayPath(value) {
  return sensitiveFilenameRegex.test(value) ? '<redacted-sensitive-filename>' : value;
}

function isPlaceholder(value) {
  const normalized = String(value).trim().replace(/^["'`]|["'`]$/g, '').trim();
  if (normalized.length === 0) return true;
  return normalized.startsWith('${')
    || normalized.startsWith('$env:')
    || normalized.startsWith('$$(')
    || normalized.startsWith('$(')
    || normalized.startsWith('/run/secrets/')
    || normalized.startsWith('process.env')
    || normalized.startsWith('Buffer.')
    || normalized.startsWith('createPrivateKey(')
    || normalized.startsWith('privateKeyToAccount(')
    || normalized.startsWith('mnemonicToAccount(')
    || (normalized.includes('${') && normalized.includes('}'))
    || normalized.startsWith('<')
    || normalized.startsWith('__REQUIRED_')
    || normalized.includes('REDACTED')
    || normalized.includes('NOT_COMMITTED')
    || normalized.includes('SECRET_FILE')
    || normalized.includes('example.invalid');
}

function looksLikeLiteralSecret(value, logicalName = '') {
  const normalized = String(value).trim().replace(/^["'`]|["'`]$/g, '').trim();
  if (isPlaceholder(normalized)) return false;
  if (/^(?:true|false|null|undefined|env|stdin)$/i.test(normalized)) return false;
  if (/\.(?:cs|js|mjs|ps1|ts)$/i.test(logicalName)
    && (/^[A-Za-z_$][\w$]*$/.test(normalized)
      || /^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)?[\t ]*\(/.test(normalized))) {
    return false;
  }
  if (/^[0-9a-f]{64}$/i.test(normalized)) return true;
  if (/^(?:gh[pousr]_|github_pat_|AKIA)[A-Za-z0-9_]{16,}$/.test(normalized)) return true;
  if (/^eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}$/.test(normalized)) return true;
  if (/^(?:[a-z]{3,12}\s+){11,23}[a-z]{3,12}$/i.test(normalized)) return true;
  return normalized.length >= 8;
}

function lineNumberAt(content, offset) {
  let line = 1;
  for (let index = 0; index < offset; index += 1) if (content.charCodeAt(index) === 10) line += 1;
  return line;
}

function fingerprint(ruleId, file, line) {
  return createHash('sha256').update(`${ruleId}\0${file}\0${line}`).digest('hex').slice(0, 16);
}

function finding(ruleId, file, line = null) {
  return {
    ruleId,
    path: safeDisplayPath(file),
    line,
    fingerprint: fingerprint(ruleId, file, line ?? 0)
  };
}

function isProbablyText(filePath, buffer) {
  const extension = path.extname(filePath).toLowerCase();
  if (textExtensions.has(extension) || path.basename(filePath).includes('Dockerfile')) return true;
  const sample = buffer.subarray(0, Math.min(buffer.length, 4096));
  if (sample.includes(0)) return false;
  if (sample.length === 0) return true;
  let controls = 0;
  for (const byte of sample) {
    if (byte < 9 || (byte > 13 && byte < 32)) controls += 1;
  }
  return controls / sample.length < 0.02;
}

async function walkFiles(root) {
  const files = [];
  if (!existsSync(root)) return files;
  const resolvedRoot = path.resolve(root);
  const realRoot = await realpath(resolvedRoot);
  const pending = [resolvedRoot];
  while (pending.length > 0) {
    const current = pending.pop();
    const currentInfo = await lstat(current);
    if (currentInfo.isSymbolicLink()) throw new Error('scan roots cannot contain symlink/reparse points');
    if (!inside(realRoot, await realpath(current))) throw new Error('scan target resolves outside selected root');
    for (const entry of await readdir(current, { withFileTypes: true })) {
      if (entry.isSymbolicLink()) throw new Error('scan roots cannot contain symlink/reparse points');
      const fullPath = path.join(current, entry.name);
      if (entry.isDirectory()) {
        if (!ignoredDirectoryNames.has(entry.name)) pending.push(fullPath);
      } else if (entry.isFile()) files.push(fullPath);
      else throw new Error('scan roots may contain only directories and regular files');
    }
  }
  return files;
}

function trackedFiles(root) {
  const result = spawnSync('git', ['-C', root, 'ls-files', '-z'], { encoding: 'buffer', windowsHide: true });
  if (result.status !== 0) throw new Error('unable to enumerate tracked files');
  return result.stdout.toString('utf8').split('\0').filter(Boolean).map(file => path.join(root, file));
}

function validateEntryName(name) {
  const normalized = name.replaceAll('\\', '/');
  if (!normalized || normalized.startsWith('/') || /^[A-Za-z]:/.test(normalized)) {
    throw new Error('archive contains an absolute entry path');
  }
  if (normalized.split('/').some(part => part === '..')) throw new Error('archive contains path traversal');
  if (normalized.includes('\0')) throw new Error('archive contains an invalid entry name');
  return normalized;
}

function zipEntries(buffer) {
  const entries = [];
  let offset = 0;
  while (offset + 4 <= buffer.length) {
    const signature = buffer.readUInt32LE(offset);
    if (signature === 0x04034b50) {
      if (offset + 30 > buffer.length) throw new Error('truncated ZIP local header');
      const flags = buffer.readUInt16LE(offset + 6);
      const method = buffer.readUInt16LE(offset + 8);
      const compressedSize = buffer.readUInt32LE(offset + 18);
      const uncompressedSize = buffer.readUInt32LE(offset + 22);
      const nameLength = buffer.readUInt16LE(offset + 26);
      const extraLength = buffer.readUInt16LE(offset + 28);
      if ((flags & 0x08) !== 0) throw new Error('ZIP data descriptors are not accepted for evidence');
      const nameStart = offset + 30;
      const dataStart = nameStart + nameLength + extraLength;
      const dataEnd = dataStart + compressedSize;
      if (dataEnd > buffer.length) throw new Error('truncated ZIP entry');
      const name = validateEntryName(buffer.subarray(nameStart, nameStart + nameLength).toString('utf8'));
      if (!name.endsWith('/')) {
        let data;
        if (method === 0) data = buffer.subarray(dataStart, dataEnd);
        else if (method === 8) data = inflateRawSync(buffer.subarray(dataStart, dataEnd), { maxOutputLength: MAX_ENTRY_BYTES + 1 });
        else throw new Error('unsupported ZIP compression method');
        if (data.length !== uncompressedSize) throw new Error('ZIP expanded size mismatch');
        entries.push({ name, data });
      }
      offset = dataEnd;
      continue;
    }
    if (signature === 0x02014b50 || signature === 0x06054b50) break;
    throw new Error('invalid ZIP structure');
  }
  return entries;
}

function tarEntries(buffer) {
  const entries = [];
  for (let offset = 0; offset + 512 <= buffer.length;) {
    const header = buffer.subarray(offset, offset + 512);
    if (header.every(byte => byte === 0)) break;
    const name = validateEntryName(header.subarray(0, 100).toString('utf8').replace(/\0.*$/, ''));
    const sizeText = header.subarray(124, 136).toString('ascii').replace(/\0.*$/, '').trim();
    if (!/^[0-7]*$/.test(sizeText)) throw new Error('invalid TAR entry size');
    const size = Number.parseInt(sizeText || '0', 8);
    const type = header[156];
    const dataStart = offset + 512;
    const dataEnd = dataStart + size;
    if (!Number.isSafeInteger(size) || dataEnd > buffer.length) throw new Error('truncated TAR entry');
    if (type === 0 || type === 48) entries.push({ name, data: buffer.subarray(dataStart, dataEnd) });
    else if (![53].includes(type)) throw new Error('TAR links and special entries are not accepted');
    offset = dataStart + Math.ceil(size / 512) * 512;
  }
  return entries;
}

function inspectText(content, logicalName, findings) {
  assignmentRegex.lastIndex = 0;
  for (let match = assignmentRegex.exec(content); match; match = assignmentRegex.exec(content)) {
    if (looksLikeLiteralSecret(match[2], logicalName)) {
      findings.push(finding('sensitive-assignment', logicalName, lineNumberAt(content, match.index)));
    }
    if (match[0].length === 0) assignmentRegex.lastIndex += 1;
  }
  for (const rule of directRules) {
    rule.regex.lastIndex = 0;
    for (let match = rule.regex.exec(content); match; match = rule.regex.exec(content)) {
      const captured = rule.capture ? match[rule.capture] : match[0];
      if (rule.capture && isPlaceholder(captured)) continue;
      findings.push(finding(rule.id, logicalName, lineNumberAt(content, match.index)));
      if (match[0].length === 0) rule.regex.lastIndex += 1;
    }
  }
}

function inspectBuffer(buffer, logicalName, findings, state, depth = 0, manifestEntry = null) {
  state.entries += 1;
  state.expandedBytes += buffer.length;
  if (state.entries > MAX_ARCHIVE_ENTRIES) throw new Error('archive entry limit exceeded');
  if (state.expandedBytes > MAX_ARCHIVE_EXPANDED_BYTES) throw new Error('archive expanded-size limit exceeded');
  if (buffer.length > MAX_ENTRY_BYTES) {
    if (manifestEntry?.handling === 'hash-only' && manifestEntry?.approvedOpaqueSignedBinary === true) return;
    findings.push(finding('unscannable-large-file', logicalName));
    return;
  }
  if (sensitiveFilenameRegex.test(logicalName)) {
    findings.push(finding('sensitive-filename', logicalName));
  }
  const extension = path.extname(logicalName).toLowerCase();
  if (archiveExtensions.has(extension)) {
    if (depth >= MAX_ARCHIVE_DEPTH) throw new Error('archive recursion depth exceeded');
    let entries;
    if (extension === '.gz') {
      const uncompressed = gunzipSync(buffer, { maxOutputLength: MAX_ARCHIVE_EXPANDED_BYTES + 1 });
      const nestedName = logicalName.slice(0, -3) || `${logicalName}.payload`;
      inspectBuffer(uncompressed, nestedName, findings, state, depth + 1);
      return;
    }
    entries = extension === '.tar' ? tarEntries(buffer) : zipEntries(buffer);
    for (const entry of entries) {
      inspectBuffer(entry.data, `${logicalName}::${entry.name}`, findings, state, depth + 1);
    }
    return;
  }
  if (isProbablyText(logicalName, buffer)) {
    inspectText(buffer.toString('utf8'), logicalName, findings);
    state.textFiles += 1;
    return;
  }
  if (manifestEntry?.handling === 'hash-only' && manifestEntry?.approvedOpaqueSignedBinary === true) return;
  findings.push(finding('unknown-binary-file', logicalName));
}

async function loadManifest(filePath) {
  const raw = await readFile(filePath);
  const document = JSON.parse(raw.toString('utf8'));
  if (document.schemaVersion !== '1.0.0' || document.status !== 'prepared' || !Array.isArray(document.files)) {
    throw new Error('upload manifest has an unsupported schema or status');
  }
  return {
    document,
    sha256: createHash('sha256').update(raw).digest('hex')
  };
}

export async function scan(options = {}) {
  const root = path.resolve(options.root ?? repositoryRoot);
  const includeTracked = options.includeTracked !== false && !options.manifest;
  const artifactRoots = (options.artifactRoots ?? (options.manifest ? [] : [path.join(root, 'artifacts')])).map(item => path.resolve(item));
  const explicitPaths = (options.paths ?? []).map(item => path.resolve(item));
  const candidates = new Map();
  let selectedManifestSha256 = null;
  if (options.manifest) {
    const loadedManifest = await loadManifest(path.resolve(options.manifest));
    const manifest = loadedManifest.document;
    selectedManifestSha256 = loadedManifest.sha256;
    const stagingRoot = options.stagingRoot
      ? path.resolve(options.stagingRoot)
      : path.resolve(path.dirname(path.resolve(options.manifest)), manifest.stagingRoot ?? '');
    const realStagingRoot = await realpath(stagingRoot);
    for (const entry of manifest.files) {
      if (!entry || typeof entry.path !== 'string' || !/^[0-9a-f]{64}$/i.test(entry.sha256 ?? '')) {
        throw new Error('upload manifest entry is incomplete');
      }
      const filePath = path.resolve(stagingRoot, ...entry.path.split('/'));
      if (!inside(stagingRoot, filePath)) throw new Error('upload manifest path escapes staging root');
      const info = await lstat(filePath);
      if (info.isSymbolicLink() || !info.isFile()) throw new Error('manifested artifact is not a regular file');
      if (!inside(realStagingRoot, await realpath(filePath))) throw new Error('manifested artifact resolves outside staging root');
      const buffer = await readFile(filePath);
      if (buffer.length !== entry.size || createHash('sha256').update(buffer).digest('hex') !== entry.sha256.toLowerCase()) {
        throw new Error('manifested artifact changed after manifest preparation');
      }
      candidates.set(filePath, { logical: entry.path, entry, buffer });
    }
    if (candidates.size !== manifest.fileCount) throw new Error('upload manifest file count mismatch');
  } else {
    if (includeTracked) for (const file of trackedFiles(root)) candidates.set(file, {});
    for (const target of [...artifactRoots, ...explicitPaths]) {
      if (!existsSync(target)) continue;
      const targetInfo = await lstat(target);
      if (targetInfo.isSymbolicLink()) throw new Error('scan target cannot be a symlink/reparse point');
      if (targetInfo.isDirectory()) {
        for (const file of await walkFiles(target)) candidates.set(file, {});
      } else if (targetInfo.isFile()) candidates.set(target, {});
      else throw new Error('scan target must be a regular file or directory');
    }
  }

  const findings = [];
  const state = { entries: 0, expandedBytes: 0, textFiles: 0 };
  for (const [filePath, metadata] of [...candidates.entries()].sort(([left], [right]) => left.localeCompare(right))) {
    const logical = metadata.logical ?? logicalPath(root, filePath, [...artifactRoots, ...explicitPaths]);
    const artifactRelative = Boolean(options.manifest) || artifactRoots.some(artifactRoot => inside(artifactRoot, filePath));
    const extension = path.extname(filePath).toLowerCase();
    if (artifactRelative && (forbiddenArtifactNames.has(path.basename(filePath).toLowerCase()) || forbiddenUploadExtensions.has(extension))) {
      findings.push(finding('forbidden-raw-artifact', logical));
    }
    const fileInfo = await stat(filePath);
    const buffer = metadata.buffer ?? await readFile(filePath);
    if (fileInfo.size > MAX_FILE_BYTES && !(metadata.entry?.handling === 'hash-only' && metadata.entry?.approvedOpaqueSignedBinary === true)) {
      findings.push(finding('unscannable-large-file', logical));
      continue;
    }
    inspectBuffer(buffer, logical, findings, state, 0, metadata.entry);
  }

  const unique = [...new Map(findings.map(item => [
    `${item.ruleId}\0${item.path}\0${item.line ?? ''}`, item
  ])).values()];
  return {
    schemaVersion: '2.0.0',
    status: unique.length === 0 ? 'ok' : 'failed',
    programRevisionSha256: PROGRAM_REVISION_SHA,
    scannedFiles: candidates.size,
    scannedTextEntries: state.textFiles,
    archiveEntriesInspected: Math.max(0, state.entries - candidates.size),
    selectedManifestSha256,
    findingCount: unique.length,
    findings: unique
  };
}

function parseArguments(argv) {
  const options = { artifactRoots: [], paths: [] };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === '--no-tracked') {
      options.includeTracked = false;
      continue;
    }
    const key = {
      '--root': 'root',
      '--artifacts': 'artifactRoots',
      '--path': 'paths',
      '--summary': 'summaryPath',
      '--manifest': 'manifest',
      '--staging-root': 'stagingRoot'
    }[argument];
    if (!key) throw new Error(`unknown argument: ${argument}`);
    const value = argv[index + 1];
    if (!value || value.startsWith('--')) throw new Error(`${argument} requires a value`);
    if (Array.isArray(options[key])) options[key].push(value);
    else options[key] = value;
    index += 1;
  }
  if (options.artifactRoots.length === 0) delete options.artifactRoots;
  return options;
}

export async function main(argv = process.argv.slice(2)) {
  const options = parseArguments(argv);
  const root = path.resolve(options.root ?? repositoryRoot);
  const result = await scan({ ...options, root });
  const summaryPath = path.resolve(options.summaryPath
    ?? path.join(root, 'artifacts', 'security', 'secret-scan-summary.json'));
  const summary = {
    ...result,
    generatedAt: process.env.DEEP_EVIDENCE_NOW ?? new Date().toISOString(),
    summaryPath: inside(root, summaryPath) ? toPosix(path.relative(root, summaryPath)) : 'external-summary.json'
  };
  await mkdir(path.dirname(summaryPath), { recursive: true });
  await writeFile(summaryPath, `${JSON.stringify(summary, null, 2)}\n`, 'utf8');
  if (summary.findingCount > 0) {
    console.error(`Secret scan failed closed with ${summary.findingCount} finding(s).`);
    for (const item of summary.findings) {
      console.error(`- ${item.ruleId} at ${item.path}${item.line ? `:${item.line}` : ''} [${item.fingerprint}]`);
    }
    process.exitCode = 1;
    return summary;
  }
  console.log(`Secret scan passed (${summary.scannedFiles} manifested/selected files).`);
  return summary;
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  main().catch(error => {
    console.error(`Secret scan failed closed: ${error.message}`);
    process.exitCode = 1;
  });
}
