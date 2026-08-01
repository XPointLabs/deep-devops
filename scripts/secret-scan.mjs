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
import {
  validatePreparedManifest,
  verifyPreparedStaging
} from './artifact-upload-manifest.mjs';

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
const blockedArchiveExtensions = new Set([
  '.7z', '.aab', '.apk', '.gz', '.msix', '.rar', '.tar', '.tgz', '.zip'
]);
const ignoredDirectoryNames = new Set(['.git', 'node_modules', 'bin', 'obj']);
const ignoredGeneratedArtifactDirectoryNames = new Set([
  '.dotnet-home', '.nuget', '.scratch', '.vs', 'build-contexts',
  'global-packages', 'global-packages-no-rid', 'packages', 'publish'
]);
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
  `(?:^|[,\\{;])[\t ]*(?:export[\t ]+)?["']?(${assignmentName})["']?[\t ]*(?:=|:|=>)[\t ]*(?:["'\`])?(\\$\\{\\{[^\\r\\n]+?\\}\\}|\\$\\{[^}\\r\\n]+\\}|[^\\r\\n"',};#]+)`,
  'gim'
);
const sensitiveFilenameRegex = new RegExp(`${assignmentName}\\s*(?:=|:|=>)\\s*[^/\\\\:]+`, 'i');
const forbiddenFilenameTokens = new Set([
  'mnemonic',
  'seed',
  'seed phrase',
  'private key',
  'privatekey',
  'credential',
  'credentials',
  'wallet',
  'keystore',
  'key store',
  'dump',
  'database'
]);

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
  return sensitiveFilenameRegex.test(value) || hasSensitiveFilename(value)
    ? '<redacted-sensitive-filename>'
    : value;
}

function normalizedFilenameParts(value) {
  return String(value)
    .normalize('NFKC')
    .split(/::|[/\\]/)
    .filter(Boolean)
    .map(part => ({
      raw: part.toLowerCase(),
      normalized: part
        .toLowerCase()
        .replace(/[\p{P}\p{S}_]+/gu, ' ')
        .replace(/\s+/g, ' ')
        .trim()
    }));
}

function hasSensitiveFilename(value) {
  return normalizedFilenameParts(value).some(({ raw, normalized }) => {
    if (raw === '.env' || raw.startsWith('.env.') || normalized === 'env') return true;
    const words = normalized.split(' ');
    return forbiddenFilenameTokens.has(normalized)
      || [...forbiddenFilenameTokens].some(token => token.includes(' ')
        ? normalized.includes(token)
        : words.includes(token));
  });
}

function isPlaceholder(value) {
  const normalized = String(value).trim().replace(/^["'`]|["'`]$/g, '').trim();
  if (normalized.length === 0) return true;
  return /^\$\{[A-Za-z_][A-Za-z0-9_]*\}$/.test(normalized)
    || /^\$\{\{\s*(?:github\.(?:actor|token)|secrets\.[A-Za-z_][A-Za-z0-9_]*|env\.[A-Za-z_][A-Za-z0-9_]*)\s*\}\}$/.test(normalized)
    || /^\$env:[A-Za-z_][A-Za-z0-9_]*$/i.test(normalized)
    || /^\/run\/secrets\/[A-Za-z0-9._-]+$/.test(normalized)
    || /^process\.env\.[A-Za-z_][A-Za-z0-9_]*$/.test(normalized)
    || /^<(?:(?:removed-)?compromised-value|redacted|load-from-protected-secret-store|alchemy-key)>$/i.test(normalized)
    || /^__(?:REQUIRED_[A-Z0-9_]+|REDACTED|NOT_COMMITTED|SECRET_FILE)__$/.test(normalized)
    || /^(?:REDACTED|NOT_COMMITTED|SECRET_FILE)$/.test(normalized)
    || /^https?:\/\/example\.invalid(?:\/[^\s]*)?$/i.test(normalized);
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

async function walkFiles(root, { ignoreGeneratedArtifacts = false } = {}) {
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
        if (!ignoredDirectoryNames.has(entry.name)
          && !(ignoreGeneratedArtifacts && ignoredGeneratedArtifactDirectoryNames.has(entry.name))) {
          pending.push(fullPath);
        }
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

function decodeZipName(buffer, flags) {
  if ((flags & 0x800) === 0 && buffer.some(byte => byte > 0x7f)) {
    throw new Error('ZIP non-ASCII names require the UTF-8 flag');
  }
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(buffer);
  } catch {
    throw new Error('ZIP contains an invalid UTF-8 name or comment');
  }
}

function zipEntries(buffer) {
  if (buffer.length < 22) throw new Error('truncated ZIP end-of-central-directory record');
  let eocdOffset = -1;
  const minimumOffset = Math.max(0, buffer.length - 22 - 0xffff);
  for (let offset = buffer.length - 22; offset >= minimumOffset; offset -= 1) {
    if (buffer.readUInt32LE(offset) !== 0x06054b50) continue;
    const commentLength = buffer.readUInt16LE(offset + 20);
    if (offset + 22 + commentLength === buffer.length) {
      eocdOffset = offset;
      break;
    }
  }
  if (eocdOffset < 0) throw new Error('ZIP EOCD is missing or trailing bytes remain unparsed');
  if (eocdOffset >= 20 && buffer.readUInt32LE(eocdOffset - 20) === 0x07064b50) {
    throw new Error('ZIP64 archives are not accepted for evidence');
  }
  const disk = buffer.readUInt16LE(eocdOffset + 4);
  const centralDisk = buffer.readUInt16LE(eocdOffset + 6);
  const diskEntries = buffer.readUInt16LE(eocdOffset + 8);
  const totalEntries = buffer.readUInt16LE(eocdOffset + 10);
  const centralSize = buffer.readUInt32LE(eocdOffset + 12);
  const centralOffset = buffer.readUInt32LE(eocdOffset + 16);
  const eocdCommentLength = buffer.readUInt16LE(eocdOffset + 20);
  if (disk !== 0
    || centralDisk !== 0
    || diskEntries !== totalEntries
    || totalEntries === 0xffff
    || centralSize === 0xffffffff
    || centralOffset === 0xffffffff
    || centralOffset + centralSize !== eocdOffset) {
    throw new Error('ZIP multi-disk, ZIP64, or inconsistent central directory is not accepted');
  }
  const entries = [];
  const centralRecords = [];
  let centralCursor = centralOffset;
  for (let index = 0; index < totalEntries; index += 1) {
    if (centralCursor + 46 > eocdOffset || buffer.readUInt32LE(centralCursor) !== 0x02014b50) {
      throw new Error('ZIP central directory is truncated or malformed');
    }
    const versionMadeBy = buffer.readUInt16LE(centralCursor + 4);
    const flags = buffer.readUInt16LE(centralCursor + 8);
    const method = buffer.readUInt16LE(centralCursor + 10);
    const expectedCrc = buffer.readUInt32LE(centralCursor + 16);
    const compressedSize = buffer.readUInt32LE(centralCursor + 20);
    const uncompressedSize = buffer.readUInt32LE(centralCursor + 24);
    const nameLength = buffer.readUInt16LE(centralCursor + 28);
    const extraLength = buffer.readUInt16LE(centralCursor + 30);
    const commentLength = buffer.readUInt16LE(centralCursor + 32);
    const diskStart = buffer.readUInt16LE(centralCursor + 34);
    const externalAttributes = buffer.readUInt32LE(centralCursor + 38);
    const localOffset = buffer.readUInt32LE(centralCursor + 42);
    const recordEnd = centralCursor + 46 + nameLength + extraLength + commentLength;
    if (recordEnd > eocdOffset
      || (flags & ~0x800) !== 0
      || ![0, 8].includes(method)
      || compressedSize === 0xffffffff
      || uncompressedSize === 0xffffffff
      || localOffset === 0xffffffff
      || diskStart !== 0
      || extraLength !== 0) {
      throw new Error('ZIP encrypted, descriptor, ZIP64, extra-field, or unsupported form is not accepted');
    }
    const unixType = (versionMadeBy >>> 8) === 3 ? (externalAttributes >>> 16) & 0xf000 : 0;
    if (unixType === 0xa000) throw new Error('ZIP symbolic-link entries are not accepted');
    const nameBytes = buffer.subarray(centralCursor + 46, centralCursor + 46 + nameLength);
    const name = validateEntryName(decodeZipName(nameBytes, flags));
    const commentStart = centralCursor + 46 + nameLength + extraLength;
    const comment = buffer.subarray(commentStart, commentStart + commentLength);
    if (comment.length > 0) {
      entries.push({ name: `${name}.__central_comment.txt`, data: comment, metadata: true });
    }
    centralRecords.push({
      name,
      nameBytes,
      flags,
      method,
      expectedCrc,
      compressedSize,
      uncompressedSize,
      localOffset
    });
    centralCursor = recordEnd;
  }
  if (centralCursor !== eocdOffset) throw new Error('ZIP central directory has unparsed bytes');

  let localCursor = 0;
  for (const record of [...centralRecords].sort((left, right) => left.localOffset - right.localOffset)) {
    if (record.localOffset !== localCursor
      || localCursor + 30 > centralOffset
      || buffer.readUInt32LE(localCursor) !== 0x04034b50) {
      throw new Error('ZIP local entries are missing, reordered, or have unparsed gaps');
    }
    const flags = buffer.readUInt16LE(localCursor + 6);
    const method = buffer.readUInt16LE(localCursor + 8);
    const expectedCrc = buffer.readUInt32LE(localCursor + 14);
    const compressedSize = buffer.readUInt32LE(localCursor + 18);
    const uncompressedSize = buffer.readUInt32LE(localCursor + 22);
    const nameLength = buffer.readUInt16LE(localCursor + 26);
    const extraLength = buffer.readUInt16LE(localCursor + 28);
    const nameStart = localCursor + 30;
    const dataStart = nameStart + nameLength + extraLength;
    const dataEnd = dataStart + compressedSize;
    if (dataEnd > centralOffset
      || extraLength !== 0
      || flags !== record.flags
      || method !== record.method
      || expectedCrc !== record.expectedCrc
      || compressedSize !== record.compressedSize
      || uncompressedSize !== record.uncompressedSize
      || !buffer.subarray(nameStart, nameStart + nameLength).equals(record.nameBytes)) {
      throw new Error('ZIP local and central entry metadata do not match');
    }
    let data;
    if (method === 0) data = buffer.subarray(dataStart, dataEnd);
    else data = inflateRawSync(buffer.subarray(dataStart, dataEnd), { maxOutputLength: MAX_ENTRY_BYTES + 1 });
    if (data.length !== uncompressedSize || crc32(data) !== expectedCrc) {
      throw new Error('ZIP expanded size or CRC mismatch');
    }
    if (!record.name.endsWith('/')) entries.push({ name: record.name, data });
    else if (data.length !== 0) throw new Error('ZIP directory entry contains data');
    localCursor = dataEnd;
  }
  if (localCursor !== centralOffset) throw new Error('ZIP local region has trailing or unparsed bytes');
  const eocdComment = buffer.subarray(eocdOffset + 22, eocdOffset + 22 + eocdCommentLength);
  if (eocdComment.length > 0) {
    entries.push({ name: '__archive_comment.txt', data: eocdComment, metadata: true });
  }
  return entries;
}

function tarChecksum(header) {
  let sum = 0;
  for (let index = 0; index < header.length; index += 1) {
    sum += index >= 148 && index < 156 ? 0x20 : header[index];
  }
  return sum;
}

function tarString(buffer) {
  return buffer.toString('utf8').replace(/\0.*$/, '').trim();
}

function tarEntries(buffer) {
  if (buffer.length < 1024 || buffer.length % 512 !== 0) {
    throw new Error('TAR must contain complete 512-byte records and end blocks');
  }
  const entries = [];
  let offset = 0;
  let endBlocks = 0;
  while (offset + 512 <= buffer.length) {
    const header = buffer.subarray(offset, offset + 512);
    if (header.every(byte => byte === 0)) {
      endBlocks += 1;
      offset += 512;
      if (endBlocks === 2) break;
      continue;
    }
    if (endBlocks > 0) throw new Error('TAR contains data between end-of-archive blocks');
    const storedChecksumText = tarString(header.subarray(148, 156));
    if (!/^[0-7]+$/.test(storedChecksumText)
      || Number.parseInt(storedChecksumText, 8) !== tarChecksum(header)) {
      throw new Error('TAR header checksum is invalid');
    }
    const prefix = tarString(header.subarray(345, 500));
    const baseName = tarString(header.subarray(0, 100));
    const name = validateEntryName(prefix ? `${prefix}/${baseName}` : baseName);
    const sizeText = header.subarray(124, 136).toString('ascii').replace(/\0.*$/, '').trim();
    if (!/^[0-7]*$/.test(sizeText)) throw new Error('invalid TAR entry size');
    const size = Number.parseInt(sizeText || '0', 8);
    const type = header[156];
    const dataStart = offset + 512;
    const dataEnd = dataStart + size;
    if (!Number.isSafeInteger(size) || dataEnd > buffer.length) throw new Error('truncated TAR entry');
    const paddedEnd = dataStart + Math.ceil(size / 512) * 512;
    if (paddedEnd > buffer.length) throw new Error('truncated TAR entry padding');
    if (buffer.subarray(dataEnd, paddedEnd).some(byte => byte !== 0)) {
      throw new Error('TAR entry padding contains unparsed nonzero bytes');
    }
    if (type === 0 || type === 48) entries.push({ name, data: buffer.subarray(dataStart, dataEnd) });
    else if (type === 53) {
      if (size !== 0) throw new Error('TAR directory entry contains data');
    } else throw new Error('TAR links, extensions, and special entries are not accepted');
    for (const [field, value] of [
      ['uname', tarString(header.subarray(265, 297))],
      ['gname', tarString(header.subarray(297, 329))]
    ]) {
      if (value) entries.push({ name: `${name}.__tar_${field}.txt`, data: Buffer.from(value), metadata: true });
    }
    offset = paddedEnd;
  }
  if (endBlocks !== 2) throw new Error('TAR is missing two end-of-archive blocks');
  if (buffer.subarray(offset).some(byte => byte !== 0)) {
    throw new Error('TAR has nonzero trailing bytes after end-of-archive blocks');
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

function inspectBuffer(
  buffer,
  logicalName,
  findings,
  state,
  depth = 0,
  manifestEntry = null,
  enforceFilenamePolicy = false) {
  if (depth > 0) {
    state.archiveEntries += 1;
    state.archiveExpandedBytes += buffer.length;
    if (state.archiveEntries > MAX_ARCHIVE_ENTRIES) throw new Error('archive entry limit exceeded');
    if (state.archiveExpandedBytes > MAX_ARCHIVE_EXPANDED_BYTES) {
      throw new Error('archive expanded-size limit exceeded');
    }
  }
  if (buffer.length > MAX_ENTRY_BYTES) {
    findings.push(finding('unscannable-large-file', logicalName));
    return;
  }
  if (sensitiveFilenameRegex.test(logicalName) || (enforceFilenamePolicy && hasSensitiveFilename(logicalName))) {
    findings.push(finding('sensitive-filename', logicalName));
  }
  const extension = path.extname(logicalName).toLowerCase();
  const blockedArchiveMagic = (buffer.length >= 4
    && ['504b0304', '504b0506', '504b0708', '52617221'].includes(buffer.subarray(0, 4).toString('hex')))
    || (buffer.length >= 6 && buffer.subarray(0, 6).toString('hex') === '377abcaf271c')
    || (buffer.length >= 2 && buffer[0] === 0x1f && buffer[1] === 0x8b)
    || (buffer.length >= 512 && (() => {
      const checksumText = buffer.subarray(148, 156).toString('ascii').replace(/\0.*$/, '').trim();
      return /^[0-7]+$/.test(checksumText)
        && Number.parseInt(checksumText, 8) === tarChecksum(buffer.subarray(0, 512));
    })());
  if (blockedArchiveExtensions.has(extension) || blockedArchiveMagic) {
    findings.push(finding('forbidden-archive-artifact', logicalName));
  }
  if (archiveExtensions.has(extension)) {
    if (depth >= MAX_ARCHIVE_DEPTH) throw new Error('archive recursion depth exceeded');
    let entries;
    if (extension === '.gz') {
      const uncompressed = gunzipSync(buffer, { maxOutputLength: MAX_ARCHIVE_EXPANDED_BYTES + 1 });
      const nestedName = logicalName.slice(0, -3) || `${logicalName}.payload`;
      inspectBuffer(uncompressed, nestedName, findings, state, depth + 1, null, enforceFilenamePolicy);
      return;
    }
    entries = extension === '.tar' ? tarEntries(buffer) : zipEntries(buffer);
    for (const [index, entry] of entries.entries()) {
      const metadataPath = `${logicalName}::entry-${index}-name`;
      inspectText(entry.name, metadataPath, findings);
      if (sensitiveFilenameRegex.test(entry.name) || hasSensitiveFilename(entry.name)) {
        findings.push(finding('sensitive-filename', metadataPath));
      }
      const extension = path.extname(entry.name).toLowerCase();
      const nestedArchiveSuffix = archiveExtensions.has(extension) ? extension : '';
      inspectBuffer(
        entry.data,
        `${logicalName}::entry-${index}${nestedArchiveSuffix}`,
        findings,
        state,
        depth + 1,
        null,
        enforceFilenamePolicy
      );
    }
    return;
  }
  if (isProbablyText(logicalName, buffer)) {
    inspectText(buffer.toString('utf8'), logicalName, findings);
    state.textFiles += 1;
    return;
  }
  findings.push(finding('unknown-binary-file', logicalName));
}

async function loadManifest(filePath) {
  const raw = await readFile(filePath);
  const document = JSON.parse(raw.toString('utf8'));
  validatePreparedManifest(document);
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
    await verifyPreparedStaging(manifest, stagingRoot);
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
        const isArtifactRoot = artifactRoots.some(artifactRoot => path.resolve(artifactRoot) === path.resolve(target));
        for (const file of await walkFiles(target, { ignoreGeneratedArtifacts: isArtifactRoot })) {
          candidates.set(file, {});
        }
      } else if (targetInfo.isFile()) candidates.set(target, {});
      else throw new Error('scan target must be a regular file or directory');
    }
  }

  const findings = [];
  const state = { archiveEntries: 0, archiveExpandedBytes: 0, textFiles: 0 };
  for (const [filePath, metadata] of [...candidates.entries()].sort(([left], [right]) => left.localeCompare(right))) {
    const logical = metadata.logical ?? logicalPath(root, filePath, [...artifactRoots, ...explicitPaths]);
    const artifactRelative = Boolean(options.manifest)
      || artifactRoots.some(artifactRoot => inside(artifactRoot, filePath))
      || explicitPaths.some(target => inside(target, filePath) || path.resolve(target) === path.resolve(filePath));
    const extension = path.extname(filePath).toLowerCase();
    if (artifactRelative && (forbiddenArtifactNames.has(path.basename(filePath).toLowerCase()) || forbiddenUploadExtensions.has(extension))) {
      findings.push(finding('forbidden-raw-artifact', logical));
    }
    const fileInfo = await stat(filePath);
    const buffer = metadata.buffer ?? await readFile(filePath);
    if (fileInfo.size > MAX_FILE_BYTES) {
      findings.push(finding('unscannable-large-file', logical));
      continue;
    }
    inspectBuffer(buffer, logical, findings, state, 0, metadata.entry, artifactRelative);
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
    archiveEntriesInspected: state.archiveEntries,
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
