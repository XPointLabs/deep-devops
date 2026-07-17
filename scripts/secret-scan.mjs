import { createHash } from 'node:crypto';
import { existsSync } from 'node:fs';
import { mkdir, readFile, readdir, stat, writeFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const repositoryRoot = path.resolve(__dirname, '..');
const PROGRAM_REVISION_SHA = 'ca5ad9f0c9d4dfb509dedcbf8133524c15867fce5534816da21ff86a07057383';
const MAX_FILE_BYTES = 8 * 1024 * 1024;
const forbiddenArtifactNames = new Set([
  'compose.log',
  'compose.resolved.yml',
  'compose.resolved.yaml',
  'docker-compose.resolved.yml',
  'docker-compose.resolved.yaml'
]);
const ignoredDirectoryNames = new Set(['.git', 'node_modules', 'bin', 'obj']);
const textExtensions = new Set([
  '.conf', '.cs', '.cmd', '.dockerfile', '.env', '.example', '.html', '.js',
  '.json', '.md', '.mjs', '.ps1', '.sh', '.txt', '.xml', '.yaml', '.yml'
]);
const assignmentName = '(?:mnemonic|seed(?:[_ -]?phrase)?|private[_ -]?(?:key|seed|scalar)|'
  + 'bls[_ -]?private(?:[_ -]?(?:key|scalar))?|ed25519[_ -]?private(?:[_ -]?(?:key|seed))?|'
  + 'password|passwd|secret|client[_ -]?secret|api[_ -]?key|auth[_ -]?token|access[_ -]?token|bearer[_ -]?token)';

const rules = [
  {
    id: 'private-key-block',
    regex: /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/gi
  },
  {
    id: 'known-provider-token',
    regex: /\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|AKIA[0-9A-Z]{16})\b/g
  },
  {
    id: 'jwt',
    regex: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g
  },
  {
    id: 'credential-in-url',
    regex: /\b(?:https?|wss?):\/\/[^/\s:@]+:[^/\s@]{8,}@/gi
  },
  {
    id: 'sensitive-interpolation-hex-default',
    regex: /\$\{[^}\r\n]*:-([0-9a-f]{64})\}/gi,
    capture: 1
  },
  {
    id: 'sensitive-assignment',
    regex: new RegExp(`\\b${assignmentName}\\b\\s*(?:=|:)\\s*([^\\r\\n#,]+)`, 'gi'),
    capture: 1
  },
  {
    id: 'private-hex-context',
    regex: new RegExp(`\\b${assignmentName}\\b[^\\r\\n]{0,120}\\b([0-9a-f]{64})\\b`, 'gi'),
    capture: 1
  },
  {
    id: 'mnemonic-shape',
    regex: /\b(?:mnemonic|seed(?:[_ -]?phrase)?)\b[^=\r\n:]{0,40}(?:=|:)\s*["'`]?\s*((?:[a-z]{3,12}\s+){11,23}[a-z]{3,12})\b/gi,
    capture: 1
  }
];

function toPosix(value) {
  return value.split(path.sep).join('/');
}

function relativeSafe(root, filePath) {
  const relative = path.relative(root, filePath);
  if (relative.startsWith('..') || path.isAbsolute(relative)) {
    throw new Error('scan target escapes the selected root');
  }
  return toPosix(relative || '.');
}

function isInside(parent, child) {
  const relative = path.relative(parent, child);
  return relative === '' || (!relative.startsWith('..') && !path.isAbsolute(relative));
}

function logicalPath(root, filePath, externalRoots = []) {
  if (isInside(root, filePath)) return relativeSafe(root, filePath);
  for (const [index, externalRoot] of externalRoots.entries()) {
    if (isInside(externalRoot, filePath)) {
      const relative = path.relative(externalRoot, filePath);
      return `external-artifacts/${index}${relative ? `/${toPosix(relative)}` : ''}`;
    }
  }
  throw new Error('scan target escapes the selected roots');
}

function isPlaceholder(value) {
  const normalized = String(value).trim().replace(/^["'`]|["'`]$/g, '').trim();
  if (normalized.length === 0) return true;
  return normalized.startsWith('${')
    || normalized.startsWith('$env:')
    || normalized.startsWith('/run/secrets/')
    || normalized.startsWith('<')
    || normalized.startsWith('__REQUIRED_')
    || normalized.includes('REDACTED')
    || normalized.includes('NOT_COMMITTED')
    || normalized.includes('SECRET_FILE')
    || normalized.includes('example.invalid');
}

function looksLikeLiteralSecret(value) {
  const normalized = String(value).trim().replace(/^["'`]|["'`]$/g, '').trim();
  if (isPlaceholder(normalized)) return false;
  if (/^(?:true|false|null|undefined|env|stdin)$/i.test(normalized)) return false;
  if (/^[0-9a-f]{64}$/i.test(normalized)) return true;
  if (/^(?:gh[pousr]_|github_pat_|AKIA)[A-Za-z0-9_]{16,}$/.test(normalized)) return true;
  if (/^eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}$/.test(normalized)) return true;
  if (/^(?:[a-z]{3,12}\s+){11,23}[a-z]{3,12}$/i.test(normalized)) return true;
  return normalized.length >= 16 && /^[A-Za-z0-9+/_=-]+$/.test(normalized);
}

function lineNumberAt(content, offset) {
  let line = 1;
  for (let index = 0; index < offset; index += 1) {
    if (content.charCodeAt(index) === 10) line += 1;
  }
  return line;
}

function fingerprint(ruleId, file, line) {
  return createHash('sha256').update(`${ruleId}\0${file}\0${line}`).digest('hex').slice(0, 16);
}

function isProbablyText(filePath, buffer) {
  const extension = path.extname(filePath).toLowerCase();
  if (textExtensions.has(extension) || path.basename(filePath).includes('Dockerfile')) return true;
  const sample = buffer.subarray(0, Math.min(buffer.length, 4096));
  return !sample.includes(0);
}

async function walkFiles(root) {
  const files = [];
  if (!existsSync(root)) return files;
  const pending = [root];
  while (pending.length > 0) {
    const current = pending.pop();
    const entries = await readdir(current, { withFileTypes: true });
    for (const entry of entries) {
      if (entry.isSymbolicLink()) continue;
      const fullPath = path.join(current, entry.name);
      if (entry.isDirectory()) {
        if (!ignoredDirectoryNames.has(entry.name)) pending.push(fullPath);
      } else if (entry.isFile()) {
        files.push(fullPath);
      }
    }
  }
  return files;
}

function trackedFiles(root) {
  const result = spawnSync('git', ['-C', root, 'ls-files', '-z'], {
    encoding: 'buffer',
    windowsHide: true
  });
  if (result.status !== 0) {
    throw new Error('unable to enumerate tracked files');
  }
  return result.stdout.toString('utf8').split('\0').filter(Boolean).map(file => path.join(root, file));
}

export async function scan(options = {}) {
  const root = path.resolve(options.root ?? repositoryRoot);
  const includeTracked = options.includeTracked !== false;
  const artifactRoots = (options.artifactRoots ?? [path.join(root, 'artifacts')]).map(item => path.resolve(item));
  const explicitPaths = (options.paths ?? []).map(item => path.resolve(item));
  const candidates = new Set();
  if (includeTracked) {
    for (const file of trackedFiles(root)) candidates.add(file);
  }
  for (const target of [...artifactRoots, ...explicitPaths]) {
    if (!existsSync(target)) continue;
    const targetStat = await stat(target);
    if (targetStat.isDirectory()) {
      for (const file of await walkFiles(target)) candidates.add(file);
    } else if (targetStat.isFile()) {
      candidates.add(target);
    }
  }

  const findings = [];
  let scannedFiles = 0;
  for (const filePath of [...candidates].sort()) {
    const relativePath = logicalPath(root, filePath, [...artifactRoots, ...explicitPaths]);
    const fileStat = await stat(filePath);
    if (fileStat.size > MAX_FILE_BYTES) {
      findings.push({
        ruleId: 'unscannable-large-file',
        path: relativePath,
        line: null,
        fingerprint: fingerprint('unscannable-large-file', relativePath, 0)
      });
      continue;
    }
    const buffer = await readFile(filePath);
    if (!isProbablyText(filePath, buffer)) continue;
    scannedFiles += 1;
    const content = buffer.toString('utf8');
    const artifactRelative = artifactRoots.some(artifactRoot => {
      const relative = path.relative(artifactRoot, filePath);
      return relative === '' || (!relative.startsWith('..') && !path.isAbsolute(relative));
    });
    if (artifactRelative && forbiddenArtifactNames.has(path.basename(filePath).toLowerCase())) {
      findings.push({
        ruleId: 'forbidden-raw-artifact',
        path: relativePath,
        line: null,
        fingerprint: fingerprint('forbidden-raw-artifact', relativePath, 0)
      });
    }
    for (const rule of rules) {
      rule.regex.lastIndex = 0;
      for (let match = rule.regex.exec(content); match; match = rule.regex.exec(content)) {
        const captured = rule.capture ? match[rule.capture] : match[0];
        if (rule.id === 'sensitive-assignment' && !looksLikeLiteralSecret(captured)) continue;
        if (rule.capture && rule.id !== 'sensitive-assignment' && isPlaceholder(captured)) continue;
        const line = lineNumberAt(content, match.index);
        findings.push({
          ruleId: rule.id,
          path: relativePath,
          line,
          fingerprint: fingerprint(rule.id, relativePath, line)
        });
        if (match[0].length === 0) rule.regex.lastIndex += 1;
      }
    }
  }

  const unique = [...new Map(findings.map(finding => [
    `${finding.ruleId}\0${finding.path}\0${finding.line ?? ''}`,
    finding
  ])).values()];
  return {
    schemaVersion: '1.0.0',
    status: unique.length === 0 ? 'ok' : 'failed',
    programRevisionSha256: PROGRAM_REVISION_SHA,
    scannedFiles,
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
      '--summary': 'summaryPath'
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
  const summaryRoots = [
    ...(options.artifactRoots ?? []).map(item => path.resolve(item)),
    ...(options.paths ?? []).map(item => path.resolve(item)),
    path.dirname(summaryPath)
  ];
  const logicalSummaryPath = logicalPath(root, summaryPath, summaryRoots);
  const summary = {
    ...result,
    generatedAt: process.env.DEEP_EVIDENCE_NOW ?? new Date().toISOString(),
    summaryPath: logicalSummaryPath
  };
  await mkdir(path.dirname(summaryPath), { recursive: true });
  await writeFile(summaryPath, `${JSON.stringify(summary, null, 2)}\n`, 'utf8');
  if (summary.findingCount > 0) {
    console.error(`Secret scan failed closed with ${summary.findingCount} finding(s).`);
    for (const finding of summary.findings) {
      console.error(`- ${finding.ruleId} at ${finding.path}${finding.line ? `:${finding.line}` : ''} [${finding.fingerprint}]`);
    }
    process.exitCode = 1;
    return summary;
  }
  console.log(`Secret scan passed (${summary.scannedFiles} text files).`);
  return summary;
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  main().catch(error => {
    console.error(`Secret scan failed closed: ${error.message}`);
    process.exitCode = 1;
  });
}
