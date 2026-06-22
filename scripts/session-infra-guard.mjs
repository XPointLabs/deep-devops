import { access, mkdir, readFile, readdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const devopsRoot = path.resolve(__dirname, '..');
const workspaceRoot = path.resolve(devopsRoot, '..');
const artifactRoot = process.env.DEEP_RELEASE_ARTIFACT_ROOT
  ? path.resolve(process.env.DEEP_RELEASE_ARTIFACT_ROOT)
  : path.join(devopsRoot, 'artifacts');
const outputDir = path.join(artifactRoot, 'release');
const outputPath = path.join(outputDir, 'session-infra-guard-summary.json');

const scanTargets = [
  {
    id: 'devops-production-config',
    root: path.join(workspaceRoot, 'deep-devops'),
    include: [
      '.github',
      'docker',
      'docker-compose.yml',
      'scripts',
      'tools',
      'observability'
    ]
  },
  {
    id: 'xnode-production-source',
    root: path.join(workspaceRoot, 'xnode'),
    include: [
      'deploy',
      'src',
      'examples'
    ]
  },
  {
    id: 'registry-production-source',
    root: path.join(workspaceRoot, 'deep-registry-api'),
    include: [
      'src',
      'deploy',
      'appsettings.json'
    ]
  },
  {
    id: 'client-shared-production-source',
    root: path.join(workspaceRoot, 'deep-client-shared'),
    include: [
      'src'
    ]
  },
  {
    id: 'client-maui-production-source',
    root: path.join(workspaceRoot, 'deep-client-maui'),
    include: [
      'src'
    ]
  }
];

const forbiddenHostPatterns = [
  { id: 'getsession-host', pattern: /\b(?:[a-z0-9-]+\.)*getsession\.org\b/i },
  { id: 'session-foundation-host', pattern: /\b(?:[a-z0-9-]+\.)*session\.foundation\b/i },
  { id: 'session-network-host', pattern: /\b(?:[a-z0-9-]+\.)*session\.network\b/i },
  { id: 'session-messenger-host', pattern: /\b(?:[a-z0-9-]+\.)*sessionmessenger\.com\b/i },
  { id: 'oxen-host', pattern: /\b(?:[a-z0-9-]+\.)*oxen\.(?:io|network|observer)\b/i },
  { id: 'lokinet-host', pattern: /\b(?:[a-z0-9-]+\.)*lokinet\.(?:org|net|network)\b/i },
  { id: 'loki-host', pattern: /\b(?:[a-z0-9-]+\.)*loki\.(?:network|foundation)\b/i },
  { id: 'loki-foundation-host', pattern: /\b(?:[a-z0-9-]+\.)*loki\.foundation\b/i }
];

const ignoredDirectoryNames = new Set([
  '.git',
  '.vs',
  'artifacts',
  'bin',
  'docs',
  'node_modules',
  'obj',
  'TestResults',
  'tests'
]);

const allowedExtensions = new Set([
  '.cs',
  '.csproj',
  '.env',
  '.json',
  '.js',
  '.mjs',
  '.props',
  '.ps1',
  '.targets',
  '.yaml',
  '.yml'
]);

const checks = [];
const scannedFiles = [];
const findings = [];

function addCheck(name, passed, details = {}) {
  checks.push({ name, passed: Boolean(passed), ...details });
}

async function fileExists(filePath) {
  try {
    await access(filePath);
    return true;
  } catch {
    return false;
  }
}

function relativeToWorkspace(filePath) {
  return path.relative(workspaceRoot, filePath).replaceAll('\\', '/');
}

function shouldScanFile(filePath) {
  const parsed = path.parse(filePath);
  return allowedExtensions.has(parsed.ext)
    || parsed.base.endsWith('Dockerfile')
    || parsed.base === 'Dockerfile'
    || parsed.base === 'docker-compose.yml';
}

async function walk(filePath) {
  const entries = await readdir(filePath, { withFileTypes: true });
  const files = [];

  for (const entry of entries) {
    const entryPath = path.join(filePath, entry.name);
    if (entry.isDirectory()) {
      if (ignoredDirectoryNames.has(entry.name)) {
        continue;
      }
      files.push(...await walk(entryPath));
      continue;
    }

    if (entry.isFile() && shouldScanFile(entryPath)) {
      files.push(entryPath);
    }
  }

  return files;
}

async function expandTarget(target) {
  const files = [];
  for (const include of target.include) {
    const includePath = path.join(target.root, include);
    if (!await fileExists(includePath)) {
      continue;
    }

    const entries = await readdir(path.dirname(includePath), { withFileTypes: true });
    const matchingEntry = entries.find(entry => entry.name === path.basename(includePath));
    if (!matchingEntry) {
      continue;
    }

    if (matchingEntry.isDirectory()) {
      files.push(...await walk(includePath));
    } else if (matchingEntry.isFile() && shouldScanFile(includePath)) {
      files.push(includePath);
    }
  }

  return files;
}

function scanContent(filePath, content) {
  const lines = content.split(/\r?\n/);
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    for (const forbidden of forbiddenHostPatterns) {
      const match = forbidden.pattern.exec(line);
      if (!match) {
        continue;
      }

      findings.push({
        id: forbidden.id,
        file: relativeToWorkspace(filePath),
        line: index + 1,
        match: match[0],
        excerpt: line.trim().slice(0, 240)
      });
    }
  }
}

for (const target of scanTargets) {
  const exists = await fileExists(target.root);
  addCheck(`${target.id}:root-exists`, exists, { path: target.root });
  if (!exists) {
    continue;
  }

  const files = await expandTarget(target);
  addCheck(`${target.id}:files-scanned`, files.length > 0, { observed: files.length });
  for (const filePath of files) {
    scannedFiles.push(relativeToWorkspace(filePath));
    const content = await readFile(filePath, 'utf8');
    scanContent(filePath, content);
  }
}

addCheck('session-infra:forbidden-hosts-absent', findings.length === 0, {
  observed: findings.length
});

const failed = checks.filter(check => !check.passed);
const summary = {
  status: failed.length === 0 ? 'ok' : 'failed',
  generatedAt: new Date().toISOString(),
  workspaceRoot,
  artifactRoot,
  scannedFileCount: scannedFiles.length,
  scannedFiles,
  forbiddenHostPatterns: forbiddenHostPatterns.map(pattern => pattern.id),
  findings,
  checks,
  failedChecks: failed.map(check => check.name)
};

await mkdir(outputDir, { recursive: true });
await writeFile(outputPath, `${JSON.stringify(summary, null, 2)}\n`, 'utf8');

if (failed.length > 0) {
  console.error(`Session infrastructure guard failed (${failed.length} checks). Summary: ${outputPath}`);
  for (const check of failed) {
    console.error(`- ${check.name}`);
  }
  process.exit(1);
}

console.log(`Session infrastructure guard passed (${checks.length} checks, ${scannedFiles.length} files). Summary: ${outputPath}`);
