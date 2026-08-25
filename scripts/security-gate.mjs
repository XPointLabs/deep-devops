import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';

const defaultRepos = [
  'deep-protocol',
  'xnode',
  'deep-registry-api',
  'xpoint-staking-backend',
  'xpoint-staking-contracts',
  'deep-client-shared',
  'deep-client-maui',
  'deep-tests-e2e',
  'deep-devops'
];

function defaultDevopsDir() {
  const cwd = resolve(process.cwd());
  if (existsSync(join(cwd, 'scripts', 'security-gate.mjs'))) {
    return cwd;
  }

  const childDevopsDir = join(cwd, 'deep-devops');
  if (existsSync(join(childDevopsDir, 'scripts', 'security-gate.mjs'))) {
    return childDevopsDir;
  }

  return cwd;
}

const devopsDir = resolve(process.env.DEEP_DEVOPS_DIR ?? defaultDevopsDir());
const workspaceRoot = resolve(process.env.DEEP_ROOT ?? join(devopsDir, '..'));
const artifactDir = resolve(
  process.env.DEEP_SECURITY_ARTIFACT_DIR
    ?? process.env.DEEP_ARTIFACT_DIR
    ?? join(devopsDir, 'artifacts', 'security')
);
const repos = String(process.env.DEEP_SECURITY_REPOS ?? defaultRepos.join(','))
  .split(',')
  .map(value => value.trim())
  .filter(Boolean);
const skipDependencyAudit = /^(1|true|yes)$/i.test(process.env.DEEP_SECURITY_SKIP_DEP_AUDIT ?? '');

const excludedDirectories = new Set([
  '.git',
  '.secrets',
  '.vs',
  '.vscode',
  '.idea',
  'artifacts',
  'bin',
  'obj',
  'node_modules',
  '.tools',
  '.pnpm-store',
  '.yarn',
  'TestResults',
  'coverage',
  'dist',
  'build',
  'out',
  'cache',
  '.tmp',
  '.openzeppelin',
  'deployments'
]);

const excludedFileExtensions = new Set([
  '.png',
  '.jpg',
  '.jpeg',
  '.gif',
  '.webp',
  '.ico',
  '.zip',
  '.gz',
  '.tar',
  '.dll',
  '.exe',
  '.pdb',
  '.so',
  '.dylib',
  '.woff',
  '.woff2',
  '.ttf'
]);

const secretPatterns = [
  { id: 'private-key-block', severity: 'critical', pattern: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/ },
  { id: 'aws-access-key', severity: 'high', pattern: /AKIA[0-9A-Z]{16}/ },
  { id: 'github-token', severity: 'high', pattern: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}\b/ },
  { id: 'slack-token', severity: 'high', pattern: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/ },
  { id: 'stripe-live-secret', severity: 'high', pattern: /\bsk_live_[A-Za-z0-9]{20,}\b/ },
  { id: 'google-api-key', severity: 'high', pattern: /\bAIza[0-9A-Za-z\-_]{35}\b/ },
  { id: 'jwt-token', severity: 'high', pattern: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/ }
];

const allowedSecretPathPatterns = [
  /^deep-client-maui\/src\/Deep\.Client\.Maui\/Platforms\/Android\/google-services\.json$/i,
  /^xpoint-staking-contracts\/test\/cpp\/external\/ethyl\/external\/cpr\/test\/data\/keys\/[^/]+\.key$/i
];

function ensureArtifactDir() {
  mkdirSync(artifactDir, { recursive: true });
}

function repoPath(repo) {
  return resolve(workspaceRoot, repo);
}

function writeJson(name, value) {
  ensureArtifactDir();
  writeFileSync(join(artifactDir, name), `${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

function walkFiles(root) {
  const files = [];
  const stack = [root];

  while (stack.length > 0) {
    const current = stack.pop();
    let entries = [];
    try {
      entries = readdirSync(current, { withFileTypes: true });
    } catch {
      continue;
    }

    for (const entry of entries) {
      const fullPath = join(current, entry.name);
      if (entry.isDirectory()) {
        if (!excludedDirectories.has(entry.name)) {
          stack.push(fullPath);
        }
        continue;
      }

      if (entry.isFile()) {
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
  if (result.status !== 0 || !Buffer.isBuffer(result.stdout)) {
    return [];
  }

  return result.stdout
    .toString('utf8')
    .split('\0')
    .filter(Boolean)
    .map(file => resolve(root, file))
    .filter(file => existsSync(file) && statSync(file).isFile());
}

function secretScanFiles(root) {
  return [...new Set([...walkFiles(root), ...trackedFiles(root)])];
}

function isProbablyTextFile(filePath) {
  const lower = filePath.toLowerCase();
  if ([...excludedFileExtensions].some(extension => lower.endsWith(extension))) {
    return false;
  }

  const size = statSync(filePath).size;
  if (size > 2_000_000) {
    return false;
  }

  const sample = readFileSync(filePath);
  return !sample.includes(0);
}

function isAllowedExample(line) {
  return /(<secret>|placeholder|example|dummy|fake|mock|sample|redacted|invalid)/i.test(line);
}

function isAllowedSecretFinding(filePath, line) {
  const relativePath = relative(workspaceRoot, filePath).replace(/\\/g, '/');
  return isAllowedExample(line) || allowedSecretPathPatterns.some(pattern => pattern.test(relativePath));
}

function runSecretScan() {
  const findings = [];
  for (const repo of repos) {
    const root = repoPath(repo);
    if (!existsSync(root)) {
      continue;
    }

    for (const filePath of secretScanFiles(root)) {
      if (!isProbablyTextFile(filePath)) {
        continue;
      }

      const text = readFileSync(filePath, 'utf8');
      const lines = text.split(/\r?\n/);
      for (const [lineIndex, line] of lines.entries()) {
        if (isAllowedSecretFinding(filePath, line)) {
          continue;
        }

        for (const secretPattern of secretPatterns) {
          if (secretPattern.pattern.test(line)) {
            findings.push({
              repo,
              file: relative(workspaceRoot, filePath).replace(/\\/g, '/'),
              line: lineIndex + 1,
              rule: secretPattern.id,
              severity: secretPattern.severity
            });
          }
        }
      }
    }
  }

  return {
    status: findings.length === 0 ? 'ok' : 'failed',
    generatedAt: new Date().toISOString(),
    findings
  };
}

function parseCsprojPackageReferences(filePath) {
  const text = readFileSync(filePath, 'utf8');
  const references = [];
  const regex = /<PackageReference\b([^>]*?)(?:\/>|>([\s\S]*?)<\/PackageReference>)/gi;
  let match;
  while ((match = regex.exec(text)) !== null) {
    const attributes = match[1] ?? '';
    const body = match[2] ?? '';
    const include = /Include="([^"]+)"/i.exec(attributes)?.[1] ?? /Update="([^"]+)"/i.exec(attributes)?.[1];
    const version = /Version="([^"]+)"/i.exec(attributes)?.[1] ?? /<Version>([^<]+)<\/Version>/i.exec(body)?.[1];
    if (include) {
      references.push({
        type: 'nuget',
        name: include,
        version: version ?? null,
        path: relative(workspaceRoot, filePath).replace(/\\/g, '/')
      });
    }
  }

  return references;
}

function parseJsonFile(filePath) {
  return JSON.parse(readFileSync(filePath, 'utf8').replace(/^\uFEFF/, ''));
}

function parsePackageJsonDependencies(filePath) {
  const packageJson = parseJsonFile(filePath);
  const references = [];
  for (const section of ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']) {
    const dependencies = packageJson[section] ?? {};
    for (const [name, version] of Object.entries(dependencies)) {
      references.push({
        type: 'npm',
        scope: section,
        name,
        version: String(version),
        path: relative(workspaceRoot, filePath).replace(/\\/g, '/')
      });
    }
  }

  return references;
}

function metadataPath(filePath) {
  return relative(workspaceRoot, filePath).replace(/\\/g, '/');
}

function metadataFailure(filePath, message) {
  return new Error(`Malformed dependency metadata ${metadataPath(filePath)}: ${message}`);
}

function isRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function parseMetadataJson(filePath) {
  try {
    return parseJsonFile(filePath);
  } catch {
    throw metadataFailure(filePath, 'invalid JSON');
  }
}

function exactDependency(type, name, version, filePath) {
  const normalizedName = String(name ?? '').trim();
  const normalizedVersion = String(version ?? '').trim();
  const validName = type === 'npm'
    ? /^(?:@[A-Za-z0-9][A-Za-z0-9._~-]*\/)?[A-Za-z0-9][A-Za-z0-9._~-]*$/.test(normalizedName)
    : /^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(normalizedName);
  if (!validName) {
    throw metadataFailure(filePath, `invalid ${type} package name`);
  }
  if (!/^[0-9A-Za-z][0-9A-Za-z.+_-]*$/.test(normalizedVersion)) {
    throw metadataFailure(filePath, `invalid resolved version for ${normalizedName}`);
  }
  return { type, name: normalizedName, version: normalizedVersion };
}

function npmNameFromPackagePath(packagePath, filePath) {
  const parts = packagePath.replace(/\\/g, '/').split('/');
  const nodeModulesIndex = parts.lastIndexOf('node_modules');
  if (nodeModulesIndex < 0 || nodeModulesIndex === parts.length - 1) {
    throw metadataFailure(filePath, 'invalid package-lock packages entry path');
  }
  const first = parts[nodeModulesIndex + 1];
  return first.startsWith('@')
    ? `${first}/${parts[nodeModulesIndex + 2] ?? ''}`
    : first;
}

function parsePackageLock(filePath) {
  const document = parseMetadataJson(filePath);
  if (!isRecord(document) || !Number.isInteger(document.lockfileVersion)) {
    throw metadataFailure(filePath, 'lockfileVersion must be an integer');
  }

  const components = [];
  if ([2, 3].includes(document.lockfileVersion)) {
    if (!isRecord(document.packages)) {
      throw metadataFailure(filePath, 'packages must be an object');
    }
    for (const [packagePath, packageMetadata] of Object.entries(document.packages)) {
      if (packagePath === '' || !packagePath.replace(/\\/g, '/').includes('node_modules/')) {
        continue;
      }
      if (!isRecord(packageMetadata)) {
        throw metadataFailure(filePath, 'package entry must be an object');
      }
      if (packageMetadata.link === true) {
        continue;
      }
      components.push(exactDependency(
        'npm',
        packageMetadata.name ?? npmNameFromPackagePath(packagePath, filePath),
        packageMetadata.version,
        filePath));
    }
    return components;
  }

  if (document.lockfileVersion !== 1 || !isRecord(document.dependencies)) {
    throw metadataFailure(filePath, 'version 1 lock must contain dependencies');
  }
  const visitDependencies = dependencies => {
    if (!isRecord(dependencies)) {
      throw metadataFailure(filePath, 'dependencies must be an object');
    }
    for (const [name, packageMetadata] of Object.entries(dependencies)) {
      if (!isRecord(packageMetadata)) {
        throw metadataFailure(filePath, 'dependency entry must be an object');
      }
      components.push(exactDependency('npm', name, packageMetadata.version, filePath));
      if (packageMetadata.dependencies !== undefined) {
        visitDependencies(packageMetadata.dependencies);
      }
    }
  };
  visitDependencies(document.dependencies);
  return components;
}

function parseYamlKey(value, filePath) {
  const trimmed = value.trim();
  if (trimmed.startsWith("'") && trimmed.endsWith("'")) {
    return trimmed.slice(1, -1).replace(/''/g, "'");
  }
  if (trimmed.startsWith('"') && trimmed.endsWith('"')) {
    try {
      return JSON.parse(trimmed);
    } catch {
      throw metadataFailure(filePath, 'invalid quoted pnpm package key');
    }
  }
  return trimmed;
}

function parsePnpmLocator(rawLocator, filePath) {
  let locator = rawLocator.replace(/^\//, '');
  const peerSuffix = locator.indexOf('(');
  if (peerSuffix >= 0) {
    locator = locator.slice(0, peerSuffix);
  }
  if (/^(?:file|link|workspace):/i.test(locator)) {
    return null;
  }

  let separator = locator.lastIndexOf('@');
  if (separator <= 0) {
    separator = locator.lastIndexOf('/');
  }
  if (separator <= 0 || separator === locator.length - 1) {
    throw metadataFailure(filePath, 'invalid pnpm package locator');
  }
  return exactDependency('npm', locator.slice(0, separator), locator.slice(separator + 1), filePath);
}

function parsePnpmLock(filePath) {
  const text = readFileSync(filePath, 'utf8').replace(/^\uFEFF/, '').replace(/\r\n/g, '\n');
  const versionMatch = /^lockfileVersion:\s*['"]?([^'"\s]+)['"]?\s*$/m.exec(text);
  if (!versionMatch) {
    throw metadataFailure(filePath, 'lockfileVersion is missing');
  }
  if (!/^\d+(?:\.\d+)?$/.test(versionMatch[1])) {
    throw metadataFailure(filePath, 'lockfileVersion is invalid');
  }

  const lines = text.split('\n');
  const packagesStart = lines.findIndex(line => line.startsWith('packages:'));
  if (packagesStart < 0) {
    return [];
  }
  if (lines[packagesStart] !== 'packages:') {
    throw metadataFailure(filePath, 'packages must be a block mapping');
  }

  const components = [];
  for (let index = packagesStart + 1; index < lines.length; index += 1) {
    const line = lines[index];
    if (line.length > 0 && !/^\s/.test(line)) {
      break;
    }
    if (!/^  \S/.test(line)) {
      continue;
    }
    if (!line.trim().endsWith(':')) {
      throw metadataFailure(filePath, 'invalid pnpm packages entry');
    }
    const key = parseYamlKey(line.trim().slice(0, -1), filePath);
    const component = parsePnpmLocator(key, filePath);
    if (component !== null) {
      components.push(component);
    }
  }
  return components;
}

function parseNugetPackagesLock(filePath) {
  const document = parseMetadataJson(filePath);
  if (!isRecord(document) || !Number.isInteger(document.version) || document.version < 1
    || !isRecord(document.dependencies)) {
    throw metadataFailure(filePath, 'version and dependencies are required');
  }

  const components = [];
  for (const targetDependencies of Object.values(document.dependencies)) {
    if (!isRecord(targetDependencies)) {
      throw metadataFailure(filePath, 'target dependencies must be an object');
    }
    for (const [name, packageMetadata] of Object.entries(targetDependencies)) {
      if (!isRecord(packageMetadata) || typeof packageMetadata.type !== 'string') {
        throw metadataFailure(filePath, 'package entry must declare its type');
      }
      if (packageMetadata.type.toLowerCase() === 'project') {
        continue;
      }
      if (!['direct', 'transitive', 'centraltransitive'].includes(packageMetadata.type.toLowerCase())) {
        throw metadataFailure(filePath, 'package type is not supported');
      }
      components.push(exactDependency('nuget', name, packageMetadata.resolved, filePath));
    }
  }
  return components;
}

function parseNugetProjectAssets(filePath) {
  const document = parseMetadataJson(filePath);
  if (!isRecord(document) || !Number.isInteger(document.version) || document.version < 1
    || !isRecord(document.libraries)) {
    throw metadataFailure(filePath, 'version and libraries are required');
  }

  const components = [];
  for (const [locator, library] of Object.entries(document.libraries)) {
    if (!isRecord(library) || typeof library.type !== 'string') {
      throw metadataFailure(filePath, 'library entry must declare its type');
    }
    if (library.type.toLowerCase() === 'project') {
      continue;
    }
    if (library.type.toLowerCase() !== 'package') {
      throw metadataFailure(filePath, 'library type must be package or project');
    }
    const separator = locator.lastIndexOf('/');
    if (separator <= 0 || separator === locator.length - 1) {
      throw metadataFailure(filePath, 'invalid NuGet library locator');
    }
    components.push(exactDependency(
      'nuget', locator.slice(0, separator), locator.slice(separator + 1), filePath));
  }
  return components;
}

function findNodeLock(manifestPath, repoRoot) {
  let current = resolve(manifestPath, '..');
  const absoluteRepoRoot = resolve(repoRoot);
  while (true) {
    const relativeDirectory = relative(absoluteRepoRoot, current);
    if (relativeDirectory === '..' || relativeDirectory.startsWith(`..${process.platform === 'win32' ? '\\' : '/'}`)) {
      break;
    }
    const packageLock = join(current, 'package-lock.json');
    const pnpmLock = join(current, 'pnpm-lock.yaml');
    const locks = [packageLock, pnpmLock].filter(existsSync);
    if (locks.length > 1) {
      throw metadataFailure(manifestPath, 'multiple applicable Node lockfiles');
    }
    if (locks.length === 1) {
      return locks[0];
    }
    if (current === absoluteRepoRoot) {
      break;
    }
    current = resolve(current, '..');
  }
  return null;
}

function purlEncode(value) {
  return encodeURIComponent(value)
    .replace(/[!'()*]/g, character => `%${character.charCodeAt(0).toString(16).toUpperCase()}`);
}

function npmPurl(name, version) {
  if (name.startsWith('@') && name.includes('/')) {
    const separator = name.indexOf('/');
    const namespace = name.slice(0, separator);
    const packageName = name.slice(separator + 1);
    return `pkg:npm/${purlEncode(namespace)}/${purlEncode(packageName)}@${purlEncode(version)}`;
  }

  return `pkg:npm/${purlEncode(name)}@${purlEncode(version)}`;
}

function nugetPurl(name, version) {
  return `pkg:nuget/${purlEncode(name)}@${purlEncode(version)}`;
}

function canonicalComponent(component) {
  const version = String(component.version ?? 'unspecified').trim() || 'unspecified';
  const name = String(component.name).trim();
  const purl = component.type === 'npm'
    ? npmPurl(name, version)
    : nugetPurl(name, version);
  return {
    type: 'library',
    'bom-ref': purl,
    name,
    version,
    purl
  };
}

function compareComponents(left, right) {
  if (left.purl === right.purl) return 0;
  return left.purl < right.purl ? -1 : 1;
}

function sourceDateEpochTimestamp() {
  const raw = process.env.SOURCE_DATE_EPOCH;
  if (raw === undefined || raw === '') {
    return null;
  }

  if (!/^(?:0|[1-9][0-9]*)$/.test(raw)) {
    throw new Error('SOURCE_DATE_EPOCH must be a non-negative integer Unix timestamp');
  }

  const milliseconds = Number(raw) * 1000;
  const date = new Date(milliseconds);
  if (!Number.isSafeInteger(milliseconds) || Number.isNaN(date.getTime())) {
    throw new Error('SOURCE_DATE_EPOCH is outside the supported timestamp range');
  }

  return date.toISOString();
}

function buildSbom() {
  const discoveredComponents = [];
  const parsedMetadata = new Set();
  for (const repo of repos) {
    const root = repoPath(repo);
    if (!existsSync(root)) {
      continue;
    }

    for (const filePath of walkFiles(root)) {
      if (filePath.endsWith('.csproj')) {
        const projectDirectory = resolve(filePath, '..');
        const packagesLock = join(projectDirectory, 'packages.lock.json');
        const projectAssets = join(projectDirectory, 'obj', 'project.assets.json');
        if (existsSync(packagesLock)) {
          discoveredComponents.push(...parseNugetPackagesLock(packagesLock));
        } else if (existsSync(projectAssets)) {
          discoveredComponents.push(...parseNugetProjectAssets(projectAssets));
        } else {
          discoveredComponents.push(...parseCsprojPackageReferences(filePath));
        }
      } else if (filePath.endsWith('package.json')) {
        const lockPath = findNodeLock(filePath, root);
        if (lockPath === null) {
          discoveredComponents.push(...parsePackageJsonDependencies(filePath));
        } else if (!parsedMetadata.has(lockPath)) {
          parsedMetadata.add(lockPath);
          discoveredComponents.push(...(
            lockPath.endsWith('package-lock.json')
              ? parsePackageLock(lockPath)
              : parsePnpmLock(lockPath)));
        }
      }
    }
  }

  const byPurl = new Map();
  for (const discovered of discoveredComponents) {
    const component = canonicalComponent(discovered);
    byPurl.set(component.purl, component);
  }
  const components = [...byPurl.values()].sort(compareComponents);
  const releaseVersion = String(
    process.env.DEEP_RELEASE_VERSION
      ?? process.env.DEEP_SOURCE_COMMIT
      ?? 'workspace'
  ).trim() || 'workspace';
  const applicationPurl = `pkg:generic/network.xpoint.deep@${purlEncode(releaseVersion)}`;
  const metadata = {
    component: {
      type: 'application',
      'bom-ref': applicationPurl,
      name: 'network.xpoint.deep',
      version: releaseVersion,
      purl: applicationPurl
    }
  };
  const timestamp = sourceDateEpochTimestamp();
  if (timestamp !== null) {
    metadata.timestamp = timestamp;
  }

  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    version: 1,
    metadata,
    components
  };
}

function runCommand(command, args, cwd) {
  const isWindowsCommandShim = process.platform === 'win32' && ['corepack', 'npm', 'pnpm'].includes(command);
  const executable = isWindowsCommandShim ? 'cmd.exe' : command;
  const commandArgs = isWindowsCommandShim
    ? ['/d', '/s', '/c', [command, ...args].map(quoteWindowsCommandArg).join(' ')]
    : args;
  const result = spawnSync(executable, commandArgs, {
    cwd,
    encoding: 'utf8',
    maxBuffer: 20 * 1024 * 1024
  });

  return {
    command: [command, ...args].join(' '),
    cwd: relative(workspaceRoot, cwd).replace(/\\/g, '/') || '.',
    exitCode: result.status ?? 1,
    stdout: result.stdout ?? '',
    stderr: result.stderr ?? '',
    error: result.error ? String(result.error.message ?? result.error) : null
  };
}

function quoteWindowsCommandArg(value) {
  if (/^[A-Za-z0-9._:=/\\-]+$/.test(value)) {
    return value;
  }

  return `"${value.replace(/"/g, '\\"')}"`;
}

function countHighCriticalVulnerabilities(stdout) {
  try {
    const parsed = JSON.parse(stdout);
    const metadata = parsed.metadata?.vulnerabilities;
    if (metadata && typeof metadata === 'object') {
      return Number(metadata.high ?? 0) + Number(metadata.critical ?? 0);
    }

    if (parsed.advisories && typeof parsed.advisories === 'object') {
      return Object.values(parsed.advisories)
        .filter(advisory => ['high', 'critical'].includes(String(advisory.severity ?? '').toLowerCase()))
        .length;
    }

    if (parsed.vulnerabilities && typeof parsed.vulnerabilities === 'object') {
      return Object.values(parsed.vulnerabilities)
        .filter(vulnerability => ['high', 'critical'].includes(String(vulnerability.severity ?? '').toLowerCase()))
        .length;
    }
  } catch {
    return null;
  }

  return null;
}

function packageAuditStatus(result) {
  if (result.exitCode === 0) {
    return { status: 'ok', blockingVulnerabilities: 0 };
  }

  const blockingVulnerabilities = countHighCriticalVulnerabilities(result.stdout);
  if (blockingVulnerabilities !== null) {
    return {
      status: blockingVulnerabilities === 0 ? 'ok' : 'failed',
      blockingVulnerabilities
    };
  }

  return { status: 'failed', blockingVulnerabilities: null };
}

function discoverDotnetProjects(root) {
  return walkFiles(root)
    .filter(filePath => filePath.endsWith('.csproj'))
    .filter(filePath => !filePath.includes(`${join('test', 'cpp')}${pathSeparator()}`));
}

function pathSeparator() {
  return process.platform === 'win32' ? '\\' : '/';
}

function hasDotnetVulnerability(output) {
  return /has the following vulnerable packages/i.test(output) || /\b(Critical|High)\b/i.test(output);
}

function hasMissingDotnetWorkload(output) {
  return /NETSDK1147: To build this project, the following workloads must be installed/i.test(output);
}

function dotnetAuditStatus(result) {
  const output = `${result.stdout}\n${result.stderr}`;
  if (result.exitCode === 0 && !hasDotnetVulnerability(output)) {
    return { status: 'ok' };
  }

  if (hasMissingDotnetWorkload(output)) {
    return {
      status: 'skipped',
      reason: 'platform-specific .NET workload is not available on this runner; platform CI covers this project'
    };
  }

  return { status: 'failed' };
}

function runDotnetAudits() {
  const audits = [];
  for (const repo of repos) {
    const root = repoPath(repo);
    if (!existsSync(root)) {
      continue;
    }

    for (const project of discoverDotnetProjects(root)) {
      const result = runCommand('dotnet', ['list', project, 'package', '--vulnerable', '--include-transitive'], root);
      const auditStatus = dotnetAuditStatus(result);
      audits.push({
        ecosystem: 'nuget',
        repo,
        manifest: relative(workspaceRoot, project).replace(/\\/g, '/'),
        status: auditStatus.status,
        reason: auditStatus.reason,
        command: result.command,
        exitCode: result.exitCode,
        stdout: result.stdout,
        stderr: result.stderr,
        error: result.error
      });
    }
  }

  return audits;
}

function npmAuditForRepo(repo, root) {
  const packageJsonPath = join(root, 'package.json');
  if (!existsSync(packageJsonPath)) {
    return [];
  }

  const packageJson = parseJsonFile(packageJsonPath);
  const hasDependencies = ['dependencies', 'devDependencies', 'optionalDependencies']
    .some(section => Object.keys(packageJson[section] ?? {}).length > 0);
  if (!hasDependencies) {
    return [{
      ecosystem: 'npm',
      repo,
      manifest: relative(workspaceRoot, packageJsonPath).replace(/\\/g, '/'),
      status: 'skipped',
      reason: 'package.json has no dependencies'
    }];
  }

  if (existsSync(join(root, 'pnpm-lock.yaml'))) {
    let result = runCommand('pnpm', ['audit', '--audit-level', 'high', '--json'], root);
    if (result.exitCode !== 0 && /not recognized|command not found|not found/i.test(`${result.stderr}\n${result.error ?? ''}`)) {
      result = runCommand('corepack', ['pnpm', 'audit', '--audit-level', 'high', '--json'], root);
    }
    const auditStatus = packageAuditStatus(result);

    return [{
      ecosystem: 'npm',
      repo,
      manifest: relative(workspaceRoot, packageJsonPath).replace(/\\/g, '/'),
      lockfile: relative(workspaceRoot, join(root, 'pnpm-lock.yaml')).replace(/\\/g, '/'),
      status: auditStatus.status,
      blockingVulnerabilities: auditStatus.blockingVulnerabilities,
      command: result.command,
      exitCode: result.exitCode,
      stdout: result.stdout,
      stderr: result.stderr,
      error: result.error
    }];
  }

  if (existsSync(join(root, 'package-lock.json'))) {
    const result = runCommand('npm', ['audit', '--audit-level=high', '--json'], root);
    const auditStatus = packageAuditStatus(result);
    return [{
      ecosystem: 'npm',
      repo,
      manifest: relative(workspaceRoot, packageJsonPath).replace(/\\/g, '/'),
      lockfile: relative(workspaceRoot, join(root, 'package-lock.json')).replace(/\\/g, '/'),
      status: auditStatus.status,
      blockingVulnerabilities: auditStatus.blockingVulnerabilities,
      command: result.command,
      exitCode: result.exitCode,
      stdout: result.stdout,
      stderr: result.stderr,
      error: result.error
    }];
  }

  return [{
    ecosystem: 'npm',
    repo,
    manifest: relative(workspaceRoot, packageJsonPath).replace(/\\/g, '/'),
    status: 'failed',
    reason: 'package.json has dependencies but no supported lockfile'
  }];
}

function runDependencyAudits() {
  if (skipDependencyAudit) {
    return [{
      ecosystem: 'all',
      status: 'skipped',
      reason: 'DEEP_SECURITY_SKIP_DEP_AUDIT requested'
    }];
  }

  const audits = [...runDotnetAudits()];
  for (const repo of repos) {
    const root = repoPath(repo);
    if (existsSync(root)) {
      audits.push(...npmAuditForRepo(repo, root));
    }
  }

  return audits;
}

function summarize(secretScan, dependencyAudit, sbom) {
  const dependencyFailures = dependencyAudit.filter(audit => audit.status === 'failed');
  const summary = {
    status: secretScan.findings.length === 0 && dependencyFailures.length === 0 ? 'ok' : 'failed',
    generatedAt: new Date().toISOString(),
    repos,
    secretFindings: secretScan.findings.length,
    dependencyAuditCount: dependencyAudit.length,
    dependencyFailures: dependencyFailures.length,
    sbomComponents: sbom.components.length
  };

  return summary;
}

function main() {
  ensureArtifactDir();
  const secretScan = runSecretScan();
  const sbom = buildSbom();
  const dependencyAudit = runDependencyAudits();
  const summary = summarize(secretScan, dependencyAudit, sbom);

  writeJson('secret-scan.json', secretScan);
  writeJson('sbom.json', sbom);
  writeJson('dependency-audit.json', {
    status: dependencyAudit.some(audit => audit.status === 'failed') ? 'failed' : 'ok',
    generatedAt: new Date().toISOString(),
    audits: dependencyAudit
  });
  writeJson('security-gate-summary.json', summary);

  console.log(JSON.stringify(summary, null, 2));
  if (summary.status !== 'ok') {
    process.exitCode = 1;
  }
}

main();
