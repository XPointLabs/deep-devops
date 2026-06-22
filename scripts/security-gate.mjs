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

    for (const filePath of walkFiles(root)) {
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

function parsePackageJsonDependencies(filePath) {
  const packageJson = JSON.parse(readFileSync(filePath, 'utf8'));
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

function buildSbom() {
  const components = [];
  for (const repo of repos) {
    const root = repoPath(repo);
    if (!existsSync(root)) {
      continue;
    }

    for (const filePath of walkFiles(root)) {
      if (filePath.endsWith('.csproj')) {
        components.push(...parseCsprojPackageReferences(filePath).map(component => ({ ...component, repo })));
      } else if (filePath.endsWith('package.json')) {
        components.push(...parsePackageJsonDependencies(filePath).map(component => ({ ...component, repo })));
      }
    }
  }

  return {
    bomFormat: 'Deep-SBOM',
    specVersion: '0.1',
    generatedAt: new Date().toISOString(),
    workspaceRoot,
    repositories: repos,
    componentCount: components.length,
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

  const packageJson = JSON.parse(readFileSync(packageJsonPath, 'utf8'));
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
    workspaceRoot,
    artifactDir,
    repos,
    secretFindings: secretScan.findings.length,
    dependencyAuditCount: dependencyAudit.length,
    dependencyFailures: dependencyFailures.length,
    sbomComponents: sbom.componentCount
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
