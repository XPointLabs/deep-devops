import { execFileSync } from 'node:child_process';
import {
  copyFileSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync
} from 'node:fs';
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { pathToFileURL } from 'node:url';

const dotnetRootFiles = new Set([
  'Directory.Build.props',
  'Directory.Build.targets',
  'Directory.Packages.props',
  'NuGet.Config',
  'global.json'
]);
const contractsRootFiles = new Set([
  'package.json',
  'pnpm-lock.yaml',
  'pnpm-workspace.yaml',
  'hardhat.config.js',
  'hardhat.config.cjs',
  'hardhat.config.mjs',
  'hardhat.config.ts',
  'tsconfig.json'
]);
const contractsRoots = ['contracts/', 'deploy/', 'ignition/', 'lib/', 'scripts/', 'src/', 'tasks/'];

function fail(message) {
  throw new Error(`Survival development context export failed closed: ${message}`);
}

function isChild(root, target) {
  const relation = relative(root, target);
  return Boolean(relation) && relation !== '..' && !relation.startsWith(`..${sep}`) && !isAbsolute(relation);
}

function normalizeEntry(entry) {
  if (!entry || entry.includes('\\') || entry.startsWith('/') || entry.split('/').some(part => !part || part === '.' || part === '..')) {
    fail('source inventory contains unsafe paths');
  }
  return entry;
}

function isSelected(kind, entry) {
  if (kind === 'dotnet') return entry.startsWith('src/') || dotnetRootFiles.has(entry) || /\.(?:sln|slnx)$/.test(entry);
  if (kind === 'contracts') return contractsRootFiles.has(entry) || contractsRoots.some(root => entry.startsWith(root));
  fail('unknown context kind');
}

function isProhibited(entry) {
  const parts = entry.toLowerCase().split('/');
  const name = parts.at(-1);
  return parts.some(part => part === '.git' || part === '.secrets' || part === 'secrets')
    || /^\.env(?:\.|$)/.test(name)
    || /(?:^|[._-])(?:credential|credentials|mnemonic|private[._-]?key)(?:[._-]|$)/.test(name)
    || /^(?:id_rsa|id_ed25519)$/.test(name)
    || /\.(?:jks|key|keystore|p12|pfx|pem)$/.test(name);
}

function decodeXmlAttribute(value) {
  return value
    .replaceAll('&quot;', '"')
    .replaceAll('&apos;', "'")
    .replaceAll('&lt;', '<')
    .replaceAll('&gt;', '>')
    .replaceAll('&amp;', '&');
}

function sourceEntry(source, target) {
  const relation = relative(source, target);
  if (!relation || relation === '..' || relation.startsWith(`..${sep}`) || isAbsolute(relation)) {
    fail('referenced restore input escapes the source');
  }
  return normalizeEntry(relation.split(sep).join('/'));
}

function resolveMsBuildPath(source, declaringEntry, value) {
  const declaringDirectory = dirname(join(source, ...declaringEntry.split('/')));
  let expanded = decodeXmlAttribute(value).trim();
  expanded = expanded.replace(/^\$\(MSBuildThisFileDirectory\)/i, `${declaringDirectory}${sep}`);
  if (/\$\([^)]+\)/.test(expanded) || /%[^%]+%/.test(expanded)) {
    fail('referenced restore input uses an unsupported dynamic path');
  }
  return resolve(declaringDirectory, expanded.replaceAll('\\', sep).replaceAll('/', sep));
}

function referencedRestoreInputs(source, inventory, initiallySelected) {
  const inventorySet = new Set(inventory);
  const selected = new Set(initiallySelected);
  const configs = new Set();

  for (const entry of initiallySelected) {
    if (!/\.(?:csproj|fsproj|vbproj|props|targets)$/i.test(entry)) continue;
    const content = readFileSync(join(source, ...entry.split('/')), 'utf8');
    for (const match of content.matchAll(/<RestoreConfigFile\b[^>]*>([\s\S]*?)<\/RestoreConfigFile>/gi)) {
      const configEntry = sourceEntry(source, resolveMsBuildPath(source, entry, match[1]));
      if (!inventorySet.has(configEntry)) fail('referenced restore config is absent from source inventory');
      selected.add(configEntry);
      configs.add(configEntry);
    }
  }

  for (const configEntry of configs) {
    const content = readFileSync(join(source, ...configEntry.split('/')), 'utf8');
    const packageSources = /<packageSources\b[^>]*>([\s\S]*?)<\/packageSources>/i.exec(content)?.[1] ?? '';
    for (const match of packageSources.matchAll(/<add\b([^>]*)\/?>/gi)) {
      const value = /\bvalue\s*=\s*(["'])(.*?)\1/i.exec(match[1])?.[2];
      if (!value) continue;
      const decodedValue = decodeXmlAttribute(value).trim();
      if (/^[a-z][a-z0-9+.-]*:\/\//i.test(decodedValue)) continue;
      const localSource = resolveMsBuildPath(source, configEntry, decodedValue);
      const localSourceEntry = sourceEntry(source, localSource);
      const prefix = `${localSourceEntry}/`;
      const packages = inventory.filter(entry => entry.startsWith(prefix));
      if (packages.length === 0) fail('referenced local package source is absent from source inventory');
      for (const packageEntry of packages) selected.add(packageEntry);
    }
  }

  return [...selected];
}

function gitVisibleFiles(source) {
  try {
    // The supported launcher can run under an isolated service account while
    // the workspace is owned by the interactive developer. Trust only this
    // already-canonical source for this one invocation; never mutate global
    // Git configuration or accept a wildcard safe.directory.
    const output = execFileSync('git', [
      '-c',
      `safe.directory=${source}`,
      '-C',
      source,
      'ls-files',
      '-co',
      '--exclude-standard',
      '-z'
    ], {
      encoding: 'utf8',
      maxBuffer: 64 * 1024 * 1024,
      stdio: ['ignore', 'pipe', 'pipe']
    });
    return output.split('\0').filter(Boolean).map(normalizeEntry);
  } catch {
    fail('source inventory is unavailable');
  }
}

export function exportDevelopmentContext({ kind, source, destination, ownedRoot }) {
  const fullSource = resolve(source);
  const fullOwnedRoot = resolve(ownedRoot);
  const fullDestination = resolve(destination);
  let sourceIsCanonical = false;
  try {
    sourceIsCanonical = existsSync(fullSource)
      && lstatSync(fullSource).isDirectory()
      && realpathSync(fullSource) === fullSource;
  } catch {}
  if (!sourceIsCanonical) {
    fail('source must be a canonical directory');
  }
  mkdirSync(fullOwnedRoot, { recursive: true });
  if (!isChild(fullOwnedRoot, fullDestination)) fail('destination must stay inside the owned context root');

  const inventory = gitVisibleFiles(fullSource);
  const initiallySelected = inventory.filter(entry => isSelected(kind, entry));
  const selected = kind === 'dotnet'
    ? referencedRestoreInputs(fullSource, inventory, initiallySelected)
    : initiallySelected;
  if (selected.length === 0) fail('source allowlist is empty');
  let prohibited = 0;
  for (const entry of selected) {
    if (isProhibited(entry)) {
      prohibited += 1;
      continue;
    }
    try {
      const item = lstatSync(join(fullSource, ...entry.split('/')));
      if (!item.isFile() || item.isSymbolicLink() || (item.attributes & 0x400) !== 0) prohibited += 1;
    } catch {
      prohibited += 1;
    }
  }
  if (prohibited !== 0) fail(`prohibited source entries detected (${prohibited})`);

  const stage = mkdtempSync(join(fullOwnedRoot, `.${basename(fullDestination)}-`));
  try {
    for (const entry of selected) {
      const target = join(stage, ...entry.split('/'));
      mkdirSync(dirname(target), { recursive: true });
      copyFileSync(join(fullSource, ...entry.split('/')), target);
    }
    rmSync(fullDestination, { recursive: true, force: true });
    renameSync(stage, fullDestination);
  } catch {
    rmSync(stage, { recursive: true, force: true });
    fail('context materialization failed');
  }
  return { kind, fileCount: selected.length };
}

function main() {
  const [kind, source, destination, ownedRoot] = process.argv.slice(2);
  if (!ownedRoot) fail('kind, source, destination and owned root are required');
  const result = exportDevelopmentContext({ kind, source, destination, ownedRoot });
  process.stdout.write(`Prepared filtered ${result.kind} build context (${result.fileCount} files).\n`);
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  try { main(); } catch (error) { console.error(error.message); process.exitCode = 1; }
}
