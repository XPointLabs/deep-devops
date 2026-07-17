import { mkdir, writeFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repositoryRoot = path.resolve(__dirname, '..');
const PROGRAM_REVISION_SHA = 'ca5ad9f0c9d4dfb509dedcbf8133524c15867fce5534816da21ff86a07057383';

function fail(message) {
  throw new Error(message);
}

function argumentValue(argv, name) {
  const index = argv.indexOf(name);
  if (index < 0) return null;
  const value = argv[index + 1];
  if (!value || value.startsWith('--')) fail(`${name} requires a value`);
  return value;
}

function relativeInsideRoot(filePath) {
  const relative = path.relative(repositoryRoot, filePath);
  if (relative.startsWith('..') || path.isAbsolute(relative)) {
    fail('output must remain inside the deep-devops repository');
  }
  return relative.split(path.sep).join('/');
}

function parseComposeJson(stdout) {
  const trimmed = stdout.trim();
  if (!trimmed) return [];
  try {
    const parsed = JSON.parse(trimmed);
    return Array.isArray(parsed) ? parsed : [parsed];
  } catch {
    return trimmed.split(/\r?\n/).filter(Boolean).map(line => JSON.parse(line));
  }
}

function normalizePort(publisher) {
  return {
    protocol: String(publisher.Protocol ?? '').toLowerCase() || null,
    publishedPort: Number.isInteger(Number(publisher.PublishedPort))
      ? Number(publisher.PublishedPort)
      : null,
    targetPort: Number.isInteger(Number(publisher.TargetPort))
      ? Number(publisher.TargetPort)
      : null
  };
}

export async function main(argv = process.argv.slice(2)) {
  const composeFile = path.resolve(argumentValue(argv, '--compose-file')
    ?? path.join(repositoryRoot, 'docker-compose.yml'));
  const outputPath = path.resolve(argumentValue(argv, '--output')
    ?? path.join(repositoryRoot, 'artifacts', 'compose.topology.redacted.json'));
  relativeInsideRoot(outputPath);

  const result = spawnSync(
    'docker',
    ['compose', '-f', composeFile, 'ps', '--all', '--format', 'json'],
    { encoding: 'utf8', windowsHide: true }
  );
  if (result.status !== 0) {
    fail(`docker compose topology query failed with exit code ${result.status ?? 'unknown'}`);
  }

  const containers = parseComposeJson(result.stdout).map(container => ({
    service: String(container.Service ?? ''),
    name: String(container.Name ?? ''),
    state: String(container.State ?? ''),
    health: String(container.Health ?? ''),
    publishers: Array.isArray(container.Publishers)
      ? container.Publishers.map(normalizePort)
      : []
  })).sort((left, right) => left.service.localeCompare(right.service) || left.name.localeCompare(right.name));

  const payload = {
    schemaVersion: '1.0.0',
    status: 'ok',
    programRevisionSha256: PROGRAM_REVISION_SHA,
    capturedAt: process.env.DEEP_EVIDENCE_NOW ?? new Date().toISOString(),
    containerCount: containers.length,
    containers
  };
  await mkdir(path.dirname(outputPath), { recursive: true });
  await writeFile(outputPath, `${JSON.stringify(payload, null, 2)}\n`, 'utf8');
  console.log(`Redacted compose topology captured (${containers.length} containers).`);
  return payload;
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  main().catch(error => {
    console.error(`Redacted compose topology failed closed: ${error.message}`);
    process.exitCode = 1;
  });
}
