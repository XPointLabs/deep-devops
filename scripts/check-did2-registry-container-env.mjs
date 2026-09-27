import { spawnSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';

const prefix = 'deepidv2directoryauthority__';
const maximumInspectionBytes = 4 * 1024 * 1024;

export function auditDid2ContainerEnvironment(inspection) {
  if (!Array.isArray(inspection) || inspection.length !== 1 ||
      !Array.isArray(inspection[0]?.Config?.Env)) {
    throw new Error('Expected one Docker container inspection with Config.Env.');
  }
  const seen = new Set();
  const repeated = new Set();
  for (const entry of inspection[0].Config.Env) {
    if (typeof entry !== 'string') {
      throw new Error('Docker Config.Env contains a non-string entry.');
    }
    const separator = entry.indexOf('=');
    if (separator < 1) {
      throw new Error('Docker Config.Env contains a malformed entry.');
    }
    const name = entry.slice(0, separator);
    const normalizedName = name.toLowerCase();
    if (!normalizedName.startsWith(prefix)) continue;
    if (seen.has(normalizedName)) repeated.add(normalizedName);
    else seen.add(normalizedName);
  }
  return {
    uniqueKeyCount: seen.size,
    repeatedKeys: [...repeated].sort()
  };
}

async function readInspectionFromStdin() {
  const chunks = [];
  let length = 0;
  for await (const chunk of process.stdin) {
    length += chunk.length;
    if (length > maximumInspectionBytes) {
      throw new Error('Docker inspection exceeds the bounded input size.');
    }
    chunks.push(chunk);
  }
  return Buffer.concat(chunks, length).toString('utf8');
}

async function main() {
  const args = process.argv.slice(2);
  let encoded;
  if (args.length === 1 && args[0] === '--stdin') {
    encoded = await readInspectionFromStdin();
  } else if (args.length === 2 && args[0] === '--container' &&
             /^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(args[1])) {
    const result = spawnSync('docker',
      ['inspect', '--type', 'container', args[1]],
      { encoding: 'utf8', maxBuffer: maximumInspectionBytes });
    if (result.error || result.status !== 0) {
      throw new Error('Docker inspection failed; no DID2 environment was accepted.');
    }
    encoded = result.stdout;
  } else {
    throw new Error('Usage: --container <exact-name> or --stdin');
  }
  let inspection;
  try {
    inspection = JSON.parse(encoded);
  } catch {
    throw new Error('Docker inspection is not valid JSON.');
  }
  const result = auditDid2ContainerEnvironment(inspection);
  if (result.uniqueKeyCount === 0) {
    throw new Error('Docker container has no DID2 authority environment keys.');
  }
  if (result.repeatedKeys.length !== 0) {
    throw new Error('Repeated DID2 authority environment keys: ' +
      result.repeatedKeys.join(', '));
  }
  process.stdout.write(
    `DID2 environment preflight passed: ${result.uniqueKeyCount} unique keys.\n`);
}

if (process.argv[1] &&
    pathToFileURL(process.argv[1]).href === import.meta.url) {
  main().catch(error => {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  });
}
