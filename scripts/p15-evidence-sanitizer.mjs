import { readFile, writeFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';

const schema = 'deep-p15-compat-lab-evidence.v1';
const requiredScenarios = Object.freeze([
  'source-lock',
  'image-lock',
  'empty-start',
  'health-identity',
  'operations',
  'restart-persistence',
  'network-fault-recovery',
  'privacy-scan',
  'cleanup'
]);

const exactKeys = Object.freeze({
  root: [
    'schema',
    'evidenceClass',
    'productRuntime',
    'clock',
    'source',
    'image',
    'scenarios',
    'counts',
    'durationBoundsMs',
    'result'
  ],
  source: ['sha', 'tree'],
  image: ['baseDigest', 'baseImageId', 'architecture', 'contextSha256'],
  counts: ['services', 'probes', 'restarts', 'networkFaults', 'residualResources', 'residualImages'],
  durationBoundsMs: ['health', 'operation', 'networkFailure']
});

const forbiddenField = /(?:private.?key|secret|seed|mnemonic|token|bearer|authorization|credential|public.?key|session.?id|mailbox|capability|endpoint|url|uri|path|container.?id|raw|response|environment|env(?:ironment)?|payload.?hash|message.?(?:hash|sha)|finding|warning)/i;
const forbiddenText = [
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/i,
  /\bBearer\s+\S+/i,
  /\b(?:https?|wss?):\/\/\S+/i,
  /\b[A-Za-z]:\\(?:Users|Work|Windows|Program Files)\\\S*/i,
  /\/(?:home|Users|var\/lib\/docker|workspace)\/\S+/i,
  /\b05[0-9a-f]{64}\b/i,
  /\b(?:mailbox|capability)[-_:=][A-Za-z0-9+/=_-]+\b/i
];

export function canonicalJson(value) {
  return `${JSON.stringify(sortValue(value), null, 2)}\n`;
}

export function sanitizeEvidence(value) {
  if (!isRecord(value)) {
    fail('evidence must be an object');
  }
  assertExactKeys(value, exactKeys.root, 'evidence');
  assertExactKeys(value.source, exactKeys.source, 'source');
  assertExactKeys(value.image, exactKeys.image, 'image');
  assertExactKeys(value.counts, exactKeys.counts, 'counts');
  assertExactKeys(value.durationBoundsMs, exactKeys.durationBoundsMs, 'duration bounds');
  assertExactKeys(value.scenarios, requiredScenarios, 'scenarios');

  if (value.schema !== schema ||
      value.evidenceClass !== 'compatibility-lab' ||
      value.productRuntime !== false ||
      value.result !== 'pass') {
    fail('evidence identity or result is invalid');
  }
  if (!isUtcClock(value.clock)) {
    fail('evidence clock must be a canonical UTC instant');
  }
  if (!isSha(value.source.sha) || !isSha(value.source.tree)) {
    fail('source identity is invalid');
  }
  if (!isDigest(value.image.baseDigest) ||
      !isDigest(value.image.baseImageId) ||
      !isDigest(value.image.contextSha256) ||
      value.image.architecture !== 'arm64') {
    fail('image identity is invalid');
  }
  if (!Object.values(value.scenarios).every(result => result === 'pass')) {
    fail('every required scenario must pass');
  }

  const expectedCounts = {
    services: 4,
    probes: 4,
    restarts: 4,
    networkFaults: 1,
    residualResources: 0,
    residualImages: 0
  };
  for (const [name, expected] of Object.entries(expectedCounts)) {
    if (value.counts[name] !== expected) {
      fail(`evidence count ${name} is invalid`);
    }
  }
  for (const [name, bound] of Object.entries(value.durationBoundsMs)) {
    if (!Number.isSafeInteger(bound) || bound <= 0 || bound > 120_000) {
      fail(`duration bound ${name} is invalid`);
    }
  }

  scanObject(value, []);
  return structuredClone(value);
}

export function scanText(value) {
  const text = String(value ?? '');
  for (const pattern of forbiddenText) {
    if (pattern.test(text)) {
      fail('privacy or secret finding in runtime text');
    }
  }
  return true;
}

function scanObject(value, path) {
  if (Array.isArray(value)) {
    value.forEach((entry, index) => scanObject(entry, [...path, String(index)]));
    return;
  }
  if (isRecord(value)) {
    for (const [key, entry] of Object.entries(value)) {
      if (forbiddenField.test(key)) {
        fail(`forbidden privacy field at ${[...path, key].join('.')}`);
      }
      scanObject(entry, [...path, key]);
    }
    return;
  }
  if (typeof value === 'string') {
    for (const pattern of forbiddenText) {
      if (pattern.test(value)) {
        fail(`forbidden privacy value at ${path.join('.')}`);
      }
    }
  }
}

function assertExactKeys(value, keys, label) {
  if (!isRecord(value)) {
    fail(`${label} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length ||
      actual.some((key, index) => key !== expected[index])) {
    fail(`${label} contains a forbidden or missing field`);
  }
}

function sortValue(value) {
  if (Array.isArray(value)) {
    return value.map(sortValue);
  }
  if (!isRecord(value)) {
    return value;
  }
  return Object.fromEntries(
    Object.keys(value)
      .sort()
      .map(key => [key, sortValue(value[key])])
  );
}

function isRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function isSha(value) {
  return typeof value === 'string' && /^[0-9a-f]{40}$/.test(value);
}

function isDigest(value) {
  return typeof value === 'string' && /^sha256:[0-9a-f]{64}$/.test(value);
}

function isUtcClock(value) {
  return typeof value === 'string' &&
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value) &&
    new Date(value).toISOString() === value;
}

function fail(message) {
  throw new Error(`P15A privacy failure: ${message}`);
}

async function main() {
  const [command, ...args] = process.argv.slice(2);
  if (command === 'scan-text') {
    const chunks = [];
    for await (const chunk of process.stdin) {
      chunks.push(Buffer.from(chunk));
    }
    scanText(Buffer.concat(chunks).toString('utf8'));
    return;
  }
  if (command === 'write-evidence' && args.length === 2) {
    const value = JSON.parse(await readFile(args[0], 'utf8'));
    const sanitized = sanitizeEvidence(value);
    await writeFile(args[1], canonicalJson(sanitized), { encoding: 'utf8', flag: 'wx' });
    return;
  }
  throw new Error('P15A sanitizer command is invalid');
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  main().catch(error => {
    console.error(error instanceof Error ? error.message : 'P15A privacy failure');
    process.exitCode = 1;
  });
}
