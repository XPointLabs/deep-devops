import { readFileSync, writeFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

const forbiddenName = /(?:path|endpoint|url|uri|docker|container|networkId|volumeId|imageId|key|secret|seed|mnemonic|identity|payload|request|response|token|hash|nonce|address)/i;
function fail(message) { throw new Error(`P15C evidence failure: ${message}`); }

function scan(value, name = '') {
  if (forbiddenName.test(name)) fail(`field ${name} is prohibited`);
  if (Array.isArray(value)) return value.forEach(item => scan(item, name));
  if (value && typeof value === 'object') for (const [key, child] of Object.entries(value)) scan(child, key);
  if (typeof value === 'string' && (/[A-Za-z]:[\\/]|\/(?:home|run|tmp|var)\/|https?:\/\/|\bsha256:[0-9a-f]{64}\b|\b[0-9a-f]{64}\b/i.test(value))) fail('sensitive raw value is prohibited');
}

export function sanitizeEvidence(value) {
  if (!value || value.schema !== 'deep-p15c-headless-evidence.v1' || value.evidenceClass !== 'headless-harness' || value.productRuntime !== false || value.result !== 'pass') fail('evidence envelope is invalid');
  const gates = ['source', 'images', 'contracts', 'runtime', 'e2e', 'cleanup'];
  if (Object.keys(value.gates ?? {}).sort().join(',') !== gates.sort().join(',') || gates.some(name => value.gates[name] !== 'pass')) fail('required aggregate gates are incomplete');
  scan(value);
  const encoded = JSON.stringify(value);
  if (Buffer.byteLength(encoded) > 16384) fail('evidence exceeds the bounded size');
  return value;
}

export function canonicalJson(value) {
  const sort = item => Array.isArray(item) ? item.map(sort) : item && typeof item === 'object' ? Object.fromEntries(Object.keys(item).sort().map(key => [key, sort(item[key])])) : item;
  return `${JSON.stringify(sort(value), null, 2)}\n`;
}

async function main() {
  const [command, input, output] = process.argv.slice(2);
  if (command !== 'write' || !input || !output) fail('command is invalid');
  const value = sanitizeEvidence(JSON.parse(readFileSync(input, 'utf8')));
  writeFileSync(output, canonicalJson(value), { encoding: 'utf8', flag: 'wx' });
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) main().catch(error => { console.error(error.message); process.exitCode = 1; });
