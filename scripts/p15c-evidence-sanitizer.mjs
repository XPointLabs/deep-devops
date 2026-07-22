import { readFileSync, writeFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

const forbiddenName = /(?:path|endpoint|url|uri|docker|container|networkId|volumeId|imageId|key|secret|seed|mnemonic|identity|payload|request|response|token|hash|nonce|address)/i;
const forbiddenPositiveClaim = /(?:PRODUCT-RUNTIME-GO|VLESS-GO|DEVICE-E2E-GO|PROFILE-ACTIVATION-GO|PRODUCTION[-_ ]?READY)/i;
function fail(message) { throw new Error(`P15C evidence failure: ${message}`); }

function exactKeys(value, expected) {
  return value && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).sort().join(',') === [...expected].sort().join(',');
}

function scan(value, name = '') {
  if (forbiddenName.test(name)) fail(`field ${name} is prohibited`);
  if (Array.isArray(value)) return value.forEach(item => scan(item, name));
  if (value && typeof value === 'object') for (const [key, child] of Object.entries(value)) scan(child, key);
  if (typeof value === 'string' && (/[A-Za-z]:[\\/]|\/(?:home|run|tmp|var)\/|https?:\/\/|\bsha256:[0-9a-f]{64}\b|\b[0-9a-f]{64}\b/i.test(value) || forbiddenPositiveClaim.test(value))) fail('sensitive raw value or positive product claim is prohibited');
}

export function sanitizeEvidence(value) {
  if (!exactKeys(value, ['schema', 'evidenceClass', 'productRuntime', 'result', 'gates', 'counts']) || value.schema !== 'deep-p15c-headless-evidence.v1' || value.evidenceClass !== 'headless-harness' || value.productRuntime !== false || value.result !== 'pass') fail('evidence envelope is invalid');
  const gates = ['source', 'images', 'contracts', 'runtime', 'e2e', 'cleanup'];
  if (!exactKeys(value.gates, gates) || gates.some(name => value.gates[name] !== 'pass')) fail('required aggregate gates are incomplete');
  if (!exactKeys(value.counts, ['services', 'xnodes', 'localContracts']) || value.counts.services !== 11 || value.counts.xnodes !== 3 || value.counts.localContracts !== 4) fail('aggregate counts are invalid');
  scan(value);
  const encoded = JSON.stringify(value);
  if (Buffer.byteLength(encoded) > 16384) fail('evidence exceeds the bounded size');
  return value;
}

function assertNoDuplicateJsonKeys(text) {
  let index = 0;
  const whitespace = () => { while (/\s/.test(text[index] ?? '')) index += 1; };
  const string = () => {
    const start = index;
    if (text[index++] !== '"') fail('JSON string is invalid');
    while (index < text.length) {
      if (text[index] === '\\') { index += 2; continue; }
      if (text[index++] === '"') return JSON.parse(text.slice(start, index));
    }
    fail('JSON string is unterminated');
  };
  const value = () => {
    whitespace();
    if (text[index] === '{') return object();
    if (text[index] === '[') return array();
    if (text[index] === '"') { string(); return; }
    const match = /^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/.exec(text.slice(index));
    if (!match) fail('JSON value is invalid');
    index += match[0].length;
  };
  const object = () => {
    index += 1; whitespace();
    const keys = new Set();
    if (text[index] === '}') { index += 1; return; }
    while (index < text.length) {
      whitespace();
      const key = string();
      if (keys.has(key)) fail(`duplicate JSON key: ${key}`);
      keys.add(key); whitespace();
      if (text[index++] !== ':') fail('JSON object separator is invalid');
      value(); whitespace();
      if (text[index] === '}') { index += 1; return; }
      if (text[index++] !== ',') fail('JSON object delimiter is invalid');
    }
    fail('JSON object is unterminated');
  };
  const array = () => {
    index += 1; whitespace();
    if (text[index] === ']') { index += 1; return; }
    while (index < text.length) {
      value(); whitespace();
      if (text[index] === ']') { index += 1; return; }
      if (text[index++] !== ',') fail('JSON array delimiter is invalid');
    }
    fail('JSON array is unterminated');
  };
  value(); whitespace();
  if (index !== text.length) fail('JSON has trailing content');
}

export function parseEvidenceJson(text) {
  assertNoDuplicateJsonKeys(String(text));
  return sanitizeEvidence(JSON.parse(text));
}

export function canonicalJson(value) {
  const sort = item => Array.isArray(item) ? item.map(sort) : item && typeof item === 'object' ? Object.fromEntries(Object.keys(item).sort().map(key => [key, sort(item[key])])) : item;
  return `${JSON.stringify(sort(value), null, 2)}\n`;
}

async function main() {
  const [command, input, output] = process.argv.slice(2);
  if (command !== 'write' || !input || !output) fail('command is invalid');
  const value = parseEvidenceJson(readFileSync(input, 'utf8'));
  writeFileSync(output, canonicalJson(value), { encoding: 'utf8', flag: 'wx' });
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) main().catch(error => { console.error(error.message); process.exitCode = 1; });
