import { readFile, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

const utf8Bom = Buffer.from([0xef, 0xbb, 0xbf]);

export async function normalizePackageJson(path) {
  if (typeof path !== 'string' || path.length === 0) {
    throw new TypeError('package JSON path is required');
  }

  const bytes = await readFile(path);
  const hasBom = bytes.length >= utf8Bom.length &&
    bytes.subarray(0, utf8Bom.length).equals(utf8Bom);
  const jsonBytes = hasBom ? bytes.subarray(utf8Bom.length) : bytes;
  const text = new TextDecoder('utf-8', { fatal: true }).decode(jsonBytes);
  JSON.parse(text);

  if (hasBom) await writeFile(path, jsonBytes);
  return hasBom;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  await normalizePackageJson(process.argv[2]);
}
