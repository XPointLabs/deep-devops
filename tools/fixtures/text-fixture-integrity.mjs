import { createHash } from 'node:crypto';

export function normalizedUtf8FixtureBytes(value) {
  const bytes = value instanceof Uint8Array ? value : Buffer.from(value);
  if (bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) {
    throw new Error('text fixture must not contain a UTF-8 BOM');
  }
  const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  const normalized = text.replaceAll('\r\n', '\n');
  if (normalized.includes('\r')) {
    throw new Error('text fixture contains a noncanonical carriage return');
  }
  return Buffer.from(normalized, 'utf8');
}

export function normalizedUtf8FixtureSha256(value) {
  return createHash('sha256').update(normalizedUtf8FixtureBytes(value)).digest('hex');
}
