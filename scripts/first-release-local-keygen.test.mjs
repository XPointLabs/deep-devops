import test from 'node:test';
import assert from 'node:assert/strict';
import { parseRealityKeyPair } from './first-release-local-keygen.mjs';

const privateKey = 'A'.repeat(43);
const publicKey = 'B'.repeat(43);

test('parses current Xray Reality labels', () => {
  assert.deepEqual(
    parseRealityKeyPair(`Private key: ${privateKey}\nPublic key: ${publicKey}\n`),
    { privateKey, publicKey }
  );
});

test('parses legacy Xray Password public-key label', () => {
  assert.deepEqual(
    parseRealityKeyPair(`PrivateKey: ${privateKey}\nPassword: ${publicKey}\n`),
    { privateKey, publicKey }
  );
});

test('rejects missing or malformed Reality key material', () => {
  assert.throws(() => parseRealityKeyPair('Private key: short\n'), /unsupported Reality/);
});
