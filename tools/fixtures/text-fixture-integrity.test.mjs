import assert from 'node:assert/strict';
import test from 'node:test';
import {
  normalizedUtf8FixtureBytes,
  normalizedUtf8FixtureSha256
} from './text-fixture-integrity.mjs';

test('text fixture integrity is stable across Git LF and Windows CRLF checkouts', () => {
  const lf = Buffer.from('{\n  "status": "ok"\n}\n', 'utf8');
  const crlf = Buffer.from('{\r\n  "status": "ok"\r\n}\r\n', 'utf8');
  assert.deepEqual(normalizedUtf8FixtureBytes(crlf), lf);
  assert.equal(normalizedUtf8FixtureSha256(crlf), normalizedUtf8FixtureSha256(lf));
});

test('text fixture integrity rejects BOM, lone carriage returns, and invalid UTF-8', () => {
  assert.throws(
    () => normalizedUtf8FixtureBytes(Buffer.from([0xef, 0xbb, 0xbf, 0x7b, 0x7d])),
    /BOM/
  );
  assert.throws(() => normalizedUtf8FixtureBytes(Buffer.from('left\rright', 'utf8')), /carriage return/);
  assert.throws(() => normalizedUtf8FixtureBytes(Buffer.from([0xc3, 0x28])), /encoded data was not valid/);
});
