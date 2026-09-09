import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { chmodSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';

const script = path.resolve(import.meta.dirname, 'new-xnode-identity.mjs');

test('protected identity output contains VLESS file path but no credential values', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'deep-node-identity-'));
  try {
    if (process.platform !== 'win32') {
      chmodSync(root, 0o777);
      writeFileSync(path.join(root, 'vless-client-id'), 'stale\n', { mode: 0o666 });
      chmodSync(path.join(root, 'vless-client-id'), 0o666);
    }
    const stdout = execFileSync(
      process.execPath,
      [script, '--as-env', '--out-dir', root],
      { encoding: 'utf8', windowsHide: true }
    );
    const environment = Object.fromEntries(stdout.trim().split(/\r?\n/).map(line => {
      const separator = line.indexOf('=');
      assert.notEqual(separator, -1);
      return [line.slice(0, separator), line.slice(separator + 1)];
    }));

    assert.equal(Object.hasOwn(environment, 'DEEP_NODE_VLESS_CLIENT_ID'), false);
    assert.equal(Object.hasOwn(environment, 'DEEP_NODE_ED25519_PRIVATE_KEY'), false);
    assert.equal(Object.hasOwn(environment, 'DEEP_NODE_X25519_PRIVATE_KEY'), false);
    assert.equal(Object.hasOwn(environment, 'DEEP_NODE_BLS_PRIVATE_KEY'), false);
    const clientIdPath = environment.DEEP_NODE_VLESS_CLIENT_ID_FILE;
    assert.equal(path.dirname(clientIdPath), root);
    assert.match(readFileSync(clientIdPath, 'utf8'),
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\n$/);
    if (process.platform !== 'win32') {
      assert.equal(statSync(root).mode & 0o777, 0o700);
      assert.equal(statSync(clientIdPath).mode & 0o777, 0o600);
    }
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
