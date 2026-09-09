import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { main } from './production-authority-provision.mjs';

const root = mkdtempSync(path.join(os.tmpdir(), 'deep-production-authority-'));
const target = path.join(root, 'authority');
try {
  main(['--out-dir', target]);
  const manifest = JSON.parse(readFileSync(path.join(target, 'public', 'custody-manifest.v1.json'), 'utf8'));
  assert.equal(manifest.schema, 'deep-production-authority-custody.v1');
  assert.equal(manifest.authorityOwner, 'Mr. X');
  assert.equal(manifest.roles.length, 10);
  assert.equal(new Set(manifest.roles.map((role) => role.ed25519PublicKeyHex)).size, 10);
  assert.equal(new Set(manifest.roles.map((role) => role.custodyDomainHashHex)).size, 10);
  assert.equal(readdirSync(path.join(target, 'private')).length, 13);
  assert.throws(() => main(['--out-dir', target]), /not empty/u);
  process.stdout.write('production authority provisioning tests passed\n');
} finally {
  rmSync(root, { recursive: true, force: true });
}
