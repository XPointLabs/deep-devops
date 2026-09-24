import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, readdirSync, rmSync, unlinkSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { augmentMailbox, main } from './production-authority-provision.mjs';

const root = mkdtempSync(path.join(os.tmpdir(), 'deep-production-authority-'));
const target = path.join(root, 'authority');
try {
  main(['--out-dir', target]);
  const manifest = JSON.parse(readFileSync(path.join(target, 'public', 'custody-manifest.v1.json'), 'utf8'));
  assert.equal(manifest.schema, 'deep-production-authority-custody.v1');
  assert.equal(manifest.authorityOwner, 'Mr. X');
  assert.equal(manifest.roles.length, 12);
  assert.equal(new Set(manifest.roles.map((role) => role.ed25519PublicKeyHex)).size, 12);
  assert.equal(new Set(manifest.roles.map((role) => role.custodyDomainHashHex)).size, 12);
  assert.equal(readdirSync(path.join(target, 'private')).length, 16);
  assert.equal(readFileSync(path.join(target, 'private', 'account-directory-integrity.key')).length, 32);
  assert.throws(() => main(['--out-dir', target]), /not empty/u);

  const oldSeed = readFileSync(path.join(target, 'private', 'offline-root-1.ed25519.seed'));
  const oldManifest = { ...manifest, roles: manifest.roles.slice(0, 10) };
  for (const role of ['mailbox-deposit-issuer', 'mailbox-retrieve-issuer']) {
    unlinkSync(path.join(target, 'private', `${role}.ed25519.seed`));
    unlinkSync(path.join(target, 'public', `${role}.ed25519.public`));
  }
  const manifestPath = path.join(target, 'public', 'custody-manifest.v1.json');
  writeFileSync(manifestPath, `${JSON.stringify(oldManifest, null, 2)}\n`);
  augmentMailbox(['--authority-root', target]);
  const augmented = JSON.parse(readFileSync(manifestPath, 'utf8'));
  assert.equal(augmented.roles.length, 12);
  assert.deepEqual(augmented.roles.slice(0, 10), oldManifest.roles);
  assert.deepEqual(readFileSync(path.join(target, 'private', 'offline-root-1.ed25519.seed')), oldSeed);
  assert.deepEqual(JSON.parse(readFileSync(path.join(target, 'public',
    'custody-manifest.pre-mailbox.v1.json'), 'utf8')), oldManifest);
  assert.equal(readdirSync(path.join(target, 'private')).length, 16);
  assert.throws(() => augmentMailbox(['--authority-root', target]), /pre-mailbox/u);

  const partial = path.join(root, 'partial');
  main(['--out-dir', partial]);
  const partialManifestPath = path.join(partial, 'public', 'custody-manifest.v1.json');
  const partialManifest = JSON.parse(readFileSync(partialManifestPath, 'utf8'));
  writeFileSync(partialManifestPath, `${JSON.stringify({ ...partialManifest,
    roles: partialManifest.roles.slice(0, 10) }, null, 2)}\n`);
  assert.throws(() => augmentMailbox(['--authority-root', partial]), /needs review/u);

  const tampered = path.join(root, 'tampered');
  main(['--out-dir', tampered]);
  const tamperedManifestPath = path.join(tampered, 'public', 'custody-manifest.v1.json');
  const tamperedManifest = JSON.parse(readFileSync(tamperedManifestPath, 'utf8'));
  writeFileSync(tamperedManifestPath, `${JSON.stringify({ ...tamperedManifest,
    roles: tamperedManifest.roles.slice(0, 10) }, null, 2)}\n`);
  for (const role of ['mailbox-deposit-issuer', 'mailbox-retrieve-issuer']) {
    unlinkSync(path.join(tampered, 'private', `${role}.ed25519.seed`));
    unlinkSync(path.join(tampered, 'public', `${role}.ed25519.public`));
  }
  writeFileSync(path.join(tampered, 'public', 'offline-root-1.ed25519.public'), Buffer.alloc(32));
  assert.throws(() => augmentMailbox(['--authority-root', tampered]), /does not match/u);
  assert.equal(readdirSync(path.join(tampered, 'private')).length, 14);
  process.stdout.write('production authority provisioning tests passed\n');
} finally {
  rmSync(root, { recursive: true, force: true });
}
