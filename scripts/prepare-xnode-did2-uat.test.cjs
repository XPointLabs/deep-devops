'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');
const { prepare } = require('./prepare-xnode-did2-uat.cjs');
const sha = bytes => crypto.createHash('sha256').update(bytes).digest('hex').toUpperCase();
const mount = '/run/did2-network/';

function fixture(run) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'deep-did2-host-input-'));
  try {
    const assets = path.join(root, 'assets');
    const rollover = path.join(root, 'rollover');
    fs.mkdirSync(assets); fs.mkdirSync(rollover);
    const artifacts = [];
    for (const role of ['xna1', 'dts1', 'xvp1', 'xnv1', 'xnh1', 'xnd1', 'pmt2']) {
      const bytes = Buffer.from(role + '-synthetic-structural-input');
      const file = role + '.0000.bin';
      fs.writeFileSync(path.join(assets, file), bytes);
      artifacts.push({ Role: role, Ordinal: 0, FileName: file, Length: bytes.length, Sha256Hex: sha(bytes) });
    }
    const head = Buffer.from('synthetic-reader-v2-head');
    const observer = Buffer.alloc(2052, 1); observer.write('DID2');
    fs.writeFileSync(path.join(assets, 'genesis.adh1'), head);
    fs.writeFileSync(path.join(assets, 'observer.did2'), observer);
    const config = {
      DeepIdV2DirectoryProof: { Enabled: true, NetworkIdHex: '11'.repeat(16),
        GenesisAuthorityCoreHashHex: '22'.repeat(32), RegistryOrigin: 'https://registry.example/',
        ExactAuthorityPaths: [mount + 'xna1.0000.bin'],
        ExactTimePolicyPaths: [mount + 'dts1.0000.bin'], GenesisHeadPath: mount + 'genesis.adh1' },
      DeepIdV2NetworkPlacement: { Enabled: true, ExactPolicyPaths: [mount + 'xvp1.0000.bin'],
        ExactViewPaths: [mount + 'xnv1.0000.bin'], ExactHeadPaths: [mount + 'xnh1.0000.bin'],
        ExactActiveNodePaths: [mount + 'xnd1.0000.bin'], ExactMailboxProjectionPaths: [mount + 'pmt2.0000.bin'],
        PublicObservationDid2Path: mount + 'observer.did2' }, DeepIdV2ReplicaStage: { Enabled: true }
    };
    const configuration = Buffer.from(JSON.stringify(config));
    fs.writeFileSync(path.join(assets, 'xnode.did2.json'), configuration);
    fs.writeFileSync(path.join(assets, 'public-assets.v2.json'), JSON.stringify({
      schema: 'deep-xnode-did2-public-assets.v2', authorityOwner: 'Mr. X', artifacts,
      genesisHeadSha256: sha(head), observerDid2Sha256: sha(observer), configurationSha256: sha(configuration),
      currentTimeEvidence: false, deploymentEvidence: false
    }));
    const input = { assets, rollover, node: 'seed1', output: path.join(root, 'prepared') };
    const openssl = process.platform === 'win32' ? 'C:\\Program Files\\Git\\usr\\bin\\openssl.exe' : 'openssl';
    const cert = path.join(root, 'origin.crt'), key = path.join(root, 'origin.key');
    const issued = spawnSync(openssl, ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
      '-nodes', '-keyout', key, '-out', cert, '-days', '2', '-subj', '/CN=synthetic.invalid',
      '-addext', 'subjectAltName=IP:8.8.8.1,IP:8.8.8.2,IP:8.8.8.3'], { encoding: 'utf8' });
    assert.equal(issued.status, 0, 'Synthetic test certificate generation must succeed.');
    const certificate = fs.readFileSync(cert), keyBytes = fs.readFileSync(key);
    const pin = sha(new crypto.X509Certificate(certificate).publicKey.export({ format: 'der', type: 'spki' })).toLowerCase();
    const nextCert = path.join(root, 'next.crt'), nextKey = path.join(root, 'next.key');
    const nextIssued = spawnSync(openssl, ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
      '-nodes', '-keyout', nextKey, '-out', nextCert, '-days', '2', '-subj', '/CN=synthetic.invalid',
      '-addext', 'subjectAltName=IP:8.8.8.1,IP:8.8.8.2,IP:8.8.8.3'], { encoding: 'utf8' });
    assert.equal(nextIssued.status, 0);
    const nextCertificate = fs.readFileSync(nextCert), nextPrivate = fs.readFileSync(nextKey);
    const nextPin = sha(new crypto.X509Certificate(nextCertificate).publicKey.export({ format: 'der', type: 'spki' })).toLowerCase();
    for (const [index, name] of ['seed1', 'seed2', 'seed3'].entries()) {
      input[name] = path.join(root, name); fs.mkdirSync(input[name]);
      const secrets = path.join(input[name], 'secrets'); fs.mkdirSync(secrets);
      const seed = Buffer.alloc(32, index + 10);
      const pair = crypto.createPrivateKey({ format: 'der', type: 'pkcs8',
        key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]) });
      const id = crypto.createPublicKey(pair).export({ format: 'der', type: 'spki' }).subarray(-32).toString('hex');
      fs.writeFileSync(path.join(input[name], '.env.node.prod'),
        'DEEP_NODE_ED25519_PUBLIC_KEY=' + id + '\nDEEP_NODE_PUBLIC_IP=8.8.8.' + (index + 1) + '\n');
      fs.writeFileSync(path.join(secrets, 'key_ed25519'), '0x' + seed.toString('hex') + '\n');
      fs.writeFileSync(path.join(secrets, 'onion-state-protection.key'), Buffer.alloc(32, 42));
      const rolled = path.join(rollover, name); fs.mkdirSync(rolled);
      fs.writeFileSync(path.join(rolled, 'current-origin.cer'), certificate);
      fs.writeFileSync(path.join(rolled, 'current-origin.key'), keyBytes);
      fs.writeFileSync(path.join(rolled, 'current-origin.spki-sha256'), pin + '\n');
      fs.writeFileSync(path.join(rolled, 'next-origin.cer'), nextCertificate);
      fs.writeFileSync(path.join(rolled, 'next-origin.key'), nextPrivate);
      fs.writeFileSync(path.join(rolled, 'next-origin.spki-sha256'), nextPin + '\n');
      fs.writeFileSync(path.join(rolled, 'current.x25519.seed'), Buffer.alloc(32, index + 20));
    }
    run(input);
  } finally { fs.rmSync(root, { recursive: true }); }
}

if (require.main === module) {
test('prepares independent UAT custody without rewriting identities or claiming a carrier', () => fixture(input => {
  const source = fs.readFileSync(path.join(input.seed1, 'secrets', 'key_ed25519'));
  const summary = prepare(input);
  assert.deepEqual(summary, { publicRecords: 7, peers: 2, carrierEnabled: false, deploymentEvidence: false });
  assert.deepEqual(fs.readFileSync(path.join(input.seed1, 'secrets', 'key_ed25519')), source);
  const config = JSON.parse(fs.readFileSync(path.join(input.output, 'appsettings.UAT.json')));
  assert.equal(config.Vless.Enabled, false); assert.equal(config.Vless.MockProcess, false);
  assert.equal(config.ContactAuthority.Enabled, false); assert.equal(config.PrivacyRouting.Peers.length, 2);
  assert.equal(config.PrivacyRouting.AllowInsecureHttpPeerTransport, false);
  assert.equal(config.Node.ManagedIngressH2ListenUrl, '');
  assert.equal(config.Node.PrivacyPeerH2ListenUrl, '');
  assert.equal(fs.readFileSync(path.join(input.output, 'secrets', 'key_x25519')).length, 65);
  assert.deepEqual(fs.readdirSync(path.join(input.output, 'state')), []);
  assert.equal(fs.existsSync(path.join(input.output, 'public', 'xnode.did2.json')), true);
  assert.equal(fs.existsSync(path.join(input.output, 'secrets', 'next-origin.key')), true);
  assert.throws(() => prepare(input));
}));

test('rejects changed public records, observer, config and traversal before any output', () => {
  for (const file of ['xnd1.0000.bin', 'observer.did2', 'xnode.did2.json']) fixture(input => {
    const selected = path.join(input.assets, file);
    const bytes = fs.readFileSync(selected); bytes[bytes.length - 1] ^= 1; fs.writeFileSync(selected, bytes);
    assert.throws(() => prepare(input)); assert.equal(fs.existsSync(input.output), false);
  });
  fixture(input => {
    const file = path.join(input.assets, 'public-assets.v2.json');
    const manifest = JSON.parse(fs.readFileSync(file)); manifest.artifacts[0].FileName = '../outside';
    fs.writeFileSync(file, JSON.stringify(manifest));
    assert.throws(() => prepare(input)); assert.equal(fs.existsSync(input.output), false);
  });
});

test('rejects substituted identity, duplicate peer and hostile private seed lengths', () => {
  fixture(input => {
    fs.writeFileSync(path.join(input.seed1, 'secrets', 'key_ed25519'), 'ab'.repeat(32));
    assert.throws(() => prepare(input)); assert.equal(fs.existsSync(input.output), false);
  });
  fixture(input => {
    fs.copyFileSync(path.join(input.seed1, '.env.node.prod'), path.join(input.seed2, '.env.node.prod'));
    assert.throws(() => prepare(input)); assert.equal(fs.existsSync(input.output), false);
  });
  for (const bytes of [Buffer.alloc(32), Buffer.alloc(33, 1)]) fixture(input => {
    fs.writeFileSync(path.join(input.rollover, 'seed1', 'current.x25519.seed'), bytes);
    assert.throws(() => prepare(input)); assert.equal(fs.existsSync(input.output), false);
  });
});
}
module.exports = { fixture };
