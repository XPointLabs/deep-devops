#!/usr/bin/env node
import { generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

const scalarOrder = BigInt('0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001');
const pkcs8SeedPrefix = Buffer.from('302e020100300506032b657004220420', 'hex');
const spkiPublicPrefix = Buffer.from('302a300506032b6570032100', 'hex');

function newBlsScalarHex() {
  for (;;) {
    const bytes = randomBytes(32);
    const scalar = BigInt(`0x${bytes.toString('hex')}`);
    if (scalar > 0n && scalar < scalarOrder) {
      return bytes.toString('hex');
    }
  }
}

function requireDerPrefix(der, prefix, name) {
  if (der.length !== prefix.length + 32 || !der.subarray(0, prefix.length).equals(prefix)) {
    throw new Error(`Unexpected Ed25519 ${name} DER shape; cannot safely extract raw key bytes.`);
  }

  return der.subarray(prefix.length).toString('hex');
}

function newEd25519Identity() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const privateDer = Buffer.from(privateKey.export({ type: 'pkcs8', format: 'der' }));
  const publicDer = Buffer.from(publicKey.export({ type: 'spki', format: 'der' }));

  return {
    privateKey: requireDerPrefix(privateDer, pkcs8SeedPrefix, 'private key'),
    publicKey: requireDerPrefix(publicDer, spkiPublicPrefix, 'public key')
  };
}

const ed25519 = newEd25519Identity();
const identity = {
  DEEP_NODE_ED25519_PRIVATE_KEY: ed25519.privateKey,
  DEEP_NODE_ED25519_PUBLIC_KEY: ed25519.publicKey,
  DEEP_NODE_BLS_PRIVATE_KEY: newBlsScalarHex(),
  DEEP_NODE_VLESS_CLIENT_ID: randomUUID()
};

const argv = process.argv.slice(2);
const args = new Set(argv.map((item) => item.toLowerCase()));
function getArgValue(...names) {
  const normalizedNames = new Set(names.map((name) => name.toLowerCase()));
  for (let i = 0; i < argv.length; i++) {
    if (normalizedNames.has(argv[i].toLowerCase())) {
      const value = argv[i + 1];
      if (!value || value.startsWith('-')) {
        throw new Error(`${argv[i]} requires a value.`);
      }

      return value;
    }
  }

  return '';
}

const outDir = getArgValue('--out-dir', '-outdir');
const output = { ...identity };
if (outDir) {
  const directory = resolve(outDir);
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  const ed25519Path = resolve(directory, 'key_ed25519');
  const blsPath = resolve(directory, 'key_bls');
  writeFileSync(ed25519Path, `0x${identity.DEEP_NODE_ED25519_PRIVATE_KEY}\n`, { mode: 0o600 });
  writeFileSync(blsPath, `0x${identity.DEEP_NODE_BLS_PRIVATE_KEY}\n`, { mode: 0o600 });
  delete output.DEEP_NODE_ED25519_PRIVATE_KEY;
  delete output.DEEP_NODE_BLS_PRIVATE_KEY;
  output.DEEP_NODE_ED25519_PRIVATE_KEY_FILE = ed25519Path;
  output.DEEP_NODE_BLS_PRIVATE_KEY_FILE = blsPath;
}

if (args.has('--as-env') || args.has('-asenv')) {
  for (const [key, value] of Object.entries(output)) {
    console.log(`${key}=${value}`);
  }
} else {
  console.log(JSON.stringify(output, null, 2));
}
