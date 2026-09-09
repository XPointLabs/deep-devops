import { generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';

const scalarOrder = BigInt('0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001');
const pkcs8SeedPrefix = Buffer.from('302e020100300506032b657004220420', 'hex');
const spkiPublicPrefix = Buffer.from('302a300506032b6570032100', 'hex');

function rawDerSuffix(der, prefix, name) {
  if (der.length !== prefix.length + 32 || !der.subarray(0, prefix.length).equals(prefix)) {
    throw new Error(`Unexpected Ed25519 ${name} DER shape.`);
  }
  return der.subarray(prefix.length).toString('hex');
}

function generateEd25519() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return {
    seed: rawDerSuffix(Buffer.from(privateKey.export({ type: 'pkcs8', format: 'der' })), pkcs8SeedPrefix, 'private key'),
    publicKey: rawDerSuffix(Buffer.from(publicKey.export({ type: 'spki', format: 'der' })), spkiPublicPrefix, 'public key')
  };
}

function generateBlsScalar() {
  for (;;) {
    const bytes = randomBytes(32);
    const scalar = BigInt(`0x${bytes.toString('hex')}`);
    if (scalar > 0n && scalar < scalarOrder) return bytes.toString('hex');
  }
}

export function parseRealityKeyPair(output) {
  let privateKey = '';
  let publicKey = '';
  for (const line of output.split(/\r?\n/u)) {
    const separator = line.indexOf(':');
    if (separator < 0) continue;
    const name = line.slice(0, separator).toLowerCase().replace(/[^a-z]/gu, '');
    const value = line.slice(separator + 1).trim();
    if (name.includes('privatekey')) privateKey = value;
    if (name.includes('publickey') || name === 'password') publicKey = value;
  }
  const xrayKey = /^[A-Za-z0-9_-]{43}$/u;
  if (!xrayKey.test(privateKey) || !xrayKey.test(publicKey) || privateKey === publicKey) {
    throw new Error('Xray returned an unsupported Reality key-pair format.');
  }
  return { privateKey, publicKey };
}

function argumentValue(argumentsList, name) {
  const index = argumentsList.indexOf(name);
  if (index < 0 || index + 1 >= argumentsList.length) throw new Error(`Missing ${name}.`);
  return argumentsList[index + 1];
}

export function generateIdentity({ outputDirectory, nodeIndex, xnodeImage, spawn = spawnSync }) {
  const directory = path.resolve(outputDirectory);
  if (!Number.isInteger(nodeIndex) || nodeIndex < 1 || nodeIndex > 3) {
    throw new Error('Node index must be between 1 and 3.');
  }
  if (!/^[A-Za-z0-9./:@_-]+$/u.test(xnodeImage)) throw new Error('Invalid XNode image reference.');
  mkdirSync(directory, { recursive: false, mode: 0o700 });

  const ed25519 = generateEd25519();
  let x25519;
  do {
    x25519 = randomBytes(32).toString('hex');
  } while (x25519 === ed25519.seed || /^0+$/u.test(x25519));
  const bls = generateBlsScalar();
  const realityResult = spawn(
    'docker',
    ['run', '--rm', '--network', 'none', '--entrypoint', 'xray', xnodeImage, 'x25519'],
    { encoding: 'utf8', windowsHide: true, maxBuffer: 64 * 1024 }
  );
  if (realityResult.error || realityResult.status !== 0) {
    throw new Error('The local XNode image could not generate a Reality key pair.');
  }
  const reality = parseRealityKeyPair(realityResult.stdout);

  const prefix = `xnode-${nodeIndex}`;
  const writePrivate = (name, value) => writeFileSync(
    path.join(directory, name), `${value}\n`, { encoding: 'utf8', mode: 0o600, flag: 'wx' });
  writePrivate(`${prefix}-ed25519.seed`, ed25519.seed);
  writePrivate(`${prefix}-x25519.private`, x25519);
  writePrivate(`${prefix}-bls.private`, bls);
  writeFileSync(
    path.join(directory, `${prefix}-identity.private.json`),
    `${JSON.stringify({
      routerId: ed25519.publicKey,
      vlessClientId: randomUUID(),
      realityPublicKey: reality.publicKey,
      realityPrivateKey: reality.privateKey,
      realityShortId: randomBytes(8).toString('hex')
    }, null, 2)}\n`,
    { encoding: 'utf8', mode: 0o600, flag: 'wx' }
  );
}

export function main(argumentsList = process.argv.slice(2)) {
  const expected = ['--out-dir', '--node-index', '--xnode-image'];
  if (argumentsList.length !== expected.length * 2
      || expected.some(name => argumentsList.filter(value => value === name).length !== 1)) {
    throw new Error('Expected exactly --out-dir, --node-index and --xnode-image.');
  }
  process.umask(0o077);
  generateIdentity({
    outputDirectory: argumentValue(argumentsList, '--out-dir'),
    nodeIndex: Number(argumentValue(argumentsList, '--node-index')),
    xnodeImage: argumentValue(argumentsList, '--xnode-image')
  });
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  try {
    main();
  } catch (error) {
    console.error(`First-release identity generation failed closed: ${error.message}`);
    process.exitCode = 1;
  }
}
