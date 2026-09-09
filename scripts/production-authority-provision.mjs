import { createHash, generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, readdirSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const privatePrefix = Buffer.from('302e020100300506032b657004220420', 'hex');
const publicPrefix = Buffer.from('302a300506032b6570032100', 'hex');
const roles = [
  'offline-root-1',
  'network-witness-1',
  'network-witness-2',
  'network-witness-3',
  'registry-dtt-signer-1',
  'registry-dtt-signer-2',
  'registry-dtt-signer-3',
  'msg-authenticated-evidence',
  'contact-xpk',
  'group-gsr1-dcr1',
];

function fail(message) {
  throw new Error(`Production authority provisioning failed closed: ${message}`);
}

function rawKey(der, prefix, name) {
  const bytes = Buffer.from(der);
  if (bytes.length !== prefix.length + 32 || !bytes.subarray(0, prefix.length).equals(prefix)) {
    fail(`unexpected Ed25519 ${name} DER shape`);
  }
  return bytes.subarray(prefix.length);
}

function newAuthority(role) {
  const pair = generateKeyPairSync('ed25519');
  const seed = rawKey(pair.privateKey.export({ type: 'pkcs8', format: 'der' }), privatePrefix, 'private key');
  const publicKey = rawKey(pair.publicKey.export({ type: 'spki', format: 'der' }), publicPrefix, 'public key');
  const id = createHash('sha256').update('Deep/Production/Authority/Id/v1\0').update(role).update(publicKey).digest();
  const domain = createHash('sha256').update('Deep/Production/Authority/Custody/v1\0').update(role).digest();
  return { seed, publicKey, id, domain };
}

function requireEmptyTarget(target) {
  if (!existsSync(target)) return;
  if (readdirSync(target).length !== 0) fail('target already exists and is not empty');
  rmSync(target, { recursive: false });
}

function setPrivateMode(file) {
  if (process.platform !== 'win32') chmodSync(file, 0o600);
}

export function main(argv) {
  if (argv.length !== 2 || argv[0] !== '--out-dir' || !argv[1]) {
    fail('expected exactly --out-dir DIR');
  }
  const target = path.resolve(argv[1]);
  requireEmptyTarget(target);
  const parent = path.dirname(target);
  mkdirSync(parent, { recursive: true });
  const staging = path.join(parent, `.authority-provision-${randomUUID()}`);
  const privateDir = path.join(staging, 'private');
  const publicDir = path.join(staging, 'public');
  process.umask(0o077);
  mkdirSync(privateDir, { recursive: true, mode: 0o700 });
  mkdirSync(publicDir, { recursive: true, mode: 0o700 });

  const manifestRoles = [];
  try {
    for (const role of roles) {
      const key = newAuthority(role);
      const privatePath = path.join(privateDir, `${role}.ed25519.seed`);
      const publicPath = path.join(publicDir, `${role}.ed25519.public`);
      writeFileSync(privatePath, key.seed, { mode: 0o600, flag: 'wx' });
      writeFileSync(publicPath, key.publicKey, { mode: 0o600, flag: 'wx' });
      setPrivateMode(privatePath);
      setPrivateMode(publicPath);
      manifestRoles.push({
        role,
        authorityIdHex: key.id.toString('hex'),
        keyGeneration: 0,
        ed25519PublicKeyHex: key.publicKey.toString('hex'),
        custodyDomainHashHex: key.domain.toString('hex'),
      });
      key.seed.fill(0);
    }

    for (const name of ['trusted-time-integrity', 'request-ledger-integrity', 'artifact-state-integrity']) {
      const secretPath = path.join(privateDir, `${name}.key`);
      writeFileSync(secretPath, randomBytes(32), { mode: 0o600, flag: 'wx' });
      setPrivateMode(secretPath);
    }

    const manifest = {
      schema: 'deep-production-authority-custody.v1',
      environment: 'prod',
      authorityOwner: 'Mr. X',
      operatorModel: 'single-operator-temporary',
      networkIdHex: randomBytes(16).toString('hex'),
      thresholds: {
        offlineRoot: '1-of-1',
        networkWitnesses: '2-of-3',
        registryDtt: '2-of-3',
      },
      distribution: {
        offlineRootPrivateKey: 'local-only-never-deploy',
        serverPrivateKeys: [
          'registry-dtt-signer-*',
          'msg-authenticated-evidence',
          'contact-xpk',
          'group-gsr1-dcr1',
        ],
      },
      roles: manifestRoles,
    };
    writeFileSync(path.join(publicDir, 'custody-manifest.v1.json'), `${JSON.stringify(manifest, null, 2)}\n`, {
      encoding: 'utf8', mode: 0o600, flag: 'wx',
    });
    renameSync(staging, target);
  } catch (error) {
    rmSync(staging, { recursive: true, force: true });
    throw error;
  }
  process.stdout.write('Production authority custody provisioned without exporting private values.\n');
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  main(process.argv.slice(2));
}
