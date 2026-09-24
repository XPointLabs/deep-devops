import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { chmodSync, constants, copyFileSync, existsSync, lstatSync, mkdirSync, readdirSync, renameSync, rmdirSync, rmSync, unlinkSync, writeFileSync, readFileSync } from 'node:fs';
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
  'mailbox-deposit-issuer',
  'mailbox-retrieve-issuer',
];
const mailboxRoles = ['mailbox-deposit-issuer', 'mailbox-retrieve-issuer'];

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

function regularDirectory(directory) {
  const info = lstatSync(directory);
  if (!info.isDirectory() || info.isSymbolicLink()) fail('authority directory is not regular');
}

function regularFile(file) {
  const info = lstatSync(file);
  if (!info.isFile() || info.isSymbolicLink()) fail('authority file is not regular');
}

/** One-time, add-only custody expansion: existing identities are never replaced. */
export function augmentMailbox(argv) {
  if (argv.length !== 2 || argv[0] !== '--authority-root' || !argv[1]) {
    fail('expected exactly --authority-root DIR');
  }
  const root = path.resolve(argv[1]);
  const privateDir = path.join(root, 'private');
  const publicDir = path.join(root, 'public');
  const manifestPath = path.join(publicDir, 'custody-manifest.v1.json');
  for (const directory of [root, privateDir, publicDir]) regularDirectory(directory);
  regularFile(manifestPath);
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
  const originalRoles = roles.filter(role => !mailboxRoles.includes(role));
  if (manifest.schema !== 'deep-production-authority-custody.v1'
      || manifest.environment !== 'prod' || manifest.authorityOwner !== 'Mr. X'
      || !Array.isArray(manifest.roles) || manifest.roles.length !== originalRoles.length
      || new Set(manifest.roles.map(entry => entry.role)).size !== originalRoles.length
      || originalRoles.some(role => !manifest.roles.some(entry => entry.role === role))) {
    fail('custody manifest is not the exact pre-mailbox Mr. X production generation');
  }
  for (const role of originalRoles) {
    const seedPath = path.join(privateDir, `${role}.ed25519.seed`);
    const publicPath = path.join(publicDir, `${role}.ed25519.public`);
    regularFile(seedPath);
    regularFile(publicPath);
    const entry = manifest.roles.find(value => value.role === role);
    const seed = readFileSync(seedPath);
    try {
      if (seed.length !== 32 || entry.keyGeneration !== 0) {
        fail('an existing custody key or generation is invalid');
      }
      const privateDer = Buffer.concat([privatePrefix, seed]);
      const derived = rawKey(createPublicKey(createPrivateKey({
        key: privateDer, format: 'der', type: 'pkcs8',
      })).export({ type: 'spki', format: 'der' }), publicPrefix, 'public key');
      privateDer.fill(0);
      const stored = readFileSync(publicPath);
      const expectedId = createHash('sha256').update('Deep/Production/Authority/Id/v1\0')
        .update(role).update(derived).digest('hex');
      const expectedDomain = createHash('sha256')
        .update('Deep/Production/Authority/Custody/v1\0').update(role).digest('hex');
      if (stored.length !== 32 || !timingSafeEqual(stored, derived)
          || entry.ed25519PublicKeyHex !== derived.toString('hex')
          || entry.authorityIdHex !== expectedId
          || entry.custodyDomainHashHex !== expectedDomain) {
        fail('an existing custody key does not match its public manifest');
      }
    } finally { seed.fill(0); }
  }
  const newFiles = mailboxRoles.flatMap(role => [
    path.join(privateDir, `${role}.ed25519.seed`),
    path.join(publicDir, `${role}.ed25519.public`),
  ]);
  const backupPath = path.join(publicDir, 'custody-manifest.pre-mailbox.v1.json');
  const lockPath = path.join(root, '.mailbox-custody-augmentation.lock');
  if (newFiles.some(existsSync) || existsSync(backupPath) || existsSync(lockPath)) {
    fail('mailbox custody is present or an earlier augmentation needs review');
  }
  writeFileSync(lockPath, 'in-progress\n', { mode: 0o600, flag: 'wx', flush: true });
  setPrivateMode(lockPath);
  const staging = path.join(root, `.mailbox-custody-${randomUUID()}`);
  mkdirSync(staging, { mode: 0o700 });
  const added = [];
  try {
    for (const role of mailboxRoles) {
      const key = newAuthority(role);
      try {
        const seedName = `${role}.ed25519.seed`;
        const publicName = `${role}.ed25519.public`;
        writeFileSync(path.join(staging, seedName), key.seed,
          { mode: 0o600, flag: 'wx', flush: true });
        writeFileSync(path.join(staging, publicName), key.publicKey,
          { mode: 0o600, flag: 'wx', flush: true });
        setPrivateMode(path.join(staging, seedName));
        setPrivateMode(path.join(staging, publicName));
        added.push({
          role, authorityIdHex: key.id.toString('hex'), keyGeneration: 0,
          ed25519PublicKeyHex: key.publicKey.toString('hex'),
          custodyDomainHashHex: key.domain.toString('hex'),
        });
      } finally { key.seed.fill(0); }
    }
    const nextManifest = path.join(staging, 'custody-manifest.v1.json');
    writeFileSync(nextManifest,
      `${JSON.stringify({ ...manifest, roles: [...manifest.roles, ...added] }, null, 2)}\n`,
      { encoding: 'utf8', mode: 0o600, flag: 'wx', flush: true });
    setPrivateMode(nextManifest);
    copyFileSync(manifestPath, backupPath, constants.COPYFILE_EXCL);
    for (const role of mailboxRoles) {
      renameSync(path.join(staging, `${role}.ed25519.seed`),
        path.join(privateDir, `${role}.ed25519.seed`));
      renameSync(path.join(staging, `${role}.ed25519.public`),
        path.join(publicDir, `${role}.ed25519.public`));
    }
    renameSync(nextManifest, manifestPath);
    rmdirSync(staging);
    unlinkSync(lockPath);
    process.stdout.write('Mailbox authority roles added without rotating existing custody.\n');
  } catch (error) {
    // Preserve the lock and staging for review; never silently retry a partial
    // key/manifest transaction or overwrite existing production custody.
    throw error;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  if (process.argv[2] === '--augment-mailbox') augmentMailbox(process.argv.slice(3));
  else main(process.argv.slice(2));
}
