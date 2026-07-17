import {
  createHash,
  createPublicKey,
  verify
} from 'node:crypto';
import { lstat, readFile, readdir, realpath, stat } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repositoryRoot = path.resolve(__dirname, '..');
const retiredManifestPath = path.join(repositoryRoot, 'config', 'retired-uat-public-identities.json');
const expectedSecretFiles = new Set([
  'reward-keeper.env', 'node-1.env', 'node-2.env', 'node-3.env'
]);

function parse(argv) {
  const options = {};
  for (let index = 0; index < argv.length; index += 2) {
    const name = argv[index];
    const value = argv[index + 1];
    if (!value || value.startsWith('--')) throw new Error(`${name} requires a value`);
    if (name === '--receipt') options.receipt = value;
    else if (name === '--secret-dir') options.secretDir = value;
    else if (name === '--trusted-signer-sha256') options.trustedSignerSha256 = value;
    else throw new Error(`unknown argument: ${name}`);
  }
  options.trustedSignerSha256 ??= process.env.DEEP_UAT_ROTATION_SIGNER_SHA256;
  if (!options.receipt || !options.secretDir || !/^[0-9a-f]{64}$/i.test(options.trustedSignerSha256 ?? '')) {
    throw new Error('receipt, secret directory, and trusted signer SHA256 are required');
  }
  return options;
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

async function assertSecretFile(filePath, secretRootReal) {
  const info = await lstat(filePath);
  if (info.isSymbolicLink() || !info.isFile()) throw new Error('secret files must be canonical regular files without reparse points');
  const canonical = await realpath(filePath);
  if (path.dirname(canonical).toLowerCase() !== secretRootReal.toLowerCase()) {
    throw new Error('secret file canonical path escapes the protected directory');
  }
  if (process.platform === 'win32') {
    const acl = spawnSync('icacls.exe', [canonical], { encoding: 'utf8', windowsHide: true });
    if (acl.status !== 0) throw new Error('unable to validate secret file ACL');
    if (/(Everyone|BUILTIN\\Users|Authenticated Users|APPLICATION PACKAGE AUTHORITY)/i.test(acl.stdout)) {
      throw new Error('secret file ACL grants access to a broad principal');
    }
  } else if ((info.mode & 0o077) !== 0) {
    throw new Error('secret file permissions must not grant group or world access');
  }
}

function exactSet(actual, expected, label) {
  if (actual.length !== expected.size || actual.some(value => !expected.has(String(value).toLowerCase()))) {
    throw new Error(`${label} does not exactly cover every retired public identity`);
  }
}

export async function preflight(options) {
  const retiredRaw = await readFile(retiredManifestPath);
  const retired = JSON.parse(retiredRaw.toString('utf8'));
  const receipt = JSON.parse(await readFile(path.resolve(options.receipt), 'utf8'));
  if (receipt.schemaVersion !== '1.0.0'
    || typeof receipt.signedPayloadBase64 !== 'string'
    || typeof receipt.signatureBase64 !== 'string'
    || typeof receipt.signerPublicKeyPem !== 'string') {
    throw new Error('rotation receipt schema is invalid');
  }
  const publicKey = createPublicKey(receipt.signerPublicKeyPem);
  const signerDer = publicKey.export({ type: 'spki', format: 'der' });
  if (sha256(signerDer) !== options.trustedSignerSha256.toLowerCase()) {
    throw new Error('rotation receipt signer is not the trusted Mr. X signing key');
  }
  const payloadBytes = Buffer.from(receipt.signedPayloadBase64, 'base64');
  if (!verify(null, payloadBytes, publicKey, Buffer.from(receipt.signatureBase64, 'base64'))) {
    throw new Error('rotation receipt signature verification failed');
  }
  const payload = JSON.parse(payloadBytes.toString('utf8'));
  if (payload.schemaVersion !== '1.0.0'
    || payload.retiredManifestSha256 !== sha256(retiredRaw)
    || payload.network !== retired.network
    || payload.chainId !== retired.chainId) {
    throw new Error('signed rotation payload does not bind the retired UAT manifest and chain');
  }
  exactSet(
    payload.rotatedOperatorAddresses?.map(item => String(item.oldAddress).toLowerCase()) ?? [],
    new Set(retired.retiredOperatorAddresses.map(item => item.toLowerCase())),
    'operator rotation'
  );
  exactSet(
    payload.rotatedRouterPublicIds?.map(item => String(item.oldPublicId).toLowerCase()) ?? [],
    new Set(retired.retiredRouterPublicIds.map(item => item.toLowerCase())),
    'router rotation'
  );
  for (const item of [...payload.rotatedOperatorAddresses, ...payload.rotatedRouterPublicIds]) {
    const oldValue = String(item.oldAddress ?? item.oldPublicId).toLowerCase();
    const newValue = String(item.newAddress ?? item.newPublicId).toLowerCase();
    if (!newValue || oldValue === newValue) throw new Error('replacement public identity must differ from retired identity');
  }
  const requiredActions = new Set(retired.requiredOnChainActions);
  const receipts = payload.transactionReceipts ?? [];
  for (const action of requiredActions) {
    const transaction = receipts.find(item => item.action === action);
    if (!transaction
      || transaction.chainId !== retired.chainId
      || transaction.status !== 1
      || !/^0x[0-9a-f]{64}$/i.test(transaction.transactionHash ?? '')
      || !Number.isSafeInteger(transaction.blockNumber)
      || transaction.blockNumber <= 0) {
      throw new Error(`signed rotation payload lacks successful transaction receipt metadata for ${action}`);
    }
  }

  const secretDir = path.resolve(options.secretDir);
  const directoryInfo = await lstat(secretDir);
  if (directoryInfo.isSymbolicLink() || !directoryInfo.isDirectory()) {
    throw new Error('secret directory must be canonical and contain no reparse point');
  }
  const secretRootReal = await realpath(secretDir);
  const entries = await readdir(secretDir, { withFileTypes: true });
  if (entries.some(entry => entry.isSymbolicLink() || !entry.isFile())) {
    throw new Error('secret directory may contain only canonical regular files');
  }
  const names = entries.map(entry => entry.name);
  if (names.length !== expectedSecretFiles.size || names.some(name => !expectedSecretFiles.has(name))) {
    throw new Error('secret directory must contain exactly the four expected UAT secret files');
  }
  for (const name of names) await assertSecretFile(path.join(secretDir, name), secretRootReal);
  return {
    schemaVersion: '1.0.0',
    status: 'ok',
    retiredPublicIdentityCount: retired.retiredOperatorAddresses.length + retired.retiredRouterPublicIds.length,
    transactionReceiptCount: receipts.length,
    secretFileCount: names.length
  };
}

export async function main(argv = process.argv.slice(2)) {
  const result = await preflight(parse(argv));
  console.log(`UAT rotation preflight passed (${result.retiredPublicIdentityCount} retired public identities covered).`);
  return result;
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  main().catch(error => {
    console.error(`UAT rotation preflight failed closed: ${error.message}`);
    process.exitCode = 1;
  });
}
