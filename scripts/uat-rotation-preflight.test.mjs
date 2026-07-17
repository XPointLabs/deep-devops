import assert from 'node:assert/strict';
import {
  createHash,
  generateKeyPairSync,
  sign
} from 'node:crypto';
import { chmod, mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { preflight } from './uat-rotation-preflight.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repositoryRoot = path.resolve(__dirname, '..');

async function fixture({ omitRegistrationReceipt = false } = {}) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'deep-uat-rotation-'));
  const secretDir = path.join(root, 'secrets');
  await mkdir(secretDir);
  for (const name of ['reward-keeper.env', 'node-1.env', 'node-2.env', 'node-3.env']) {
    const filePath = path.join(secretDir, name);
    await writeFile(filePath, 'VALUE=__REQUIRED_SECRET_NOT_COMMITTED__\n');
    if (process.platform === 'win32') {
      const acl = spawnSync('icacls.exe', [
        filePath,
        '/inheritance:r',
        '/grant:r',
        `${process.env.USERNAME}:F`,
        'SYSTEM:F'
      ], { encoding: 'utf8', windowsHide: true });
      assert.equal(acl.status, 0);
    } else {
      await chmod(filePath, 0o600);
    }
  }
  const retiredRaw = await readFile(path.join(repositoryRoot, 'config', 'retired-uat-public-identities.json'));
  const retired = JSON.parse(retiredRaw.toString('utf8'));
  const payload = {
    schemaVersion: '1.0.0',
    network: retired.network,
    chainId: retired.chainId,
    retiredManifestSha256: createHash('sha256').update(retiredRaw).digest('hex'),
    rotatedOperatorAddresses: retired.retiredOperatorAddresses.map((oldAddress, index) => ({
      oldAddress,
      newAddress: `0x${String(index + 1).padStart(40, '1')}`
    })),
    rotatedRouterPublicIds: retired.retiredRouterPublicIds.map((oldPublicId, index) => ({
      oldPublicId,
      newPublicId: String(index + 1).repeat(64)
    })),
    transactionReceipts: [
      {
        action: 'retired-node-exit-or-revocation',
        chainId: retired.chainId,
        status: 1,
        transactionHash: `0x${'a'.repeat(64)}`,
        blockNumber: 1
      },
      ...omitRegistrationReceipt ? [] : [{
        action: 'replacement-identity-registration',
        chainId: retired.chainId,
        status: 1,
        transactionHash: `0x${'b'.repeat(64)}`,
        blockNumber: 2
      }]
    ]
  };
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const payloadBytes = Buffer.from(JSON.stringify(payload));
  const publicDer = publicKey.export({ type: 'spki', format: 'der' });
  const receipt = {
    schemaVersion: '1.0.0',
    signedPayloadBase64: payloadBytes.toString('base64'),
    signatureBase64: sign(null, payloadBytes, privateKey).toString('base64'),
    signerPublicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString()
  };
  const receiptPath = path.join(root, 'receipt.json');
  await writeFile(receiptPath, `${JSON.stringify(receipt, null, 2)}\n`);
  return {
    root,
    receipt: receiptPath,
    secretDir,
    trustedSignerSha256: createHash('sha256').update(publicDer).digest('hex')
  };
}

test('accepts only a trusted signed receipt bound to retired public fingerprints and successful transaction metadata', async () => {
  const item = await fixture();
  try {
    const result = await preflight(item);
    assert.equal(result.status, 'ok');
    assert.equal(result.secretFileCount, 4);
  } finally {
    await rm(item.root, { recursive: true, force: true });
  }
});

test('fails closed when signed transaction receipt metadata is incomplete', async () => {
  const item = await fixture({ omitRegistrationReceipt: true });
  try {
    await assert.rejects(preflight(item), /lacks successful transaction receipt metadata/);
  } finally {
    await rm(item.root, { recursive: true, force: true });
  }
});
