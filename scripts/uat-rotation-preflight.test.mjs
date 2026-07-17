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

function transactionEvidence(
  index,
  contractAddress,
  eventTopic0,
  decodedArgs,
  observedFinalizedBlock = 1000
) {
  const blockNumber = 900 + index;
  return {
    transactionHash: `0x${index.toString(16).padStart(64, '0')}`,
    contractAddress,
    status: 1,
    blockNumber,
    blockHash: `0x${(100 + index).toString(16).padStart(64, '0')}`,
    transactionIndex: index,
    logIndex: index,
    eventTopic0,
    confirmations: observedFinalizedBlock - blockNumber + 1,
    decodedArgs
  };
}

async function fixture({
  omitRegistration = false,
  duplicateTransaction = false,
  insufficientFinality = false,
  wrongContract = false,
  reusedReplacementIdentity = false,
  wrongEventTopic = false,
  wrongDecodedArguments = false,
  reusedRetiredBlsIdentity = false,
  duplicateRetiredCoverage = false,
  duplicateReplacementCoverage = false,
  permissiveAcl = false
} = {}) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'deep-uat-rotation-'));
  const secretDir = path.join(root, 'secrets');
  await mkdir(secretDir);
  if (process.platform === 'win32') {
    const directoryAcl = spawnSync('icacls.exe', [
      secretDir,
      '/inheritance:r',
      '/grant:r',
      `${process.env.USERNAME}:(OI)(CI)F`,
      'SYSTEM:(OI)(CI)F'
    ], { encoding: 'utf8', windowsHide: true });
    assert.equal(directoryAcl.status, 0, directoryAcl.stderr);
  } else {
    await chmod(secretDir, 0o700);
  }
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
  const observedFinalizedBlock = 1000;
  const rotatedOperatorAddresses = retired.retiredOperatorAddresses.map((oldAddress, index) => ({
    oldAddress,
    newAddress: `0x${String(index + 1).repeat(40)}`
  }));
  const rotatedRouterPublicIds = retired.retiredRouterPublicIds.map((oldPublicId, index) => ({
    oldPublicId,
    newPublicId: String(index + 1).repeat(64)
  }));
  const retiredNodeActions = retired.retiredNodeBindings.map((binding, index) => ({
    contractNodeId: binding.contractNodeId,
    oldRouterPublicId: binding.routerPublicId,
    action: 'service-node-exit',
    transaction: transactionEvidence(
      index + 1,
      retired.serviceNodeRewardsContract,
      retired.eventAbi.serviceNodeExitTopic0,
      {
        serviceNodeID: binding.contractNodeId,
        initiator: retired.retiredOperatorAddresses[0],
        pubkeyDataSha256: binding.blsPublicKeySha256,
        returnedAmount: '1000000000000000000'
      },
      observedFinalizedBlock
    )
  }));
  const replacementRegistrations = retired.retiredNodeBindings.map((binding, index) => ({
    replacementForContractNodeId: binding.contractNodeId,
    newContractNodeId: 7 + index,
    operatorAddress: rotatedOperatorAddresses[0].newAddress,
    routerPublicId: rotatedRouterPublicIds[index].newPublicId,
    blsPublicKeySha256: String.fromCharCode(97 + index).repeat(64),
    action: 'replacement-identity-registration',
    transaction: transactionEvidence(
      index + 4,
      retired.serviceNodeRewardsContract,
      retired.eventAbi.newServiceNodeV2Topic0,
      {
        serviceNodeID: 7 + index,
        initiator: rotatedOperatorAddresses[0].newAddress,
        pubkeyDataSha256: String.fromCharCode(97 + index).repeat(64),
        serviceNodePubkey: rotatedRouterPublicIds[index].newPublicId,
        serviceNodeSignature1: String(1000 + index),
        serviceNodeSignature2: String(2000 + index),
        fee: 100,
        contributors: [{
          addr: rotatedOperatorAddresses[0].newAddress,
          beneficiary: rotatedOperatorAddresses[0].newAddress,
          stakedAmount: '15000000000000000000000'
        }]
      },
      observedFinalizedBlock
    )
  }));
  if (omitRegistration) replacementRegistrations.pop();
  if (duplicateTransaction) {
    replacementRegistrations[0].transaction = structuredClone(retiredNodeActions[0].transaction);
  }
  if (insufficientFinality) {
    replacementRegistrations[0].transaction.blockNumber = 995;
    replacementRegistrations[0].transaction.confirmations = 6;
  }
  if (wrongContract) {
    replacementRegistrations[0].transaction.contractAddress = `0x${'9'.repeat(40)}`;
  }
  if (reusedReplacementIdentity) {
    replacementRegistrations[1].routerPublicId = replacementRegistrations[0].routerPublicId;
  }
  if (wrongEventTopic) {
    replacementRegistrations[0].transaction.eventTopic0 = retired.eventAbi.serviceNodeExitTopic0;
  }
  if (wrongDecodedArguments) {
    replacementRegistrations[0].transaction.decodedArgs.serviceNodeID = 999;
  }
  if (reusedRetiredBlsIdentity) {
    replacementRegistrations[0].blsPublicKeySha256 = retired.retiredNodeBindings[0].blsPublicKeySha256;
    replacementRegistrations[0].transaction.decodedArgs.pubkeyDataSha256 =
      retired.retiredNodeBindings[0].blsPublicKeySha256;
  }
  if (duplicateRetiredCoverage) {
    retiredNodeActions[2].contractNodeId = retiredNodeActions[0].contractNodeId;
    retiredNodeActions[2].oldRouterPublicId = retiredNodeActions[0].oldRouterPublicId;
    retiredNodeActions[2].transaction.decodedArgs.serviceNodeID = retiredNodeActions[0].contractNodeId;
    retiredNodeActions[2].transaction.decodedArgs.pubkeyDataSha256 =
      retiredNodeActions[0].transaction.decodedArgs.pubkeyDataSha256;
  }
  if (duplicateReplacementCoverage) {
    replacementRegistrations[2].replacementForContractNodeId =
      replacementRegistrations[0].replacementForContractNodeId;
  }
  if (permissiveAcl) {
    if (process.platform === 'win32') {
      const acl = spawnSync('icacls.exe', [
        secretDir,
        '/grant',
        'Everyone:(RX)'
      ], { encoding: 'utf8', windowsHide: true });
      assert.equal(acl.status, 0, acl.stderr);
    } else {
      await chmod(secretDir, 0o750);
    }
  }
  const payload = {
    schemaVersion: '2.0.0',
    attestationType: 'mr-x-human-verified-chain-state-v1',
    attestationScope: 'offline-human-attestation-no-rpc-proof',
    attestedAtUtc: '2026-07-18T00:00:00.000Z',
    network: retired.network,
    chainId: retired.chainId,
    serviceNodeRewardsContract: retired.serviceNodeRewardsContract,
    retiredManifestSha256: createHash('sha256').update(retiredRaw).digest('hex'),
    observedFinalizedBlock,
    minimumConfirmations: 12,
    rotatedOperatorAddresses,
    rotatedRouterPublicIds,
    retiredNodeActions,
    replacementRegistrations
  };
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const payloadBytes = Buffer.from(JSON.stringify(payload));
  const publicDer = publicKey.export({ type: 'spki', format: 'der' });
  const receipt = {
    schemaVersion: '2.0.0',
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

test('accepts only a trusted Mr. X offline attestation with exact finalized node mappings', async () => {
  const item = await fixture();
  try {
    const result = await preflight(item);
    assert.equal(result.status, 'accepted-human-offline-attestation');
    assert.equal(result.uatRestartAuthorized, false);
    assert.equal(result.productionReady, false);
    assert.equal(result.retiredNodeActionCount, 3);
    assert.equal(result.replacementRegistrationCount, 3);
    assert.equal(result.transactionEvidenceCount, 6);
    assert.equal(result.secretFileCount, 4);
  } finally {
    await rm(item.root, { recursive: true, force: true });
  }
});

test('fails closed when a replacement registration mapping is missing', async () => {
  const item = await fixture({ omitRegistration: true });
  try {
    await assert.rejects(preflight(item), /does not exactly cover the expected set/);
  } finally {
    await rm(item.root, { recursive: true, force: true });
  }
});

test('fails closed when duplicate retired IDs hide a missing identity', async () => {
  const item = await fixture({ duplicateRetiredCoverage: true });
  try {
    await assert.rejects(preflight(item), /does not exactly cover/);
  } finally {
    await rm(item.root, { recursive: true, force: true });
  }
});

test('fails closed when duplicate replacement mappings hide a missing retired identity', async () => {
  const item = await fixture({ duplicateReplacementCoverage: true });
  try {
    await assert.rejects(preflight(item), /does not exactly cover/);
  } finally {
    await rm(item.root, { recursive: true, force: true });
  }
});

test('fails closed when two node actions reuse a synthetic transaction fixture', async () => {
  const item = await fixture({ duplicateTransaction: true });
  try {
    await assert.rejects(preflight(item), /unique transaction hash/);
  } finally {
    await rm(item.root, { recursive: true, force: true });
  }
});

test('fails closed when signed offline evidence lacks minimum finality', async () => {
  const item = await fixture({ insufficientFinality: true });
  try {
    await assert.rejects(preflight(item), /finalized transaction\/log evidence/);
  } finally {
    await rm(item.root, { recursive: true, force: true });
  }
});

test('fails closed when transaction evidence targets a different contract', async () => {
  const item = await fixture({ wrongContract: true });
  try {
    await assert.rejects(preflight(item), /finalized transaction\/log evidence/);
  } finally {
    await rm(item.root, { recursive: true, force: true });
  }
});

test('fails closed when a replacement router identity is reused', async () => {
  const item = await fixture({ reusedReplacementIdentity: true });
  try {
    await assert.rejects(preflight(item), /incomplete, reused, or inconsistent/);
  } finally {
    await rm(item.root, { recursive: true, force: true });
  }
});

test('fails closed when an event topic is not the exact ABI-derived topic', async () => {
  const item = await fixture({ wrongEventTopic: true });
  try {
    await assert.rejects(preflight(item), /event topic outside the checked-in ABI/);
  } finally {
    await rm(item.root, { recursive: true, force: true });
  }
});

test('fails closed when decoded event arguments do not bind the signed mapping', async () => {
  const item = await fixture({ wrongDecodedArguments: true });
  try {
    await assert.rejects(preflight(item), /decoded event arguments do not exactly bind/);
  } finally {
    await rm(item.root, { recursive: true, force: true });
  }
});

test('fails closed when a replacement reuses a retired BLS public identity', async () => {
  const item = await fixture({ reusedRetiredBlsIdentity: true });
  try {
    await assert.rejects(preflight(item), /incomplete, reused, or inconsistent/);
  } finally {
    await rm(item.root, { recursive: true, force: true });
  }
});

test('fails closed when the secret directory ACL or mode grants an extra principal', async () => {
  const item = await fixture({ permissiveAcl: true });
  try {
    await assert.rejects(
      preflight(item),
      process.platform === 'win32' ? /exact non-inherited full control/ : /exactly 0700/
    );
  } finally {
    await rm(item.root, { recursive: true, force: true });
  }
});
