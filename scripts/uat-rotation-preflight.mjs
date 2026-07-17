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
const ADDRESS_PATTERN = /^0x[0-9a-f]{40}$/i;
const HASH_PATTERN = /^0x[0-9a-f]{64}$/i;
const PUBLIC_FINGERPRINT_PATTERN = /^[0-9a-f]{64}$/i;
const MINIMUM_FINALITY_CONFIRMATIONS = 12;

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
  const normalizedExpected = new Set([...expected].map(value => String(value).toLowerCase()));
  if (actual.length !== normalizedExpected.size
    || actual.some(value => !normalizedExpected.has(String(value).toLowerCase()))) {
    throw new Error(`${label} does not exactly cover the expected set`);
  }
}

function exactKeys(value, expected, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    throw new Error(`${label} contains unsupported or missing fields`);
  }
}

function canonicalAddress(value, label) {
  if (!ADDRESS_PATTERN.test(value ?? '')) throw new Error(`${label} must be an EVM address`);
  return String(value).toLowerCase();
}

function canonicalFingerprint(value, label) {
  if (!PUBLIC_FINGERPRINT_PATTERN.test(value ?? '')) {
    throw new Error(`${label} must be a SHA256/public identity fingerprint`);
  }
  return String(value).toLowerCase();
}

function validateTransactionEvidence(
  transaction,
  expectedContract,
  observedFinalizedBlock,
  minimumConfirmations,
  seenTransactions,
  seenLogs,
  label) {
  exactKeys(transaction, [
    'transactionHash',
    'contractAddress',
    'status',
    'blockNumber',
    'blockHash',
    'transactionIndex',
    'logIndex',
    'eventTopic0',
    'confirmations'
  ], `${label} transaction evidence`);
  const transactionHash = String(transaction.transactionHash ?? '').toLowerCase();
  const contractAddress = canonicalAddress(transaction.contractAddress, `${label} contractAddress`);
  const blockHash = String(transaction.blockHash ?? '').toLowerCase();
  const eventTopic0 = String(transaction.eventTopic0 ?? '').toLowerCase();
  if (!HASH_PATTERN.test(transactionHash)
    || !HASH_PATTERN.test(blockHash)
    || !HASH_PATTERN.test(eventTopic0)
    || transaction.status !== 1
    || contractAddress !== expectedContract
    || !Number.isSafeInteger(transaction.blockNumber)
    || transaction.blockNumber <= 0
    || transaction.blockNumber > observedFinalizedBlock
    || !Number.isSafeInteger(transaction.transactionIndex)
    || transaction.transactionIndex < 0
    || !Number.isSafeInteger(transaction.logIndex)
    || transaction.logIndex < 0
    || !Number.isSafeInteger(transaction.confirmations)
    || transaction.confirmations !== observedFinalizedBlock - transaction.blockNumber + 1
    || transaction.confirmations < minimumConfirmations) {
    throw new Error(`${label} lacks exact successful finalized transaction/log evidence`);
  }
  if (seenTransactions.has(transactionHash)) {
    throw new Error('each rotation action must bind a unique transaction hash');
  }
  seenTransactions.add(transactionHash);
  const logBinding = `${contractAddress}:${transactionHash}:${transaction.logIndex}:${eventTopic0}`;
  if (seenLogs.has(logBinding)) throw new Error('rotation transaction log bindings must be unique');
  seenLogs.add(logBinding);
}

export async function preflight(options) {
  const retiredRaw = await readFile(retiredManifestPath);
  const retired = JSON.parse(retiredRaw.toString('utf8'));
  exactKeys(retired, [
    'schemaVersion',
    'network',
    'chainId',
    'serviceNodeRewardsContract',
    'retiredOperatorAddresses',
    'retiredRouterPublicIds',
    'retiredContractNodeIds',
    'retiredNodeBindings'
  ], 'retired UAT identity manifest');
  if (retired.schemaVersion !== '2.0.0'
    || typeof retired.network !== 'string'
    || !Number.isSafeInteger(retired.chainId)
    || !Array.isArray(retired.retiredOperatorAddresses)
    || !Array.isArray(retired.retiredRouterPublicIds)
    || !Array.isArray(retired.retiredContractNodeIds)
    || !Array.isArray(retired.retiredNodeBindings)) {
    throw new Error('retired UAT identity manifest schema is invalid');
  }
  canonicalAddress(retired.serviceNodeRewardsContract, 'retired serviceNodeRewardsContract');
  exactSet(
    retired.retiredNodeBindings.map(item => item.contractNodeId),
    new Set(retired.retiredContractNodeIds),
    'checked-in retired contract node bindings'
  );
  exactSet(
    retired.retiredNodeBindings.map(item => String(item.routerPublicId).toLowerCase()),
    new Set(retired.retiredRouterPublicIds.map(item => String(item).toLowerCase())),
    'checked-in retired router bindings'
  );
  for (const item of retired.retiredNodeBindings) {
    exactKeys(item, ['contractNodeId', 'routerPublicId'], 'retired node binding');
    canonicalFingerprint(item.routerPublicId, 'retired node router public id');
  }
  const receipt = JSON.parse(await readFile(path.resolve(options.receipt), 'utf8'));
  exactKeys(receipt, [
    'schemaVersion',
    'signedPayloadBase64',
    'signatureBase64',
    'signerPublicKeyPem'
  ], 'rotation receipt');
  if (receipt.schemaVersion !== '2.0.0'
    || typeof receipt.signedPayloadBase64 !== 'string'
    || typeof receipt.signatureBase64 !== 'string'
    || typeof receipt.signerPublicKeyPem !== 'string') throw new Error('rotation receipt schema is invalid');
  const publicKey = createPublicKey(receipt.signerPublicKeyPem);
  if (publicKey.asymmetricKeyType !== 'ed25519') {
    throw new Error('rotation receipt signer must use Ed25519');
  }
  const signerDer = publicKey.export({ type: 'spki', format: 'der' });
  if (sha256(signerDer) !== options.trustedSignerSha256.toLowerCase()) {
    throw new Error('rotation receipt signer is not the trusted Mr. X signing key');
  }
  const payloadBytes = Buffer.from(receipt.signedPayloadBase64, 'base64');
  if (!verify(null, payloadBytes, publicKey, Buffer.from(receipt.signatureBase64, 'base64'))) {
    throw new Error('rotation receipt signature verification failed');
  }
  const payload = JSON.parse(payloadBytes.toString('utf8'));
  exactKeys(payload, [
    'schemaVersion',
    'attestationType',
    'attestationScope',
    'attestedAtUtc',
    'retiredManifestSha256',
    'network',
    'chainId',
    'serviceNodeRewardsContract',
    'observedFinalizedBlock',
    'minimumConfirmations',
    'rotatedOperatorAddresses',
    'rotatedRouterPublicIds',
    'retiredNodeActions',
    'replacementRegistrations'
  ], 'signed rotation payload');
  if (payload.schemaVersion !== '2.0.0'
    || payload.attestationType !== 'mr-x-human-verified-chain-state-v1'
    || payload.attestationScope !== 'offline-human-attestation-no-rpc-proof'
    || !Number.isFinite(Date.parse(payload.attestedAtUtc ?? ''))
    || payload.retiredManifestSha256 !== sha256(retiredRaw)
    || payload.network !== retired.network
    || payload.chainId !== retired.chainId
    || canonicalAddress(payload.serviceNodeRewardsContract, 'serviceNodeRewardsContract')
      !== canonicalAddress(retired.serviceNodeRewardsContract, 'retired serviceNodeRewardsContract')
    || !Number.isSafeInteger(payload.observedFinalizedBlock)
    || payload.observedFinalizedBlock <= 0
    || !Number.isSafeInteger(payload.minimumConfirmations)
    || payload.minimumConfirmations < MINIMUM_FINALITY_CONFIRMATIONS) {
    throw new Error('signed rotation payload does not bind the retired UAT manifest and chain');
  }
  if (!Array.isArray(payload.rotatedOperatorAddresses)
    || !Array.isArray(payload.rotatedRouterPublicIds)
    || !Array.isArray(payload.retiredNodeActions)
    || !Array.isArray(payload.replacementRegistrations)) {
    throw new Error('signed rotation payload mapping collections are invalid');
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
  const newOperators = new Set();
  for (const item of payload.rotatedOperatorAddresses) {
    exactKeys(item, ['oldAddress', 'newAddress'], 'operator rotation mapping');
    const oldValue = canonicalAddress(item.oldAddress, 'old operator address');
    const newValue = canonicalAddress(item.newAddress, 'new operator address');
    if (oldValue === newValue || newOperators.has(newValue)) {
      throw new Error('replacement operator identity must be new and unique');
    }
    newOperators.add(newValue);
  }
  const routerReplacements = new Map();
  for (const item of payload.rotatedRouterPublicIds) {
    exactKeys(item, ['oldPublicId', 'newPublicId'], 'router rotation mapping');
    const oldValue = canonicalFingerprint(item.oldPublicId, 'old router public id');
    const newValue = canonicalFingerprint(item.newPublicId, 'new router public id');
    if (oldValue === newValue || routerReplacements.has(oldValue)
      || [...routerReplacements.values()].includes(newValue)
      || retired.retiredRouterPublicIds.some(value => value.toLowerCase() === newValue)) {
      throw new Error('replacement router identity must be new and unique');
    }
    routerReplacements.set(oldValue, newValue);
  }

  const retiredBindings = new Map(retired.retiredNodeBindings.map(item => [
    item.contractNodeId,
    String(item.routerPublicId).toLowerCase()
  ]));
  exactSet(
    payload.retiredNodeActions.map(item => item.contractNodeId),
    new Set(retired.retiredContractNodeIds),
    'retired contract node action mapping'
  );
  const seenTransactions = new Set();
  const seenLogs = new Set();
  for (const item of payload.retiredNodeActions) {
    exactKeys(item, [
      'contractNodeId',
      'oldRouterPublicId',
      'action',
      'transaction'
    ], 'retired node action');
    const oldRouter = canonicalFingerprint(item.oldRouterPublicId, 'retired action router public id');
    if (item.action !== 'exit-or-revocation'
      || retiredBindings.get(item.contractNodeId) !== oldRouter) {
      throw new Error('retired node action does not match the checked-in node binding');
    }
    validateTransactionEvidence(
      item.transaction,
      canonicalAddress(retired.serviceNodeRewardsContract, 'retired serviceNodeRewardsContract'),
      payload.observedFinalizedBlock,
      payload.minimumConfirmations,
      seenTransactions,
      seenLogs,
      `retired node ${item.contractNodeId}`
    );
  }

  exactSet(
    payload.replacementRegistrations.map(item => item.replacementForContractNodeId),
    new Set(retired.retiredContractNodeIds),
    'replacement registration mapping'
  );
  const newContractNodeIds = new Set();
  const blsFingerprints = new Set();
  for (const item of payload.replacementRegistrations) {
    exactKeys(item, [
      'replacementForContractNodeId',
      'newContractNodeId',
      'operatorAddress',
      'routerPublicId',
      'blsPublicKeySha256',
      'action',
      'transaction'
    ], 'replacement registration');
    const oldRouter = retiredBindings.get(item.replacementForContractNodeId);
    const newRouter = canonicalFingerprint(item.routerPublicId, 'replacement router public id');
    const blsFingerprint = canonicalFingerprint(item.blsPublicKeySha256, 'replacement BLS public fingerprint');
    const operator = canonicalAddress(item.operatorAddress, 'replacement operator address');
    if (item.action !== 'replacement-identity-registration'
      || routerReplacements.get(oldRouter) !== newRouter
      || !newOperators.has(operator)
      || !Number.isSafeInteger(item.newContractNodeId)
      || item.newContractNodeId <= 0
      || retired.retiredContractNodeIds.includes(item.newContractNodeId)
      || newContractNodeIds.has(item.newContractNodeId)
      || blsFingerprints.has(blsFingerprint)) {
      throw new Error('replacement registration mapping is incomplete, reused, or inconsistent');
    }
    newContractNodeIds.add(item.newContractNodeId);
    blsFingerprints.add(blsFingerprint);
    validateTransactionEvidence(
      item.transaction,
      canonicalAddress(retired.serviceNodeRewardsContract, 'retired serviceNodeRewardsContract'),
      payload.observedFinalizedBlock,
      payload.minimumConfirmations,
      seenTransactions,
      seenLogs,
      `replacement node ${item.newContractNodeId}`
    );
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
    schemaVersion: '2.0.0',
    status: 'accepted-human-offline-attestation',
    proofKind: 'mr-x-signed-offline-attestation-not-independent-on-chain-proof',
    uatRestartAuthorized: false,
    productionReady: false,
    retiredPublicIdentityCount: retired.retiredOperatorAddresses.length + retired.retiredRouterPublicIds.length,
    retiredNodeActionCount: payload.retiredNodeActions.length,
    replacementRegistrationCount: payload.replacementRegistrations.length,
    transactionEvidenceCount: seenTransactions.size,
    secretFileCount: names.length
  };
}

export async function main(argv = process.argv.slice(2)) {
  const result = await preflight(parse(argv));
  console.log(
    `UAT rotation offline attestation accepted (${result.retiredPublicIdentityCount} retired public identities covered); UAT restart remains blocked.`
  );
  return result;
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  main().catch(error => {
    console.error(`UAT rotation preflight failed closed: ${error.message}`);
    process.exitCode = 1;
  });
}
