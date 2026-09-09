import {
  createHash,
  createPublicKey,
  verify
} from 'node:crypto';
import { lstat, readFile, readdir, realpath } from 'node:fs/promises';
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
const DECIMAL_UINT_PATTERN = /^(0|[1-9][0-9]*)$/;
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

function assertExactWindowsAcl(targetPath, isDirectory) {
  const script = [
    "$ErrorActionPreference = 'Stop'",
    '$target = $env:DEEP_ACL_TARGET',
    `$acl = [System.IO.${isDirectory ? 'Directory' : 'File'}]::GetAccessControl($target)`,
    '$owner = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value',
    '$current = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value',
    '$entries = @($acl.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier]) | ForEach-Object {',
    '  $identity = $_.IdentityReference.Value',
    '  [pscustomobject]@{ identity = $identity; type = [string]$_.AccessControlType; rights = [int]$_.FileSystemRights; inherited = $_.IsInherited; inheritance = [int]$_.InheritanceFlags; propagation = [int]$_.PropagationFlags }',
    '})',
    '$attributes = [System.IO.File]::GetAttributes($target)',
    '[pscustomobject]@{ owner = $owner; current = $current; protected = $acl.AreAccessRulesProtected; reparsePoint = (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0); entries = $entries } | ConvertTo-Json -Compress -Depth 5'
  ].join('\n');
  const result = spawnSync('powershell.exe', [
    '-NoLogo', '-NoProfile', '-NonInteractive', '-Command', script
  ], {
    encoding: 'utf8',
    windowsHide: true,
    env: { ...process.env, DEEP_ACL_TARGET: targetPath }
  });
  if (result.status !== 0) {
    const reason = result.error?.code
      ?? result.stderr.trim().split(/\r?\n/u).filter(Boolean).at(-1)
      ?? `exit ${result.status}`;
    throw new Error(`unable to validate exact Windows secret ACL (${reason})`);
  }
  let acl;
  try {
    acl = JSON.parse(result.stdout.trim());
  } catch {
    throw new Error('unable to parse exact Windows secret ACL');
  }
  const entries = Array.isArray(acl.entries) ? acl.entries : acl.entries ? [acl.entries] : [];
  const expectedSids = new Set([String(acl.current).toUpperCase(), 'S-1-5-18']);
  const expectedInheritance = isDirectory ? 3 : 0;
  if (acl.owner !== acl.current
    || acl.protected !== true
    || acl.reparsePoint !== false
    || entries.length !== 2
    || entries.some(entry => !expectedSids.has(String(entry.identity).toUpperCase())
      || entry.type !== 'Allow'
      || entry.rights !== 2032127
      || entry.inherited !== false
      || entry.inheritance !== expectedInheritance
      || entry.propagation !== 0)
    || new Set(entries.map(entry => String(entry.identity).toUpperCase())).size !== 2) {
    throw new Error('secret ACL must grant exact non-inherited full control only to the owner and SYSTEM');
  }
}

async function assertSecretFile(filePath, secretRootReal) {
  const info = await lstat(filePath);
  if (info.isSymbolicLink() || !info.isFile()) throw new Error('secret files must be canonical regular files without reparse points');
  const canonical = await realpath(filePath);
  if (path.dirname(canonical).toLowerCase() !== secretRootReal.toLowerCase()) {
    throw new Error('secret file canonical path escapes the protected directory');
  }
  if (process.platform === 'win32') {
    assertExactWindowsAcl(canonical, false);
  } else if ((info.mode & 0o777) !== 0o600) {
    throw new Error('secret file permissions must be exactly 0600');
  }
}

function exactSet(actual, expected, label) {
  const normalizedExpected = new Set([...expected].map(value => String(value).toLowerCase()));
  const normalizedActual = actual.map(value => String(value).toLowerCase());
  if (actual.length !== normalizedExpected.size
    || new Set(normalizedActual).size !== normalizedActual.length
    || normalizedActual.some(value => !normalizedExpected.has(value))) {
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

function canonicalUintString(value, label) {
  if (!DECIMAL_UINT_PATTERN.test(value ?? '')) throw new Error(`${label} must be a canonical unsigned decimal string`);
  return String(value);
}

function validateRetirementDecodedArgs(decoded, action, binding) {
  const commonKeys = ['serviceNodeID', 'initiator', 'pubkeyDataSha256'];
  exactKeys(
    decoded,
    action === 'service-node-exit' ? [...commonKeys, 'returnedAmount'] : commonKeys,
    'retirement decoded event arguments'
  );
  canonicalAddress(decoded.initiator, 'retirement decoded initiator');
  if (decoded.serviceNodeID !== binding.contractNodeId
    || canonicalFingerprint(decoded.pubkeyDataSha256, 'retirement decoded BLS fingerprint')
      !== binding.blsPublicKeySha256
    || (action === 'service-node-exit'
      && canonicalUintString(decoded.returnedAmount, 'retirement decoded returnedAmount') !== decoded.returnedAmount)) {
    throw new Error('retirement decoded event arguments do not exactly bind the retired public identity');
  }
}

function validateRegistrationDecodedArgs(decoded, item) {
  exactKeys(decoded, [
    'serviceNodeID',
    'initiator',
    'pubkeyDataSha256',
    'serviceNodePubkey',
    'serviceNodeSignature1',
    'serviceNodeSignature2',
    'fee',
    'contributors'
  ], 'registration decoded event arguments');
  if (decoded.serviceNodeID !== item.newContractNodeId
    || canonicalAddress(decoded.initiator, 'registration decoded initiator')
      !== canonicalAddress(item.operatorAddress, 'replacement operator address')
    || canonicalFingerprint(decoded.pubkeyDataSha256, 'registration decoded BLS fingerprint')
      !== canonicalFingerprint(item.blsPublicKeySha256, 'replacement BLS public fingerprint')
    || canonicalFingerprint(decoded.serviceNodePubkey, 'registration decoded router public id')
      !== canonicalFingerprint(item.routerPublicId, 'replacement router public id')
    || !Number.isSafeInteger(decoded.fee)
    || decoded.fee < 0
    || decoded.fee > 65535
    || !Array.isArray(decoded.contributors)
    || decoded.contributors.length === 0) {
    throw new Error('registration decoded event arguments do not exactly bind the replacement identity');
  }
  canonicalUintString(decoded.serviceNodeSignature1, 'registration decoded serviceNodeSignature1');
  canonicalUintString(decoded.serviceNodeSignature2, 'registration decoded serviceNodeSignature2');
  for (const contributor of decoded.contributors) {
    exactKeys(contributor, ['addr', 'beneficiary', 'stakedAmount'], 'registration decoded contributor');
    canonicalAddress(contributor.addr, 'registration decoded contributor address');
    canonicalAddress(contributor.beneficiary, 'registration decoded contributor beneficiary');
    canonicalUintString(contributor.stakedAmount, 'registration decoded contributor stake');
  }
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
    'confirmations',
    'decodedArgs'
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
  if (!transaction.decodedArgs || typeof transaction.decodedArgs !== 'object'
    || Array.isArray(transaction.decodedArgs)) {
    throw new Error(`${label} lacks exact ABI-decoded event arguments`);
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
    'eventAbi',
    'retiredOperatorAddresses',
    'retiredRouterPublicIds',
    'retiredContractNodeIds',
    'retiredNodeBindings'
  ], 'retired UAT identity manifest');
  if (retired.schemaVersion !== '3.0.0'
    || typeof retired.network !== 'string'
    || !Number.isSafeInteger(retired.chainId)
    || !Array.isArray(retired.retiredOperatorAddresses)
    || !Array.isArray(retired.retiredRouterPublicIds)
    || !Array.isArray(retired.retiredContractNodeIds)
    || !Array.isArray(retired.retiredNodeBindings)) {
    throw new Error('retired UAT identity manifest schema is invalid');
  }
  exactKeys(retired.eventAbi, [
    'source',
    'contract',
    'newServiceNodeV2Topic0',
    'serviceNodeExitTopic0',
    'serviceNodeLiquidatedTopic0'
  ], 'retired UAT event ABI provenance');
  if (retired.eventAbi.source !== 'xpoint-staking-contracts/contracts/ServiceNodeRewards.sol'
    || retired.eventAbi.contract !== 'ServiceNodeRewards'
    || retired.eventAbi.newServiceNodeV2Topic0 !== '0xe4329316e9100fa3706d6ee3f89fdc25cc950ff098b7c6a533f6c89b5b7a949c'
    || retired.eventAbi.serviceNodeExitTopic0 !== '0x1869657b8fe34c364e4f67b337513e34de4f0a803d6e53ae13d3c17296d2b7da'
    || retired.eventAbi.serviceNodeLiquidatedTopic0 !== '0x69d6674298663cd2ab512bfbcbffe46965bfb13ada7e933e2befa5044a931716') {
    throw new Error('retired UAT event ABI topics or provenance are invalid');
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
    exactKeys(item, ['contractNodeId', 'routerPublicId', 'blsPublicKeySha256'], 'retired node binding');
    canonicalFingerprint(item.routerPublicId, 'retired node router public id');
    canonicalFingerprint(item.blsPublicKeySha256, 'retired node BLS public fingerprint');
  }
  if (new Set(retired.retiredNodeBindings.map(
    item => String(item.blsPublicKeySha256).toLowerCase()
  )).size !== retired.retiredNodeBindings.length) {
    throw new Error('checked-in retired BLS public fingerprints must be unique');
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
    {
      contractNodeId: item.contractNodeId,
      routerPublicId: String(item.routerPublicId).toLowerCase(),
      blsPublicKeySha256: String(item.blsPublicKeySha256).toLowerCase()
    }
  ]));
  const retiredBlsFingerprints = new Set(
    retired.retiredNodeBindings.map(item => String(item.blsPublicKeySha256).toLowerCase())
  );
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
    const binding = retiredBindings.get(item.contractNodeId);
    if (!['service-node-exit', 'service-node-liquidated'].includes(item.action)
      || binding?.routerPublicId !== oldRouter) {
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
    const expectedTopic = item.action === 'service-node-exit'
      ? retired.eventAbi.serviceNodeExitTopic0
      : retired.eventAbi.serviceNodeLiquidatedTopic0;
    if (item.transaction.eventTopic0.toLowerCase() !== expectedTopic) {
      throw new Error('retired node action uses an event topic outside the checked-in ABI');
    }
    validateRetirementDecodedArgs(
      item.transaction.decodedArgs,
      item.action,
      binding
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
    const oldRouter = retiredBindings.get(item.replacementForContractNodeId)?.routerPublicId;
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
      || blsFingerprints.has(blsFingerprint)
      || retiredBlsFingerprints.has(blsFingerprint)) {
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
    if (item.transaction.eventTopic0.toLowerCase() !== retired.eventAbi.newServiceNodeV2Topic0) {
      throw new Error('replacement registration uses an event topic outside the checked-in ABI');
    }
    validateRegistrationDecodedArgs(item.transaction.decodedArgs, item);
  }

  const secretDir = path.resolve(options.secretDir);
  const directoryInfo = await lstat(secretDir);
  if (directoryInfo.isSymbolicLink() || !directoryInfo.isDirectory()) {
    throw new Error('secret directory must be canonical and contain no reparse point');
  }
  const secretRootReal = await realpath(secretDir);
  const sameCanonicalDirectory = process.platform === 'win32'
    ? secretRootReal.toLowerCase() === secretDir.toLowerCase()
    : secretRootReal === secretDir;
  if (!sameCanonicalDirectory) {
    throw new Error('secret directory must resolve to its exact canonical path');
  }
  if (process.platform === 'win32') {
    assertExactWindowsAcl(secretRootReal, true);
  } else if ((directoryInfo.mode & 0o777) !== 0o700) {
    throw new Error('secret directory permissions must be exactly 0700');
  }
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
