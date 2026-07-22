import { readFileSync, writeFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

function fail(message) { throw new Error(`P15C local contract manifest failure: ${message}`); }
const requiredContracts = Object.freeze(['token', 'serviceNodeRewards', 'serviceNodeContributionFactory', 'rewardRatePool']);

function exactKeys(value, expected) {
  return value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).sort().join(',') === [...expected].sort().join(',');
}

export function addressesForCodeQuery(manifest) {
  return requiredContracts.map(name => manifest.contracts?.[name]);
}

export function validateLocalContractManifest(manifest, observation) {
  if (!manifest || manifest.schema !== 'deep-p15c-local-contracts.v1' || manifest.network !== 'localhost' || typeof manifest.chainId !== 'number' || manifest.chainId !== 31337 || observation?.chainIdHex !== '0x7a69') fail('local chain identity must be exact schema/localhost/31337');
  if (!exactKeys(manifest.contracts, requiredContracts) || !exactKeys(manifest.deployBlocks, requiredContracts)) fail('local manifest contract/deploy-block key set is invalid');
  const addresses = addressesForCodeQuery(manifest);
  if (addresses.some(value => !/^0x[0-9a-fA-F]{40}$/.test(value ?? '') || /^0x0{40}$/i.test(value))) fail('required contract address is missing or zero');
  if (new Set(addresses.map(value => value.toLowerCase())).size !== addresses.length) fail('contract addresses must be unique');
  for (const name of requiredContracts) {
    const block = manifest.deployBlocks[name];
    if (typeof block !== 'number' || !Number.isSafeInteger(block) || block < 1) fail(`deploy block is invalid for ${name}`);
    const code = observation.code?.[manifest.contracts[name].toLowerCase()];
    if (typeof code !== 'string' || !/^0x[0-9a-f]+$/i.test(code) || code === '0x' || code === '0x0') fail(`deployed bytecode is missing for ${name}`);
  }
  return true;
}

async function rpc(url, method, params = [], fetchImpl = fetch) {
  const response = await fetchImpl(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }), signal: AbortSignal.timeout(5000) });
  if (!response.ok) fail('local RPC request failed');
  const value = await response.json();
  if (value.error) fail('local RPC returned an error');
  return value.result;
}

export async function observeAndValidateLocalContractManifest(manifest, rpcUrl, fetchImpl = fetch) {
  const chainIdHex = await rpc(rpcUrl, 'eth_chainId', [], fetchImpl);
  const code = {};
  for (const address of addressesForCodeQuery(manifest)) {
    if (/^0x[0-9a-fA-F]{40}$/.test(address ?? '')) code[address.toLowerCase()] = await rpc(rpcUrl, 'eth_getCode', [address, 'latest'], fetchImpl);
  }
  validateLocalContractManifest(manifest, { chainIdHex, code });
  return true;
}

async function main() {
  const [command, manifestPath, outputOrRpc, maybeRpc] = process.argv.slice(2);
  if (command === 'validate-shape' && manifestPath) {
    const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
    const code = Object.fromEntries(addressesForCodeQuery(manifest).map(address => [String(address).toLowerCase(), '0x01']));
    validateLocalContractManifest(manifest, { chainIdHex: '0x7a69', code });
    return;
  }
  const rpcUrl = command === 'normalize' ? maybeRpc : outputOrRpc;
  if (!['validate', 'normalize'].includes(command) || !manifestPath || !/^http:\/\/(?:127\.0\.0\.1|localhost):\d+$/.test(rpcUrl ?? '')) fail('command is invalid');
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
  if (command === 'normalize') {
    const chainIdHex = await rpc(rpcUrl, 'eth_chainId');
    const rawRequired = requiredContracts;
    const normalized = {
      schema: 'deep-p15c-local-contracts.v1', network: 'localhost', chainId: 31337,
      contracts: Object.fromEntries(rawRequired.map(name => [name, manifest.contracts?.[name]])),
      deployBlocks: Object.fromEntries(rawRequired.map(name => [name, Number(manifest.deployBlocks?.[name] ?? manifest.deploymentTransactions?.[name]?.blockNumber)]))
    };
    const code = {};
    for (const address of addressesForCodeQuery(normalized)) if (/^0x[0-9a-fA-F]{40}$/.test(address)) code[address.toLowerCase()] = await rpc(rpcUrl, 'eth_getCode', [address, 'latest']);
    validateLocalContractManifest(normalized, { chainIdHex, code });
    if (!outputOrRpc) fail('normalized manifest output is missing');
    writeFileSync(outputOrRpc, `${JSON.stringify(normalized, null, 2)}\n`, { encoding: 'utf8', flag: 'wx' });
    return;
  }
  await observeAndValidateLocalContractManifest(manifest, rpcUrl);
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) main().catch(error => { console.error(error.message); process.exitCode = 1; });
