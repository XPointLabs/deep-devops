import assert from 'node:assert/strict';
import test from 'node:test';

import { addressesForCodeQuery, validateLocalContractManifest } from './p15c-local-contract-manifest.mjs';

const address = digit => `0x${digit.repeat(40)}`;
const manifest = {
  schema: 'deep-p15c-local-contracts.v1',
  network: 'localhost',
  chainId: 31337,
  contracts: {
    token: address('1'),
    serviceNodeRewards: address('2'),
    serviceNodeContributionFactory: address('3'),
    rewardRatePool: address('4')
  },
  deployBlocks: { token: 1, serviceNodeRewards: 2, serviceNodeContributionFactory: 3, rewardRatePool: 4 }
};

test('local manifest requires chain 31337, unique nonzero addresses and bytecode', () => {
  const code = Object.fromEntries(Object.values(manifest.contracts).map(value => [value.toLowerCase(), '0x6001']));
  assert.equal(validateLocalContractManifest(manifest, { chainIdHex: '0x7a69', code }), true);
  assert.throws(() => validateLocalContractManifest({ ...manifest, chainId: 421614 }, { chainIdHex: '0x7a69', code }));
  assert.throws(() => validateLocalContractManifest({ ...manifest, contracts: { ...manifest.contracts, token: address('0') } }, { chainIdHex: '0x7a69', code }));
  assert.throws(() => validateLocalContractManifest({ ...manifest, contracts: { ...manifest.contracts, rewardRatePool: address('1') } }, { chainIdHex: '0x7a69', code }));
  assert.throws(() => validateLocalContractManifest(manifest, { chainIdHex: '0x7a69', code: { ...code, [address('2').toLowerCase()]: '0x' } }));
});

test('manifest envelope, exact keys and bounded deploy blocks fail closed', () => {
  const code = Object.fromEntries(Object.values(manifest.contracts).map(value => [value.toLowerCase(), '0x6001']));
  for (const value of [
    { ...manifest, schema: undefined },
    { ...manifest, schema: 'other' },
    { ...manifest, chainId: undefined },
    { ...manifest, chainId: '31337' },
    { ...manifest, contracts: { ...manifest.contracts, extra: address('5') } },
    { ...manifest, deployBlocks: { ...manifest.deployBlocks, extra: 5 } },
    { ...manifest, deployBlocks: { ...manifest.deployBlocks, token: 0 } },
    { ...manifest, deployBlocks: { ...manifest.deployBlocks, token: -1 } },
    { ...manifest, deployBlocks: { ...manifest.deployBlocks, token: 1.5 } },
    { ...manifest, deployBlocks: { ...manifest.deployBlocks, token: Number.MAX_SAFE_INTEGER + 1 } }
  ]) assert.throws(() => validateLocalContractManifest(value, { chainIdHex: '0x7a69', code }));
});

test('bytecode query list contains exactly the four required addresses', () => {
  assert.deepEqual(addressesForCodeQuery({ ...manifest, contracts: { ...manifest.contracts, ignored: address('9') } }), Object.values(manifest.contracts));
});
