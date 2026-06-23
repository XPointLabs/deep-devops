import { readFile } from 'node:fs/promises';
import path from 'node:path';
import {
  createPublicClient,
  createWalletClient,
  formatUnits,
  fallback,
  http,
} from 'viem';
import { arbitrumSepolia } from 'viem/chains';
import { mnemonicToAccount, privateKeyToAccount } from 'viem/accounts';

const rpcUrl = requireEnv('ARB_SEPOLIA_RPC_URL');
const rpcUrls = unique([
  rpcUrl,
  ...splitRpcUrls(process.env.ARB_SEPOLIA_FALLBACK_RPC_URLS),
]);
const rewardRatePoolAddress = normalizeAddress(requireEnv('REWARD_RATE_POOL_ADDRESS'));
const tokenAddress = normalizeAddress(requireEnv('XPNT_TOKEN_ADDRESS'));
const serviceNodeRewardsAddress = normalizeAddress(requireEnv('SERVICE_NODE_REWARDS_ADDRESS'));
const abiDir = process.env.ABI_DIR ?? '/abis';
const intervalMs = Number(process.env.CHECKPOINT_INTERVAL_MS ?? '300000');
const minReleaseAtomic = BigInt(process.env.MIN_RELEASE_ATOMIC ?? '1000000000');

const account = loadAccount();
const tokenAbi = await loadAbi('XPNTL2.json');
const rewardRatePoolAbi = await loadAbi('RewardRatePool.json');
const transport = createRpcTransport(rpcUrls, { timeout: 30_000 });
const publicClient = createPublicClient({ chain: arbitrumSepolia, transport });
const walletClient = createWalletClient({ account, chain: arbitrumSepolia, transport });

console.log(JSON.stringify({
  service: 'deep-uat-reward-keeper',
  rewardRatePoolAddress,
  serviceNodeRewardsAddress,
  tokenAddress,
  account: account.address,
  intervalMs,
  minReleaseAtomic: minReleaseAtomic.toString(),
  rpcEndpointCount: rpcUrls.length,
}));

while (true) {
  try {
    await checkpointOnce();
  } catch (error) {
    console.error('reward checkpoint failed', error);
  }

  await delay(intervalMs);
}

async function checkpointOnce() {
  const [totalPaidOut, releasedAmount, poolBalance, rewardsBalance] = await Promise.all([
    readPool('totalPaidOut'),
    readPool('calculateReleasedAmount'),
    readTokenBalance(rewardRatePoolAddress),
    readTokenBalance(serviceNodeRewardsAddress),
  ]);
  const releasable = releasedAmount > totalPaidOut ? releasedAmount - totalPaidOut : 0n;
  if (releasable < minReleaseAtomic) {
    console.log(JSON.stringify({
      action: 'skip',
      releasable: formatUnits(releasable, 9),
      poolBalance: formatUnits(poolBalance, 9),
      serviceNodeRewardsBalance: formatUnits(rewardsBalance, 9),
    }));
    return;
  }

  const hash = await submitCheckpoint();
  console.log(JSON.stringify({
    action: 'checkpoint-submitted',
    transactionHash: hash,
    releasable: formatUnits(releasable, 9),
  }));

  const receipt = await publicClient.waitForTransactionReceipt({
    hash,
    confirmations: 1,
    timeout: 120_000,
  });
  const newRewardsBalance = await readTokenBalance(serviceNodeRewardsAddress);
  console.log(JSON.stringify({
    action: 'checkpoint-confirmed',
    status: receipt.status,
    blockNumber: receipt.blockNumber.toString(),
    transactionHash: receipt.transactionHash,
    serviceNodeRewardsBalance: formatUnits(newRewardsBalance, 9),
  }));
}

async function submitCheckpoint() {
  for (let attempt = 0; attempt < 2; attempt++) {
    const nonce = await publicClient.getTransactionCount({
      address: account.address,
      blockTag: 'pending',
    });
    try {
      return await walletClient.writeContract({
        address: rewardRatePoolAddress,
        abi: rewardRatePoolAbi,
        functionName: 'checkpoint',
        nonce,
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      if (attempt === 0 && message.toLowerCase().includes('nonce too low')) {
        console.warn('checkpoint nonce was stale; retrying with refreshed pending nonce');
        await delay(2_000);
        continue;
      }

      throw error;
    }
  }

  throw new Error('checkpoint retry loop exited unexpectedly');
}

function readPool(functionName) {
  return publicClient.readContract({
    address: rewardRatePoolAddress,
    abi: rewardRatePoolAbi,
    functionName,
  });
}

function readTokenBalance(address) {
  return publicClient.readContract({
    address: tokenAddress,
    abi: tokenAbi,
    functionName: 'balanceOf',
    args: [address],
  });
}

function loadAccount() {
  const privateKey = process.env.UAT_DEPLOYER_PRIVATE_KEY;
  if (privateKey) {
    return privateKeyToAccount(privateKey.startsWith('0x') ? privateKey : `0x${privateKey}`);
  }

  return mnemonicToAccount(requireEnv('UAT_DEPLOYER_MNEMONIC'));
}

async function loadAbi(fileName) {
  return JSON.parse(await readFile(path.join(abiDir, fileName), 'utf8'));
}

function normalizeAddress(value) {
  return String(value ?? '').trim();
}

function requireEnv(name) {
  const value = process.env[name];
  if (!value) {
    throw new Error(`${name} is required`);
  }

  return value;
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function splitRpcUrls(value) {
  return String(value ?? '')
    .split(/[,\s;]+/)
    .map(item => item.trim())
    .filter(Boolean);
}

function unique(values) {
  const result = [];
  for (const value of values) {
    if (!result.some(item => item.toLowerCase() === value.toLowerCase())) {
      result.push(value);
    }
  }

  return result;
}

function createRpcTransport(urls, options) {
  const transports = urls.map(url => http(url, options));
  return transports.length === 1 ? transports[0] : fallback(transports, { rank: false });
}
