import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { createPublicClient, decodeEventLog, fallback, http } from 'viem';
import { arbitrum, arbitrumSepolia } from 'viem/chains';

const chainId = Number(process.env.CHAIN_ID ?? arbitrumSepolia.id);
const chain = selectChain(chainId);
const rpcUrl = requireFirstEnv('ARBITRUM_RPC_URL', 'ARB_SEPOLIA_RPC_URL');
const rpcUrls = unique([
  rpcUrl,
  ...splitRpcUrls(process.env.ARBITRUM_FALLBACK_RPC_URLS ?? process.env.ARB_SEPOLIA_FALLBACK_RPC_URLS),
]);
const backendUrl = trimTrailingSlash(requireEnv('STAKING_BACKEND_URL'));
const rewardsAddress = normalizeAddress(requireEnv('SERVICE_NODE_REWARDS_ADDRESS'));
const factoryAddress = normalizeAddress(requireEnv('SERVICE_NODE_CONTRIBUTION_FACTORY_ADDRESS'));
const startBlock = BigInt(process.env.START_BLOCK ?? '0');
const pollMs = Number(process.env.POLL_MS ?? '12000');
const catchupDelayMs = Number(process.env.CATCHUP_DELAY_MS ?? '250');
const rpcTimeoutMs = Number(process.env.RPC_TIMEOUT_MS ?? '30000');
const confirmations = BigInt(process.env.CONFIRMATIONS ?? '2');
const batchBlocks = BigInt(process.env.BATCH_BLOCKS ?? '2000');
const maxLogBlockRange = BigInt(process.env.MAX_LOG_BLOCK_RANGE ?? batchBlocks.toString());
const stateFile = process.env.STATE_FILE ?? '/var/lib/deep/uat-chain-indexer/state.json';
const abiDir = process.env.ABI_DIR ?? '/abis';
const alchemyFastBackfill = parseBoolean(
  process.env.ALCHEMY_FAST_BACKFILL,
  rpcUrl.toLowerCase().includes('alchemy.com'),
);
const alchemyFastBackfillCategories = (process.env.ALCHEMY_FAST_BACKFILL_CATEGORIES ?? 'external')
  .split(',')
  .map(value => value.trim())
  .filter(Boolean);
const alchemyFastBackfillMinLag = BigInt(process.env.ALCHEMY_FAST_BACKFILL_MIN_LAG_BLOCKS ?? '1000');
const alchemyFastBackfillIntervalMs = Number(process.env.ALCHEMY_FAST_BACKFILL_INTERVAL_MS ?? '60000');
let lastAlchemyFastBackfillAt = 0;

const rewardsAbi = await loadAbi('ServiceNodeRewards.json');
const factoryAbi = await loadAbi('ServiceNodeContributionFactory.json');
const contributionAbi = await loadAbi('ServiceNodeContribution.json');
const rewardsEvents = extractEvents(rewardsAbi);
const factoryEvents = extractEvents(factoryAbi);
const contributionEvents = extractEvents(contributionAbi);

const client = createPublicClient({
  chain,
  transport: createRpcTransport(rpcUrls, { timeout: rpcTimeoutMs, retryCount: 2 }),
});

const state = await loadState();
console.log(JSON.stringify({
  service: process.env.SERVICE_NAME ?? (chainId === arbitrum.id ? 'deep-chain-indexer' : 'deep-uat-chain-indexer'),
  chain: chain.name,
  chainId,
  rewardsAddress,
  factoryAddress,
  startBlock: startBlock.toString(),
  nextBlock: state.nextBlock.toString(),
  batchBlocks: batchBlocks.toString(),
  maxLogBlockRange: maxLogBlockRange.toString(),
  rpcEndpointCount: rpcUrls.length,
  alchemyFastBackfill,
  alchemyFastBackfillCategories,
  knownContributionContracts: Object.keys(state.contributionContracts).length,
}));

while (true) {
  let processed = false;
  try {
    processed = await scanOnce();
  } catch (error) {
    console.error('indexer scan failed', error);
  }

  await delay(processed ? catchupDelayMs : pollMs);
}

async function scanOnce() {
  const latest = await client.getBlockNumber();
  const safeLatest = latest > confirmations ? latest - confirmations : 0n;
  if (state.nextBlock > safeLatest) {
    return false;
  }

  await maybeAlchemyFastBackfill(safeLatest);

  const fromBlock = state.nextBlock;
  const effectiveBatchBlocks = maxLogBlockRange > 0n
    ? minBigInt(batchBlocks, maxLogBlockRange)
    : batchBlocks;
  const toBlock = minBigInt(safeLatest, fromBlock + effectiveBatchBlocks - 1n);
  const logs = [];

  logs.push(...await getLogsSafe({
    address: rewardsAddress,
    events: rewardsEvents,
    fromBlock,
    toBlock,
  }));

  const factoryLogs = await getLogsSafe({
    address: factoryAddress,
    events: factoryEvents,
    fromBlock,
    toBlock,
  });
  logs.push(...factoryLogs);

  for (const log of factoryLogs) {
    trackFactoryContributionContract(log);
  }

  const contributionAddresses = Object.keys(state.contributionContracts);
  if (contributionAddresses.length > 0) {
    logs.push(...await getLogsSafe({
      address: contributionAddresses,
      events: contributionEvents,
      fromBlock,
      toBlock,
    }));
  }

  logs.sort((left, right) => {
    if (left.blockNumber === right.blockNumber) {
      return left.logIndex - right.logIndex;
    }

    return left.blockNumber < right.blockNumber ? -1 : 1;
  });

  for (const log of logs) {
    await postLog(log);
  }

  state.nextBlock = toBlock + 1n;
  await saveState();
  await postChainTip(toBlock);
  if (logs.length > 0 || (state.nextBlock % 10_000n) === 0n || toBlock === safeLatest) {
    console.log(JSON.stringify({
      action: 'indexed-range',
      fromBlock: fromBlock.toString(),
      toBlock: toBlock.toString(),
      nextBlock: state.nextBlock.toString(),
      logs: logs.length,
      safeLatest: safeLatest.toString(),
    }));
  }

  return true;
}

async function maybeAlchemyFastBackfill(safeLatest) {
  if (!alchemyFastBackfill) {
    return;
  }

  if (state.nextBlock + alchemyFastBackfillMinLag > safeLatest) {
    return;
  }

  const now = Date.now();
  if (now - lastAlchemyFastBackfillAt < alchemyFastBackfillIntervalMs) {
    return;
  }

  lastAlchemyFastBackfillAt = now;
  const fromBlock = state.nextBlock;
  const toBlock = safeLatest;
  const watchedAddresses = [
    rewardsAddress,
    factoryAddress,
    ...Object.keys(state.contributionContracts),
  ];
  const seenTransactions = new Set();
  let transactionCount = 0;
  let eventCount = 0;

  for (const address of watchedAddresses) {
    const transfers = await getAlchemyTransfersToAddress(address, fromBlock, toBlock);
    for (const transfer of transfers) {
      const hash = normalizeHash(transfer.hash);
      if (!hash || seenTransactions.has(hash)) {
        continue;
      }

      seenTransactions.add(hash);
      transactionCount += 1;
      const receipt = await client.getTransactionReceipt({ hash });
      const decodedLogs = [];
      for (const receiptLog of receipt.logs) {
        const decodedLog = decodeWatchedReceiptLog(receiptLog);
        if (!decodedLog) {
          continue;
        }

        trackFactoryContributionContract(decodedLog);
        decodedLogs.push(decodedLog);
      }

      decodedLogs.sort((left, right) => left.logIndex - right.logIndex);
      for (const log of decodedLogs) {
        await postLog(log);
        eventCount += 1;
      }
    }
  }

  if (transactionCount > 0 || eventCount > 0) {
    console.log(JSON.stringify({
      action: 'alchemy-fast-backfill',
      fromBlock: fromBlock.toString(),
      toBlock: toBlock.toString(),
      transactions: transactionCount,
      events: eventCount,
      watchedAddresses: watchedAddresses.length,
    }));
  }
}

async function getAlchemyTransfersToAddress(address, fromBlock, toBlock) {
  const transfers = [];
  let pageKey;
  do {
    const params = [{
      fromBlock: toHexBlock(fromBlock),
      toBlock: toHexBlock(toBlock),
      toAddress: address,
      category: alchemyFastBackfillCategories,
      withMetadata: false,
      excludeZeroValue: false,
      maxCount: '0x3e8',
      ...(pageKey ? { pageKey } : {}),
    }];
    const result = await rpcCall('alchemy_getAssetTransfers', params);
    transfers.push(...(result?.transfers ?? []));
    pageKey = result?.pageKey;
  } while (pageKey);

  return transfers;
}

async function rpcCall(method, params, attempt = 0) {
  const response = await fetch(rpcUrl, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method,
      params,
    }),
  });

  if (response.status === 429 && attempt < 6) {
    const delayMs = Math.min(60_000, 2 ** attempt * 2_000);
    console.warn(`RPC rate limited during ${method}; retrying in ${delayMs}ms`);
    await delay(delayMs);
    return rpcCall(method, params, attempt + 1);
  }

  const body = await response.json();
  if (!response.ok || body.error) {
    throw new Error(`${method} failed: ${response.status} ${JSON.stringify(body.error ?? body)}`);
  }

  return body.result;
}

function decodeWatchedReceiptLog(log) {
  const address = normalizeAddress(log.address);
  const events = getEventsForAddress(address);
  if (!events) {
    return null;
  }

  try {
    const decoded = decodeEventLog({
      abi: events,
      data: log.data,
      topics: log.topics,
    });

    return {
      ...log,
      address,
      eventName: decoded.eventName,
      args: decoded.args ?? {},
    };
  } catch {
    return null;
  }
}

function getEventsForAddress(address) {
  if (address === rewardsAddress) {
    return rewardsEvents;
  }

  if (address === factoryAddress) {
    return factoryEvents;
  }

  if (state.contributionContracts[address]) {
    return contributionEvents;
  }

  return null;
}

function trackFactoryContributionContract(log) {
  if (log.eventName !== 'NewServiceNodeContributionContract') {
    return;
  }

  const address = normalizeAddress(log.args?.contributorContract);
  state.contributionContracts[address] = {
    firstBlock: log.blockNumber.toString(),
    serviceNodePubkey: stringifyValue(log.args?.serviceNodePubkey),
    operator: normalizeAddress(log.args?.operator),
  };
}

async function postChainTip(blockNumber) {
  let blockHash = '';
  try {
    const block = await client.getBlock({ blockNumber });
    blockHash = block.hash ?? '';
  } catch (error) {
    console.warn('failed to fetch chain tip block hash', error);
  }

  const response = await fetch(`${backendUrl}/api/chain-tip`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      blockNumber: Number(blockNumber),
      blockHash,
    }),
  });

  if (!response.ok) {
    const body = await response.text();
    throw new Error(`staking backend rejected chain tip ${blockNumber}: ${response.status} ${body}`);
  }
}

async function postLog(log) {
  const payload = {
    chainId,
    blockNumber: Number(log.blockNumber),
    blockHash: log.blockHash ?? '',
    transactionHash: log.transactionHash,
    logIndex: log.logIndex,
    address: normalizeAddress(log.address),
    mainArg: inferMainArg(log),
    name: log.eventName,
    args: sanitize(log.args ?? {}),
  };

  const response = await fetch(`${backendUrl}/api/events`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    const body = await response.text();
    throw new Error(`staking backend rejected ${payload.name} ${payload.transactionHash}:${payload.logIndex}: ${response.status} ${body}`);
  }
}

async function getLogsSafe(params, attempt = 0) {
  try {
    return await client.getLogs(params);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (shouldSplitLogRange(message) && params.fromBlock < params.toBlock) {
      const middle = params.fromBlock + ((params.toBlock - params.fromBlock) / 2n);
      return [
        ...await getLogsSafe({ ...params, toBlock: middle }, attempt),
        ...await getLogsSafe({ ...params, fromBlock: middle + 1n }, attempt),
      ];
    }

    if ((message.includes('Too Many Requests') || message.includes('Status: 429')) && attempt < 6) {
      const delayMs = Math.min(60_000, 2 ** attempt * 2_000);
      console.warn(`RPC rate limited; retrying in ${delayMs}ms`);
      await delay(delayMs);
      return getLogsSafe(params, attempt + 1);
    }

    throw error;
  }
}

function shouldSplitLogRange(message) {
  const normalized = message.toLowerCase();
  return normalized.includes('block range')
    || normalized.includes('query returned more than')
    || normalized.includes('request timeout')
    || normalized.includes('timed out')
    || normalized.includes('http request failed');
}

function inferMainArg(log) {
  switch (log.eventName) {
    case 'NewServiceNodeContributionContract':
      return normalizeAddress(log.args?.contributorContract);
    case 'NewServiceNodeV2':
    case 'NewSeededServiceNode':
    case 'ServiceNodeExitRequest':
    case 'ServiceNodeExit':
    case 'ServiceNodeLiquidated':
      return stringifyValue(log.args?.serviceNodeID);
    default:
      return normalizeAddress(log.address);
  }
}

async function loadAbi(fileName) {
  const raw = await readFile(path.join(abiDir, fileName), 'utf8');
  return JSON.parse(raw);
}

function extractEvents(abi) {
  return abi.filter((entry) => entry?.type === 'event');
}

async function loadState() {
  try {
    const parsed = JSON.parse(await readFile(stateFile, 'utf8'));
    return {
      nextBlock: BigInt(parsed.nextBlock ?? startBlock),
      contributionContracts: parsed.contributionContracts ?? {},
    };
  } catch {
    return {
      nextBlock: startBlock,
      contributionContracts: {},
    };
  }
}

async function saveState() {
  await mkdir(path.dirname(stateFile), { recursive: true });
  await writeFile(stateFile, JSON.stringify({
    nextBlock: state.nextBlock.toString(),
    contributionContracts: state.contributionContracts,
    updatedAt: new Date().toISOString(),
  }, null, 2));
}

function sanitize(value) {
  if (typeof value === 'bigint') {
    return value.toString();
  }

  if (Array.isArray(value)) {
    return value.map(sanitize);
  }

  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([key, entry]) => [key, sanitize(entry)]));
  }

  return value;
}

function stringifyValue(value) {
  return typeof value === 'bigint' ? value.toString() : String(value ?? '');
}

function normalizeAddress(value) {
  return String(value ?? '').trim().toLowerCase();
}

function normalizeHash(value) {
  const normalized = String(value ?? '').trim();
  return normalized.startsWith('0x') ? normalized : '';
}

function trimTrailingSlash(value) {
  return value.endsWith('/') ? value.slice(0, -1) : value;
}

function requireEnv(name) {
  const value = process.env[name];
  if (!value) {
    throw new Error(`${name} is required`);
  }

  return value;
}

function requireFirstEnv(...names) {
  for (const name of names) {
    const value = process.env[name];
    if (value) {
      return value;
    }
  }

  throw new Error(`${names.join(' or ')} is required`);
}

function selectChain(id) {
  if (id === arbitrum.id) {
    return arbitrum;
  }

  if (id === arbitrumSepolia.id) {
    return arbitrumSepolia;
  }

  throw new Error(`Unsupported chain id ${id}. Expected ${arbitrum.id} or ${arbitrumSepolia.id}.`);
}

function minBigInt(left, right) {
  return left < right ? left : right;
}

function toHexBlock(block) {
  return `0x${block.toString(16)}`;
}

function parseBoolean(value, fallback) {
  if (value === undefined || value === null || value === '') {
    return fallback;
  }

  return ['1', 'true', 'yes', 'on'].includes(String(value).trim().toLowerCase());
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

function delay(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}
