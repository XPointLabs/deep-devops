# syntax=docker/dockerfile:1.6

FROM node:22-bookworm-slim

WORKDIR /src
RUN set -eux; \
    for attempt in 1 2 3 4 5; do \
      rm -rf /var/lib/apt/lists/*; \
      apt-get update \
        -o Acquire::Retries=5 \
        -o Acquire::http::Timeout=60 \
        -o Acquire::https::Timeout=60 && break; \
      if [ "$attempt" = "5" ]; then exit 1; fi; \
      sleep $((attempt * 10)); \
    done \
    && apt-get install -y --no-install-recommends \
      -o Acquire::Retries=5 \
      ca-certificates python3 make g++ \
    && rm -rf /var/lib/apt/lists/*

COPY . .

ARG NEXT_PUBLIC_BACKEND_API_URL
ARG NEXT_PUBLIC_NETWORK_API_URL
ARG NEXT_PUBLIC_WALLET_CONNECT_PROJECT_ID
ARG NEXT_PUBLIC_RPC_URL_ARB
ARG NEXT_PUBLIC_RPC_URL_ETH
ARG NEXT_PUBLIC_PRICE_TOKEN=xpnt
ARG NEXT_PUBLIC_TESTNET=true
ARG NEXT_PUBLIC_ENV_FLAG=prd
ARG SESSION_WEBSITES_COMMIT_HASH=unknown
ARG NEXT_PUBLIC_TOKEN_ADDRESS_ARB_SEPOLIA
ARG NEXT_PUBLIC_SERVICE_NODE_REWARDS_ADDRESS_ARB_SEPOLIA
ARG NEXT_PUBLIC_REWARD_RATE_POOL_ADDRESS_ARB_SEPOLIA
ARG NEXT_PUBLIC_SERVICE_NODE_CONTRIBUTION_FACTORY_ADDRESS_ARB_SEPOLIA
ARG NEXT_PUBLIC_STAKING_REQUIREMENT_ATOMIC=120000000000

ENV NEXT_TELEMETRY_DISABLED=1 \
    NEXT_PUBLIC_BACKEND_API_URL=${NEXT_PUBLIC_BACKEND_API_URL} \
    NEXT_PUBLIC_NETWORK_API_URL=${NEXT_PUBLIC_NETWORK_API_URL} \
    NEXT_PUBLIC_WALLET_CONNECT_PROJECT_ID=${NEXT_PUBLIC_WALLET_CONNECT_PROJECT_ID} \
    NEXT_PUBLIC_RPC_URL_ARB=${NEXT_PUBLIC_RPC_URL_ARB} \
    NEXT_PUBLIC_RPC_URL_ETH=${NEXT_PUBLIC_RPC_URL_ETH} \
    NEXT_PUBLIC_PRICE_TOKEN=${NEXT_PUBLIC_PRICE_TOKEN} \
    NEXT_PUBLIC_TESTNET=${NEXT_PUBLIC_TESTNET} \
    NEXT_PUBLIC_ENV_FLAG=${NEXT_PUBLIC_ENV_FLAG} \
    SESSION_WEBSITES_COMMIT_HASH=${SESSION_WEBSITES_COMMIT_HASH} \
    NEXT_PUBLIC_ENABLE_FAUCET=false \
    NEXT_PUBLIC_ENABLE_LEADERBOARD=false \
    NEXT_PUBLIC_TOKEN_ADDRESS_ARB_SEPOLIA=${NEXT_PUBLIC_TOKEN_ADDRESS_ARB_SEPOLIA} \
    NEXT_PUBLIC_SERVICE_NODE_REWARDS_ADDRESS_ARB_SEPOLIA=${NEXT_PUBLIC_SERVICE_NODE_REWARDS_ADDRESS_ARB_SEPOLIA} \
    NEXT_PUBLIC_REWARD_RATE_POOL_ADDRESS_ARB_SEPOLIA=${NEXT_PUBLIC_REWARD_RATE_POOL_ADDRESS_ARB_SEPOLIA} \
    NEXT_PUBLIC_SERVICE_NODE_CONTRIBUTION_FACTORY_ADDRESS_ARB_SEPOLIA=${NEXT_PUBLIC_SERVICE_NODE_CONTRIBUTION_FACTORY_ADDRESS_ARB_SEPOLIA} \
    NEXT_PUBLIC_STAKING_REQUIREMENT_ATOMIC=${NEXT_PUBLIC_STAKING_REQUIREMENT_ATOMIC}

RUN node <<'EOF'
const fs = require('node:fs');

const addressFromEnv = (name, fallback) => {
  const value = process.env[name];
  if (value && /^0x[0-9a-fA-F]{40}$/.test(value)) return value;
  return fallback;
};

const zeroAddress = '0x0000000000000000000000000000000000000000';
const isTestnetBuild = process.env.NEXT_PUBLIC_TESTNET === 'true';
const testnetAddressFromEnv = (name, fallback) => isTestnetBuild
  ? addressFromEnv(name, fallback)
  : zeroAddress;

const buildInfoPath = 'packages/util-js/build.ts';
let buildInfo = fs.readFileSync(buildInfoPath, 'utf8');
buildInfo = buildInfo.replace(
  "const commitHash = execSync('git rev-parse HEAD').toString().trim();",
  "const commitHash = process.env.SESSION_WEBSITES_COMMIT_HASH || execSync('git rev-parse HEAD').toString().trim();"
);
fs.writeFileSync(buildInfoPath, buildInfo);

const tokenAddress = testnetAddressFromEnv(
  'NEXT_PUBLIC_TOKEN_ADDRESS_ARB_SEPOLIA',
  '0x992E6EA54d74e79cd2CEC8D9fBD101a9a105ace5'
);
const serviceNodeRewardsAddress = testnetAddressFromEnv(
  'NEXT_PUBLIC_SERVICE_NODE_REWARDS_ADDRESS_ARB_SEPOLIA',
  '0x08A5a47E67fCd18e14AdFB535e8d8644476D4197'
);
const rewardRatePoolAddress = testnetAddressFromEnv(
  'NEXT_PUBLIC_REWARD_RATE_POOL_ADDRESS_ARB_SEPOLIA',
  '0xe055c7200aE13984fe66c2e8AaC608bC80E19D57'
);
const serviceNodeContributionFactoryAddress = testnetAddressFromEnv(
  'NEXT_PUBLIC_SERVICE_NODE_CONTRIBUTION_FACTORY_ADDRESS_ARB_SEPOLIA',
  '0x34e50278dbeDdB0F8EC7641D2304CFf4F116066b'
);

fs.writeFileSync('packages/contracts/constants.ts', `import type { Address } from 'viem';
import { arbitrum, arbitrumSepolia, mainnet } from 'viem/chains';
import type { ContractWithAbiName } from './abis';

const contracts = [
  'RewardRatePool',
  'Token',
  'ServiceNodeRewards',
  'ServiceNodeContributionFactory',
  'ServiceNodeContribution',
  'TokenVestingStaking',
] as const satisfies Array<ContractWithAbiName>;
export type ContractName = (typeof contracts)[number];

const ethChainId = mainnet.id;
const arbitrumChainId = arbitrum.id;
const arbitrumSepoliaChainId = arbitrumSepolia.id;

export type ChainId = typeof ethChainId | typeof arbitrumChainId | typeof arbitrumSepoliaChainId;

export const isValidChainId = (chainId?: number | undefined): chainId is ChainId =>
  chainId === arbitrumChainId || chainId === arbitrumSepoliaChainId || chainId === ethChainId;

const zero = '0x0000000000000000000000000000000000000000' as Address;

export const addresses: Record<ContractName, Record<ChainId, Address>> = {
  Token: {
    [arbitrumChainId]: '0x63B2cdb8B0d8774F1Fdca91D24803698582a079F',
    [ethChainId]: zero,
    [arbitrumSepoliaChainId]: '${tokenAddress}' as Address,
  },
  ServiceNodeRewards: {
    [arbitrumChainId]: '0xc52284b7aBAebbEF7BdE0E1ca8251B44AeA12F5f',
    [ethChainId]: zero,
    [arbitrumSepoliaChainId]: '${serviceNodeRewardsAddress}' as Address,
  },
  RewardRatePool: {
    [arbitrumChainId]: '0xEd894fb5f0BA3b141A562190D4c9941FEd348356',
    [ethChainId]: zero,
    [arbitrumSepoliaChainId]: '${rewardRatePoolAddress}' as Address,
  },
  ServiceNodeContributionFactory: {
    [arbitrumChainId]: '0x289d88A8C06881634Fb619Ec528361C7b88521f1',
    [ethChainId]: zero,
    [arbitrumSepoliaChainId]: '${serviceNodeContributionFactoryAddress}' as Address,
  },
  ServiceNodeContribution: {
    [arbitrumChainId]: zero,
    [ethChainId]: zero,
    [arbitrumSepoliaChainId]: zero,
  },
  TokenVestingStaking: {
    [arbitrumChainId]: zero,
    [ethChainId]: zero,
    [arbitrumSepoliaChainId]: zero,
  },
} as const;

export enum TOKEN {
  DECIMALS = 9,
  SYMBOL = 'XPNT',
}

export const SENT_DECIMALS = 9;
export const SENT_SYMBOL = 'XPNT';
`);

const stakingConstantsPath = 'apps/staking/lib/constants.ts';
let stakingConstants = fs.readFileSync(stakingConstantsPath, 'utf8');
stakingConstants = stakingConstants.replace(
  "export const SESSION_NETWORK = 'Session Network' as const;",
  "export const SESSION_NETWORK = 'Deep Network' as const;"
);
stakingConstants = stakingConstants.replace(
  /export const SESSION_NODE_FULL_STAKE_AMOUNT = [^;]+;/,
  "export const SESSION_NODE_FULL_STAKE_AMOUNT = BigInt(process.env.NEXT_PUBLIC_STAKING_REQUIREMENT_ATOMIC ?? '120000000000');"
);
fs.writeFileSync(stakingConstantsPath, stakingConstants);
EOF

RUN --mount=type=cache,id=xpoint-staking-portal-pnpm,target=/pnpm/store \
    corepack enable \
    && corepack prepare pnpm@10.6.4 --activate \
    && pnpm config set store-dir /pnpm/store \
    && pnpm config set fetch-retries 6 \
    && pnpm config set fetch-retry-mintimeout 10000 \
    && pnpm config set fetch-retry-maxtimeout 120000 \
    && pnpm config set network-concurrency 8 \
    && pnpm install --frozen-lockfile --prefer-offline \
    && pnpm --filter @session/staking build

EXPOSE 3000
CMD ["pnpm", "--filter", "@session/staking", "start", "--hostname", "0.0.0.0", "--port", "3000"]
