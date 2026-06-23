# Production Node Runbook

This is the manual production path for one Deep service-node host. Run the same compose file on every node host with a unique Ed25519 identity file, BLS identity file, public Ed25519 key, VLESS UUID, Reality key pair, and local storage volume.

## Build And Push Image

From `C:\Work\Deep\deep-devops`:

```powershell
$org = "ghcr.io/xpointlabs"
$tag = git -C ..\xnode rev-parse --short HEAD
docker buildx build `
  --platform linux/amd64,linux/arm64 `
  -f .\docker\xnode-xray.Dockerfile `
  --build-arg PROJECT=src/XNode/XNode.csproj `
  --build-arg APP_DLL=XNode.dll `
  --build-arg XRAY_VERSION=v26.3.27 `
  -t "$org/xnode:$tag" `
  -t "$org/xnode:latest" `
  --push ..\xnode

docker buildx build `
  --platform linux/amd64,linux/arm64 `
  -f .\docker\storage-service.Dockerfile `
  -t "$org/deep-storage-service:$tag" `
  -t "$org/deep-storage-service:latest" `
  --push .
```

Use `XNODE_XRAY_SHA256`/`XRAY_SHA256` for release builds when the Xray archive checksum is pinned by the release process.

## Prepare Node Host

1. Install Docker Engine with the Compose plugin.
2. Open inbound TCP `443` to the node host.
3. Keep the node API/signing port private. The example binds it to `127.0.0.1:8080`; expose it through a private VPN, private reverse proxy, or another controlled internal path used by the registry/staking backend.
4. Copy `docker-compose.node.prod.yml` and create `.env.node.prod` from `.env.node.prod.example`.
5. Generate node identity files. This follows the upstream Session/Oxen model:
   service-node keys are local node files (`key_ed25519` and `key_bls`) loaded
   from the node data/config folder, not private seeds passed as environment
   variables. `DEEP_NODE_ED25519_PUBLIC_KEY` is derived from
   `key_ed25519` and is the node/router id used by signed relay contact
   manifests and staking registration.

```powershell
New-Item -ItemType Directory -Force .\secrets | Out-Null
powershell -ExecutionPolicy Bypass -File .\scripts\new-xnode-identity.ps1 -AsEnv -OutDir .\secrets
```

Copy the printed `DEEP_NODE_ED25519_PUBLIC_KEY`,
`DEEP_NODE_ED25519_PRIVATE_KEY_FILE`,
`DEEP_NODE_BLS_PRIVATE_KEY_FILE`, and
`DEEP_NODE_VLESS_CLIENT_ID` values into `.env.node.prod`. Keep the
`secrets` directory local to the node host and back it up as node identity
state.

6. Generate Xray Reality keys with the final image:

```powershell
docker run --rm --entrypoint xray ghcr.io/xpointlabs/xnode:latest x25519
```

Put the generated private/public key pair into `DEEP_NODE_REALITY_PRIVATE_KEY` and `DEEP_NODE_REALITY_PUBLIC_KEY`. Generate a unique 8-byte hex `DEEP_NODE_REALITY_SHORT_ID` per host.

## Required Env Values

- `XNODE_IMAGE`: pushed image tag.
- `DEEP_STORAGE_SERVICE_IMAGE`: pushed per-node storage service image tag.
- `DEEP_NODE_PUBLIC_HOST`: public DNS name or public IP clients can reach.
- `DEEP_NODE_RPC_ENDPOINT`: http(s) endpoint other router nodes can reach for `/api/session/rpc`; use a private mesh/VPN or controlled reverse proxy, not an unauthenticated public admin port.
- `DEEP_NODE_SIGNING_ENDPOINT`: HTTPS URL that staking backend can call for `/api/staking/quorum/sign`.
- `DEEP_NODE_STORAGE_BIND`: host bind address for the per-node storage sidecar; keep it private or expose it through the approved node/onion ingress path.
- `DEEP_PUSH_NOTIFY_URL`: optional centralized push notify endpoint used by storage to trigger push delivery.
- `DEEP_REGISTRY_URL`: production registry API base URL.
- `DEEP_STORAGE_RPC_URL`: node-local or private storage RPC base URL used only by the exit router hop.
- `DEEP_OPERATOR_ADDRESS` and `DEEP_REWARDS_ADDRESS`: staked operator/reward wallet.
- `DEEP_ARBITRUM_RPC_URL`: backend-only Arbitrum One RPC. Use Alchemy or
  another private provider here if desired; do not expose this value through
  frontend `NEXT_PUBLIC_*` configuration.
- `DEEP_ARBITRUM_FALLBACK_RPC_URLS`: fallback Arbitrum One RPC list. The default
  production fallback is `https://arb1.arbitrum.io/rpc`.
- `DEEP_SERVICE_NODE_REWARDS_ADDRESS`: production `ServiceNodeRewards` contract.
- `DEEP_NODE_ED25519_PUBLIC_KEY`: public node/router id derived from `key_ed25519`.
- `DEEP_NODE_ED25519_PRIVATE_KEY_FILE` and `DEEP_NODE_BLS_PRIVATE_KEY_FILE`: local files mounted as Docker secrets; do not put private key material directly in `.env`.
- `DEEP_NODE_VLESS_CLIENT_ID` and Reality fields: unique per node.

## Start And Verify

```powershell
docker compose --env-file .\.env.node.prod -f .\docker-compose.node.prod.yml config --quiet
docker compose --env-file .\.env.node.prod -f .\docker-compose.node.prod.yml up -d
docker compose --env-file .\.env.node.prod -f .\docker-compose.node.prod.yml ps
docker compose --env-file .\.env.node.prod -f .\docker-compose.node.prod.yml logs --tail 100 xnode
docker compose --env-file .\.env.node.prod -f .\docker-compose.node.prod.yml logs --tail 100 storage-service
```

Host checks:

```powershell
curl http://127.0.0.1:8080/health/live
curl http://127.0.0.1:8080/health/ready
curl http://127.0.0.1:8080/status
curl http://127.0.0.1:22021/health/ready
curl http://127.0.0.1:22021/stats
```

The relay contact published by heartbeat must include `x25519PublicKey`,
`rpcEndpoint`, and `onion-v1` capability. Clients use these fields to build
Session-style three-hop onion envelopes; entry and middle nodes only see the
next hop, while the exit node calls storage.

Control-plane checks:

```powershell
curl https://registry.deep.example/api/nodes
curl https://staking.deep.example/obligations
curl https://staking.deep.example/exit_liquidation_list
```

After the stake transaction is submitted on the staking portal, the router heartbeat publishes the BLS public key, proof of possession, transport bundle, signed relay contact, and signing endpoint. The staking backend builds the BLS quorum signer set from chain-active service nodes and service-node obligation status, then uses registry-published endpoints only as an address cache. There is no UAT reward signer endpoint in the production path.

## Contracts Readiness

Production staking contracts are deployed on Arbitrum One and recorded in
`xpoint-staking-contracts/docs/ARBITRUM_STAKING_PRODUCTION_DEPLOYMENT.md`.
Configure production services with:

```text
Contracts__TokenAddress=0x63B2cdb8B0d8774F1Fdca91D24803698582a079F
Contracts__ServiceNodeRewardsAddress=0xc52284b7aBAebbEF7BdE0E1ca8251B44AeA12F5f
Contracts__ServiceNodeContributionFactoryAddress=0x289d88A8C06881634Fb619Ec528361C7b88521f1
Contracts__RewardRatePoolAddress=0xEd894fb5f0BA3b141A562190D4c9941FEd348356
Contracts__StakingRequirementAtomic=25000000000000
Registry__StakingRequirementAtomic=25000000000000
DEEP_ARBITRUM_RPC_URL=https://arb-mainnet.g.alchemy.com/v2/<alchemy-key>
DEEP_ARBITRUM_FALLBACK_RPC_URLS=https://arb1.arbitrum.io/rpc
DEEP_SERVICE_NODE_REWARDS_ADDRESS=0xc52284b7aBAebbEF7BdE0E1ca8251B44AeA12F5f
```

Deployment facts:

- XPNT token: `0x63B2cdb8B0d8774F1Fdca91D24803698582a079F`.
- RewardRatePool proxy: `0xEd894fb5f0BA3b141A562190D4c9941FEd348356`, funded with `40,000,000 XPNT`.
- ServiceNodeRewards proxy: `0xc52284b7aBAebbEF7BdE0E1ca8251B44AeA12F5f`.
- ServiceNodeContributionFactory proxy: `0x289d88A8C06881634Fb619Ec528361C7b88521f1`.
- Staking requirement: `25,000 XPNT`.
- Owner / deployer: `0x62174f6e6a25E7D8135Bd172C1053D7ABd7D2750`.
- `ServiceNodeRewards.isStarted` was `false` in the post-deploy snapshot; start
  it only after the production bootstrap flow is chosen.
- Subscription contracts were intentionally not deployed in this staking run.

The active rewards path uses `BLS12-381` (`contracts/libraries/BLS12381.sol`) and the EIP-2537 precompiles available on Arbitrum One. Legacy `BN256*` libraries are not imported by production contracts.

Before future production upgrades or redeploy rehearsals:

```powershell
cd C:\Work\Deep\xpoint-staking-contracts
pnpm build
pnpm test
```

Then use the production deployment scripts and write final addresses into the
production secret store and this release runbook. Do not put production private
keys or mnemonics in git.

## Still Centralized

- Registry API/control plane: bootstrap cache, transport metadata cache, heartbeat mirror, and diagnostics are still centralized services, but they are not the authority for active service-node membership or reward quorum membership.
- Staking backend, chain indexer, reward checkpoint keeper, and the UI price endpoint are centralized application services around decentralized Arbitrum contracts. The chain/indexer determines active membership; service-node obligations gate reward/exit/liquidation signatures. XPNT price is sourced from the on-chain XPNT/USDC Uniswap V3 pool on Arbitrum One rather than a third-party price API.
- Staking portal/web frontend and public DNS/bootstrap URLs are centralized.
- Storage runs as a per-node sidecar with node-local state, matching the upstream Session service-node storage model more closely than a single central storage service.
- File/avatar and push services remain operated infrastructure. Push can never be fully decentralized while Android/iOS delivery goes through FCM/APNs/Huawei provider gateways.
- Container registry, observability, alerting, CI release evidence, and incident/rollback automation are centralized operations systems.
- Contract ownership/governance remains centralized until ownership is transferred to the final multisig/governance process.

The decentralized pieces in the current architecture are the Arbitrum contracts, signed relay contacts, and BLS quorum signatures produced by active, obligation-eligible service nodes. The next decentralization frontier is replacing the centralized bootstrap/cache endpoints with node-network gossip for client discovery while keeping FCM/APNs/Huawei push delivery centralized by platform necessity.
