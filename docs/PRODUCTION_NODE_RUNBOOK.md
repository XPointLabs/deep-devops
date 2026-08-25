# Production Node Runbook

This is the manual production path for one Deep service-node host. Run the same compose file on every node host with a unique Ed25519 identity file, BLS identity file, public Ed25519 key, VLESS UUID, Reality key pair, and local storage volume.

## Build And Push Images

The normal production path is the `publish-production-images` GitHub Actions
workflow in `XPointLabs/deep-devops`. It is intentionally manual-only and does
not run the full DevOps validation suite inside the publish job; run release
gates separately before approving a production tag.

Run it from the GitHub UI with:

- `xnode_ref`: the `XPointLabs/xnode` branch, tag, or SHA to build.
- `image_tag`: optional common release tag. When empty, the workflow uses
  `prod-<xnode-sha>-<devops-sha>`.
- `push_latest`: keep enabled for the currently approved production image set.
- `xray_version`: Xray-core release bundled into the `xnode` image.

The workflow validates `xnode` and the storage service, then publishes:

```text
ghcr.io/xpointlabs/xnode:<tag>
ghcr.io/xpointlabs/xnode:xnode-<xnode-sha>
ghcr.io/xpointlabs/xnode:latest
ghcr.io/xpointlabs/deep-storage-service:<tag>
ghcr.io/xpointlabs/deep-storage-service:devops-<devops-sha>
ghcr.io/xpointlabs/deep-storage-service:latest
```

Make the resulting GitHub Container Registry packages public, or log in on
node hosts with a token that has `read:packages` before running the installer.

Manual fallback from `C:\Work\Deep\deep-devops`:

```powershell
$org = "ghcr.io/xpointlabs"
$tag = git -C ..\xnode rev-parse --short HEAD
docker buildx build `
  --platform linux/amd64,linux/arm64 `
  -f .\docker\xnode-xray.Dockerfile `
  --build-arg PROJECT=src/XNode/XNode.csproj `
  --build-arg APP_DLL=XNode.dll `
  --build-arg XRAY_VERSION=v26.3.27 `
  --build-arg XRAY_SHA256_AMD64=23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae `
  --build-arg XRAY_SHA256_ARM64=4d30283ae614e3057f730f67cd088a42be6fdf91f8639d82cb69e48cde80413c `
  -t "$org/xnode:$tag" `
  -t "$org/xnode:latest" `
  --push ..\xnode

docker buildx build `
  --platform linux/amd64,linux/arm64 `
  -f .\docker\storage-service.Dockerfile `
  --build-arg NODE_IMAGE=node:24-bookworm-slim@sha256:242549cd46785b480c832479a730f4f2a20865d61ea2e404fdb2a5c3d3b73ecf `
  -t "$org/deep-storage-service:$tag" `
  -t "$org/deep-storage-service:latest" `
  --push .
```

Use `XNODE_XRAY_SHA256`/`XRAY_SHA256` for release builds when the Xray archive checksum is pinned by the release process.

## Prepare Node Host

1. Run the public XPoint node installer:

```bash
curl -fsSL https://raw.githubusercontent.com/XPointLabs/xpoint-node-installer/main/install-xpoint-node.sh \
  -o /tmp/install-xpoint-node.sh
chmod +x /tmp/install-xpoint-node.sh
sudo /tmp/install-xpoint-node.sh --no-start --prune-docker
```

The public installer is idempotent. It installs Docker Engine and the Compose
plugin plus bootstrap host tools when needed, configures Docker `json-file` log
rotation (`50m` x `5` files by default), writes the production node compose/env
files, and can prune stopped containers, unused images, and build cache when
`--prune-docker` is passed. Docker volumes are never pruned. On existing
production hosts, `--prune-docker` can remove unused rollback images and build
cache, so preserve any rollback tags you need before using it.

Use the public installer README for the complete operator flow and CLI options.

2. Open only the hardened ingress TCP port (`443` by default). The ingress
   terminates exact-host HTTPS and passes the exact Reality SNI through to
   Xray on the same port. Follow `docs/PRODUCTION_NODE_TLS_INGRESS.md`.
3. Do not publish the raw node API, peer RPC, storage, health, status, or
   signing ports. The compose file keeps every backend container-only.
4. If you are not using the public installer end to end, copy
   `docker-compose.node.prod.yml` and create `.env.node.prod` from
   `.env.node.prod.example`.
5. Generate node identity files. Service-node keys are local node files
   (`key_ed25519`, independent `key_x25519`, and `key_bls`) loaded
   from the node data/config folder, not private seeds passed as environment
   variables. `DEEP_NODE_ED25519_PUBLIC_KEY` is derived from
   `key_ed25519` and is the node/router id used by signed DPC1 privacy contacts
   and staking registration. `key_x25519` is used only to open this node's
   native privacy layer and must never be derived from the Ed25519 seed.

```powershell
New-Item -ItemType Directory -Force .\secrets | Out-Null
powershell -ExecutionPolicy Bypass -File .\scripts\new-xnode-identity.ps1 -AsEnv -OutDir .\secrets
```

Copy the printed `DEEP_NODE_ED25519_PUBLIC_KEY`,
`DEEP_NODE_ED25519_PRIVATE_KEY_FILE`,
`DEEP_NODE_X25519_PRIVATE_KEY_FILE`,
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
- `DEEP_NODE_PUBLIC_HOST`: exact public DNS name clients can reach.
- `DEEP_INGRESS_CERTIFICATE_PROFILE`, `DEEP_INGRESS_HOST`, and the six
  current/next cert/key/SPKI file variables: mandatory TLS ingress authority;
  see `docs/PRODUCTION_NODE_TLS_INGRESS.md`.
- `DEEP_NODE_PUBLIC_PORT`: public shared ingress/VLESS Reality port clients use.
  Keep it equal to `DEEP_INGRESS_HTTPS_BIND` unless an approved NAT rule
  translates the port.
- `DEEP_NODE_PUBLIC_IP`: public origin IPv4 address advertised to other nodes.
- `DEEP_NODE_X25519_PRIVATE_KEY_FILE`: independent X25519 private scalar used
  to open exactly one native privacy layer.
- `DEEP_PRIVACY_PEER_<N>_*`: each authorized next-hop router id, HTTPS base
  URL, and distinct current/next SPKI pins. Peer frames use
  `/api/peer/privacy/v1/frame`, Ed25519 request authentication, bounded replay
  protection, and never trust an endpoint supplied by an inbound frame.
- The BLS signing URL is derived from the signed peer RPC contact and is not an
  operator setting. Production images accept that route only from the staking
  control-plane network.
- `DEEP_PUSH_NOTIFY_URL`: optional centralized push notify endpoint used by storage to trigger push delivery.
- `DEEP_REGISTRY_URL`: production registry API base URL.
- `DEEP_STAKING_BACKEND_URL`: production staking backend API base URL used by
  xnodes to verify quorum-signing policy quotes before signing reward,
  exit, or liquidation messages.
- `DEEP_OPERATOR_ADDRESS` and `DEEP_REWARDS_ADDRESS`: staked operator/reward wallet.
- `DEEP_ARBITRUM_RPC_URL`: backend-only Arbitrum One RPC. Use Alchemy or
  another private provider here if desired; do not expose this value through
  frontend `NEXT_PUBLIC_*` configuration.
- `DEEP_ARBITRUM_FALLBACK_RPC_URLS`: fallback Arbitrum One RPC list. The default
  production fallback is `https://arb1.arbitrum.io/rpc`.
- `DEEP_SERVICE_NODE_REWARDS_ADDRESS`: production `ServiceNodeRewards` contract.
- `DEEP_NODE_ED25519_PUBLIC_KEY`: public node/router id derived from `key_ed25519`.
- `DEEP_NODE_ED25519_PRIVATE_KEY_FILE`, `DEEP_NODE_X25519_PRIVATE_KEY_FILE`, and
  `DEEP_NODE_BLS_PRIVATE_KEY_FILE`: local files mounted as Docker secrets; do
  not put private key material directly in `.env`.
- `DEEP_NODE_VLESS_CLIENT_ID` and Reality fields: unique per node.
- `DEEP_DOCKER_LOG_MAX_SIZE` and `DEEP_DOCKER_LOG_MAX_FILE`: optional compose
  overrides for Docker `json-file` log rotation; defaults are `50m` and `5`.

## Start And Verify

Run the protected certificate/SPKI preflight from
`docs/PRODUCTION_NODE_TLS_INGRESS.md` first. Then:

```powershell
docker compose --env-file .\.env.node.prod -f .\docker-compose.node.prod.yml config --quiet
docker compose --env-file .\.env.node.prod -f .\docker-compose.node.prod.yml up -d
docker compose --env-file .\.env.node.prod -f .\docker-compose.node.prod.yml ps
docker compose --env-file .\.env.node.prod -f .\docker-compose.node.prod.yml logs --tail 100 xnode
docker compose --env-file .\.env.node.prod -f .\docker-compose.node.prod.yml logs --tail 100 storage-service
```

The only host listener is ingress. Raw backend health/status checks are
container-local and public admin/status paths are deliberately denied:

```powershell
docker compose --env-file .\.env.node.prod -f .\docker-compose.node.prod.yml exec xnode curl -fsS http://127.0.0.1:8080/health/ready
docker compose --env-file .\.env.node.prod -f .\docker-compose.node.prod.yml exec storage-service node -e "fetch('http://127.0.0.1:8080/health/ready').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
curl --fail --cacert <trusted-ca.pem> --pinnedpubkey "sha256//<approved-spki-base64>" https://<ingress-host>/api/bootstrap/client
```

The privacy contact published by heartbeat must be a canonical signed DPC1
contact with the sole `privacy-routing-v1` capability, the independent X25519
public key, and `https://<host>/api/peer/privacy/v1/frame`. A signed client
route contains exactly three distinct routers. Each router opens one layer and
learns only its predecessor plus the next router id; only the exit receives the
inner MAU2 mailbox frame. Storage replication happens after that exit and is
not counted as a privacy hop.

Control-plane checks:

```powershell
curl https://registry.deep.example/api/nodes
curl https://staking.deep.example/obligations
curl https://staking.deep.example/exit_liquidation_list
```

After the stake transaction is submitted on the staking portal, the router heartbeat publishes the BLS public key, proof of possession, transport bundle, signed privacy contact, and signing endpoint. The staking backend builds the BLS quorum signer set from chain-active service nodes and service-node obligation status, then uses registry-published endpoints only as an address cache. There is no UAT reward signer endpoint in the production path.

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

- Registry API/control plane: bootstrap cache, transport metadata cache, heartbeat mirror, and diagnostics are still centralized services, but they are not the authority for active service-node membership or reward quorum membership. The public node view is sanitized; the complete transport catalog is returned only to a healthy registered node after Ed25519 request authentication.
- Staking backend, chain indexer, reward checkpoint keeper, and the UI price endpoint are centralized application services around decentralized Arbitrum contracts. The chain/indexer determines active membership; service-node obligations gate reward/exit/liquidation signatures. XPNT price is sourced from the on-chain XPNT/USDC Uniswap V3 pool on Arbitrum One rather than a third-party price API.
- Staking portal/web frontend and the initial seed DNS names are centralized.
- Storage runs as a per-node sidecar with node-local state, matching the upstream Session service-node storage model more closely than a single central storage service.
- File/avatar and push services remain operated infrastructure. Push can never be fully decentralized while Android/iOS delivery goes through FCM/APNs/Huawei provider gateways.
- Container registry, observability, alerting, CI release evidence, and incident/rollback automation are centralized operations systems.
- Contract ownership/governance remains centralized until ownership is transferred to the final multisig/governance process.

The decentralized pieces in the current architecture are the Arbitrum contracts,
signed DPC1 privacy contacts, authenticated native layered relay transport, and
BLS quorum signatures produced by active, obligation-eligible service nodes.
Clients use an activation-authorized, hash-bound route artifact and verify every
contact. The next decentralization frontier is replacing the authenticated
registry cache with node-network gossip while keeping FCM/APNs/Huawei push
delivery centralized by platform necessity.
