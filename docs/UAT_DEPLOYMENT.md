# Deep UAT Deployment

Last updated: 2026-07-18.

This runbook brings up the first QA UAT stack on the LAN host `192.168.1.44`.
It uses Arbitrum Sepolia for XPNT staking contracts and Docker on this machine
for the backend, staking portal, product storage/file/calls services, push compatibility service, and three router nodes.

## Stop-the-line: credentials retired

All UAT deployer, Ed25519, and BLS private values that were previously tracked
in this repository are compromised. The old UAT stack and registrations are
historical evidence only. Do not restart the stack, sign a transaction, claim a
reward, or reuse any old identity until Mr. X completes the irreversible
rotation checklist in `docs/SECRET_SAFE_EVIDENCE.md`.

## Historical Deployment Status

Contracts are deployed on Arbitrum Sepolia and are ready for UAT. The current
staking contract set uses BLS12-381/EIP-2537 precompiles for service node BLS
proof-of-possession and aggregate signature verification.

`ServiceNodeRewards` was activated with `start()` on 2026-06-12:

```text
SERVICE_NODE_REWARDS_STARTED=true
SERVICE_NODE_REWARDS_START_TX=0xc595feb3a3cb9b1236e1292a47b6754335e45c00158b99b074b065171dd906b3
SERVICE_NODE_REWARDS_START_BLOCK=276205387
```

`RewardRatePool` is funded with `40,000,000 XPNT`. `ServiceNodeRewards` starts
with `0 XPNT` by design; node stake is transferred into it by
`addBLSPublicKey`/staking transactions after wallet approval. UAT now also runs
`staking-reward-keeper`, which periodically calls `RewardRatePool.checkpoint()`
so accrued reward funds are moved on-chain into `ServiceNodeRewards` before QA
claims rewards.

Initial UAT checkpoint executed on 2026-06-18:

```text
REWARD_RATE_POOL_CHECKPOINT_TX=0xe9da7b107670c424966210544525f6e4c92b84fe635ba4c6c115b47309bca226
REWARD_RATE_POOL_CHECKPOINT_BLOCK=278498755
SERVICE_NODE_REWARDS_BALANCE_AFTER=114524.733637747 XPNT
```

UAT reward validation on 2026-06-18 after the first QA claim:

```text
SERVICE_NODE_REWARDS_TOTAL_NODES=3
DEPLOYER_RECIPIENT_REWARDS_ATOMIC=101721299656280
DEPLOYER_RECIPIENT_CLAIMED_ATOMIC=101721299656280
SERVICE_NODE_REWARDS_BALANCE=13284.5119395 XPNT
REWARD_RATE_POOL_BALANCE=39885354.188404225 XPNT
```

The staking backend reconciles `GET /rewards/{wallet}` and
`POST /rewards/{wallet}` with `ServiceNodeRewards.recipients(wallet)` before
returning claimable rewards or a BLS reward signature. For reward signatures,
the backend requests partial signatures from the registered router nodes and
aggregates them; backend does not hold service-node BLS private scalars. This
keeps the portal in sync even if an already-mined `RewardsClaimed` event has not
been replayed by the local chain indexer yet.

Generated UAT deployer:

```text
address: 0xb0cE3b1229c00d1B85c7083E31Dae531f3B352C0
mnemonic: <removed-compromised-value>
```

The removed mnemonic is compromised. UAT credentials are secrets even when
they hold no production funds.

## Contract Addresses

Current Arbitrum Sepolia UAT deployment:

```text
XPNT_TOKEN_ADDRESS=0x992E6EA54d74e79cd2CEC8D9fBD101a9a105ace5
SERVICE_NODE_REWARDS_ADDRESS=0x08A5a47E67fCd18e14AdFB535e8d8644476D4197
SERVICE_NODE_CONTRIBUTION_FACTORY_ADDRESS=0x34e50278dbeDdB0F8EC7641D2304CFf4F116066b
SERVICE_NODE_CONTRIBUTION_IMPLEMENTATION_ADDRESS=0x0561C7aEee3F72a14796BD5ed5b35622eC5ef4D2
REWARD_RATE_POOL_ADDRESS=0xe055c7200aE13984fe66c2e8AaC608bC80E19D57
UAT_CONTRACT_START_BLOCK=276115489
STAKING_REQUIREMENT_ATOMIC=120000000000
```

## Deploy Contracts

This section is blocked until Mr. X provisions a new wallet through the
protected secret procedure. Never reuse the retired deployer.

Run from `C:\Work\Deep\xpoint-staking-contracts`.

```powershell
$env:ARB_SEPOLIA_RPC_URL = "https://arb-sepolia.g.alchemy.com/v2/<alchemy-key>"
$env:ARB_SEPOLIA_FALLBACK_RPC_URLS = "https://sepolia-rollup.arbitrum.io/rpc"
$env:ARB_SEPOLIA_MNEMONIC = <load-from-protected-secret-store>

docker compose run --rm `
  -e ARB_SEPOLIA_RPC_URL="$env:ARB_SEPOLIA_RPC_URL" `
  -e ARB_SEPOLIA_FALLBACK_RPC_URLS="$env:ARB_SEPOLIA_FALLBACK_RPC_URLS" `
  -e ARB_SEPOLIA_MNEMONIC=<load-from-protected-secret-store> `
  contracts-devnet pnpm deploy-uat-arbitrum-sepolia
```

Expected output:

- a deployment manifest at `deployments/arbitrumSepolia.latest.json`;
- deployed or reused XPNT token, `ServiceNodeRewards`, `ServiceNodeContributionFactory`, `ServiceNodeContribution` implementation, and `RewardRatePool`;
- staking requirement of `120 XPNT` (`120000000000` atomic units), unless overridden.

After a redeploy, update the contract address block above and
`UAT_CONTRACT_START_BLOCK` from the deployment manifest so the indexer starts
at the first relevant contract event.

## Configure UAT Docker

Run from `C:\Work\Deep\deep-devops`.

```powershell
Copy-Item .env.uat.example .env.uat
New-Item -ItemType Directory -Force .secrets/uat
Copy-Item secret-templates/uat/reward-keeper.env.example .secrets/uat/reward-keeper.env
Copy-Item secret-templates/uat/node-1.env.example .secrets/uat/node-1.env
Copy-Item secret-templates/uat/node-2.env.example .secrets/uat/node-2.env
Copy-Item secret-templates/uat/node-3.env.example .secrets/uat/node-3.env
notepad .env.uat
```

Set:

- `ARB_SEPOLIA_RPC_URL` to the private/backend-only Arbitrum Sepolia RPC, for
  example `https://arb-sepolia.g.alchemy.com/v2/<alchemy-key>`.
- `ARB_SEPOLIA_FALLBACK_RPC_URLS` to `https://sepolia-rollup.arbitrum.io/rpc`.
- `UAT_BROWSER_ARBITRUM_RPC_URL` to `/api/network/rpc/arbitrum`. Do not point
  `NEXT_PUBLIC_RPC_URL_ARB` or any `NEXT_PUBLIC_*` variable at `alchemy.com`;
  the browser must call the staking backend RPC proxy so provider tokens remain
  server-side.
- Keep the prefilled contract addresses and `UAT_CONTRACT_START_BLOCK` unless UAT contracts were redeployed.
- Keep `UAT_OPERATOR_ADDRESS` and `UAT_REWARDS_ADDRESS` on the UAT deployer wallet while QA uses deployer-owned nodes.
- Set only secret-file paths in `.env.uat`. Put the newly generated deployer
  mnemonic in `.secrets/uat/reward-keeper.env`; put each newly generated
  Ed25519/BLS private value in its matching node file. Compose injects those
  variables through `env_file` and the repository never resolves or captures
  them.
- Keep the `PRICE_*` / `XPNT_UNISWAP_V3_POOL_ADDRESS` values pointed at the production Arbitrum One XPNT/USDC Uniswap V3 pool. UAT still runs staking on Arbitrum Sepolia, but XPNT price is intentionally read from the production pool for every environment.
- Router nodes derive their BLS signer URL from the signed peer RPC contact. The staking backend discovers signer metadata through the Docker-only `/api/internal/nodes` catalog, matches it to active on-chain BLS public keys from `ServiceNodeRewards`, and aggregates only signatures returned by registered active nodes. The public `/api/nodes` response never includes signer URLs or transport credentials.
- The router signing endpoint supports the contract-level quorum messages used by `ServiceNodeRewards`: reward balance updates, normal exits, and liquidations. The staking backend derives service-node obligations from on-chain state plus registry heartbeat/transport health. `/obligations` shows the full status set, `/exit_liquidation_list` exposes only currently eligible exits/liquidations, and direct `/exit/{bls}` or `/liquidation/{bls}` requests are rejected until the indexed state is eligible.
- Keep `SERVICE_NODE_HEARTBEAT_GRACE_SECONDS`, `SERVICE_NODE_DECOMMISSION_GRACE_SECONDS`, and `SERVICE_NODE_LIQUIDATION_GRACE_SECONDS` at their defaults for QA unless you intentionally need faster local failure drills.
- Keep `UAT_INDEXER_ALCHEMY_FAST_BACKFILL=false` unless the backend/indexer is
  intentionally allowed to use Alchemy-specific namespace calls. Normal JSON-RPC
  calls use `ARB_SEPOLIA_RPC_URL` first and `ARB_SEPOLIA_FALLBACK_RPC_URLS` if
  the primary endpoint is transiently unavailable.
- Keep `UAT_INDEXER_BATCH_BLOCKS=1000000` and
  `UAT_INDEXER_MAX_LOG_BLOCK_RANGE=1000000` with the public Arbitrum Sepolia
  RPC. The indexer queries only the watched contract addresses, so this keeps a
  redeployed UAT environment from spending hours replaying a sparse history.
  If QA moves to a stricter RPC tier, lower both values together.
- `NEXT_PUBLIC_WALLET_CONNECT_PROJECT_ID` to the WalletConnect project id used by QA.
- `DEEP_STAKING_PORTAL_DIR` to `..\xpoint-staking-portal`.
- `STAKING_PORTAL_COMMIT_HASH` to `git -C ..\xpoint-staking-portal rev-parse HEAD`.
- Keep `NEXT_PUBLIC_ENV_FLAG=prd` for production-like staking portal behavior.

Do not commit `.env.uat` or `.secrets/`. Run
`node scripts/secret-scan.mjs` before any evidence collection or upload.

## Start UAT

The start remains technically blocked until the signed, public-only rotation
receipt and protected secret-file metadata pass:

```powershell
node scripts/uat-rotation-preflight.mjs `
  --receipt <rotation-receipt.json> `
  --secret-dir .secrets/uat `
  --trusted-signer-sha256 <Mr-X-public-signing-key-sha256>
```

The receipt contains only retired/replacement public identities and successful
transaction receipt metadata. Never place an old mnemonic, private scalar,
private key, or its hash in this receipt. The preflight cryptographically
verifies the receipt, requires exit/revocation and replacement-registration
transaction metadata, and rejects non-canonical, reparse-linked, broadly
readable, or unexpected secret files without reading their contents.

```powershell
docker compose -f docker-compose.uat.yml --env-file .env.uat up -d --build
```

LAN endpoints:

```text
Registry/admin:        http://192.168.1.44:28080
Staking backend API:   http://192.168.1.44:28082
Staking portal:        http://192.168.1.44:28083
Storage service:       http://192.168.1.44:28100
File service:          http://192.168.1.44:28101
Push service:          http://192.168.1.44:28102
Call signaling:        http://192.168.1.44:28103
Router node 1 API:     http://192.168.1.44:29281
Router node 2 API:     http://192.168.1.44:29282
Router node 3 API:     http://192.168.1.44:29283
Router node 1 VLESS:   192.168.1.44:20443
Router node 2 VLESS:   192.168.1.44:20444
Router node 3 VLESS:   192.168.1.44:20445
```

UAT uses the `28xxx/29xxx` host port ranges so it can run side-by-side with
the existing local `deep-dev` stack. The VLESS host ports intentionally
use `20443-20445`; on this Windows host `19443` is reserved by the system and
Docker cannot bind it.

Health checks:

```powershell
Invoke-RestMethod http://192.168.1.44:28082/info
Invoke-RestMethod http://192.168.1.44:28082/obligations
Invoke-RestMethod http://192.168.1.44:28082/exit_liquidation_list
Invoke-RestMethod http://192.168.1.44:28080/api/nodes/runtime
Invoke-RestMethod http://192.168.1.44:29281/health/ready
Invoke-RestMethod http://192.168.1.44:29282/health/ready
Invoke-RestMethod http://192.168.1.44:29283/health/ready
```

Reward checks:

```powershell
Invoke-RestMethod http://192.168.1.44:28082/rewards/0xb0cE3b1229c00d1B85c7083E31Dae531f3B352C0
Invoke-RestMethod http://192.168.1.44:28082/daily-rewards/0xb0cE3b1229c00d1B85c7083E31Dae531f3B352C0
Invoke-RestMethod http://192.168.1.44:28082/rewards/0xb0cE3b1229c00d1B85c7083E31Dae531f3B352C0 -Method Post
docker logs --tail 50 deep-uat-staking-reward-keeper-1
```

`GET /rewards/{wallet}` is the local Session-compatible rewards projection.
`POST /rewards/{wallet}` returns the BLS12-381 aggregate signature used by the
staking portal to call `ServiceNodeRewards.updateRewardsBalance`, followed by
`claimRewards`. The aggregate signature is built from xnode partial
signatures; any active node that does not return a valid signature is reported
in `non_signer_indices`.

The UAT chain indexer is configured with 10-block log ranges because the current
Alchemy Free endpoint rejects wider ranges. If the indexer state is ever far
behind while the backend already has the expected node projection, first verify:

```powershell
Invoke-RestMethod http://192.168.1.44:28082/contract_nodes
docker exec deep-uat-staking-reward-keeper-1 node --input-type=module -e "import { createPublicClient, http, parseAbi } from 'viem'; import { arbitrumSepolia } from 'viem/chains'; const c=createPublicClient({chain:arbitrumSepolia,transport:http(process.env.ARB_SEPOLIA_RPC_URL)}); const abi=parseAbi(['function totalNodes() view returns (uint256)']); console.log((await c.readContract({address:process.env.SERVICE_NODE_REWARDS_ADDRESS,abi,functionName:'totalNodes'})).toString());"
```

Only after backend node count and `totalNodes()` match, the indexer cursor can
be advanced to the current safe block so it watches new events from the chain
head instead of replaying millions of old empty blocks through a 10-block RPC
limit.

## Staking And Manual Node Registration

The router nodes do not auto-stake and do not register themselves on-chain.
They publish prepared BLS12-381 registration payloads to the local registry.
The staking backend exposes those payloads through `/registrations/{walletOrKey}`,
so the staking portal can show them for the deployer/operator wallet. This mirrors
the original Session flow: the node produces registration data, while staking and
finalization remain operator actions.

Retired UAT router identities. The Ed25519 public key was both the signed relay
router id and the staking registration `serviceNodePubkey`, matching the
production model and upstream Session/Oxen HF21 identity model. Contract IDs
1, 2, and 3 are the old `0201` / `0202` / `0203` registrations and are now in
`exit-requested` state. Contract IDs 4, 5, and 6 must also be exited/revoked
before newly generated identities are registered.

| Router | Active contract ID | Retired Ed25519 public id | API | VLESS |
| --- | --- | --- | --- | --- |
| node 1 | `4` | `5979c8dda9c10cff26db46b96cefd9ea3527c2ce90b99886342d71c54e8ed4dc` | `http://192.168.1.44:29281` | `192.168.1.44:20443` |
| node 2 | `5` | `298f4fb1eb601d5f900332c728829d19be6282f5e50c2bd3cea055a27d83c51c` | `http://192.168.1.44:29282` | `192.168.1.44:20444` |
| node 3 | `6` | `c08f5aecc314da789193719a15f1fa2e21a1aeadf266a6b53bd667974870c846` | `http://192.168.1.44:29283` | `192.168.1.44:20445` |

Manual staking flow:

1. Open the staking portal at `http://192.168.1.44:28083`.
2. Connect the operator wallet on Arbitrum Sepolia.
3. Select one of the prepared deployer-owned node registrations shown by the portal.
4. For multi-contributor nodes, leave `manual finalize` enabled if QA wants the node to remain visible as pending until the operator finalizes.
5. Contribute the required XPNT stake into the smart contract.
6. Manually finalize/register after the stake is complete.
7. The registry already contains the LAN transport data from the running router heartbeat.

Prepared registration checks:

```powershell
Invoke-RestMethod http://192.168.1.44:28080/api/nodes
Invoke-RestMethod http://192.168.1.44:28082/registrations/0xb0cE3b1229c00d1B85c7083E31Dae531f3B352C0
```

Onion route smoke check:

```powershell
dotnet run --project tools\uat-onion-smoke\XNode.UatOnionSmoke.csproj -- `
  --routers http://192.168.1.44:29281,http://192.168.1.44:29282,http://192.168.1.44:29283
```

The smoke uses the same `XNodeRpcClient` as the MAUI client. It stores
and retrieves a message through `onion_request` and fails unless the active
route is `onion-storage` with three router nodes.

The current full BLS12-381 public keys and proof-of-possession signatures are
recorded in `docs/UAT_BLS12_REGISTRATIONS.md`.

Manual registry API shape, only if a router heartbeat must be reproduced by hand:

```powershell
$body = @{
  nodeId = "<ed25519-node-id>"
  operatorAddress = "0xb0cE3b1229c00d1B85c7083E31Dae531f3B352C0"
  rewardsAddress = "0xb0cE3b1229c00d1B85c7083E31Dae531f3B352C0"
  blsPublicKey = @{ data = "<128-byte EIP-2537 G1 public key hex>" }
  blsSignature = "<256-byte EIP-2537 G2 proof-of-possession signature hex>"
  ed25519PublicKey = "<ed25519>"
  ed25519Signature1 = "<sig1>"
  ed25519Signature2 = "<sig2>"
  operatorFeeBps = 0
  stakeAtomic = 120000000000
  contributors = @(@{
    address = "<operator-wallet>"
    beneficiary = "<rewards-wallet>"
    amountAtomic = 120000000000
  })
  transport = @{
    protocol = "vless"
    host = "192.168.1.44"
    port = 20443
    uuid = "<from http://192.168.1.44:29281/api/bootstrap/client>"
    security = "none"
    flow = ""
    sni = ""
    publicKey = ""
    shortId = ""
    fingerprint = "chrome"
    path = ""
    alpn = @()
  }
  relayContact = @{
    routerId = "<ed25519-node-id>"
    publicHost = "192.168.1.44"
    publicPort = 20443
    x25519PublicKey = "<32-byte X25519 public key hex derived from key_ed25519>"
    rpcEndpoint = "http://xnode-1:8080"
    signedAt = (Get-Date).ToUniversalTime()
    expiresAt = (Get-Date).ToUniversalTime().AddDays(30)
    routerVersion = "manual"
    isReachable = $true
    capabilities = @("vless-ingress", "session-rpc", "onion-v1")
    signatureAlgorithm = "ed25519"
    signature = "<relay contact signature>"
  }
} | ConvertTo-Json -Depth 8

Invoke-RestMethod http://192.168.1.44:28080/api/nodes/register `
  -Method Post `
  -ContentType "application/json" `
  -Body $body
```

For node 2 use API `29282` and VLESS port `20444`; for node 3 use API `29283`
and VLESS port `20445`.

## Reset UAT State After Contract Redeploy

When the contract addresses or start block change, reset the local UAT volumes
before starting the stack so the registry and indexer do not keep stale BN256 or
old-address data:

```powershell
docker compose -f docker-compose.uat.yml --env-file .env.uat down
docker volume rm deep-uat_staking-backend-state deep-uat_staking-indexer-state deep-uat_registry-state
docker compose -f docker-compose.uat.yml --env-file .env.uat up -d --build
```

## QA Clients

Release MAUI builds read `deep.release.env` from the app output
directory. It is already set to:

```text
XNODE_URLS=http://192.168.1.44:29281;http://192.168.1.44:29282;http://192.168.1.44:29283
DEEP_CALL_SIGNALING_BASE_URL=http://192.168.1.44:28103
DEEP_FILE_URL=http://192.168.1.44:28101
DEEP_PUSH_URL=http://192.168.1.44:28102
```

Build and install desktop/Android clients after the Docker stack is up. The
Android device must be on the same LAN and able to reach `192.168.1.44`.

## Stop UAT

```powershell
docker compose -f docker-compose.uat.yml --env-file .env.uat down
```

State is kept in Docker volumes:

- `deep-uat_staking-backend-state`
- `deep-uat_staking-indexer-state`
- `deep-uat_registry-state`
- `deep-uat_storage-state`
- `deep-uat_file-state`
- `deep-uat_calls-state`
- `deep-uat_compat-state` for push compatibility state
