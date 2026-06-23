# Production Seed Nodes Bootstrap

This runbook prepares the first three production XPoint nodes. These hosts are
the initial public bootstrap seeds for production clients and the initial BLS
quorum once they are staked on Arbitrum One.

Requested seed hostnames:

| Node | Public host |
| --- | --- |
| seed-1 | `seed1.expoint.network` |
| seed-2 | `seed2.xpoint.network` |
| seed-3 | `seed3.xpoint.network` |

Confirm `seed1.expoint.network` before the client release. It is recorded here
exactly as requested; if this is a DNS typo, change it to `seed1.xpoint.network`
before baking production bootstrap hosts into clients.

## Prerequisites

1. Build and push the node images from `docs/PRODUCTION_NODE_RUNBOOK.md`.
2. Create DNS `A`/`AAAA` records for all three hosts.
3. Open public TCP `443` to each host for VLESS Reality transport.
4. Keep the node API/signing endpoint private to the control plane. Use a
   private VPN, an allowlisted reverse proxy, or a private load balancer. Do not
   expose the raw node API as an unauthenticated public admin surface.
5. Prepare the production control-plane URLs:
   - registry API, used by `DEEP_REGISTRY_URL`;
   - staking backend, used by the portal and registry reconciliation;
   - push notify endpoint, optional for node-local storage sidecar.
6. The production staking contracts are on Arbitrum One:
   - XPNT token: `0x63B2cdb8B0d8774F1Fdca91D24803698582a079F`;
   - ServiceNodeRewards: `0xc52284b7aBAebbEF7BdE0E1ca8251B44AeA12F5f`;
   - ServiceNodeContributionFactory:
     `0x289d88A8C06881634Fb619Ec528361C7b88521f1`;
   - RewardRatePool: `0xEd894fb5f0BA3b141A562190D4c9941FEd348356`;
   - staking requirement: `25,000 XPNT`
     (`25000000000000` atomic).

## Prepare Each Host

Run these steps on each seed server.

```powershell
mkdir C:\xpoint-node
cd C:\xpoint-node
```

Copy these files from `deep-devops`:

```text
docker-compose.node.prod.yml
.env.node.prod.example
scripts/new-xnode-identity.ps1
scripts/new-xnode-identity.mjs
```

Create the node env:

```powershell
Copy-Item .\.env.node.prod.example .\.env.node.prod
New-Item -ItemType Directory -Force .\secrets | Out-Null
powershell -ExecutionPolicy Bypass -File .\scripts\new-xnode-identity.ps1 -AsEnv -OutDir .\secrets
```

Copy the printed values into `.env.node.prod`:

```text
DEEP_NODE_ED25519_PUBLIC_KEY=...
DEEP_NODE_ED25519_PRIVATE_KEY_FILE=./secrets/key_ed25519
DEEP_NODE_BLS_PRIVATE_KEY_FILE=./secrets/key_bls
DEEP_NODE_VLESS_CLIENT_ID=...
```

Generate Xray Reality keys:

```powershell
docker run --rm --entrypoint xray ghcr.io/xpointlabs/xnode:latest x25519
```

Put the generated key pair into:

```text
DEEP_NODE_REALITY_PRIVATE_KEY=...
DEEP_NODE_REALITY_PUBLIC_KEY=...
DEEP_NODE_REALITY_SHORT_ID=<unique 8-byte lowercase hex>
```

## Per-Node Env Values

Common production values:

```text
XNODE_IMAGE=ghcr.io/xpointlabs/xnode:<release-tag>
DEEP_STORAGE_SERVICE_IMAGE=ghcr.io/xpointlabs/deep-storage-service:<release-tag>
DEEP_NETWORK=mainnet
DEEP_NODE_PUBLIC_PORT=443
DEEP_NODE_VLESS_BIND=443
DEEP_NODE_API_BIND=127.0.0.1:8080
DEEP_NODE_STORAGE_BIND=127.0.0.1:22021
DEEP_REGISTRY_URL=https://registry.xpoint.network
DEEP_STORAGE_RPC_URL=http://storage-service:8080
DEEP_PUSH_NOTIFY_URL=https://push.xpoint.network/_compat/push-notify
DEEP_OPERATOR_ADDRESS=<staking operator wallet>
DEEP_REWARDS_ADDRESS=<staking rewards wallet>
DEEP_OPERATOR_FEE_BPS=0
DEEP_STAKE_ATOMIC=25000000000000
DEEP_ARBITRUM_RPC_URL=<private Arbitrum One RPC>
DEEP_ARBITRUM_FALLBACK_RPC_URLS=https://arb1.arbitrum.io/rpc
DEEP_ARBITRUM_CHAIN_ID=42161
DEEP_SERVICE_NODE_REWARDS_ADDRESS=0xc52284b7aBAebbEF7BdE0E1ca8251B44AeA12F5f
```

Seed-specific public hosts:

```text
# seed-1
DEEP_NODE_PUBLIC_HOST=seed1.expoint.network

# seed-2
DEEP_NODE_PUBLIC_HOST=seed2.xpoint.network

# seed-3
DEEP_NODE_PUBLIC_HOST=seed3.xpoint.network
```

Control-plane endpoints must point to the private route that the registry and
staking backend can reach. If the private management network resolves the seed
DNS names directly, use:

```text
DEEP_NODE_RPC_ENDPOINT=https://<seed-host>:8443/api/session/rpc
DEEP_NODE_SIGNING_ENDPOINT=https://<seed-host>:8443/api/staking/quorum/sign
```

If the control plane uses private hostnames or private IPs, use those instead.
The public client bootstrap host is still `DEEP_NODE_PUBLIC_HOST:443`.

## Start And Verify A Seed

```powershell
docker compose --env-file .\.env.node.prod -f .\docker-compose.node.prod.yml config --quiet
docker compose --env-file .\.env.node.prod -f .\docker-compose.node.prod.yml up -d
docker compose --env-file .\.env.node.prod -f .\docker-compose.node.prod.yml ps
docker compose --env-file .\.env.node.prod -f .\docker-compose.node.prod.yml logs --tail 100 xnode
```

Local host checks:

```powershell
curl http://127.0.0.1:8080/health/live
curl http://127.0.0.1:8080/health/ready
curl http://127.0.0.1:8080/status
curl http://127.0.0.1:22021/health/ready
curl http://127.0.0.1:22021/stats
```

Control-plane checks:

```powershell
curl https://registry.xpoint.network/api/nodes
curl https://registry.xpoint.network/api/relay-contacts
curl https://staking.xpoint.network/obligations
```

Every seed must appear in the registry with:

- matching `nodeId` / `DEEP_NODE_ED25519_PUBLIC_KEY`;
- `publicHost` equal to its seed hostname;
- `onion-v1` capability;
- non-mocked VLESS transport;
- populated BLS public key and signing endpoint.

## Stake And Start Production Registration

Production `ServiceNodeRewards` was deployed with `isStarted=false`.

For manual staking through the portal:

1. The contract owner starts the rewards contract once by calling
   `ServiceNodeRewards.start()` on Arbitrum One.
2. Open the production staking portal.
3. Go to `Register`.
4. Register each seed node with `25,000 XPNT` from the chosen operator wallet.
5. Wait for Arbitrum confirmations and indexer catch-up.
6. Confirm `/contract_nodes`, `/nodes/bls`, `/obligations`, and the portal all
   show the three seeds as active/reward-eligible.

Do not call `seedPublicKeyList(...)` if the chosen bootstrap flow is manual
portal staking. `seedPublicKeyList(...)` is only for owner-seeded initial nodes
before `start()`.

## Production Client Bootstrap

After all three nodes are active on-chain and healthy in the registry, production
clients can include these bootstrap hosts:

```text
seed1.expoint.network:443
seed2.xpoint.network:443
seed3.xpoint.network:443
```

Client releases must also point discovery/bootstrap APIs at the production
registry and staking backend. The client should use registry-published relay
contacts for live routing, not a static list of registry rows.
