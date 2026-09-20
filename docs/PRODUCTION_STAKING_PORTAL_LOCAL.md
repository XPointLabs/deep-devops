# Local Production Staking Portal

This compose stack runs the production staking portal locally without reusing
the UAT project, ports, or Arbitrum Sepolia contracts.

It starts:

- staking backend on `http://127.0.0.1:28182`;
- local registry cache on `http://127.0.0.1:28180`;
- production staking portal on `http://127.0.0.1:28183`;
- Arbitrum One chain indexer for the production staking contracts.

The browser-safe RPC URL is `/api/network/rpc/arbitrum`. Private RPC provider
tokens must stay in `PROD_ARBITRUM_RPC_URL` on the backend side and must not be
placed in `NEXT_PUBLIC_*`.

## Configuration

```powershell
cd C:\Work\DeepSession\XPointLabs\deep-devops
Copy-Item .\.env.staking.prod.local.example .\.env.staking.prod.local
(git -C ..\xpoint-staking-portal rev-parse HEAD)
```

Edit `.env.staking.prod.local`:

- set `STAKING_PORTAL_COMMIT_HASH` to the printed portal commit;
- set `NEXT_PUBLIC_WALLET_CONNECT_PROJECT_ID` to the production WalletConnect
  project id when WalletConnect testing is needed;
- keep `PROD_ARBITRUM_RPC_URL` on a backend-only Arbitrum One RPC. For local
  smoke testing the public fallback `https://arb1.arbitrum.io/rpc` is enough;
  for long indexer catch-up use a private RPC as primary and keep
  `PROD_ARBITRUM_FALLBACK_RPC_URLS=https://arb1.arbitrum.io/rpc`.

## Start

```powershell
docker compose --env-file .\.env.staking.prod.local -f .\docker-compose.staking.prod.local.yml config --quiet
docker compose --env-file .\.env.staking.prod.local -f .\docker-compose.staking.prod.local.yml up -d --build --wait
```

Open:

```text
http://127.0.0.1:28183
```

## Verify

```powershell
curl http://127.0.0.1:28182/health/live
curl http://127.0.0.1:28182/info
curl http://127.0.0.1:28180/health/live
curl http://127.0.0.1:28183/
docker compose --env-file .\.env.staking.prod.local -f .\docker-compose.staking.prod.local.yml ps
docker compose --env-file .\.env.staking.prod.local -f .\docker-compose.staking.prod.local.yml logs --tail 100 staking-indexer
```

On the registry production host, this stack also backs
`https://staking.xpoint.network/`. Check the public URL and all three staking
containers after registry maintenance; a healthy registry alone does not prove
that the staking portal is available. The backend, indexer, and portal use
`restart: unless-stopped` so host restarts do not leave them permanently down.

On 2026-09-20, the public portal returned 502 while the portal, backend, and
indexer containers were stopped. The portal's last log showed a Node.js heap
out-of-memory failure; the backend and indexer had exited with status 137.
The existing containers were started without rebuilding images or touching
volumes, and the public portal returned 200 again. This restores availability
but does not resolve the portal's possible memory growth. Monitor container
memory and exit status, especially on the approximately 2 GiB host, and
investigate repeated exits before calling the incident permanently closed.

For incident recovery, first inspect `docker ps -a` and recent container logs.
Starting existing stopped containers preserves their image and volume state.
Do not use `down -v` on the production host: it deletes persistent staking and
registry state.

The staking backend reads quorum signer metadata from
`http://registry:8080/api/internal/nodes` on the private Compose network. Add
`nginx/registry-internal-deny.conf` to the public registry virtual host; the
`/api/internal/` namespace must return `404` from the Internet.

Expected `/info` contract values:

```text
chainId=42161
token=0x63B2cdb8B0d8774F1Fdca91D24803698582a079F
serviceNodeRewards=0xc52284b7aBAebbEF7BdE0E1ca8251B44AeA12F5f
contributionFactory=0x289d88A8C06881634Fb619Ec528361C7b88521f1
rewardRatePool=0xEd894fb5f0BA3b141A562190D4c9941FEd348356
stakingRequirementAtomic=25000000000000
```

## Stop

```powershell
docker compose --env-file .\.env.staking.prod.local -f .\docker-compose.staking.prod.local.yml down
```

The `down` command stops the portal, backend, indexer and registry together;
never use it as a portal-only recovery step on the production host. Do not
pass `-v`: this stack includes persistent registry and staking volumes.
