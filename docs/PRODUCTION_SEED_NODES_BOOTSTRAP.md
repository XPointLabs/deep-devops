# Production Seed Nodes Bootstrap

This runbook prepares the first three production XPoint nodes on Linux hosts.
Use it on every seed server with a unique node identity, BLS key, VLESS client
id, and Xray Reality key pair.

These hosts are the initial public bootstrap seeds for production clients and
the initial BLS quorum once they are staked on Arbitrum One.

Requested seed hostnames:

| Node | Public host |
| --- | --- |
| seed-1 | `seed1.xpoint.network` |
| seed-2 | `seed2.xpoint.network` |
| seed-3 | `seed3.xpoint.network` |

## Prerequisites

1. Use Ubuntu 22.04/24.04 LTS or another Linux distribution with Docker Engine
   and the Docker Compose plugin.
2. Build and push the node images from `docs/PRODUCTION_NODE_RUNBOOK.md`.
3. Create DNS `A`/`AAAA` records for all three seed hosts.
4. Open only hardened ingress TCP `443`. Exact-host HTTPS and Reality SNI
   share that listener. Do not open raw peer/API/storage ports.
5. Prepare current/next TLS certificates, private keys, and PMT1 SPKI pins as
   specified by `docs/PRODUCTION_NODE_TLS_INGRESS.md`.
6. Prepare the production control-plane URLs:
   - registry API, used by `DEEP_REGISTRY_URL`;
   - staking backend, used by the portal and registry reconciliation;
   - push notify endpoint, optional for node-local storage sidecar.
7. The production staking contracts are on Arbitrum One:
   - XPNT token: `0x63B2cdb8B0d8774F1Fdca91D24803698582a079F`;
   - ServiceNodeRewards: `0xc52284b7aBAebbEF7BdE0E1ca8251B44AeA12F5f`;
   - ServiceNodeContributionFactory:
     `0x289d88A8C06881634Fb619Ec528361C7b88521f1`;
   - RewardRatePool: `0xEd894fb5f0BA3b141A562190D4c9941FEd348356`;
   - staking requirement: `25,000 XPNT`
     (`25000000000000` atomic).

## Install Host Packages

Use the public node installer from
`https://github.com/XPointLabs/xpoint-node-installer`. It is the canonical
operator-facing path for independent node owners: it installs Docker Engine and
the Compose plugin plus bootstrap host tools when needed, configures Docker
`json-file` log rotation, writes the production node compose/env files, and can
prune stopped containers, unused images, and build cache without removing
volumes.

Example from the operator workstation:

```bash
ssh root@<seed-host> 'curl -fsSL https://raw.githubusercontent.com/XPointLabs/xpoint-node-installer/main/install-xpoint-node.sh -o /tmp/install-xpoint-node.sh'
ssh root@<seed-host> 'chmod +x /tmp/install-xpoint-node.sh && /tmp/install-xpoint-node.sh --no-start --prune-docker'
```

Equivalent command when the public installer repository is already on the seed
host:

```bash
cd /opt/xpoint-node-installer
sudo ./install-xpoint-node.sh --no-start --prune-docker
```

By default, Docker host logs are capped at `50m` x `5` files. Override with
`--docker-log-max-size`, `--docker-log-max-file`, or the matching env vars
`DEEP_DOCKER_LOG_MAX_SIZE` and `DEEP_DOCKER_LOG_MAX_FILE`.

On existing production hosts, `--prune-docker` can remove unused rollback images
and build cache. It never removes Docker volumes, but preserve any rollback tags
you need before pruning.

If the deployment user should run Docker without `sudo`:

```bash
sudo usermod -aG docker "$USER"
newgrp docker
docker version
docker compose version
```

## Prepare The Node Directory

Run on each seed host:

```bash
sudo mkdir -p /opt/xpoint-node
sudo chown "$USER:$USER" /opt/xpoint-node
cd /opt/xpoint-node
```

Copy these files from `deep-devops` to `/opt/xpoint-node`:

```text
docker-compose.node.prod.yml
.env.node.prod.example
scripts/new-xnode-identity.mjs
scripts/production-ingress-entrypoint.sh
scripts/production-ingress-preflight.ps1
scripts/production-ingress-spki.mjs
scripts/production-ingress-contracts.mjs
config/production-ingress/haproxy.cfg.template
docs/PRODUCTION_NODE_TLS_INGRESS.md
```

Example from the operator workstation:

```bash
rsync -av docker-compose.node.prod.yml .env.node.prod.example scripts config docs/PRODUCTION_NODE_TLS_INGRESS.md \
  deploy@<seed-host>:/opt/xpoint-node/
```

On the seed host, create the env file:

```bash
cp .env.node.prod.example .env.node.prod
chmod 600 .env.node.prod
mkdir -p secrets
chmod 700 secrets
```

Generate the node identity:

```bash
node ./scripts/new-xnode-identity.mjs --as-env --out-dir ./secrets | tee ./identity.generated.env
chmod 600 ./identity.generated.env ./secrets/key_ed25519 ./secrets/key_bls
```

Copy the printed values from `identity.generated.env` into `.env.node.prod`:

```text
DEEP_NODE_ED25519_PUBLIC_KEY=...
DEEP_NODE_ED25519_PRIVATE_KEY_FILE=./secrets/key_ed25519
DEEP_NODE_BLS_PRIVATE_KEY_FILE=./secrets/key_bls
DEEP_NODE_VLESS_CLIENT_ID=...
```

Back up `secrets/key_ed25519`, `secrets/key_bls`, and `.env.node.prod` in the
production secret store. Losing these files means losing the node identity.

## Generate Xray Reality Keys

Run on each seed host:

```bash
docker run --rm --entrypoint xray ghcr.io/xpointlabs/xnode:latest x25519
openssl rand -hex 8
```

Put the generated values into `.env.node.prod`:

```text
DEEP_NODE_REALITY_PRIVATE_KEY=<xray private key>
DEEP_NODE_REALITY_PUBLIC_KEY=<xray public key>
DEEP_NODE_REALITY_SHORT_ID=<unique 8-byte lowercase hex from openssl>
```

## Configure Common Env Values

Set these values in `.env.node.prod` on every seed host:

```text
XNODE_IMAGE=ghcr.io/xpointlabs/xnode:<release-tag>
DEEP_STORAGE_SERVICE_IMAGE=ghcr.io/xpointlabs/deep-storage-service:<release-tag>
DEEP_NETWORK=mainnet

DEEP_NODE_PUBLIC_PORT=443
DEEP_NODE_PUBLIC_IP=<public origin IPv4 address>
DEEP_NODE_PEER_RPC_PORT=443
DEEP_NODE_PEER_RPC_ENDPOINT=https://<seed-host>/api/peer/onion

DEEP_INGRESS_CERTIFICATE_PROFILE=deep-managed
DEEP_INGRESS_HOST=<seed-host>
DEEP_INGRESS_HTTPS_BIND=443
DEEP_INGRESS_CURRENT_CERT_FILE=./secrets/ingress/current.crt
DEEP_INGRESS_CURRENT_KEY_FILE=./secrets/ingress/current.key
DEEP_INGRESS_CURRENT_SPKI_FILE=./secrets/ingress/current.spki-sha256
DEEP_INGRESS_NEXT_CERT_FILE=./secrets/ingress/next.crt
DEEP_INGRESS_NEXT_KEY_FILE=./secrets/ingress/next.key
DEEP_INGRESS_NEXT_SPKI_FILE=./secrets/ingress/next.spki-sha256
DEEP_INGRESS_CLIENT_TIMEOUT_SECONDS=30
DEEP_INGRESS_SERVER_TIMEOUT_SECONDS=30
DEEP_QUORUM_COORDINATOR_CIDR=<exact-public-coordinator-ip>/32

DEEP_REGISTRY_URL=https://registry.xpoint.network
DEEP_STAKING_BACKEND_URL=https://staking-api.xpoint.network
DEEP_PUSH_NOTIFY_URL=https://push.xpoint.network/_compat/push-notify
DEEP_REGISTRY_HEARTBEAT_INTERVAL=00:00:30
DEEP_ENFORCE_QUORUM_SIGNING_POLICY=true
DEEP_QUORUM_POLICY_BACKEND_TIMEOUT_SECONDS=5
DEEP_MAX_REWARD_SIGNATURE_INCREASE_ATOMIC=100000000000000
DEEP_MAX_QUORUM_SIGNATURE_TIMESTAMP_SKEW_SECONDS=300
DEEP_DOCKER_LOG_MAX_SIZE=50m
DEEP_DOCKER_LOG_MAX_FILE=5

DEEP_OPERATOR_ADDRESS=<staking operator wallet>
DEEP_REWARDS_ADDRESS=<staking rewards wallet>
DEEP_OPERATOR_FEE_BPS=0

DEEP_ARBITRUM_RPC_URL=<private Arbitrum One RPC>
DEEP_ARBITRUM_FALLBACK_RPC_URLS=https://arb1.arbitrum.io/rpc
DEEP_ARBITRUM_CHAIN_ID=42161
DEEP_SERVICE_NODE_REWARDS_ADDRESS=0xc52284b7aBAebbEF7BdE0E1ca8251B44AeA12F5f

DEEP_NODE_MASK_DOMAIN=www.microsoft.com
DEEP_NODE_REALITY_SERVER_NAME=www.microsoft.com
DEEP_NODE_REALITY_FINGERPRINT=chrome
DEEP_NODE_REALITY_SPIDER_X=/
```

Do not put private key material directly into `.env.node.prod`. The compose file
mounts Ed25519 and BLS keys from files as Docker secrets.

## Configure Seed-Specific Values

Set the public host per server:

```text
# seed-1
DEEP_NODE_PUBLIC_HOST=seed1.xpoint.network

# seed-2
DEEP_NODE_PUBLIC_HOST=seed2.xpoint.network

# seed-3
DEEP_NODE_PUBLIC_HOST=seed3.xpoint.network
```

The public client bootstrap endpoint is
`DEEP_NODE_PUBLIC_HOST:DEEP_NODE_PUBLIC_PORT`. Keep `DEEP_NODE_PUBLIC_PORT` and
`DEEP_INGRESS_HTTPS_BIND` equal unless an approved NAT rule maps a different
external port to the local Docker bind.

For a non-443 node:

```text
DEEP_NODE_PUBLIC_PORT=8443
DEEP_INGRESS_HTTPS_BIND=8443
```

The peer RPC endpoint is generated from the node's origin IP and peer port.
Onion requests are encrypted and signed by a registered node. The BLS signer
URL is derived automatically from this signed contact; `/api/staking/quorum/sign`
is accepted only from the production staking control-plane network. There is no
operator-configurable signer URL.

## Firewall

Open only the shared hardened ingress:

```bash
sudo ufw allow 443/tcp
sudo ufw enable
sudo ufw status verbose
```

Do not open `8080`, `8081`, `22020`, or `22021`.

## Start A Seed Node

Run on each seed host:

```bash
cd /opt/xpoint-node
node ./scripts/production-ingress-contracts.mjs
# Run production-ingress-preflight.ps1 with the six protected inputs; see TLS ingress runbook.
docker compose --env-file ./.env.node.prod -f ./docker-compose.node.prod.yml config --quiet
docker compose --env-file ./.env.node.prod -f ./docker-compose.node.prod.yml pull
docker compose --env-file ./.env.node.prod -f ./docker-compose.node.prod.yml up -d
docker compose --env-file ./.env.node.prod -f ./docker-compose.node.prod.yml ps
docker compose --env-file ./.env.node.prod -f ./docker-compose.node.prod.yml logs --tail 100 xnode
docker compose --env-file ./.env.node.prod -f ./docker-compose.node.prod.yml logs --tail 100 storage-service
```

The compose file uses `restart: unless-stopped`, so Docker restarts the node
after host reboot once Docker is enabled.

## Verify Locally

Run backend health checks inside Docker and the public API with CA plus SPKI
pin verification:

```bash
docker compose --env-file ./.env.node.prod -f ./docker-compose.node.prod.yml exec xnode curl -fsS http://127.0.0.1:8080/health/ready
curl --fail --cacert /trusted/ca.pem --pinnedpubkey "sha256//<approved-spki-base64>" https://<seed-host>/api/bootstrap/client
```

Check the public VLESS Reality port is listening:

```bash
sudo ss -lntp | grep ':443'
```

Replace `443` with the node's public port when using a non-default port.

## Verify From The Control Plane

Run from a machine that can reach the private management endpoints:

```bash
curl -fsS https://registry.xpoint.network/api/nodes
curl -fsS https://staking.xpoint.network/obligations
```

Every seed must appear in the registry with:

- matching `nodeId` / `DEEP_NODE_ED25519_PUBLIC_KEY`;
- `publicHost` equal to its seed hostname;
- `onion-v1` capability;
- non-mocked VLESS transport;
- populated BLS public key and signing endpoint;
- recent heartbeat timestamp.

`/api/relay-contacts` intentionally returns `401` to anonymous callers. XPoint
nodes fetch the complete catalog with a signed Ed25519 request; clients obtain
fresh routes through a Reality-connected seed and verify every contact locally.

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

After all three nodes are active on-chain and healthy in the registry,
production clients can include these bootstrap hosts:

```text
seed1.xpoint.network:443
seed2.xpoint.network:443
seed3.xpoint.network:443
```

If a seed uses a non-default public port, include that port in the bootstrap
entry and verify the registry relay contact advertises the same
`publicHost/publicPort`.

Client releases contain only the initial Reality seed profiles. After entering
the network, the client asks a seed for a fresh route and verifies the signed
relay contacts. Clients do not download the complete catalog from the registry.

## Operations

Useful commands on a seed host:

```bash
cd /opt/xpoint-node
docker compose --env-file ./.env.node.prod -f ./docker-compose.node.prod.yml ps
docker compose --env-file ./.env.node.prod -f ./docker-compose.node.prod.yml logs -f --tail 200 xnode
docker compose --env-file ./.env.node.prod -f ./docker-compose.node.prod.yml restart xnode
docker compose --env-file ./.env.node.prod -f ./docker-compose.node.prod.yml pull
docker compose --env-file ./.env.node.prod -f ./docker-compose.node.prod.yml up -d
```

Do not run `docker compose down -v` on production seed nodes unless you are
intentionally wiping node-local state and have already backed up the identity
files and storage volume.
