# Production Seed Nodes Bootstrap

This runbook prepares the first three production XPoint nodes on Linux hosts.
Use it on every seed server with a unique node identity, BLS key, VLESS client
id, and Xray Reality key pair.

These hosts are the initial public bootstrap seeds for production clients and
the initial BLS quorum once they are staked on Arbitrum One.

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

1. Use Ubuntu 22.04/24.04 LTS or another Linux distribution with Docker Engine
   and the Docker Compose plugin.
2. Build and push the node images from `docs/PRODUCTION_NODE_RUNBOOK.md`.
3. Create DNS `A`/`AAAA` records for all three seed hosts.
4. Open public TCP `443` to each seed host for VLESS Reality transport.
5. Keep the node API/signing endpoint private to the control plane. Use
   WireGuard, Tailscale, a private load balancer, or an allowlisted reverse
   proxy. Do not expose the raw node API as an unauthenticated public admin
   surface.
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

Run on each seed host:

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl gnupg openssl nodejs npm

sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
  | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

. /etc/os-release
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu ${VERSION_CODENAME} stable" \
  | sudo tee /etc/apt/sources.list.d/docker.list >/dev/null

sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo systemctl enable --now docker
```

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
```

Example from the operator workstation:

```bash
rsync -av docker-compose.node.prod.yml .env.node.prod.example scripts/new-xnode-identity.mjs \
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
node ./new-xnode-identity.mjs --as-env --out-dir ./secrets | tee ./identity.generated.env
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
DEEP_NODE_VLESS_BIND=443
DEEP_NODE_API_BIND=127.0.0.1:8080
DEEP_NODE_STORAGE_BIND=127.0.0.1:22021

DEEP_REGISTRY_URL=https://registry.xpoint.network
DEEP_STORAGE_RPC_URL=http://storage-service:8080
DEEP_PUSH_NOTIFY_URL=https://push.xpoint.network/_compat/push-notify
DEEP_REGISTRY_HEARTBEAT_INTERVAL=00:00:30

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
DEEP_NODE_PUBLIC_HOST=seed1.expoint.network

# seed-2
DEEP_NODE_PUBLIC_HOST=seed2.xpoint.network

# seed-3
DEEP_NODE_PUBLIC_HOST=seed3.xpoint.network
```

The public client bootstrap endpoint is always `DEEP_NODE_PUBLIC_HOST:443`.

The control-plane RPC/signing endpoints must point to the private route that the
registry and staking backend can reach. Prefer private network addresses or
private DNS names:

```text
DEEP_NODE_RPC_ENDPOINT=http://<private-management-host-or-ip>:8080/api/session/rpc
DEEP_NODE_SIGNING_ENDPOINT=http://<private-management-host-or-ip>:8080/api/staking/quorum/sign
```

If the control plane requires HTTPS, terminate TLS on a private reverse proxy
that forwards only from allowlisted control-plane IPs to `127.0.0.1:8080`.

## Firewall

Open only the public transport port:

```bash
sudo ufw allow 443/tcp
sudo ufw enable
sudo ufw status verbose
```

Keep `8080` and `22021` bound to localhost or to a private management
interface. Do not open them to the public internet.

## Start A Seed Node

Run on each seed host:

```bash
cd /opt/xpoint-node
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

Run on the seed host:

```bash
curl -fsS http://127.0.0.1:8080/health/live
curl -fsS http://127.0.0.1:8080/health/ready
curl -fsS http://127.0.0.1:8080/status
curl -fsS http://127.0.0.1:22021/health/ready
curl -fsS http://127.0.0.1:22021/stats
```

Check the public VLESS Reality port is listening:

```bash
sudo ss -lntp | grep ':443'
```

## Verify From The Control Plane

Run from a machine that can reach the private management endpoints:

```bash
curl -fsS https://registry.xpoint.network/api/nodes
curl -fsS https://registry.xpoint.network/api/relay-contacts
curl -fsS https://staking.xpoint.network/obligations
```

Every seed must appear in the registry with:

- matching `nodeId` / `DEEP_NODE_ED25519_PUBLIC_KEY`;
- `publicHost` equal to its seed hostname;
- `onion-v1` capability;
- non-mocked VLESS transport;
- populated BLS public key and signing endpoint;
- recent heartbeat timestamp.

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
seed1.expoint.network:443
seed2.xpoint.network:443
seed3.xpoint.network:443
```

Client releases must also point discovery/bootstrap APIs at the production
registry and staking backend. The client should use registry-published relay
contacts for live routing, not a static list of registry rows.

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
