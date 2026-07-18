# I01B Private-Only UAT Topology

## Status and hard stop

This document describes a chain-free, private-only UAT topology contract. It is
not a launch authorization or production-readiness claim.

```text
uatRestartAuthorized=false
productionReady=false
```

Do **not** start or restart the retired topology in
`docker-compose.uat.yml`. Its public identities, secret paths, project name,
volumes, chain services, and network assumptions are outside the I01B contract.
No old `.env.uat`, `.secrets/uat`, or `secret-templates/uat` value may be copied
into the private topology.

UAT restart remains blocked until Mr. X supplies and signs the completed
identity rotation evidence, the existing rotation preflight accepts that
evidence, and the three replacement router public IDs are proven to match the
three replacement Ed25519 seed files. Static topology acceptance does not
remove that block.

## Standalone scope

`docker-compose.uat-private.yml` has the fixed project name
`deep-i01b-private-uat` and no optional profile. Its exact seven-service set is:

- `xnode-1`, `xnode-2`, and `xnode-3`;
- `storage`, `file`, `push`, and `calls`.

Staking, registry, indexer, keeper, Ethereum, Arbitrum, contract, and blockchain
RPC services are deliberately absent. Router registry bootstrap and heartbeat
are explicitly disabled. Session storage remains connected to the routers at
`http://storage:8080`; storage-to-push notification delivery uses
`http://push:8080`.

All services join one bridge network named
`deep-i01b-private-uat-isolated`. It is `internal: true` and has the single
subnet `172.30.81.0/24`. The routers have the fixed addresses
`172.30.81.11`, `.12`, and `.13`.

## Endpoint contract

| Service | Container-visible endpoint | Host-visible endpoint |
| --- | --- | --- |
| `xnode-1` API | `http://172.30.81.11:8080` | `http://127.0.0.1:29311` |
| `xnode-2` API | `http://172.30.81.12:8080` | `http://127.0.0.1:29312` |
| `xnode-3` API | `http://172.30.81.13:8080` | `http://127.0.0.1:29313` |
| `storage` | `http://storage:8080` | none |
| `file` | `http://file:8080` | `http://127.0.0.1:29101` |
| `push` | `http://push:8080` | `http://127.0.0.1:29102` |
| `calls` | `http://calls:8080` | `http://127.0.0.1:29103` |

The ancillary loopback endpoints allow Windows and ADB-reversed physical-device
E2E to exercise attachments, live `sig_v2` push, and calls without exposing
those services on a LAN interface. Storage is never host-published. Router peer
RPC port `8081` and VLESS port `443` are never host-published.

Each router advertises exactly its literal private peer endpoint:

- `http://172.30.81.11:8081/api/peer/onion`;
- `http://172.30.81.12:8081/api/peer/onion`;
- `http://172.30.81.13:8081/api/peer/onion`.

Every router contains all three exact `(routerId, IPv4, 8081,
/api/peer/onion)` allowlist tuples, including its own tuple. Both .NET
environment variables are exactly `UAT`, both private-peer network identities
are exactly `uat`, signed relay contacts are required, and public peer
authorization is disabled. The XNode composition therefore selects the
fail-closed `DenyAll` public-peer authorizer while retaining only the nine
explicit private tuple mappings.

## Fresh identities and secrets

`.env.uat-private.example` is a field inventory, not a usable environment.
Every `__REQUIRED_*__` marker must be replaced in a new operator-controlled
environment file. The three public IDs must be distinct 64-character Ed25519
public identities that do not occur in
`config/retired-uat-public-identities.json`.

The files in `secret-templates/uat-private-i01b` contain placeholders only.
Create three new restricted files outside the repository, put one matching
Ed25519 seed in each, and set these new variables to their canonical paths:

- `I01B_PRIVATE_UAT_NODE_1_ED25519_SECRET_FILE`;
- `I01B_PRIVATE_UAT_NODE_2_ED25519_SECRET_FILE`;
- `I01B_PRIVATE_UAT_NODE_3_ED25519_SECRET_FILE`.

Compose mounts each seed as a separate read-only secret. It does not load an
`env_file`, and no private key is rendered into `environment`.

## Static fail-closed evidence

The allowed checks are static only:

```powershell
node --test .\scripts\i01b-private-uat-topology.test.mjs
node .\scripts\i01b-private-uat-topology.mjs
```

The validator supplies synthetic public identities and secret-template paths,
sets `COMPOSE_DISABLE_ENV_FILE=1`, and invokes only
`docker compose config --format json`. It does not read `.env` or `.secrets`,
contact a Docker daemon, build images, create networks, or start containers.

The gate fails closed on a changed service count, UAT/private switch, any of the
nine allowlist mappings, advertised-tuple mismatch, retired identity, extra
network, host mode, `host.docker.internal`, chain service or variable, public
storage/peer/VLESS port, non-loopback host binding, reused volume/secret, or
registry bootstrap/heartbeat dependency.

When evidence is explicitly requested, redirect the validator JSON to
`artifacts/i01b-private-uat/topology-contract.json`. Do not treat that static
file as runtime, restart, device, security, or production evidence.

## Health and cleanup expectations

The router readiness endpoint is `/health/ready`; each compatibility service
also uses `/health/ready`. Runtime health has intentionally not been collected
while `uatRestartAuthorized=false`.

All seven named volumes and all three Compose secret resources use the
`deep-i01b-private-uat-` prefix. A future authorized teardown must target the
`deep-i01b-private-uat` project explicitly and remove its named volumes only
after evidence retention is complete. It must not operate on `deep-uat` or any
old UAT volume. No cleanup or runtime command is authorized by this document.
