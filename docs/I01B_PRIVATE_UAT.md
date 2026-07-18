# I01B private-only UAT

## Reality statement

This change is static, fail-closed DevOps evidence only.

```text
uatRestartAuthorized=false
productionReady=false
realityVlessEndToEndProven=false
vless443Published=false
```

No container was built or started, no real seed was read, and no live route,
REALITY, VLESS, device, push, attachment, or call exchange was performed.
Port 443 is an internal container listener and is deliberately not published.
The old `docker-compose.uat.yml`, old identities, and old secret paths remain
forbidden.

The reviewed XNode functional corrective is commit
`be81d9939c616d9d42aae08e9ee2cf298b90d692`. A future authorized build must
supply that exact expected commit (or a separately reviewed successor) as an
explicit input. The example does not silently select it.

## Fixed topology

`docker-compose.uat-private.yml` has one exact internal bridge network,
`deep-i01b-private-uat-isolated` (`172.30.81.0/24`), and seven services:

- `xnode-1`, `xnode-2`, `xnode-3`;
- `storage`, `file`, `push`, `calls`.

There are no chain, registry, staking, keeper, indexer, Docker socket, device,
host namespace, bind-mount, `extra_hosts`, or host-gateway dependencies. Every
service drops all capabilities and uses `no-new-privileges`; routers add only
`NET_BIND_SERVICE`.

Router APIs are loopback-only at ports 29311, 29312, and 29313. File, push, and
calls are loopback-only at 29101, 29102, and 29103. Storage, peer RPC 8081, and
VLESS 443 are not host-published. Router API, peer listener, storage RPC,
private RPC advertisements, VLESS arguments, volumes, secrets, and network
membership are exact validator contracts.

Each router has the exact three-member private allowlist, including itself:

| Router | Private IP | Signed peer RPC tuple |
| --- | --- | --- |
| `xnode-1` | `172.30.81.11` | `http://172.30.81.11:8081/api/peer/onion` |
| `xnode-2` | `172.30.81.12` | `http://172.30.81.12:8081/api/peer/onion` |
| `xnode-3` | `172.30.81.13` | `http://172.30.81.13:8081/api/peer/onion` |

The runtime switches are explicit:

```text
Runtime__EnablePrivatePeerEndpoints=true
Runtime__EnablePrivateAllowlistMembership=true
Runtime__AllowPublicPeerEndpoints=false
Runtime__RequireSignedRelayContacts=true
Runtime__BootstrapFromStorage=false
```

Public authorization must remain `DenyAll`. Disabling storage bootstrap is
valid only with the host bootstrap ceremony below. Before that ceremony,
`/health/ready` must return HTTP 503.

## Required supply-chain preflight

The operator-controlled environment must provide:

- the canonical clean XNode Git worktree root;
- the canonical reviewed `docker/xnode-xray.Dockerfile`;
- the exact expected XNode commit;
- the exact reviewed Dockerfile SHA-256;
- .NET SDK and ASP.NET runtime image digests;
- the exact Xray version and its archive SHA-256.

There are no defaults. The Dockerfile path cannot be substituted, and ambient
or dirty source cannot be used. The .NET image references include required
digests, and `XRAY_SHA256` is passed into the build.

Before any future authorized build, run the offline source preflight with all
four explicit arguments:

```powershell
node .\scripts\i01b-private-uat-source-preflight.mjs `
  --xnode-context <canonical-absolute-clean-xnode-root> `
  --expected-xnode-commit <exact-lowercase-40-hex-commit> `
  --dockerfile <canonical-absolute-reviewed-xnode-xray-dockerfile> `
  --expected-dockerfile-sha256 <exact-lowercase-64-hex-sha256>
```

It rejects a noncanonical path, symlink/reparse point, wrong Git root, wrong
commit, any tracked or untracked change, alternate Dockerfile, or hash
mismatch. The required image digests and Xray hash are additionally enforced
by Compose interpolation and the topology validator. No real digest is
invented in this repository.

## Required identity preflight

Create three fresh, distinct Ed25519 seeds outside the repository. For each
seed, the offline preflight derives the public Ed25519 identity and compares it
to the exact lowercase `RouterId`:

```powershell
node .\scripts\i01b-private-uat-identity-preflight.mjs `
  --node-1-router-id <64-lowercase-hex> --node-1-seed-file <canonical-absolute-path> `
  --node-2-router-id <64-lowercase-hex> --node-2-seed-file <canonical-absolute-path> `
  --node-3-router-id <64-lowercase-hex> --node-3-seed-file <canonical-absolute-path>
```

The preflight never prints seed values. It rejects malformed, uppercase,
duplicate, retired, mismatched, noncanonical, or linked seed inputs. The files
under `secret-templates/uat-private-i01b` are placeholders, not usable secrets.
UAT restart remains blocked until the separate signed identity-rotation
evidence is accepted.

## Required host bootstrap ceremony

Only after restart is independently authorized may an operator run the host
ceremony. All six values are mandatory; there are no API or identity defaults:

```powershell
node .\scripts\i01b-private-uat-bootstrap.mjs `
  --router-1-api http://127.0.0.1:29311 --router-1-id <node-1-router-id> `
  --router-2-api http://127.0.0.1:29312 --router-2-id <node-2-router-id> `
  --router-3-api http://127.0.0.1:29313 --router-3-id <node-3-router-id>
```

The script performs this exact sequence:

1. Require HTTP 503 from all three readiness endpoints.
2. Fetch exactly three `/api/network/contact` documents.
3. Locally verify every Ed25519 signature, canonical identity, exact RPC/IP
   tuple, capability form, and freshness/expiry window.
4. Submit every full signed contact to every router through signed
   `store_rc` RPC: exactly nine stores.
5. Require each `/status` to report membership enabled, expected 3,
   registered 3, ready true, NodeDb registered 3, and `DenyAll`.
6. Require signed `fetch_rids` to return the exact three identities.
7. Require readiness HTTP 200 only after the exchange.
8. Require signed `storage_route` results to contain exactly the three
   canonical members and their exact private tuples.

The ceremony fails closed on a changed HTTP status, invalid/stale contact,
response signature mismatch, incomplete membership, duplicate identity, or
route mismatch.

## Static verification

These checks use only synthetic seeds, keys, contacts, signed RPC responses,
temporary Git repositories, and `docker compose config`:

```powershell
node --test `
  .\scripts\i01b-private-uat-topology.test.mjs `
  .\scripts\i01b-private-uat-source-preflight.test.mjs `
  .\scripts\i01b-private-uat-identity-preflight.test.mjs `
  .\scripts\i01b-private-uat-bootstrap.test.mjs
node .\scripts\i01b-private-uat-topology.mjs
```

The mutation suite covers privilege, host pid/ipc, devices, Docker socket,
arbitrary bind mounts, extra hosts/host-gateway, host build network, unexpected
service keys/networks, capabilities, security options, listeners, storage RPC,
VLESS settings, volumes, secrets, source paths, image digests, Xray hash, and
membership/bootstrap switches.

## Deferred P2

P2 for Wave 3: implement and prove a managed transport/publication path for
VLESS/REALITY, including its lifecycle, key handling, exposure policy, and
end-to-end evidence. The current unpublished internal port 443 and static
configuration do not satisfy that work item.
