# P15A isolated compatibility lifecycle lab

Status:

`COMPATIBILITY-LAB / PRODUCT-RUNTIME-NO-GO`

Decision owner: **Mr. X**.

P15A proves only the Docker lifecycle of the existing DevOps-owned storage,
file, push and calls compatibility runtimes. It proves a clean isolated start,
strict health and service identity, deterministic compatibility operations,
restart persistence, one bounded network disconnect/reconnect and scoped
cleanup on Windows ARM64.

It is not a Survival product network. It does not contain XNode, registry,
staking, blockchain, Xray, UAT or live endpoints. It has no host ports and the
push service has no external provider configuration.

## Exact local environment lock

The lab rejects a non-ARM64 Docker Engine, emulation, a missing image and a
floating image reference. Its cache-local Windows ARM64 base lock is:

```text
node@sha256:242549cd46785b480c832479a730f4f2a20865d61ea2e404fdb2a5c3d3b73ecf
image ID sha256:242549cd46785b480c832479a730f4f2a20865d61ea2e404fdb2a5c3d3b73ecf
Linux/arm64
```

This is not claimed as a universal multi-platform registry lock. Build uses
the local digest with pull disabled; container creation uses `--pull never`.
The resulting image must carry the exact source revision/tree, base-image
lock, OCI source, `evidenceClass=compatibility-lab` and
`productRuntime=false` labels.

## Run

Use a clean exact implementation commit and tree. Evidence must be written
outside the repository until the separate evidence-carrier phase:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\scripts\p15-compat-lab.ps1 `
  -ExpectedSourceSha <exact-clean-HEAD> `
  -ExpectedSourceTree <exact-clean-HEAD-tree> `
  -EvidencePath C:\W\deep-survival\evidence\P15A\run.json `
  -EvidenceClock 2026-07-20T00:00:00.000Z
```

The driver generates a bounded random project name. A supplied name is valid
only in the form `p15a-` plus sixteen lowercase hexadecimal characters.
Before `up`, no container, network or volume may have that exact Compose
project label. A foreign resource occupying an intended name stops the run.

The `finally` block checks exact project ownership, runs only:

```text
docker compose ... down --volumes --remove-orphans
```

and proves zero containers, networks and volumes with the run label. Global
prune is prohibited. Existing UAT and other Docker resources are never in
scope.

## Verification

```powershell
node --test `
  .\scripts\p15-compat-contracts.test.mjs `
  .\scripts\p15-evidence-sanitizer.test.mjs
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\scripts\p15-compat-lab.test.ps1
node .\scripts\release-gate-contracts.mjs
node .\scripts\production-readiness-status.mjs
```

The internal probe verifies the expected service identity in every health and
stats response. It starts from empty inventory; tests storage store/retrieve
and idempotency, file upload/read and content-addressed idempotency, push
subscribe/resubscribe persistence without a provider, and calls
enqueue/dequeue persistence.

Sanitized evidence contains only exact source and cache-local base-image
identity, architecture, scenario pass/fail, aggregate counts and declared
duration bounds. It contains no project/container names, IDs, endpoints,
ports, keys, tokens, Session/mailbox/capability identifiers, raw responses,
machine paths, environment dumps or message/payload hashes. A privacy or
secret finding is always fatal.

## Explicit non-claims and blockers

P15A does not prove XNode, ingress/core/storage split, N3/W2/R2 replication,
repair, bridge loss, DNS/TLS/UDP impairment, VLESS/REALITY, self-hosted
send/store/read, mobile/Windows UI E2E, battery behavior or production
readiness.

Those remain blocked by Mr. X decisions for P05/P08, missing P08/P09 product
runtime, the P10/P11B runtime chain, the P14 activation chain, accepted ARM64
locks for future impairment assets, and physical Android-device evidence.

Acceptance after two independent exact-source reviews is:

`P15A-COMPATIBILITY-LAB-GO / WINDOWS-ARM64-DOCKER-GO /`
`PRODUCT-RUNTIME-NO-GO / REPLICA-CHAOS-NO-GO /`
`BRIDGE-IMPAIRMENT-NO-GO`.
