# Retained local development network

`deep-dev` is the only supported local Deep compose project. It contains
Registry, an independent TLS PostgreSQL directory floor, three XNode processes
and a delegated operational-view publisher. It is **not** UAT or a production
release/device/message-delivery evidence profile. Production servers were not
changed. Mr. X remains the single development operator; three signer keys are
not three independent operators.

## Architecture and custody

This workstation uses native Linux ARM64 Docker. .NET and Go images are pinned
by digest. ML-DSA is the exact prebuilt Linux ARM64 asset from
[Protocol CI run 35858379369](https://github.com/XPointLabs/deep-protocol/actions/runs/35858379369),
artifact `10748341412`, commit `9364d113d8c017c04918b46a2b4d9a01d50b4879`.
The archive SHA-256 is
`4313285d22d72e406c713c289878d0e0b0d7e2a928584a103b39c4f12e563a70`;
the 73544-byte library SHA-256 is
`3997e5c296373bfd6bda1fe45bb5763b1e3bf7158395c213591eef7db2235dfd`.
The Protocol loader checks both size and digest before loading. No local C++
compiler is required. CI already builds Linux/Windows x64/ARM64; Android ARM64
has its separately checked asset. No Apple build is enabled.

Private development custody is under `C:\Work\DeepSession\secrets\dev\deep-dev`.
Registry/nodes receive only their online secrets through separate named volumes.
The publisher receives delegated witness/node custody and a protected renewal
journal; the offline root is never mounted. Public signed bootstrap/closure and
the local CA certificate are shared separately. Ordinary TLS chain/hostname
validation remains enabled; no purchased certificate or public domain is needed
inside this private Docker network.

NTS acquires authenticated packets from the two DTS1-pinned source families.
Registry persists only a lower rollback floor and reacquires a bounded upper
interval on every boot. The publisher renews short operational views every
15 minutes under the existing seven-day offline delegation. Missing/corrupt
journals, exhausted delegation or inconsistent floors fail closed. Retained
current/announced-next key slots can be selected only by verified signed views;
this does **not** yet implement indefinite generation/staging of new traffic
keys or unattended TLS certificate rotation. A new offline policy ceremony is
required before the delegation expires.

The observer and directory-exercise accounts are disposable DEV fixtures,
not recoverable user accounts. The development mailbox issuer is not a
configured shipping MSG authority. File/call/push/bridge/message services must
not be inferred from healthy node processes.

## Commands

Run from the DevOps repository:

```powershell
./scripts/deep-dev.ps1 -Action Status
./scripts/deep-dev.ps1 -Action Build
./scripts/deep-dev.ps1 -Action Up
./scripts/deep-dev.ps1 -Action Verify
./scripts/deep-dev.ps1 -Action Stop
./scripts/deep-dev.ps1 -Action Start
./scripts/deep-dev.ps1 -Action FaultMatrix
./scripts/deep-dev.ps1 -Action HistoryFault
./scripts/test-env.ps1 -Suite smoke -BackendMode deep-dev
```

`Verify` requires current Registry proof readiness and **all three verified
ONION capabilities**, not the development process-health exemption.
`FaultMatrix` scopes stop/start to these six services, always restores stopped
services, and verifies retained mount bindings. `HistoryFault` intentionally
adds 130 real disposable DID2 accounts to **this DEV directory**, with all
three nodes offline, then requires independently verified node recovery.
It is not read-only and must never be pointed at production. The probe mounts
public bootstrap only, not any retained signer, node key or protected floor.

`Init` is first-time only and refuses existing custody. `Provision` and
`ProvisionFloor` are explicit first-time operations and refuse existing
initialized state. Do not use them to repair an initialized network. There is
no automatic floor/genesis reset or volume deletion in this workflow.
First-time ADA2 provisioning also creates the NTS lower-floor custody from the
signed policy bound; no upper/freshness time is provisioned. The running worker
refuses a missing floor, including after reboot. Restore retained custody; do
not provision again. GitHub CI runs topology contracts and explicitly separate
legacy compatibility fixtures, never this workstation's private dev custody
or device E2E.

| Service | Host endpoint | Container endpoint/state |
| --- | --- | --- |
| Registry | `https://localhost:28443` | TLS 443; `registry-state` |
| Nodes 1–3 management | `http://localhost:28191`–`28193` | 8080; separate `node-N-state` |
| Nodes 1–3 privacy | `https://localhost:28194`–`28196` | TLS 443, pinned local origins |
| PostgreSQL floor | Not published | TLS 5432; `floor-data` |
| Publisher | Not published | `publisher-state`; authenticated renewal |

Old Deep compose containers and empty project networks were removed after
private backups of ephemeral node filesystems. Their volumes/images and bind
custody were retained; unrelated local database containers were not removed.
Never run a global Docker prune or `down --volumes` as network repair.

## Evidence boundary

Native ARM64 exact-asset managed/native checks passed 7/7 on 2026-09-29.
The real stop/start matrix passed for each node, Registry, the floor, publisher,
and all six containers together; observed recovery was 3–27 seconds, with
unchanged custody/state mounts.
The historical recovery run also passed: 130 real disposable admissions while
all three nodes were offline, receipt generation span 129, all three verified
ONION capabilities recovered in 46 seconds without custody/floor reset. The
initial run exposed repeated full-prefix replay overhead and timed out; the
same retained state passed after single-pass authenticated journal validation.
No failed run was erased or represented as a success. These runs do not close
the Docker-engine restart, 20-cycle, long-TTL or key-rotation gates. Follow
[NETWORK_STABILITY_RECOVERY.md](NETWORK_STABILITY_RECOVERY.md) for remaining
cases. Mr. X owns the 72-hour soak; local Windows/Android device E2E belongs
to the separate agent and is never represented as CI evidence.

The MAUI reconnect worker currently reopens the DID2 proof/closure/pre-key
composition, preserving account/floors. It does not yet restore a shipping
MSG durable inbox/outbox composition. Network reconnect tests do not close
physical messaging E2E or `NET-STAB-GATE`.
