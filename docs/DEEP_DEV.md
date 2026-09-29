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

Provider anycast sets can contain unreachable members and UDP datagrams can be
lost. The observer therefore races staggered NTS-KE dials over at most eight
addresses within the same 4 second bound and retries one lost NTP datagram on
the same session; TLS 1.3, hostname validation, the exact SPKI pin, NTS
authentication and the signed 10 second sample-age bound are unchanged. Any
other failure still discards the session and backs off.

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
./scripts/deep-dev.ps1 -Action StackFault -Cycles 2 -StableSeconds 60
./scripts/deep-dev.ps1 -Action ExpiryFault -StableSeconds 60
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

Normal services use `restart: always`: full Docker Desktop shutdown explicitly
stops containers, so `unless-stopped` left the entire network off when the engine
returned. Starting Docker now resumes the six retained services automatically,
without a Compose command or custody repair. A direct `docker stop` still stops
a service while the engine is running, but engine restart resumes it. For a
persistent maintenance stop, use this script's `Stop` (sets `unless-stopped`
before stopping); `Start` restores `always`. `Up` also restores normal policy.

Routine recovery tests use `StackFault`: it stops/starts only the six `deep-dev`
containers, preserves their IDs/mounts and compares Registry/node secret digests
in memory. Docker Desktop and unrelated projects remain running.

`EngineFault` is not a routine test. It requires separate explicit operator
approval and `-ConfirmEngineShutdown`; without that switch it rejects before
any Docker command. It refuses a remote/shared engine, unrelated running containers or
stopped dev services. It stops/starts the **whole local Docker Desktop**, not
only Compose, checks a stable current-proof/ONION window and retains exact
container IDs, canonical mount bindings and online-secret digests. Digests are
kept only in process memory. No Compose start/up repairs the tested restart.
Recovery seconds are measured after Desktop's start command completes; Desktop
startup time is additional. `ExpiryFault` first authors one genuinely signed
180-second operational view using existing delegated custody and the protected
publisher journal, then stops only the six `deep-dev` containers for 200 seconds.
Docker Desktop stays running. The normal publisher must renew that expired view
after the stack starts. It changes no clock, signature check,
policy expiry, keys or floor and does not represent a one-hour directory-head or
seven-day root-policy outage. The restored publisher resumes its usual lifetime.

Enabled privacy now returns readiness 503 while its verified capability is absent
even in Development; only explicitly disabled privacy retains the development
exemption. Initial authenticated-time/dependency loss is a visible warning;
cryptographic/custody/configuration failure remains an error, never a fallback.
Explicit management HTTP/1.1 and TLS privacy HTTP/2 listeners no longer advertise
an impossible mixed HTTP/2 mode over cleartext. TLS/encryption are unchanged.

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

2026-09-30: full Docker Desktop stop/start reproduced an auto-start defect:
`unless-stopped` left all six services exited. With `always`, one complete
engine fault case passed with a 60-second stable verified-capability window,
the same container/mount bindings and unchanged online-secret digests. An
earlier raw JSON mount comparison was order-sensitive; canonical binding
comparison fixes the harness without weakening its custody check.

The second engine cycle was **BLOCKED**, not passed: Docker Desktop 4.45.0
on Windows ARM64 aborted before starting its Linux engine because its own
`dockerInference` AF_UNIX runtime endpoint could not be removed. A clean force
quit and one subsequent detached start reproduced that host error. This is not
Registry/node state corruption. The CLI also waited beyond `--timeout`; the
fault runner now enforces its own host-process deadline and never kills the
Desktop/backend process tree. The operator subsequently restored Docker without
a Windows reboot; the engine and all six services returned. A reboot is no
longer a prerequisite. Whole-Desktop fault repetition is deferred under the
operator's instruction to use scoped container stop/start unless specifically needed.
No Docker factory reset, volume deletion, inference-settings change or custody
reset was performed. Two subsequent `StackFault` cycles passed with 20 seconds
offline, recovery in 26/16 seconds, 30-second stable current-proof/ONION windows,
unchanged Registry/node custody and retained IDs/mounts. The scoped `ExpiryFault`
then passed on the new ARM64 images: one genuinely signed 180-second delegated
view, 200 seconds with all six containers stopped, recovery in 15 seconds and
a 60-second stable current-proof/three-ONION window, unchanged Registry/node
custody, IDs and mounts. Docker Desktop stayed running throughout both tests.
Recovery seconds for scoped tests are measured after Compose start returns.
The earlier startup CryptographicException burst was not reproduced by these
scoped cases; closed safe reason codes now distinguish head/authority/epoch/
proof-lifetime coverage on recurrence. This is not proof of every long-outage
failure path. Do not treat one
successful cycle as the complete restart/TTL/soak gate. Related upstream reports:
[stale socket startup failure](https://github.com/docker/desktop-feedback/issues/554),
[disabled inference listener still bound](https://github.com/docker/desktop-feedback/issues/448).

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
