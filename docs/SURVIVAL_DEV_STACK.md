# Persistent survival development stack

`docker-compose.survival.dev.yml` is the ordinary long-running developer stack.
It uses the fixed `deep-survival-dev` project, a private bridge network,
persistent named volumes, and filtered exports of local source trees. It
contains no remote chain, release evidence, retained receipt, or one-shot
cleanup workflow. Release evidence is produced only by the current strict
client, service and production-readiness gates.

From the `deep-devops` repository, start the loopback-only messenger stack:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/survival-dev.ps1 -Action Up
```

Only after the complete stack and the one-shot membership fixture pass their
checks, the launcher writes ignored, non-secret handoff files to
`artifacts/survival-dev/client.android.env` and `client.windows.env`. Android
and Windows receive `127.0.0.1` by default; each XNode URL is pinned inline to its exact
development router ID. Debug HTTP does not use TLS pins. Use `adb reverse` for a
physical Android Debug build without exposing the unauthenticated services:

```powershell
41801, 41802, 41803, 41804, 41805, 41806, 41810, 41821, 41822, 41823 | ForEach-Object { adb reverse "tcp:$_" "tcp:$_" }
```

If the local chain profile is enabled, also reverse its optional
ports:

```powershell
41545, 41811 | ForEach-Object { adb reverse "tcp:$_" "tcp:$_" }
```

When reverse forwarding is unavailable, explicitly add
`-LanHost <workstation-ip>`. Only that opt-in binds client ports to the exact
supplied IPv4 interface and places the same address in both client artifacts. It
never binds `0.0.0.0`.

Raw `docker compose ... up` is not supported. The launcher creates filtered,
fail-closed source contexts, reads the six signed native privacy contacts,
probes host HTTP endpoints, verifies all six contacts, and writes the
client handoff files; a raw Compose invocation does not perform those steps.

All application root filesystems in this development stack are read-only. A
service may write persistent state only to its explicitly named `/state` volume
(or the designated one-shot artifact/deployment output volume). Every service
that can require temporary runtime files receives only a bounded `/tmp` tmpfs
with `noexec`, `nosuid`, and `nodev`; membership and contract artifacts remain
read-only for consumers. This is Docker containment hardening for local
development, not a substitute for application-level authorization.

The three Hardhat roles additionally receive a bounded, non-executable
`/workspace/cache` tmpfs because Hardhat's validation plugin takes a lock and
writes generated validation metadata there. The image prepares the exact
`pnpm@9.1.3` package-manager release at build time and disables Corepack network
access at runtime. The image contains the precompiled contract artifacts and
preserves Hardhat's build-time validation metadata under `/opt/hardhat-cache`;
its fixed entrypoint copies that metadata into the fresh tmpfs, and deploy/smoke
run with `--no-compile`. A read-only chain role therefore does not need a
package-manager or Solidity compiler download on start.

After rebuilding the contracts image, reproduce the containment contract
without touching the running development project:

```powershell
node --test scripts/survival-dev-readonly-runtime.test.mjs
```

The regression test creates uniquely named and labelled temporary Docker
resources, runs devnet, deploy, and smoke in a deliberately stronger
`network=none` test namespace, and verifies their removal in a `finally`
cleanup. The ordinary Compose chain roles still share the stack's `runtime`
bridge; this regression is not a claim that the Compose stack has egress
isolation.

Each supported `Up` also removes and reruns the `membership-fixture` one-shot.
It consumes only hash-pinned local `Deep.Protocol` and
`Deep.Protocol.MembershipRoutes` packages and their complete locked offline
closure (`Deep.Protocol.Abstractions`, `Deep.Protocol.Protobuf`,
`Google.Protobuf`, `Sodium.Core`, and `libsodium`). Every copied NUPKG has an
exact SHA-256 gate and an exact local-only NuGet source mapping. It creates an atomic public artifact in
the isolated `membership-route-artifact` volume, then exits. The public artifact
is a full sorted six-leaf MRL1 catalog for the exact development XNode IDs and
their `ingress|core|storage` roles, with proofs, a 3-of-5 offline-root delegation,
and a 2-of-3 online MSM1 membership statement. Its sorted halves provide two
disjoint three-hop development routes. Each descriptor signs the exact selected
client IPv4 address with host ports `41801` through `41806`; Docker-only
hostnames and container port `8080` are never signed. The host must be canonical
loopback, RFC1918, or IPv4 link-local; hostname, wildcard, and public IPv4 input
fails closed. Because the advertised host and bounded issuance time are signed,
the whole-artifact SHA-256 pin changes when either changes. The XNodes and Registry mount it
read-only and publish it at `/api/network/membership-route-catalog`; the client
handoff includes `DEEP_MEMBERSHIP_ROUTE_CATALOG_URL`.

The same bounded JSON artifact contains a `trustBootstrap` object with public
canonical genesis bytes, the expected network ID, the canonical genesis
SHA-256, the canonical 3-of-5 signed delegation, and bridge/membership anchors
bound to the verified delegation LKG at sequence 2. It is explicitly marked
`DEV-LOCAL-ONLY` and uses the profile key
base `install:deep-survival-dev-v2`. The client never uses that shared base as
the persistence key: only after exact whole-artifact pin verification it derives
`install:deep-survival-dev-v2:<lowercase-64-hex-artifact-sha256>`. Therefore
every regenerated fixture receives an isolated authority/membership LKG while
existing account, session, conversation, attachment, and other local database
state remains untouched. No trust or account database reset is part of rotation.
The artifact contains no private signing material.
The future Debug client consumer must require both of these handoff values:

- `DEEP_DEV_LOCAL_MEMBERSHIP_TRUST_URL` — the exact IPv4 HTTP catalog endpoint;
- `DEEP_DEV_LOCAL_MEMBERSHIP_TRUST_SHA256` — lowercase SHA-256 of the exact
  published catalog bytes.

The launcher deletes stale client handoff files before regeneration. It writes
a new URL and pin only after the generator container exits successfully from
its native Sodium read-after-publication verification. The generator then emits
the SHA-256 of those verified volume bytes; the launcher requires the exact
Registry HTTP response bytes to match that hash and pass bounded strict parsing.
The HTTP response cannot become a TOFU source. A consumer must reject a missing or mismatched pin;
TOFU, remote trust-root fallback, and production activation from this artifact
are prohibited.

Deterministic signing seeds
are explicitly DEV-LOCAL-ONLY and exist only in the one-shot generator image:
they are never in the artifact, runtime images, runtime volumes, client handoff,
or logs. This is contract-fixture plumbing, not a production signer, membership
authority, or client-activation claim.

The persistent artifact volume is initialized by two privilege-separated,
networkless one-shots. `membership-artifact-owner-init` runs as root with only
`CHOWN`; it uses `lstat` without traversing the directory and either validates
an existing `0700` UID/GID `65532:65532` directory or prepares a fresh
root-owned volume. `membership-artifact-init` then runs directly as
`65532:65532` with no capabilities and clears only the exact catalog filename
or its bounded atomic-temporary pattern. Unknown owners, modes, entries,
directories, or symlinks fail closed.

The same-volume regression runs this complete init and Sodium fixture sequence
twice without deleting the named volume, and verifies both container exit state
and the exact published bytes, owner, and modes:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/survival-dev-membership-fixture-repeat.ps1 -AdvertisedHost 127.0.0.1
```

Regular builds reuse BuildKit and package layers. Rebuild only edited services
when convenient:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/survival-dev.ps1 -Action Build -Service xnode-1
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/survival-dev.ps1 -Action Restart -Service xnode-1
```

## P10E mailbox client and peer rehearsal

The survival stack pins its filtered XNode context to accepted source
`e9e82f50d7cf3ded2c888c9298d29148549953b6`; a dirty checkout, another revision,
or a filtered-source manifest other than
`084876ea676180d7efa89c691b7a9e18e8cd345733b8cb31c77b56d1c8204a29`
fails closed before build. The source exporter writes a deterministic
`.survival-source-manifest.json`, and the shared XNode image carries both the exact
revision and manifest SHA-256 as OCI labels. The live rehearsal requires all six
containers to use the exact same labelled image ID. The six XNodes build the shared image once,
retain their separate named `/state` volumes, and keep P10E mailbox blobs, replay journals,
and tombstone mutations below those volumes. Their deterministic development identity seeds
are generated only into ignored `.secrets/survival-dev` files and mounted as read-only Docker
secrets; no private seed is in Compose, an artifact, or a client handoff.

P10E's canonical peer Store/Tombstone listener is Docker-network-only on each node's `8081`
peer endpoint. It has the protocol's 15-second maximum request deadline and pre-auth
host/global plus per-operation admission controls. The launcher runs the pinned protocol
implementation to write a public, DEV-LOCAL-ONLY authority environment file containing the
real current/next six-leaf MIP1 Merkle commitments, canonical MIP1/RIP1 proofs, and all
30 epoch/pair selections across the six fixed router/signing identities and
exact literal `http://172.30.82.11:8081` through `http://172.30.82.16:8081`
endpoints on the isolated DEV bridge. One node-bound generated environment enables the bounded
DEV-LOCAL-ONLY client fixture only on `xnode-1`: MAU2 issuer trust, E/E+1 placement and membership
authority, the sole durable operation ledger, and native MAU2 ingress with canonical
MEO1/MBR2/MBA2 bindings. The primary privacy route exits locally through `xnode-1`; the fully
disjoint fallback exits through `xnode-2`, which forwards unchanged MAU2 over the authenticated
Docker-only HTTP/2 peer bridge to xnode-1. xnode-2 has no client adapter, replay/outcome journal,
operation ledger, cursor authority, or MQR3 authority. `xnode-3` through `xnode-6` remain
peer-only and report `dormant-unmapped`.

The generator rounds its anchor down to the current minute and creates a genuinely
rotating overlap: current E is valid from anchor minus five minutes through anchor plus
eight hours; E+1 is valid from anchor minus one minute through anchor plus twelve hours. The
runtime loader rejects an old fixture unless at least 30 minutes remain in E. This keeps
replay retention tied to bounded epoch validity rather than an issuer-lifetime or
year-2038 sentinel.

If both persisted DEV windows were allowed to expire, ordinary preparation fails closed.
Recovery is an explicit local-only discontinuity: preserve the existing protected state,
then run `Prepare` or `Up` with `-RecoverExpiredMailboxAuthority`. The launcher copies the
retired checkpoint, carries its E+1 forward byte-for-byte as an expired bridge current epoch,
and creates one fresh live successor whose window begins at the retired epoch boundary. It
never resets to epoch 1 or reissues different bytes
for an existing epoch. XNode may start on that bridge because only the fresh successor is
live; the expired epoch remains unusable. Reissue the Android/Windows runtime pair before the
next ordinary `Up`, which then promotes the live successor while preserving the same overlap.
Recovery fails closed when the retained boundary is too old to leave at least 30 minutes in
the bounded successor; that case requires a newer checkpoint or an explicit local client reset.

The deterministic issuer seed is an ignored Docker secret mounted only into the rehearsal
driver; XNode receives only its public key. XNode reports ready only after durable
peer, operation-ledger, and authenticated replay initialization passes. Use the no-Docker
preparation action to export exact contexts and regenerate these ignored fixtures:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/survival-dev.ps1 -Action Prepare
```

For the physical Android rehearsal, regenerate with the advertised LAN origin
`http://192.168.1.44:41801`:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/survival-dev.ps1 -Action Prepare -LanHost 192.168.1.44
```

The xnode-1 activation guard binds that exact public host and port, while the
containerized driver uses `http://xnode-1:8080` only as its private transport.
It verifies that the authority still names the LAN origin and rejects a loopback
coordinator whenever the physical lane is selected.

The focused source-contract tests remain useful regressions for Store/Tombstone,
replay, corruption rejection, and partial failure:

```powershell
dotnet test ..\xnode\tests\XNode.Tests\XNode.Tests.csproj --no-restore --filter FullyQualifiedName~ReplicatedMailboxTests
dotnet test ..\xnode\tests\XNode.IntegrationTests\XNode.IntegrationTests.csproj --no-restore --filter FullyQualifiedName~ReplicatedMailboxIntegrationTests
dotnet test ..\xnode\tests\XNode.Tests\XNode.Tests.csproj --no-restore --filter FullyQualifiedName~MailboxNativeMau2BusinessInvariantTests
```

The development-only Docker rehearsal is the live wire proof. Its driver runs inside
the same private `runtime` network as the XNodes and uses XNode Core's real sender
coordinator, durable journals, Sodium signatures, and exact P10E codecs. It requires:

- authenticated canonical public Store/Retrieve/ACK through xnode-1, native
  MQR3/MRP1/MAR1 responses, exact Store replay, and an empty retrieval after ACK;
- the host-only driver regression and source-level native MAU2 business-invariant
  suite prove coordinated replay/outcome expiry: they mark replay state expired,
  delete only the exact canonical terminal outcome, and then remove the replay
  marker as a retryable batch;
- public Store with selected xnode-2 stopped to fail dependency-unavailable without
  claiming quorum, followed by exact MAU2 retry and native MQR3 after restart;
- canonical PRQ2 Store to a selected live peer and native MRR2/MQR3 2-of-2;
- exact MRR2 and MQR3 replay after force-recreating that peer with its named volume;
- a stopped selected peer to produce only one durable replica, `PartialFailure`, and no MQR3;
- retry of that exact PRQ2 after peer restart to produce native 2-of-2 MQR3;
- canonical Tombstone plus exact replay to produce native MRR2/MQR3;
- all six `/health/ready` checks, ready authoritative client ingress on xnode-1,
  forwarding-only authority role on xnode-2, dormant-unmapped ingress on xnode-3 through xnode-6,
  absence of xnode-2 coordinator-state files, and the exact shared image
  provenance binding.

Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/survival-dev-mailbox.integration.test.ps1 -BindHost <exact-lan-ipv4>
```

The driver has its own named sender-state volume so it does not contend with a running
XNode's exclusive journals. At runtime it mounts only the xnode-1 sender seed, the
DEV-LOCAL-ONLY client issuer seed, and the generated public authority fixture; it never
receives any selected recipient's private key. The issuer seed can mint only the explicitly
pinned development client capabilities; it cannot sign a peer receipt. The driver therefore
cannot synthesize a recipient MRR2 or substitute a quorum: every remote
signature must arrive in an HTTP response from the actual literal-IP `xnode-N:8081` listener and pass
XNode Core verification. The launcher reads all six ignored development seeds only in its
host-side authority-generation step to derive the public descriptors and canonical proofs;
no recipient seed enters the driver image, container, state, output, or evidence.
Its ignored state may contain protocol
wire material; the checked evidence records only statuses, byte counts, image provenance,
and booleans. The script is bounded and restores all six XNodes to readiness in `finally`
without deleting their named volumes. The public ingress and issuer are deterministic,
bounded DEV-LOCAL-ONLY fixtures; this is not production authority, production durability,
or a production-readiness claim.

### One-shot uncertain-resend rehearsal

The resend-chaos overlay is development-only and is absent from staging and production
Compose. Do not start it with raw Compose commands. `ChaosBegin` requires the CA-trusted
physical UAT TLS lane, keeps HAProxy as the sole public publisher, and changes only the
primary privacy entry backend for `:41803` from the dedicated `xnode-3:8082` h2 ingress to the opaque interposer. The
client therefore continues to use the exact `https://<LAN-IP>:41803` primary origin, public route, certificate chain,
hostname/IP validation, revocation validation, and TLS policy. Cleartext application HTTP
remains rejected.
Authenticated router-to-router privacy hops and Store/Tombstone replication stay
Docker-network-only on each node's dedicated exact-h2 `8083` listener. HAProxy translates the
external TLS request scheme to `http` for the cleartext h2c backend while setting the trusted
`X-Forwarded-Proto: https` boundary; XNode accepts that forwarded scheme only from the pinned
HAProxy/chaos addresses. The mixed peer-RPC `8081` listener is not used by those privacy paths.

The required `-ChaosFault` is `post-durable-response-drop`, `pre-dispatch-outage`, or
`post-durable-ack-response-drop`. The first and third consume their one shot only after the
upstream privacy ingress has returned a complete 2xx response; the second returns one 503
without dispatching the privacy frame upstream. The proxy cannot and does not distinguish
Store, Retrieve, or ACK inside the opaque frame. The runner therefore arms each Store fault
immediately before the Store sequence, and prepares Store/Retrieve plus the private ACK state
before arming the ACK-only crash window. The proxy never decodes or logs a payload or
identifier. The protected random lab token, private Unix control socket, bounded ingress
counters, 5–300 second deadline, process restart default-disarm, and idempotent
`ChaosEnd` cleanup bound the fault to one local rehearsal.

Manual use is intentionally explicit:

```powershell
$env:SURVIVAL_UAT_TLS_SECRET_DIR = 'C:/Work/DeepSession/secrets/survival-uat-tls'
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/survival-dev.ps1 -Action ChaosBegin -LanHost 192.168.1.43 -ChaosTtlSeconds 120 -ChaosFault post-durable-response-drop
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/survival-dev.ps1 -Action ChaosStatus
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/survival-dev.ps1 -Action ChaosEnd
```

Always run `ChaosEnd` in a `finally` block. The checked live lane does this automatically. It
uses the real MAU2 Store, observes a transport-unknown first outcome, sends the byte-identical
MAU2 again inside a fresh three-hop privacy frame, requires native MQR3 2xx and an identical
replay, and retrieves exactly one
item. It runs all supported fault modes, including a two-process ACK crash/retry window,
restores the ordinary HTTPS ingress after each,
and deletes the protected binding and lab token:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/survival-dev-resend-chaos.integration.test.ps1 -BindHost 192.168.1.43
```

The ACK crash-window handoff is created before the first driver process in a dedicated
non-reparse directory with exact Windows owner and protected current-user/SYSTEM/Administrators
DACL (or Unix mode `0700`). Its sole regular, non-reparse state file is Windows read-only
between processes with the same exact DACL (or Unix mode `0600`). Writes use a same-directory
create-new temporary file, durable flush, atomic replacement, immediate reread, and SHA-256
comparison. Every retry/replay revalidates directory, file type, owner/DACL or mode, canonical
bounded JSON, and hashes of the ACK/Retrieve/MAR1 frames before decoding them; mismatch fails
closed. The runner deletes this state in `finally`, while an abnormal exit leaves it accessible
only through the same private directory boundary.
Deletion first restores the exact current-owner private ACL and clears the Windows read-only
attribute (or restores Unix `0600/0700`), then performs a terminating removal and proves the
directory is absent. Cleanup failures are aggregated only after `ChaosEnd`, exact-off status,
container count, and proxy/token/binding checks have all been attempted; no passed evidence is
written if state deletion or any baseline check fails.

The protected, atomically written evidence envelope is
`deep-survival-resend-chaos-evidence-envelope.v2`. Its canonical v2 evidence is
content-addressed with SHA-256 and immediately reread and independently verified by the same
runner. It binds exact source/configuration hashes, runtime image identities, HTTPS origin,
fault operation, fault deadlines, and attempt/dispatch/success/injection counts. It never
contains message bytes, mailbox/operation IDs, authority material, tokens, receipts, or
device identifiers. The digest detects evidence mutation; it deliberately makes no signing
authority or production-attestation claim.

Rollback is volume-preserving: run `ChaosEnd`, which removes the private interposer and
force-recreates only HAProxy with its ordinary xnode-3 backend. No XNode is restarted and no
named volume is deleted.

The launcher verifies the six fresh DPC1 privacy contacts exposed by the
XNodes. Every client request uses exactly three distinct native privacy hops:
`xnode-3 -> xnode-4 -> xnode-1` first and the fully disjoint
`xnode-5 -> xnode-6 -> xnode-2` route only after a definitely-before-forward
failure. An ambiguous dispatch result is outcome-unknown and never triggers
fallback. The second terminal exit forwards to the same xnode-1 coordinator, so both paths share
one cursor/continuation/ACK domain while route hops remain disjoint. Storage replication remains behind the mailbox exit and can use a
fourth storage node without exposing that node to the client route.

Run the bounded chaos evidence lane after the shared transport tests have been
built. It executes instrumented transport contract tests for: pre-dispatch
ingress fallback, one retrieve fallback, and the fail-closed outcome-unknown
behavior for ambiguous stores. It then stops and restores each local XNode and
verifies the exact six-contact topology again:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/survival-dev-chaos.ps1
```

The resulting `artifacts/survival-dev/six-node-chaos.json` is machine-readable,
development-only evidence. It explicitly does not claim dynamic membership,
production anonymity, replicated storage, cross-node deduplication, persisted
contacts without bootstrap, or write continuity through an arbitrary failed
intermediate relay. The retrieve fallback is marked privacy-degraded because
the current development protocol sends the first route's router identifiers as
exclusions to the fallback ingress. Do not use it as a production anonymity
claim.

Hardhat and staking are optional because messenger development does not require
a chain. The `-Chain` profile is a local deterministic development environment,
not a UAT or release deployment. Every supported `Up -Chain` removes the prior
one-shot deployment/smoke containers and the staking backend, starts the
in-memory Hardhat node, removes any old `localhost.latest.json`, deploys the
current contracts with Hardhat's deterministic local accounts, runs the contract
smoke, and only then starts the staking backend:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/survival-dev.ps1 -Action Up -Chain
```

The deployment manifest volume survives container removal, but the Hardhat
chain does not. The lifecycle above deliberately regenerates the manifest on
every `Up -Chain`, so an address from a previous node process cannot satisfy the
backend dependency. The staking backend mounts that manifest read-only, treats
its contract addresses and staking parameters as authoritative configuration,
and exposes `/health/ready` only after the manifest, chain ID, deployed bytecode,
and persisted-state generation agree. Its ordinary `/health/live` remains only
a process-liveness signal.

All four chain lifecycle services (`contracts-devnet`, `contracts-deploy`,
`contracts-smoke`, and `staking-backend`) are an indivisible generation.
Do not pass `-Service` with `Up -Chain`, and do not restart any of those services
independently; the launcher fails closed. Rerun `-Action Up -Chain` to create a
current deploy/smoke/backend sequence. Direct `docker compose` chain
restarts are unsupported because Compose cannot guarantee rerunning a completed
one-shot service after an in-memory node restart.

The deploy and smoke containers share the `contracts-devnet` network namespace.
This makes Hardhat's local-only `localhost:8545` target resolve to the running
devnet without publishing another port or giving either one-shot container its
own network attachment.

The chain profile includes a one-shot `contracts-deployments-init` container.
It runs as root only long enough to recursively set ownership of the isolated
`contracts-deployments` volume to the standard Node UID/GID `1000:1000`, then
exits successfully. `contracts-devnet` waits for that completion and continues
to run as the unprivileged `node` user. The initializer has no network, no
build context, `cap_drop: ALL`, and only `CHOWN` added for that exact volume
path. It is local development plumbing, not a release deployment mechanism.

Status and logs:

```powershell
docker compose -f docker-compose.survival.dev.yml ps
docker compose -f docker-compose.survival.dev.yml logs -f --tail=200
docker compose -f docker-compose.survival.dev.yml logs -f --tail=200 contracts-devnet
```

Stop containers while preserving development data:

```powershell
docker compose -f docker-compose.survival.dev.yml down
```

An intentional full reset also deletes the named volumes:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/survival-dev.ps1 -Action Down -Reset
```

Default messenger host ports are XNodes `41801-41806`, registry `41810`,
storage `41820`, file `41821`, and push `41822`. Registry also owns the authenticated
call signal/inbox/ICE listener on `41823`; there is no standalone calls service or
calls state volume. The local-only
chain profile additionally uses Hardhat `41545` and staking `41811`. All traffic
is Debug HTTP intended only for loopback or the exact trusted developer IPv4
interface selected with `-LanHost`.
