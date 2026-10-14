# Retained local development network

`docker-compose.deep-dev.yml` is the supported local Deep topology. It contains
Registry, an independent TLS PostgreSQL directory floor, three XNode processes
and a delegated operational-view publisher. It is **not** UAT or a production
release/device/message-delivery evidence profile. Production servers were not
changed. Mr. X remains the single development operator; three signer keys are
not three independent operators.

The wrapper accepts exactly two isolated project names: `deep-dev` and
`deep-dev-current`. Both use the same current-only code, not different protocol
readers. `deep-dev-current` permits a new current fixture alongside the preserved
pre-cutover one: its custody defaults to `secrets/dev/deep-dev-current`, its named
volumes/network are project-scoped, its subnet is `172.31.241.0/24`, and its host
Registry/node ports are28543/28291–28296. The original defaults are unchanged.
The manifest binds the exact project and container prefix; mutating actions
reject an absent/mismatched binding rather than infer old configuration. Only
Status/Stop can inspect/stop an older fixture without that binding. Wrapper
environment overrides are restored even when an operation fails.

First-time creation of the **separate** current fixture uses `Init`, `Build`,
`Provision`, `Up` with `-ProjectName deep-dev-current`, then `Verify` with the same
project. `Init` still rejects any existing custody. Never use that sequence on
the retained pre-cutover project to make a failed recovery appear successful.
The new genesis is an isolated DEV fixture, not a production root/identity
replacement or acceptance of old-state recovery. Once created, its lifecycle
tests must retain its own keys, journal, genesis and floors.

`Up` submits the exact retained observer admission through authenticated Registry
HTTPS after starting the services. `AdmitObserver` repeats that same operation
without recreating the account; Registry's existing idempotency rules apply.
The disposable probe mounts only public bootstrap and the single prepared
admission file, not root/operator/online signer custody or protected volumes.
Receipt binding is checked, but receipt bytes are never used as current proof.
Each node still independently acquires and verifies a fresh DID2 proof.
Use `test-env.ps1 -Suite smoke -BackendMode deep-dev -DeepDevProjectName
deep-dev-current` to check that instance explicitly. It does not silently redirect
a failed older fixture to the new one. The smoke remains proof/ONION readiness,
not masked carrier delivery or a device test.

New Init retains independent `mailbox-deposit.seed` and `mailbox-retrieve.seed`
candidates matching its PMA2 public keys, instead of discarding their seeds.
That alone does not configure the protected external signers, grant/revocation
journals or mailbox admission. An already initialized fixture with discarded
issuer keys requires a properly signed policy/role successor; do not create an
unrelated seed and pretend it matches its old PMA2.

### Explicit current-dev mailbox issuer activation

The optional `docker-compose.deep-dev.mailbox.yml` overlay adds two Linux role
signers, making eight services only in `deep-dev-current`. Each has no network,
ports or HTTP listener, a read-only root filesystem, one existing role seed in
its own owned0700/0600 volume and a separate protected socket volume. Registry
receives read-only sockets and a filtered online-secrets volume containing no
mailbox seed. The original secrets volume and host custody remain recoverable;
no registered node key, offline root, genesis or floor is replaced.

Run in order, once for a genuinely uninitialized mailbox issuer:

```powershell
./scripts/deep-dev.ps1 -Action PrepareMailbox -ProjectName deep-dev-current
./scripts/deep-dev.ps1 -Action ProvisionMailbox -ProjectName deep-dev-current
./scripts/deep-dev.ps1 -Action ActivateMailbox -ProjectName deep-dev-current
./scripts/deep-dev.ps1 -Action Verify -ProjectName deep-dev-current
```

Build the matching current Registry image before activation. Preparation verifies
the original genesis, complete signed authority/time chain, authenticated NTS,
current PMA2/projection and both existing role keys. It writes exact operator
config/SQL under private dev custody; repeated differing inputs reject. No new
key or signature is authored. Provisioning repeats verification and atomically
creates the four existing canonical grant/MGR tables and explicit network/two
role roots in the independent PostgreSQL database. Existing tables reject; no
upsert, reset, floor provisioning or implicit repair exists. Preserve a failed
or uncertain transaction and inspect it; do not delete tables/markers to retry.

The `mailbox/enabled` marker selects the overlay for normal Up/Start/Stop/Verify
and retained recovery. A partial activation resumes with normal Up, not another
first enrollment. Readiness independently verifies current signed journal
winners; process/socket health alone cannot authorize grants. Node mailbox
enrollment uses the explicit workflow below. Configured issuance→client
verification→node acceptance remains separate S05 work, followed by physical
device qualification.

Pre-mailbox PrepareOperational/ApplyOperational and first floor-provisioning
commands deliberately reject once enabled: they do not yet atomically update
role volumes and journal scopes. Do not bypass this fence with a manual partial
rollover. Coordinated role rollover and uncertain first-provision recovery remain
operator-workflow gates, not claims closed by the successful initial activation.
Exact runs/failures are recorded in the
[S05 checkpoint](S05-AUTHORITY-HISTORY-2026-10-14.md#actual-protected-mailbox-issuer-activation).

### Explicit current-dev node mailbox enrollment

After issuer activation, build the matching operator image and prepare the
public scope once. Provision/enroll each genuinely new native mailbox scope:

```powershell
./scripts/deep-dev.ps1 -Action PrepareNodeMailbox -ProjectName deep-dev-current
foreach ($node in 1..3) {
    ./scripts/deep-dev.ps1 -Action ProvisionNodeMailboxKeys -ProjectName deep-dev-current -NodeNumber $node
}
./scripts/deep-dev.ps1 -Action FetchNodeMailboxControl -ProjectName deep-dev-current
foreach ($node in 1..3) {
    ./scripts/deep-dev.ps1 -Action EnrollNodeMailbox -ProjectName deep-dev-current -NodeNumber $node
}
./scripts/deep-dev.ps1 -Action ActivateNodeMailbox -ProjectName deep-dev-current
./scripts/deep-dev.ps1 -Action Verify -ProjectName deep-dev-current
```

Key provisioning runs without a network or identity/root mounts, rejects a
nonempty key-ring volume and explicitly creates one Data Protection key in a
0700 directory/0600 file. OS time controls only local protection-key lifetime,
never protocol freshness. Each node retains its existing identity and data
volume; its new independent mailbox custody and read-only key ring have
separate external volumes. Automatic key generation remains disabled.

Control capture fetches bounded exact issuer-signed MGR1 records over ordinary
validated TLS, with closed media/cache/encoding/framing checks. Public capture
files and scope bindings are not floors or admission capabilities. They may be
refetched after transport failure; node enrollment still independently verifies
current proof/time, signatures, both native floors and durable read-back.
Enrollment stops the existing node owner and invokes its supported
`current-mailbox-enroll` command against the same retained identity/data roots.
A failed or uncertain enrollment must be inspected with retained state intact;
do not delete its partial floors or key ring and retry as a new scope.

Activation requires all three successful enrollment markers and selects the
node overlay for subsequent Up/Start/Stop/Verify/fault operations. Verify then
requires `currentMailboxHost.recovered=true` and state `recovered` on every node;
`disabled` no longer qualifies. StackFault also compares mailbox-key digests in
memory alongside retained identity/role custody and mounts. This remains local
dev infrastructure evidence, not XMC2 issuance, message delivery or device E2E.

### Current-dev contact and issuer-connected client

Once all mailbox hosts are enrolled, provision separate contact protection
keys and invoke the existing node resolver enrollment command:

```powershell
foreach ($node in 1..3) {
    ./scripts/deep-dev.ps1 -Action ProvisionNodeContactKeys -ProjectName deep-dev-current -NodeNumber $node
}
foreach ($node in 1..3) {
    ./scripts/deep-dev.ps1 -Action EnrollNodeContact -ProjectName deep-dev-current -NodeNumber $node
}
./scripts/deep-dev.ps1 -Action ActivateNodeContact -ProjectName deep-dev-current
./scripts/deep-dev.ps1 -Action Verify -ProjectName deep-dev-current
./scripts/deep-dev.ps1 -Action ProvisionContactCoordination -ProjectName deep-dev-current
./scripts/deep-dev.ps1 -Action ActivateContactCoordination -ProjectName deep-dev-current
./scripts/deep-dev.ps1 -Action Verify -ProjectName deep-dev-current
```

The optional contact/coordination overlays retain eight services and every
existing node identity/data/mailbox mount. Each resolver has its own disjoint
custody volume and read-only protection key ring. First key provisioning is
networkless; resolver enrollment stops the existing owner, acquires independent
current proof/time and uses `contact-resolver-enroll` with native read-back.
Preserve uncertain or partially enrolled state; never erase it to retry.

Contact activation composes current pre-key staging/claims, resolver and the
private HTTPS mailbox issuer. Coordination preparation verifies the retained
genesis and current policy, then captures the three configured node transport
keys. This allowlist controls transport access only, not membership or issuance
authority. Explicit provisioning executes the canonical route/publication
schemas plus two first network roots in one PostgreSQL transaction. Existing
tables reject; no upsert, automatic DDL or root reset is available. Activation
adds the private threshold backend to the selected ONION terminals. All
original witness/role keys and protected journals remain retained.

Build the matching operator image before running the connected client probe:

```powershell
./scripts/deep-dev.ps1 -Action ExerciseOwnedMailbox -ProjectName deep-dev-current
```

The Linux form mounts public bootstrap only and creates one genuinely disposable
account inside its `--rm` container. Its account keys remain in process-owned
storage and the actual encrypted account database; no node/witness/root/role
custody is mounted. The Windows form below instead preserves the owned probe's
keys and exact staged state. Both call production account-owned admission, current network, pre-key
publication, contact publication and mailbox synchronization APIs. TLS uses the
image's explicit dev CA and ordinary platform validation; signed endpoints,
client route selection, issuer journal and node admission are not mocked.
Stage labels and exception categories are closed; credentials/grants/payloads
are never printed. A successful authenticated empty mailbox page is a scoped
issuer→owned-client→node read, not message delivery, durable probe recovery or
physical Windows/Android acceptance. A failed stage does not pass this scenario.
The exact receipts and remaining work belong to the
[S05 checkpoint](S05-AUTHORITY-HISTORY-2026-10-14.md).

### Current-dev TLS revocation distribution

The managed HTTPS client requires online revocation as well as ordinary
chain/hostname/EKU validation. The original local certificates had no CRL
Distribution Point; curl readiness alone did not prove this managed TLS path.
Use the explicit current-dev-only ceremony, after contact coordination is enabled:

```powershell
./scripts/deep-dev.ps1 -Action PrepareDevPki -ProjectName deep-dev-current
# Build the matching operator/publisher image before applying the candidate.
./scripts/deep-dev.ps1 -Action ApplyDevPki -ProjectName deep-dev-current
./scripts/deep-dev.ps1 -Action Verify -ProjectName deep-dev-current
./scripts/deep-dev.ps1 -Action ExerciseOwnedMailbox -ProjectName deep-dev-current
```

Preparation runs on the operator host, independently observes authenticated
time, verifies current policy and uses the retained local TLS CA key. It
preserves the CA certificate, leaf keys, SPKI bindings, DNS/SAN/extensions and
leaf validity windows. Only the standard CRL Distribution Point and fresh
certificate serial/signature change. The signed CRL preserves previously revoked
entries and advances its standard CRL number. Neither thisUpdate nor TLS
certificate times supply protocol freshness. No protocol authority, identity,
floor, signed network record or issuer journal is edited.

The candidate contains public certificates/CRL and a sealed exact installation
plan with recoverable before-images; it contains no CA/leaf private keys.
Apply validates the whole fixed whitelist before stopping the eight dev owners,
compares every retained volume certificate to its exact before/after image,
copies only server.crt with mode0600 and the retained TLS key's numeric owner
(including PostgreSQL's non-root owner), installs the host files and resumes the same retained
topology. A partial/uncertain install stays stopped: preserve the candidate and
resume Apply, not Prepare, Init, Provision or a state reset. Existing candidates
reject re-authoring. CA custody is never mounted online.

The optional PKI overlay adds **no service or published port**. The existing
publisher serves only bounded, CA-signature-verified public CRL bytes at the
fixed internal `http://publisher:8080/deep-dev-ca.crl`, without access logs,
query parameters, app API, payload or signing capability. HTTP is used only for
cryptographically authenticated CRL distribution: .NET10's Linux
[CRL cache implementation](https://github.com/dotnet/runtime/blob/v10.0.0/src/libraries/System.Security.Cryptography/src/System/Security/Cryptography/X509Certificates/OpenSslCrlCache.cs)
selects HTTP distribution points. Every application request remains HTTPS/H2;
NoCheck, unknown-revocation exceptions and TLS-accept callbacks are not added.
CRL and offline-policy expiry still require operator renewal; this is not
unattended CA rotation, production PKI or physical acceptance.

### Explicit physical LAN ingress maintenance

The current-only signed origin relocation contract is
[DR-0120](../../docs/survival-program/decisions/DR-0120-signed-operational-origin-relocation.md).
Use an explicit canonical private LAN IPv4 belonging to this host, not the VPN
or Docker bridge. Do not put actual machine addresses into tracked documentation.

```powershell
./scripts/deep-dev.ps1 -Action PreparePhysicalIngress -ProjectName deep-dev-current -IngressAddress <LAN_IPV4>
./scripts/deep-dev.ps1 -Action ApplyPhysicalIngress -ProjectName deep-dev-current
./scripts/deep-dev.ps1 -Action Verify -ProjectName deep-dev-current
./scripts/deep-dev.ps1 -Action CacheWindowsDevCrl -ProjectName deep-dev-current
./scripts/deep-dev.ps1 -Action ExerciseOwnedMailboxWindows -ProjectName deep-dev-current
```

Build the current publisher image before maintenance. Prepare stops the retained
publisher to fix its exact predecessor and leaves it stopped. It stages a new
`offline-root/physical-ingress` candidate rather than overwriting the old PKI
candidate. The original CA, all leaf private keys, node identities, BLS keys,
policy/epoch, native floors and histories remain. Same-key leaf certificates
retain subject/lifetime/extensions and existing DNS/IP SANs, add the one exact
LAN SAN and point at the existing publisher's bounded CA-signed CRL listener.
No application request becomes HTTP and no machine ROOT trust is added.
After physical installation, `Build` validates the sealed images/current policy
and rebuilds binaries without rewriting installed configuration. An unrelated or
predecessor image fails before Docker build; use the supported maintenance
ceremony rather than editing sealed peer/TLS files.

Apply validates the sealed twelve-file whitelist/current policy, stops all eight
owners, compare-replaces only server certificates in the five existing secret
volumes preserving key-file ownership, and installs exact host before/after
images. Only the public-only `online` directory is mounted into the one-shot
publisher; CA private custody and private config/plan never go online. The author
uses unchanged traffic keys/pins and the same publisher lease/journal/CAS. Its
sealed exact result precedes the journal; a complete pending rename resumes,
while partial/foreign bytes fail closed without re-authoring. The physical
configuration marker is an untrusted listener setting, never client authority.

The physical overlay adds one pinned existing HAProxy ingress: nine owners but
still exactly three nodes. It publishes Registry28543, the three signed TLS
origins28294–28296 and signed-CRL HTTP28297 on the explicit LAN address. The
three origins terminate their respective original leaf certificates/keys;
public H2 goes to exact-proxy-allowlisted internal8082, authenticated peer paths
go to original TLS443 with required CA/CRL/name verification. This corrects the
old peer-only443 mapping: a TLS handshake alone did not prove public ingress.
Only exact frame/capability/authorized-peer paths are routed; management stays
closed. Incoming forwarded identity/scheme headers are removed; only the trusted
public backend gets the exact HTTPS scheme. The proxy mounts six leaf files,
public CA/CRL and config, never whole secret volumes, node identity/BLS keys,
offline root, operator or application state. Its combined PEM files exist only
in private tmpfs. Existing loopback mappings and named volumes stay.
The internal h2c backend explicitly uses HTTP in its pseudo-header while retaining
the exact original path/query; the allowlisted proxy supplies the authenticated
external HTTPS scheme. The frontend rejects non-H2 ALPN rather than converting a
downgraded request into apparently valid H2. Diagnostic stats are read-only on
the ingress container's loopback only, never a published management endpoint.
Public responses strip framework Date/Server metadata and set exact no-store,
matching the strict carrier allowlist; response integrity checks are not relaxed.
Normal Up/Start/fault workflows retain the overlay after successful installation.
Up validates the actual proxy configuration/certificate pairs before activation.
Verify separately probes all three public TLS/H2 capability endpoints through
the proxy in addition to Registry and node runtime readiness. Neither check is
a physical message-delivery claim. The base nonphysical dev topology remains
eight owners with mailbox composition.
Already-installed Apply verifies the same sealed files/prefix and restarts;
it never authors a second relocation. A failed partial install remains stopped:
resume that same candidate, never Init/Provision or a floor reset.

Readiness, strict host TLS and immutable owned-client publication are separate
checks. A successful relocation cannot restage/re-sign an old XPP inventory that
was bound to a prior placement; such lifecycle failures remain real blockers.

### Supported Windows owned-client probe commands

After the DR-0121 semantic clean break the fixed current probe uses a separate
disposable owner. The pre-cutover probe remains untouched as negative evidence;
its view-bound XPP1 is not rewritten, migrated or dispatched through a fallback.
Current publication preserves the exact inventory/operation across ordinary
signed view renewal; epoch/selected-set changes still fail closed pending their
independent handover contract. Build matching Protocol/Shared/node inputs before
the connected check. This is an operator probe, not physical device delivery.

```powershell
./scripts/deep-dev.ps1 -Action CacheWindowsDevCrl -ProjectName deep-dev-current
./scripts/deep-dev.ps1 -Action ExerciseOwnedMailboxWindows -ProjectName deep-dev-current
```

The first command validates the bounded CA-signed public CRL and caches it with
Windows `certutil -user -addstore CA`; it imports no ROOT certificate, touches no
machine store, and adds no trust bypass. Windows online chain validation can
then use the genuine signed CRL while the Docker-only publisher name is absent
from host DNS. Private CA trust remains app-scoped through the existing supported
factory; hostname/EKU and online revocation remain required.

The Windows probe uses Registry's fixed loopback HTTPS port and supported
Windows native PQ assets. Its fixed probe directory is separate from MAUI/user
accounts. Journaled secure storage uses Data Protection keys protected with
current-user DPAPI; restarts reopen the same account and exact staged inventory,
not a recreated identity or re-encrypted retry. Existing corrupt/missing custody
fails closed. Only typed directory 429/503 receive at most three retries honoring
Retry-After inside the original five-minute operation budget. Unknown forwarding
completion is retained, never automatically acknowledged or reported as success.

This is an operator-owned runtime diagnostic, **not physical MAUI/device E2E**.
Account admission/current network/pre-key authoring have passed on Windows.
The current signed bridge-IP locators do not yet form a usable Windows TLS/H2
route: direct bridge-IP handshake times out while the published localhost port
successfully negotiates strict H2. A TCP connect alone is insufficient evidence.
Do not silently translate sealed endpoints in the client, disable pins/TLS,
change the profile on failure or reset genesis/floors. A supported signed ingress
update or production-representative reachable deployment remains required.

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
The S05 source candidate now reads terminal paired authority/time-policy and
PMA from the retained closure rather than generation zero, warns before offline
policy expiry, and rejects an exhausted horizon before signing. It does not
import a new root bundle into the protected publisher journal or update TLS
custody automatically. The retained deployment is still expired; source builds
are not a recovered network. Follow
[DR-0116](../../docs/survival-program/decisions/DR-0116-offline-root-continuity-after-expiry.md)
and the [current source checkpoint](S05-AUTHORITY-HISTORY-2026-10-14.md).

The 2026-10-14 read-only diagnosis additionally found a pre-cutover seven-chain
NCP2 in this retained deployment (610 views/heads/topologies). The current
eight-chain decoder deliberately rejects it before offline observation/signing.
`PrepareAuthority` does not convert that frame or erase retained state. This is
a separate provisioning clean-break issue, not merely policy expiry; preserving
the existing fixture is not evidence that the current deployment works.

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
./scripts/deep-dev.ps1 -Action PrepareAuthority
./scripts/deep-dev.ps1 -Action PrepareOperational
./scripts/deep-dev.ps1 -Action AdmitObserver
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
`PrepareAuthority` is an explicit Windows-host offline ceremony. It authenticates
the complete retained paired XNA1/DTS1 history against the unchanged genesis,
acquires an actual NTS observation using the retained signed source policy,
and uses the existing offline root to prepare one same-key seven-day successor.
It never clamps the observation into an expired interval. Concurrent source
change rejects; a separate exclusive offline lease prevents concurrent ceremonies.
The completed public-only candidate is under `offline-root/renewals/authority-*`;
an incomplete write retains a `.pending` sibling and is not an activation input.
No seed is copied into the candidate and no online root mount is introduced.
It does **not** publish NCP2, change public bootstrap/configuration, import the
publisher journal, renew TLS or alter account/floor/state volumes. New root/time
bytes alone cannot make old XVP1/PMA2 current: operational preparation and the
supported retained-journal activation step must still be completed before `Verify`.
`PrepareOperational` is a separate Windows-host offline ceremony. It renews
the exact paired authority, authors a root-signed policy/PMA role-key successor,
stages fresh current/next traffic keys and installable TLS/CA certificates, and
retains every original signed history byte and registered node identity. It
writes private custody plus an HMAC-authenticated candidate publisher journal
beneath `offline-root/renewals/operational-*`; do not upload that directory.
It neither installs secrets/configuration nor publishes/adopts the candidate.
It requires a running owned publisher and leaves that publisher stopped after
success so its predecessor cannot advance. Failure restores only the publisher
this command stopped.
The pending publisher uses `unless-stopped` so an engine restart cannot silently
resume it. Failure restores its prior restart policy; explicit `Start` restores
normal `always` policy and cancels preparation.
Explicit `Start` cancels the preparation by permitting
new delegated publication; prepare a new candidate rather than force old import.
After building the current publisher image, use `ApplyOperational
-ProjectName deep-dev-current -OperationalCandidate <exact completed private directory>`.
It validates the offline HMAC seal over the exact installation whitelist, PMA
issuer custody, CA identity, leaf keys/chain/hostnames and traffic metadata.
It stages HMAC-protected private before-images, rejects stale candidates or
externally changed targets, stops all six owners, verifies every owned secret
volume against before/new images, and installs only TLS/traffic/issuer files
and authority/peer configuration. Original root/genesis, registered Ed/BLS
identities, state-protection keys, passwords, databases and floors are not replaced.
The online import mounts only `candidate/operator`, never the whole candidate
or offline-root. Publisher generation/hash/prefix checks and real NTS recheck
remain mandatory, with journal commit before public distribution. An interrupted
installation can resume only against exact old/new target bytes and the exact
unadvanced candidate; do not restart an old publisher midway. After a committed
publisher advances further, that candidate is stale and is not an undo command.
Failures before restart leave scoped services stopped; readiness failure after
restart leaves retained services running for diagnosis, never resets or rolls
back protected authority. A successful import alone is not successful activation.

The first actual activation on2026-10-14 installed/imported the successor and
resumed delegated publication, but three-node proof/ONION acceptance failed.
Same-UTC-day root/DTS replacement changes the DTT1 namespace while retaining its
day number; the existing replay ledger correctly rejects it. Registry readiness
must inspect that ledger without consuming a nonce or compacting it. This is an
open S05 coordination requirement, not permission to erase the ledger, change
the clock, backdate policy, weaken fork rejection or publish a release. See the
[source/runtime checkpoint](S05-AUTHORITY-HISTORY-2026-10-14.md).

The coordinated consumer under
[DR-0119](../../docs/survival-program/decisions/DR-0119-dtt1-same-day-authority-handover.md)
now checks nonce paths across the exact verified same-day paired ancestry and
preserves its aggregate quota and markers. It does not accept an arbitrary
changed ID or clear the ledger. The current-only dev recovered Registry proof
and all three ONION capabilities after the updated Registry image, then passed
a scoped retained restart. This resolves that observed epoch collision, not
all S05 issuance/rotation gates or device/message acceptance. See the checkpoint
for exact real-runtime evidence; do not repeat unchanged full gates to infer more.

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
