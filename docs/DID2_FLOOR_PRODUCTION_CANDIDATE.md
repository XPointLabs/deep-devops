# DID2 latest-head floor production candidate

## Current production observation (2026-09-28, 17:12 UTC)

Registry and seed1–seed3 are the authorized pre-user production test contour;
historical `UAT` container/configuration names do not denote a separate remote
environment. Exactly three registered node identities remain in use.

The live receive failure was an imported generation-zero ADF1 covering only
directory generations 0–3. The protected heads created later were outside that
coverage. Independent PostgreSQL floor observation and authenticated ADA2
export agreed on generation 22/tree 8. The imported predecessor was hash-matched
to the original offline file before a generation-one successor was authored
locally under Mr. X's existing root custody. It covers generations 4–21 and
targets the exact current head. Neither floor nor genesis was reset, and no
root private key was sent to a server.

`tools/did2-adf1-offline` accepts the optional paired inputs `--previous-adf1`
and `--previous-adf1-core-hash`. These must name the independently pinned last
checkpoint; retain its complete predecessor chain. The full authenticated head
export and all original mandatory inputs remain required. Run root authoring
offline, use a new artifact output, and import only the exact signed public file.
For each successor, `scripts/append-did2-checkpoint-env.cjs` prepares a new
private environment from the selected immutable Registry inspection. It checks
the exact state path, floor schema, network and existing checkpoint path, rejects
duplicates, gaps, noncanonical indexes, repeated paths and a reused target,
preserves every prior value and appends exactly one `ForwardCheckpointPaths`
entry after the independently selected latest predecessor. It refuses a full
64-entry chain. Protocol still verifies the complete exact signed lineage;
path validation is not signature evidence. This is not a chain replacement,
root-key transfer or state-reset tool.

The same deployed Registry image was recomposed with both checkpoints and the
same mounts, external floor and loopback listener. The old stopped container is
retained, but is not run concurrently against the same mutable state. Registry
DID2 readiness and the staking portal returned HTTP 200. A bounded real XNode
trace then showed nonce-fresh directory proof responses returning HTTP 200;
a malformed frame through certificate-validated H2 returned HTTP 400. These
are receive-prerequisite observations, not authenticated messaging delivery.
The Windows publication attempt progressed to `outcome-unknown`; Android's
latest attempt reported directory-authority unavailable. The XIC1 pair and
Windows↔Android contact/message/media/group evidence remain unproved.

Fresh account admissions subsequently advanced the signed head to generation
25/tree 10. A second independently pinned offline successor now covers heads
22–24 and targets that exact head. Registry retains all three checkpoints,
the same immutable runtime image, all thirteen mounts, the same loopback
listener and the same independent floor. The previous stopped container is
retained; only one process writes the ADA2 state. Registry readiness, all three
XNode health checks and the public staking portal were successful after import.
Root custody remained local, and node keys, genesis, certbot and account floors
were not changed.

Bounded production traces also exposed proof-budget exhaustion: three idle
XNodes polling every five seconds consume the six-per-ten-second DID2 issuance
ceiling, before device enrollment or traffic-triggered proofs. The ceiling is
a replay-ledger safety constraint, not an arbitrary limit to raise. The XNode
candidate reduces idle polling and reuses only a still-current, bounded local
verified binding; see its [operator behavior](../../xnode/docs/operator.md).
Owner CI run `36459171075` succeeded with `push_latest=false`. The immutable
amd64 manifest
`sha256:a8e35ebbb3f0a7ba5b815dc5929b6dcb19884435db813aa5dfb22fadcc6acd19`
was checked against source `6764cbfce325267a60d6855fef2b7923c65dd2f2` before
rollout. The supported installer updated seed1, then seed2 and seed3. All three
XNode/ingress/storage trios were healthy; registered Ed25519/BLS/X25519 keys,
DID2 active configuration and every non-image environment value remained
byte-identical. Registry readiness and the public staking portal returned 200.
The checkpoints and healthy services alone do not establish successful physical
publication or messaging; a new device attempt remains mandatory.

Protocol focused author/reader tests passed 10/10, the full production solution
passed 2,100 tests with 11 platform skips, and exact API/package graph validation
passed. The checkpoint environment helper passed its positive and hostile-input
tests. DevOps release-gate contracts passed 51 commands; the real readiness
report is still blocked on missing release evidence. Local Docker smoke reached
healthy services and passed its scenario tests, but artifact collection failed
the secret scanner on existing mixed diagnostic binaries. Do not treat that
aggregate smoke run as passing or exclude binaries to bypass its gate.

## Earlier diagnostic history

Earlier status on 2026-09-28: **isolated floor service remains deployed on seed2;
the new loopback-only UAT Registry forward-probe is ready, but Registry
production cutover is not approved**.
The database has its schema, distinct roles and the exact signed empty
genesis row. The public Registry still serves its previous configuration.

Source verification on 2026-09-28: the local-source Registry HTTP test
`CreatedClientAccountRequiresAndCommitsRealRegistryProof` passed a multi-hop
DID2 proof through an imported root-signed ADF1 and asserted that the new
DTT1 names the latest head. This proves the tested code path, not the deployed
canary or a production cutover. The saved canary environment has no
`DeepIdV2DirectoryAuthority__ForwardCheckpointPaths` entry. Existing private
ADF1 candidate artifacts must be independently matched to the exact restored
ADA2 lineage and external floor before either canary is restarted. Keep the
public route unchanged until that reconciliation and physical client E2E pass.

Live read-only audit on 2026-09-28 refined the earlier status: two separate,
loopback-only UAT diagnostic containers were running. The old forward-probe has an
ADF1 path, unlike the saved earlier canary environment, but uses an older
image and contained six duplicate configuration keys with conflicting values
(the DID2 floor connection, ADA2 state and proof-ledger root, the ContactResolve
trusted-time state and request-ledger root, and the Registry state path). The independent UAT floor
and a newly copied ADA2 state agree on the exact generation-7/tree-5 head;
the saved ADF1 targets the authenticated generation-4 ancestor. That current
head expired on 2026-09-25. Neither old probe is a production endpoint or valid
device-E2E evidence.

The newer Registry candidate image was started only in a new, closed UAT
forward-probe, bound to loopback on a separate port. A private, mode-0600
environment file was prepared from the old Docker inspection by
`scripts/prepare-did2-forward-probe-env.cjs`; it retains the reviewed last
values of exactly those six overrides, requires the expected UAT artifact
basenames and floor schema, and refuses any other duplicate. No environment
values were printed or committed. The old protected trusted-time file was
backed up and hash-verified before its compare-and-swap rotation from an
independently observed UTC interval. The operator advanced the expired head
to generation 8/tree size 5 without changing directory content. An independent
read from the floor host returned the same new core hash, and an ADA2 export
with that floor hash re-verified the journal. The new probe returned HTTP 200
from `/health/did2/ready`; this is a server readiness result, not a
nonce-fresh physical-client proof, message transport result, or cutover approval.
The protected time anchor is intentionally short-lived and must be rotated
again before expiry for further UAT checks.

To recompose this exact reviewed UAT source, run the helper on the Registry
Docker host with `--container`, `--output`, `--expect-state`,
`--expect-ledger`, `--expect-registry-state`, `--expect-trusted-time`,
`--expect-contact-ledger`, `--expect-floor-schema`, and `--expect-adf1`
in that order. The `--expect-*` values are independently checked basenames
or the isolated floor schema, not credentials. Use a new absolute output
path under a private operator directory; the helper creates it exclusively
with mode 0600 and never overwrites an existing file. Check the resulting
container's exact network, mount count, loopback-only port and duplicate-key
preflight before start. Keep the source container for recovery.

A physical Android diagnostic then created a fresh account on the correct
network and committed its genesis: the independent floor advanced to
generation 9/tree size 6, and the ADA2 export verified the same head. Its
nonce-fresh proof still failed closed. First, the test anchor's 15-second
uncertainty exceeded the XNA1 maximum of 10 seconds; a guarded rotation to
8 seconds removed that error. The next exact failure was that the signed
XNV1 does not cover the issued interval. The UAT XVP1, all three XND1 and
XNV1 expired together on 2026-09-25. This operational closure must be
renewed with its correct predecessor, root/node/witness custody and current
time; neither a replacement generation-zero chain nor a relaxed verifier is
acceptable. The Android account and the floor/ADA2 state were preserved;
the complete post-admission UAT state and independent floor dump were copied
to private recovery storage. No physical proof or message E2E is claimed.

An additional UAT-only floor schema and ADA2 state were provisioned without
overwriting the original candidate. Physical Android confirmed the first
signed admission/proof and protected restart; an external Windows test then
created later heads. Review found that the experimental multi-hop issuer
could sign an older intermediate head with a fresh DTT1 as if it were current.
Both canaries were stopped without deleting their state. Neither that result
nor the isolated loopback route is release evidence. The next image must fail
closed across this gap until DID2 forward-checkpoint publication is complete.

The Registry ADA2 file and its latest-head rollback floor must not share a
snapshot or restore domain. The candidate floor is one isolated PostgreSQL
service on the existing seed2 host; it does not change the XNode, storage, or
ingress compose project. This placement provides separation from the Registry
host, but does not establish independent operator or provider failure domains.

`docker-compose.did2-floor.prod.yml` pins the same official PostgreSQL 17 image
digest already used by the production push database. It requires one host bind
address and port, a private admin-password
file, a private TLS certificate/key directory, and a separate private
`pg_hba.conf` directory. None of these origin coordinates, credentials, or
certificate identifiers belong in this repository. The bind address must be
the host address intended for the Registry-to-floor connection, not a proxy
address. `scripts/New-Did2FloorPgHba.ps1` creates the private, TLS-only
single-source authentication file without printing the source address.
`scripts/New-Did2FloorPassfiles.ps1` creates distinct protected runtime and
one-time provisioning passfiles for Npgsql; neither connection string needs
an inline password.

Deployment is gated in this order:

1. Verify fresh local seed2 and Registry backups by hash. Preserve all
   registered node keys. The live Registry-volume copy is best-effort, not a
   database-consistent snapshot.
2. Verify image provenance, available memory/disk, certificate chain and
   private-key permissions. The server private key must be readable only by
   the PostgreSQL process; never copy the offline CA private key to a server.
3. Generate the private pre-Docker nftables guard with
   `scripts/New-Did2FloorFirewall.ps1`. Install and activate the generated
   service before starting the compose service, and make Docker require the
   guard on boot. Check the effective rule after Docker restart. It drops
   traffic to the floor host/port unless sourced from Registry, before Docker
   DNAT. `pg_hba.conf` independently allows
   only that source, only TLS, and only the runtime and separately credentialed
   operator-provisioning roles.
4. Start the floor service and test both allowed TLS/SCRAM access with a
   separately pinned CA and denied non-TLS/unauthorized access. Provision
   the schema and initial signed empty head via an operator-only path.
   The Registry runtime role gets `SELECT` and `UPDATE`, but no DDL,
   `INSERT`, `DELETE`, or `TRUNCATE`. The operator-provisioning role gets
   `INSERT` only for the signed empty genesis. On the live candidate, the
   exact-source nftables guard, Docker boot dependency, `verify-full` TLS,
   non-TLS rejection, distinct roles and their grants were checked. An
   outside-Registry workstation could not open the port. TLS uses a private
   RSA-3072 CA because PostgreSQL/libpq rejected an Ed25519-signed server
   certificate during SCRAM channel binding; this does not alter DID2 keys.
5. Verify that the floor row equals the independently pinned ADA2 head.
   The live candidate passed exact-byte comparison to the signed head and
   rejected duplicate provisioning. A consistent PostgreSQL dump and roles
   dump were copied to private local storage with SHA-256 verification; an
   isolated temporary container restored the row byte-for-byte. The roles
   dump was not replayed in that drill. A separate, loopback-only canary on
   the Registry host then accepted one real PQ-backed DID2 genesis and issued
   an independently verified nonce-fresh proof. The client's protected LKG
   advanced to tree size 1; the independent floor advanced to the same new
   head hash. The post-admission ADA2 and floor dump were copied to private
   local storage and hash-checked. This is a real Registry/DB exchange, not
   device E2E or production cutover. A separate, non-published Production-mode
   process using the earlier valid ADA2 was rejected at startup because its
   head differed from the independent floor; a control process using the
   current ADA2 started under the same configuration. A second isolated
   Production-mode process with its network disabled failed on the PostgreSQL
   connection before HTTP startup. UAT mode does not run this startup barrier,
   so a UAT process starting is not evidence for the production gate. A full
   role-recovery drill remains open.
   The canary's trusted-time state is short-lived and must be refreshed by
   the authorized operator before subsequent admission/proof tests.
   Before promoting any Registry candidate, run
   `node scripts/check-did2-registry-container-env.mjs --container <exact-name>`
   on its Docker host, or pipe the exact remote `docker inspect` JSON to
   `node scripts/check-did2-registry-container-env.mjs --stdin` locally.
   A nonzero exit blocks promotion. The check rejects repeated DID2 authority
   keys, including case variants and identical values, and never prints
   environment values. Do not store or paste raw inspect output in evidence:
   it may contain secrets. Docker may normalize duplicates before process
   startup, so the Registry's raw-process-environment guard is insufficient
   for this check. The old isolated probes fail this preflight. The new closed
   UAT probe has one effective value per key; repeat the preflight on its exact
   container before any promotion. The environment preparation helper is
   restricted to this reviewed UAT source and is not a general-purpose
   production composer.
6. Only after the full DID2 client and physical E2E gates pass may the
   explicit Registry production-cutover attestation be set. It remains off.

### Closed HTTPS UAT distribution

The reviewed unique canary can be extended with
`scripts/prepare-did2-https-env.cjs`. Supply its exact image, protected state
basename, independent floor schema and network scope, one known reverse-proxy
address, a new private output file, and a canonical public bundle mount path.
The helper refuses duplicates, production mode, an enabled V1 directory,
cutover attestation, substituted state/network/floor and pre-existing extension
keys. It preserves custody/state values exactly and does not disclose them.
The resulting environment is UAT-only; it is not a production composer.

Use the successful Registry CI image by immutable digest. Bind its port only
to loopback, retain the reviewed canary mounts, and mount only the public NCP2
directory read-only at `/app/public-network`. The public directory must not be
inside private custody, the directory database or the web root. See the
[public export workflow](PRODUCTION_AUTHORITY_CUSTODY.md) and
[Registry distribution runbook](../../deep-registry-api/docs/NETWORK_CLOSURE_DISTRIBUTION.md).

Render `config/did2-https-uat/nginx-location.conf.template` with the single
loopback port and include it only in the existing Registry HTTPS server;
`nginx-proxy.conf` is its shared proxy snippet. Headers are overwritten from
the actual ingress scheme/address, and Registry trusts only that known proxy.
Do not modify the staking server blocks, certificate configuration or certbot.
Retain and hash-check the exact prior ingress file before installing the
candidate; require `nginx -t`, current protected time, DID2 readiness and
positive/negative transport checks before accepting the route cutover.
Cleartext without a trusted scheme must reject. The HTTPS response must equal
the complete operator-exported public bundle byte-for-byte. A successful
distribution response is not a signed current network capability: the client
must independently obtain and verify its nonce-fresh DID2 proof.

The floor does not carry message payloads and is not a contact resolver.
It is a monotonic rollback guard for the signed DID2 directory head.
