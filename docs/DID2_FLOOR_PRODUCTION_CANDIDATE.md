# DID2 latest-head floor production candidate

Status on 2026-09-25: **isolated floor service remains deployed on seed2;
both loopback-only DID2 Registry canaries are stopped pending a safe forward
checkpoint; Registry cutover is not approved**.
The database has its schema, distinct roles and the exact signed empty
genesis row. The public Registry still serves its previous configuration.

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
6. Only after the full DID2 client and physical E2E gates pass may the
   explicit Registry production-cutover attestation be set. It remains off.

The floor does not carry message payloads and is not a contact resolver.
It is a monotonic rollback guard for the signed DID2 directory head.
