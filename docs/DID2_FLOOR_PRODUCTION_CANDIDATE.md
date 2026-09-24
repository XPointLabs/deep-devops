# DID2 latest-head floor production candidate

Status: **prepared locally, not deployed or approved for cutover**.

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

Deployment is gated in this order:

1. Verify fresh local seed2 and Registry backups by hash. Preserve all
   registered node keys. The live Registry-volume copy is best-effort, not a
   database-consistent snapshot.
2. Verify image provenance, available memory/disk, certificate chain and
   private-key permissions. The server private key must be readable only by
   the PostgreSQL process; never copy the offline CA private key to a server.
3. Install a persistent host firewall rule restricting the published floor
   port to the Registry source before starting the compose service. Check the
   effective rule after Docker restart. `pg_hba.conf` independently allows
   only that source, only TLS, and only the runtime and separately credentialed
   operator-provisioning roles.
4. Start the floor service and test both allowed TLS/SCRAM access with a
   separately pinned CA and denied non-TLS/unauthorized access. Provision
   the schema and initial signed empty head via an operator-only path.
   The Registry runtime role gets `SELECT` and `UPDATE`, but no DDL,
   `INSERT`, `DELETE`, or `TRUNCATE`. The operator-provisioning role gets
   `INSERT` only for the signed empty genesis.
5. Verify that the floor row equals the independently pinned ADA2 head.
   Then prove that floor outage and a restored-old ADA2 both block Registry
   readiness. Take and test a floor backup independent of Registry snapshots.
6. Only after the full DID2 client and physical E2E gates pass may the
   explicit Registry production-cutover attestation be set. It remains off.

The floor does not carry message payloads and is not a contact resolver.
It is a monotonic rollback guard for the signed DID2 directory head.
