# Production Node TLS Ingress

Status: **pre-cutover operational evidence**. PMA1/PMT1 commands below match the
current stack; DR-0004 requires PMA2/PMT2 and signed XCB1 bindings before public
release. Do not carry these authority bytes forward as compatibility fallback.

`docker-compose.node.prod.yml` has one public listener: the hardened `ingress`
container publishes TCP `443`. XNode API ports `8080`/`8081`, Xray `443`, and
storage `8080` are container-only. Cleartext HTTP upstreams exist only on the
`internal: true` `ingress-upstream` network. Port `80` is not defined and must
remain closed unless a separately reviewed redirect-only listener is added.

The ingress inspects the TLS ClientHello without logging its contents:

- exact `DEEP_INGRESS_HOST` SNI is terminated with the approved HTTPS
  certificate;
- exact `DEEP_NODE_REALITY_SERVER_NAME` SNI is passed through to Xray Reality;
- every other non-empty SNI is dropped;
- a client addressing a node by public IPv4 may omit SNI and is routed only to
  the pinned HTTPS terminator.

The HTTPS lane requires an exact `Host`; when SNI is present it must also match
exactly. For an IPv4 origin, the certificate IP SAN, validity window, and exact
signed SPKI pin remain mandatory. The lane strips all inbound
`Forwarded`/`X-Forwarded-*` identity claims, and only exposes the explicit
bootstrap, contact, membership, Session RPC, MAU2 client, onion-peer, and
mailbox-peer paths. Health, status, metrics, debug, storage, and admin endpoints
are not public. The quorum-signing path is admitted only from the exact public
unicast IPv4 `DEEP_QUORUM_COORDINATOR_CIDR` with a `/32` prefix. Broad,
private, loopback, link-local, documentation, benchmark, multicast, and
reserved ranges fail preflight. XNode trusts only the isolated ingress address
for that route. TLS 1.2 and 1.3 are allowed; older TLS,
session tickets, unbounded bodies, and unbounded connect/client/server waits
are rejected.

## Certificate profiles and protected inputs

Choose exactly one profile in `.env.node.prod`:

- `pinned-self-issued`: the node generates distinct current/next HTTPS keys and
  exact-host certificates locally. No public CA, purchased certificate, or
  operator-owned domain is a trust prerequisite; the signed PMT2 current/next
  SPKI set is the authority. TLS consumers may ignore only the expected
  self-issued chain error after exact hostname, validity, and SPKI validation.
- `deep-managed`: Mr. X/Deep operations owns the HTTPS identity and PMT1 pin
  publication.
- `operator-managed`: an independent node owner supplies its own publicly
  trusted certificate and publishes its public current/next pins through the
  approved PMT1 workflow. It does not weaken ingress policy.

All profiles require six files outside Git:

```text
secrets/ingress/current.crt
secrets/ingress/current.key
secrets/ingress/current.spki-sha256
secrets/ingress/next.crt
secrets/ingress/next.key
secrets/ingress/next.spki-sha256
```

Private keys must be non-symlink regular files, owner-only on Linux (`0600`),
or have protected Windows ACLs limited to the owner, SYSTEM, and
Administrators. Pin files contain exactly one lowercase 64-hex SHA-256 of the
certificate SubjectPublicKeyInfo, not a certificate fingerprint:

```bash
openssl x509 -in current.crt -pubkey -noout \
  | openssl pkey -pubin -outform DER \
  | openssl dgst -sha256 | sed 's/^.*= //' > current.spki-sha256
```

The preflight proves exact SAN, cert/private-key match, validity, distinct
current/next keys, and exact SPKI-to-protected-pin equality. It emits public
hashes only:

```powershell
powershell -ExecutionPolicy Bypass -File ./scripts/production-ingress-preflight.ps1 `
  -Profile deep-managed -HostName $env:DEEP_INGRESS_HOST `
  -CurrentCertificate $env:DEEP_INGRESS_CURRENT_CERT_FILE `
  -CurrentPrivateKey $env:DEEP_INGRESS_CURRENT_KEY_FILE `
  -CurrentPin $env:DEEP_INGRESS_CURRENT_SPKI_FILE `
  -NextCertificate $env:DEEP_INGRESS_NEXT_CERT_FILE `
  -NextPrivateKey $env:DEEP_INGRESS_NEXT_KEY_FILE `
  -NextPin $env:DEEP_INGRESS_NEXT_SPKI_FILE `
  -ClientTimeoutSeconds $env:DEEP_INGRESS_CLIENT_TIMEOUT_SECONDS `
  -ServerTimeoutSeconds $env:DEEP_INGRESS_SERVER_TIMEOUT_SECONDS `
  -QuorumCoordinatorCidr $env:DEEP_QUORUM_COORDINATOR_CIDR
```

Run this before every `docker compose up`. Compose also runs the same
cert/key/pin verifier in a networkless one-shot `ingress-preflight` service and
will not start ingress unless it exits successfully. Only that isolated
preflight receives the next private key; the public ingress runtime never does.
It writes a content-and-policy-bound attestation. Ingress recomputes current
file hashes and fails closed if the preflight result is stale. Unsafe host file ACLs are
checked by the outer PowerShell preflight and cannot be inferred from a Docker
secret mount. A missing or mismatched input is a stop-the-line failure. Never
place the JSON output, compose rendering, or logs
in an artifact if another command has added key content; the supported
preflight itself never returns key bytes or paths.

## Start and verify

```powershell
node ./scripts/production-ingress-contracts.mjs
docker compose --env-file ./.env.node.prod -f ./docker-compose.node.prod.yml config --quiet
docker compose --env-file ./.env.node.prod -f ./docker-compose.node.prod.yml up -d --wait
docker compose --env-file ./.env.node.prod -f ./docker-compose.node.prod.yml ps
```

The only host publisher must be `ingress:443`. `xnode` and `storage-service`
may show exposed container ports but must have no `PublishedPort > 0`.
Externally, verify the exact CA/hostname and the independently distributed
SPKI pin. Do not use `-k`:

```bash
curl --fail --cacert /trusted/ca.pem \
  --pinnedpubkey "sha256//<approved-current-SPKI-base64>" \
  https://node.example/api/bootstrap/client
curl --fail --tls-max 1.1 https://node.example/api/bootstrap/client # must fail
```

`/status`, `/health/*`, `/stats`, and `/metrics` must return `404` through
public ingress. `/api/staking/quorum/sign` must also return `404` from every
source outside `DEEP_QUORUM_COORDINATOR_CIDR`. Health is checked from inside
Docker; no public health endpoint is needed.

## Current/next rotation

1. Generate a new next key/certificate in the protected secret store. Never
   generate or copy it through CI artifacts.
2. Calculate its SPKI SHA-256, run preflight, and publish it as PMT1 `next` in
   an exact successor topology generation.
3. Wait for that signed PMT1 generation to reach the required client/node
   population and retain public evidence of the generation and hashes only.
4. Promote the previously approved next certificate to current, create a new
   distinct next pair, and run preflight with
   `-ExpectedPriorNextSpki <previous-next-hex>`. This gate proves continuity.
5. Publish the successor PMT1 with the promoted current and new next pin.
6. Force-recreate preflight before ingress. A cached completed preflight is
   intentionally rejected after any current secret or ingress policy change:

   ```powershell
   docker compose --env-file ./.env.node.prod -f ./docker-compose.node.prod.yml up --force-recreate ingress-preflight
   docker compose --env-file ./.env.node.prod -f ./docker-compose.node.prod.yml up -d --wait --force-recreate --no-deps ingress
   ```

7. Verify CA, hostname, served SPKI, allowlisted routes, denied admin routes,
   and Reality SNI before restoring traffic.

Do not overwrite files in place while ingress is starting. Switch immutable
secret-store versions (or same-filesystem rename a completely prepared
directory), then recreate ingress.

## Rollback

Stop new traffic first. Restore an immutable prior ingress secret version only
if its SPKI is still an approved current or next pin in the live PMT1. Run the
outer preflight, force-recreate `ingress-preflight`, and then recreate ingress.
Never decrement or overwrite a committed
PMA1/PMT1 generation: publish a new exact successor describing the rollback
pin set. If no currently trusted pin can serve, keep ingress stopped and use
the signed authority/topology recovery ceremony; do not bypass TLS or SPKI.

The local gate uses only ephemeral lab CA/key material under ignored,
protected `.secrets/production-ingress-lab`. It writes PASS evidence only after
teardown proves no project containers, networks, or volumes remain and the
protected secret directory has been deleted. A cleanup failure retains that
directory for controlled recovery and fails the gate. The resulting summary
under `artifacts/test-results` contains no secrets:

```powershell
powershell -ExecutionPolicy Bypass -File ./scripts/production-ingress.integration.test.ps1
```
