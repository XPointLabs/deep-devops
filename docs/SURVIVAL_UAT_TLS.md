# Survival physical UAT TLS

This lane exposes application traffic only through a dedicated internal CA and
HAProxy. The upstream HTTP listeners remain private to the Compose network.
Port `41824` is the sole cleartext exception and publishes only the CA revocation
list named in the leaf certificate; it is PKI distribution, not application
traffic.

## Create or rotate certificates

```powershell
.\scripts\Initialize-SurvivalUatTls.ps1 `
  -LanHost 192.168.1.43 `
  -SecretRoot C:\Work\DeepSession\secrets\survival-uat-tls
```

Use `-RotateLeaf` to replace the short-lived server certificate. Do not replace
the CA during a run. CA and leaf keys stay below the secret root; only the public
CA certificate is embedded in the physical client build.

## Start the HTTPS lane

```powershell
.\scripts\survival-dev.ps1 -Action Prepare -LanHost 192.168.1.43
$env:SURVIVAL_BIND_HOST = '192.168.1.43'
$env:SURVIVAL_UAT_TLS_SECRET_DIR = 'C:/Work/DeepSession/secrets/survival-uat-tls'
docker compose -p deep-survival-dev `
  -f docker-compose.survival.dev.yml `
  -f docker-compose.survival-uat-tls.dev.yml `
  build membership-fixture
docker compose -p deep-survival-dev `
  -f docker-compose.survival.dev.yml `
  -f docker-compose.survival-uat-tls.dev.yml `
  up -d --remove-orphans
```

Always pass `-LanHost` to `Prepare`; the xnode-1 client authority binds its
coordinator URL to that exact host.

## Trust gates

Android does not require a user-CA tap. A `DeepPhysicalE2E` build contains the
exact public UAT CA as an app-scoped trust anchor and uses
`cleartextTrafficPermitted="false"`. Ordinary Debug and Release builds exclude
that CA.

Windows must approve the root once in `Cert:\CurrentUser\Root`. Import
`ca.crt` using the Windows certificate import UI, verify the displayed SHA-256
against the initializer output, and import
`public\deep-physical-uat-ca.crl` into the Current User Intermediate
Certification Authorities store. Windows intentionally displays a trust
confirmation; tooling must not bypass it.

The CRL publisher must be running before Windows TLS validation. The generator
checks CA constraints, exact IP SAN, validity, key match, and CRL status. The
client uses the platform TLS validator; there is no leaf pin or permissive
certificate callback.

## Runtime gates

```powershell
node scripts/survival-uat-tls-contracts.test.mjs
docker ps --filter label=com.docker.compose.project=deep-survival-dev `
  --format '{{.Names}} {{.Ports}}'
```

Only the ingress may publish `41801-41806`, `41810`, and `41821-41823`.
Storage `41820` must remain internal. Plain HTTP to any application port must
fail during the TLS handshake, and `/health/*` is not a public route.

## HTTPS-preserving retry chaos

The only supported retry/ACK fault lane is `survival-dev.ps1 -Action ChaosBegin` with an
explicit `-ChaosFault`. It starts a private interposer behind this HAProxy and never changes
the public HTTPS origin, certificate validation, route ACL, or port. The interposer has no
published port. Use `ChaosStatus` for exact v2 operation/attempt counters and always call the
idempotent `ChaosEnd`, which restores the ordinary HAProxy backend without restarting an
XNode or deleting state.

The integration runner exercises all supported one-shot faults, including the exact
post-durable ACK response loss followed by a retry in a fresh driver process, and writes an atomic,
ACL-protected, SHA-256 content-addressed v2 evidence envelope. That digest is an integrity
check only; it does not claim a signing authority or production attestation.
The ACK cross-process frame state is a separate private boundary: exact protected Windows
owner/DACL and read-only file semantics, or Unix `0700` directory plus `0600` file, with no
reparse traversal. Atomic writes are durably flushed and hash-reread; retry and replay reject
ACL/mode, type, owner, content, or per-frame digest changes before parsing wire material.
Final state removal is fail-closed: it restores the exact private deletion ACL/mode, clears
Windows read-only state, uses terminating deletion, asserts absence, and withholds passed
evidence on any cleanup failure while still attempting ChaosEnd and the full baseline audit.
