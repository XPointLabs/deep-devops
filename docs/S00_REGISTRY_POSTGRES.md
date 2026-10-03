# Disposable Registry provider-test lane

This local developer lane runs the complete Registry source-cutover solution
against a fresh PostgreSQL container. It is not UAT, production TLS, deployment,
physical E2E or release qualification. Product contracts remain owned by
Protocol/Registry; [S00](../../docs/architecture/IMPLEMENTATION-PLAN-V1.md#s00--воспроизводимая-исходная-точка)
owns the baseline acceptance requirement.

## Run

Requires PowerShell 7, a **local** Docker engine, .NET 10 and sibling checkouts
of Registry, Protocol, Shared and XNode. From Deep DevOps:

```powershell
./scripts/test-registry-postgres.ps1 -Lane s00
./scripts/test-registry-postgres.ps1 -Lane focused -Filter 'FullyQualifiedName~DeepIdV2RouteThresholdJournalTests'
node --test ./scripts/test-registry-postgres.test.mjs
```

`-RegistryRoot` selects a Registry checkout containing its solution. `-Lane`
is a short lowercase artifact label, not an environment selection. Every run
gets a fresh invocation UUID and a separate ignored `artifacts/s00/<lane>-<id>`
directory in Registry. Both Protocol local/source-cutover flags are set;
the default test project remains complete unless an explicit filter is supplied.
The script returns dotnet's exit code after cleanup. A failed test is not a
successful baseline; inspect the TRX locally without committing machine paths.

## Scope and cleanup

- PostgreSQL uses the same digest-pinned image as the existing Deep DEV compose.
  The script is the single operational owner of the image and arguments.
- No bind mount or named volume: database state lives in container tmpfs.
  One random host port is bound to **127.0.0.1 only**. Ephemeral synthetic tests
  use local `trust`; this is deliberately not evidence of production DB TLS.
- No PKI, production configuration, node identities or secret files are read.
  SSH/TCP Docker contexts and non-local Windows named pipes are rejected.
- Process-scoped `DEEP_TEST_*`, `*ConnectionString*` and `*POSTGRES*` inputs
  are saved in memory and temporarily removed, never logged. Only the floor,
  route and grant test DSNs are populated with the disposable loopback DB;
  opt-in external origins stay disabled. Environment is restored in `finally`.
- Readiness is bounded. Normal success/failure cleanup checks the exact
  container ID and invocation label before stopping it; Docker `--rm` removes
  the container and its tmpfs. An ownership mismatch refuses cleanup.
- If PowerShell or Docker is killed, inspect `deep.test.owner=s00-registry`
  containers and their invocation labels. Remove only a confirmed abandoned
  invocation; never bulk-remove Docker containers/volumes or use production
  state to repair a test run. A rerun always creates a new DB.

Tests create/drop their own GUID schemas; the whole container is discarded
even if a case fails. Raw TRX may contain private machine paths; publish only
sanitized case names/counts/hashes as in the
[Registry checkpoint](../../deep-registry-api/docs/testing/s00-registry-baseline-2026-10-03.md).

## What is proved

The eight executable orchestration guard tests run the real PowerShell script
with process-local Docker/dotnet doubles: remote context/override/UNC rejection,
pinned tmpfs/loopback scope, isolation and restoration of ambient inputs,
test exit propagation, failed readiness/port cleanup and wrong-owner refusal.
They are harness evidence, not actual provider integration. Actual full
Registry runs separately exercise the real disposable PostgreSQL provider.
Linux Unix-socket signer cases require the Registry Dockerfile target
`mailbox-signer-tests`; Windows skips are not converted into passes here.
