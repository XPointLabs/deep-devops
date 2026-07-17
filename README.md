# Deep DevOps

Reproducible local and CI integration environment for Deep.

## Agent Specs

- Start with [`AGENTS.md`](AGENTS.md) before changing orchestration, CI gates, release scripts, or compatibility services.
- Use [`docs/SESSION_PORTING.md`](docs/SESSION_PORTING.md) for Session service migration and cutover rules.
- Keep this repo as the reproducible evidence harness for staging/prod readiness.

## One Command

From `main-repo`:

```powershell
.\deep-devops\scripts\test-env.cmd
```

That command builds the router, registry, staking backend, contracts devnet, product storage/file/calls services, the push compatibility service, and then runs `deep-tests-e2e` as the `test-client` container. A failed run writes compose logs and the resolved config to `deep-devops/artifacts`.
It also writes `deep-devops/artifacts/runtime.snapshot.json` with post-suite runtime endpoint snapshots.
It also writes `deep-devops/artifacts/runtime.gate.json` with hard/soft gate evaluation.
In `-Suite full -BackendMode external`, it also requires `deep-devops/artifacts/test-results/backend-load-smoke.json`; missing or empty storage/file/avatar/push load deltas now fail the suite.
In `-Suite full -BackendMode external -ManagedExternalProfile backend-external`, it also requires `deep-devops/artifacts/test-results/backend-restart-smoke.json`; that artifact proves the dedicated backend services survive a real `docker compose restart` with named-volume persistence, avatar pointer reload, persisted push delivery reload, pending call-signal reload, provider-status inventory, and a post-restart storage->push notify hop.
If the e2e suite succeeds but hard-required runtime checks fail, `test-env` exits with a non-zero code.
Soft-required check failures are reported as warnings and recorded in `runtime.gate.json`.

`test-env.ps1` now supports `-BackendMode compat` (default legacy name for the in-compose stack) and `-BackendMode external`. External mode keeps the compose-managed router/registry/staking/contracts stack, but routes storage/file/push/calls traffic through env-supplied endpoints via `DEEP_STORAGE_URL`, `DEEP_FILE_URL`, `DEEP_PUSH_URL`, and optional `DEEP_CALL_SIGNALING_BASE_URL`. When the test-client needs container-visible URLs that differ from the host-visible diagnostics path, point the test-client at container-reachable URLs (for example `http://host.docker.internal:19100`) and set optional host-side `DEEP_STORAGE_STATS_URL`, `DEEP_FILE_STATS_URL`, `DEEP_PUSH_STATS_URL`, and `DEEP_CALL_STATS_URL` for runtime snapshot gating. For the local dedicated backend profile, `-ManagedExternalProfile backend-external` now bootstraps those defaults automatically, starts `storage-service`/`file-service`/`push-service`/`calls-service`, runs a host-side restart rehearsal during external full runs, and tears everything down with the named volumes after the run. Production release rehearsals can add `-RequireRouterNoMock` or set `DEEP_REQUIRE_ROUTER_NO_MOCK=true`; that swaps the router build to `docker/xnode-xray.Dockerfile`, runs the router in `Production` with `/usr/local/bin/xray`, and keeps `router-health-ready.transportMode=mocked` as a hard failure in `runtime.gate.json`. The Xray image defaults to pinned `XNODE_XRAY_VERSION=v26.3.27`; override `XNODE_XRAY_DOWNLOAD_URL` for a preapproved binary mirror or exact asset and set `XNODE_XRAY_SHA256` to verify the downloaded archive during image build. Push-provider release rehearsals can add `-RequirePushProviderCanary` or set `DEEP_REQUIRE_PUSH_PROVIDER_CANARY=true`; that runs `scripts/push-provider-canary.mjs`, requires configured provider delivery, and records `artifacts/test-results/push-provider-canary.json`.

The first dedicated external backend slice is available via the `storage-external` compose profile. It builds `docker/storage-service.Dockerfile`, runs `tools/storage-service/storage-service.mjs` as `deep-storage-service`, and keeps state in a named Docker volume so `docker compose ... down --volumes` resets the service between validation runs.

The full dedicated backend profile is available via the `backend-external` compose profile. It builds `storage-service`, `file-service`, `push-service`, and `calls-service`, each with its own service name and named Docker volume, and lets `test-env.ps1 -BackendMode external` run the same e2e suite against the dedicated endpoints. `test-env.ps1 -BackendMode external -ManagedExternalProfile backend-external` is now the reproducible local/CI path for that cutover rehearsal and handles the profile-aware cleanup automatically.

`storage-service` now uses its own standalone runtime in `tools/storage-service/storage-service-runtime.mjs` for the signed storage lifecycle, sequence/batch helpers, subaccount revoke lifecycle, health, and stats, while still forwarding storage-triggered push notifications through `PUSH_COMPAT_NOTIFY_URL`, and now has focused coverage for restart persistence, TTL pruning, idempotent store behavior, and non-blocking downstream push-notify failure handling. `file-service` uses `tools/file-service/file-service-runtime.mjs` for `/file`, deprecated `/files`, `/file/{id}/extend`, `/avatar/{sessionId}`, `/session_version`, `/token_info`, health, and stats, and now has focused coverage for restart persistence, env-backed metadata success and `502` failure semantics, upload-boundary rejection, malformed legacy upload rejection, TTL pruning across modern and legacy paths, invalid `X-FS-TTL` rejection without state mutation, avatar upload/update/fetch/info with `avatar.json` persistence, serialized file/avatar state writes, and concurrent duplicate upload/extend monotonicity on a shared file id. `calls-service` uses `tools/calls-service/calls-service-runtime.mjs` for `/api/calls/signal`, `/api/calls/inbox/{recipient}`, health, stats, and persisted `calls.json`. `push-service` uses `tools/push-service/push-service-runtime.mjs` for `/subscribe`, `/unsubscribe`, `/subscriptions/{pubkey}`, internal `/_compat/push-notify`, health, stats, provider dispatch, and persisted `push-deliveries.json`, and now has focused coverage for restart persistence, invalid subscribe-shape rejection without state mutation, idempotent resubscribe semantics, batch subscribe/unsubscribe results, TTL pruning, notify queueing, notify delivery dedupe, oversized-body truncation, notify-path pruning of expired subscriptions before any delivery is queued, provider success/failure recording, and persisted delivery reload across restart.

Production replaces the compatibility push runtime with the ASP.NET Core `deep-push-notification-server`, PostgreSQL, Firebase Admin delivery, and authenticated storage-to-push requests. Deployment and diagnostics are documented in `docs/PRODUCTION_PUSH_NOTIFICATIONS.md`.

`test-client` now starts with runtime endpoint checks (`registry /api/nodes/runtime`, `staking /api/events/stats`, and backend `/stats` probes for storage/file/push/calls when configured) before fixture compatibility and e2e suites. In external full mode it also runs a dedicated backend load smoke against storage/file/push, including signed storage idempotent retry, concurrent same-content file duplicate-upload plus same-id extend monotonicity, avatar update/fetch stats deltas, push resubscribe, redundant unsubscribe evidence, and provider-status inventory capture, and emits `backend-load-smoke.json` with stats deltas and timing summaries. When that full run is managed through `-ManagedExternalProfile backend-external`, the harness also performs a host-side restart rehearsal and emits `backend-restart-smoke.json` proving storage/file/avatar/push/calls named-volume persistence, persisted push delivery reload, pending call-signal reload, and post-restart notify behavior. The `multi-node` compose profile and `scripts/multi-node-rehearsal.ps1` run three no-mock router instances, publish their VLESS transport profiles into the registry, seed relay contacts through router RPC, and emit `multi-node-topology.json` with a three-distinct-hop `select_path` proof. CI now exercises these paths: `integration.yml` runs compat smoke, backend-external no-mock smoke, and the multi-node no-mock rehearsal before uploading `integration-artifacts`, while `nightly-full-e2e.yml` runs compat full plus backend-external no-mock full.

## Services

- `router`: real `XNode`; default local runs use mocked Xray for fast devnet feedback, while `-RequireRouterNoMock` uses a real Xray-backed router image for release rehearsal.
- `xnode-1`, `xnode-2`, `xnode-3`: three-router release rehearsal profile used by `scripts/multi-node-rehearsal.ps1`; default rehearsal uses the real Xray-backed router image and records `artifacts/test-results/multi-node-topology.json`.
- `registry`: real `Deep.Registry.Api`.
- `staking-backend`: real `XPoint.Staking.Backend`.
- `contracts-devnet`: Hardhat JSON-RPC devnet from `xpoint-staking-contracts`.
- `storage`: product storage service implementing the Session-compatible store/retrieve contract.
- `file`: product file/avatar service implementing the Session-compatible `/file` contract.
- `push`: compatibility push service (production-profile equivalent implementation of Session `/subscribe` and `/unsubscribe` semantics).
- `calls`: product call signaling service implementing `/api/calls/signal` and `/api/calls/inbox/{recipient}`.
- `test-client`: `deep-tests-e2e` Node test runner.

The storage, file, calls, and push services preserve Session-compatible HTTP contracts while avoiding the full upstream Oxen service-node, PostgreSQL, uwsgi, and native module stacks in local/CI runs. Their HTTP contracts are pinned by fixtures in `deep-tests-e2e` and by source references to `session-storage-server/network-tests`, `session-file-server/doc/api.yaml`, and `session-push-notification-server/DOCUMENTATION.md`.

The standalone runtimes persist state under their configured state directories or Docker named volumes. `COMPAT_STATE_DIR` is still accepted by storage/file/push for backward-compatible tooling, `CALLS_STATE_DIR` configures calls, and legacy `MOCK_STATE_DIR` is still accepted for local tests.

Behavior notes for service contracts:

- Storage service enforces TTL on retrieval and prunes expired rows.
- Storage `/store` supports idempotency via `idempotency_key` (or `idempotencyKey`) in request JSON; repeated calls with the same key for the same `pubkey` + `namespace` return the original hash. Unauthenticated stores are allowed only for public-inbox namespaces (`namespace % 10 == 0`); private namespaces now require a `signature` field, verifiable identities (`03...` pubkeys and `05...` pubkeys paired with `pubkey_ed25519`) are cryptographically checked, signed store requests honor `sig_timestamp` and reject timestamps outside the Session tolerance window with `406 store signature timestamp too far from current time`, out-of-range namespaces are rejected with the upstream-compatible int16 validation error, and Session-style storage `subaccount`/`subaccount_sig` tokens now enforce `write` access for signed subaccount stores (`write|delete` for public outbox namespaces).
- Storage `/retrieve` now requires a `signature` for ordinary namespace reads, while legacy closed-group (`-10`) and public outbox namespaces (`-(20n+1)`) remain readable without authentication. Requests that provide `timestamp` without `signature` are rejected with the upstream-compatible missing-signature `400`, signed retrieve requests now reject timestamps outside the Session tolerance window with `406 retrieve timestamp too far from current time`, verifiable identities return `401 retrieve signature verification failed` on bad signatures, and Session-style subaccount reads now enforce `read` access plus upstream `any_prefix` behavior.
- Signed storage lifecycle endpoints now also perform real verification for verifiable identities: `/get_expiries` returns `401 get_expiries signature verification failed` on bad signatures and `406 get_expiries timestamp too far from current time` outside the Session tolerance window, while `/expire_all`, `/expire`, `/delete`, `/delete_all`, and `/delete_before` now return the corresponding upstream-style signature verification failures for bad signatures. When a signed request uses `subaccount`/`subaccount_sig`, the compat runtime also enforces upstream read/write/delete access flags across these endpoints; write-only subaccounts can call `/expire` only in extend mode, and `shorten: true` is rejected unless the token also has delete access. Revoked subaccounts now also fail signed storage requests unless the read targets an unrevocable namespace of the form `-(100n+11)`.
- Storage `/revoke_subaccount`, `/unrevoke_subaccount`, and `/revoked_subaccounts` now provide the Session-style subaccount revocation lifecycle with owner-signed `±60s` timestamp guards, capped retention of the most recent `50` revoked tokens per owner, and persisted compat state in `storage-subaccounts.json`.
- Storage `/sequence` replays a Session-style ordered `requests` array against the storage contract, returning per-step `{ code, body }` results and stopping on the first failing operation.
- Storage `/batch` uses the same request envelope as `/sequence` but continues executing later operations even when an earlier step fails.
- Storage `/get_expiries` returns a hash -> expiration map for the requested message hashes owned by a pubkey and omits hashes that do not exist.
- Storage `/expire_all` supports Session-style bulk expiry shortening for a pubkey, returns sorted updated hashes under `swarm`, and rejects past expiry targets with `406`.
- Storage `/expire` supports Session-style targeted expiry mutation for selected hashes, accepts either one shared expiry or per-message `expiry` arrays, supports optional `shorten`/`extend` mode flags with `updated`/`unchanged` reporting, and clamps overly long expiries to the upstream 30-day max TTL window.
- Storage `/delete` supports Session-style selective hash deletion, returns sorted deleted hashes, and respects `required: true` by returning `404` when no requested messages were removed.
- Storage `/delete_all` supports Session-style purge for the default namespace or `namespace: "all"`, returns per-swarm deleted hash lists, and rejects timestamps outside the upstream ±60s tolerance window with `406`.
- Storage `/delete_before` supports Session-style cutoff deletion, removes messages with `timestamp <= before`, and rejects cutoffs more than 60 seconds into the future with `401`.
- Dedicated `storage-service` now serves the same storage contract from its own runtime module instead of importing `compat-service.mjs`, while preserving the same `storage.json` + `storage-subaccounts.json` persistence shape and outbound notify hop used by the dedicated backend triad.
- Dedicated `storage-service` now also has focused standalone runtime coverage for persisted message + revoked-subaccount reload across restart.
- Dedicated `storage-service` now also has focused standalone runtime coverage for TTL expiry pruning: expired offline messages disappear from `/storage/retrieve`, are omitted from `/storage/get_expiries`, and are removed from persisted `storage.json` after prune.
- File service prunes expired file records before reads/writes, uses the upstream-compatible default TTL of 3 weeks, generates the same salted 44-char base64url BLAKE2b IDs as upstream `session-file-server` for `POST /file`, accepts upstream-style `X-FS-TTL` overrides on `/file`, deprecated `/files`, `/file/{id}/extend`, and avatar uploads when `MAX_FILE_TTL_SECONDS` is configured, returns Session-style `{ id, expires }` from `POST /file`, preserves the original `uploaded` timestamp across duplicate uploads while only extending expiry, returns Session-style `status_code: 404` for missing `/file/{id}` and `/file/{id}/info` requests, rejects empty or oversized (`> 6_000_000` bytes) uploads with Session-style `413`, supports `POST /file/{id}/extend` for compat IDs, exposes deprecated `/files` upload/download semantics with numeric legacy IDs and JSON+base64 payloads, supports explicit avatar upload/update/fetch/info on `/avatar/{sessionId}` with supported image content-type guards and `avatar.json` persistence, and provides env-backed compatibility equivalents for deprecated `/session_version` and `/token_info`.
- Calls service persists pending signaling envelopes in `calls.json`, accepts string or `{ value }`/`{ Value }` session-id payload shapes, returns `202` from `/api/calls/signal`, and drains matched recipient signals from `/api/calls/inbox/{recipient}`.
- Dedicated `file-service` now serves the same file/avatar contract from its own runtime module instead of importing `compat-service.mjs`, while preserving the same state file shape and external contract.
- Dedicated `file-service` now also has focused standalone runtime coverage for health/stats, persisted `file.json` reload across restart, legacy `/files` state reload, `/file/{id}/extend`, and env-backed `/session_version` + `/token_info` metadata.
- Dedicated `file-service` now also has focused standalone runtime coverage for TTL expiry pruning: expired files return `404` on `/file/{id}` and `/file/{id}/info`, disappear from runtime inventory, and are removed from persisted `file.json` after prune.
- Push compatibility service supports idempotent retries via `idempotency_key`/`idempotencyKey` and prunes expired subscriptions.
- Dedicated `push-service` now also has focused standalone runtime coverage for idempotent resubscribe semantics, TTL expiry pruning, persisted `push.json` cleanup after prune, restart persistence, diagnostics, provider dispatch success/failure, persisted `push-deliveries.json` reload, and post-restart `/_compat/push-notify` delivery.
- Push `/subscribe` follows Session-style success shape (`{ success, added }` for new and `{ success, updated }` for resubscribe, with non-contractual `message`).
- Push `/subscribe` errors follow Session numeric enum shape (`error` code + `message`), including `BAD_INPUT=1`, `SERVICE_NOT_AVAILABLE=2`, and `ERROR=4` for signature-verification failures on verifiable identities.
- Push `/subscribe` accepts either a single object or an array of objects and returns per-item results for batched requests.
- Push `/subscribe` expects Session signature payload fields (`data`, `sig_ts`, `signature`, `enc_key`, `service_info.token`, and `session_ed25519` for `05...` pubkeys).
- Push `/subscribe` now cryptographically verifies signatures for verifiable `03...` and `05...` + `session_ed25519` identities, validates optional Session `subaccount` (36 bytes) and `subaccount_sig` (64 bytes) fields, preserves them in `/subscriptions/{pubkey}` responses, and enforces upstream read-permission requirements on delegated subaccounts.
- Push `/subscribe` validates signature age windows (older than 14 days or too far in future is rejected) and namespace integrity (non-empty, sorted, no duplicates).
- Push `/unsubscribe` removes registrations by `pubkey` + `service` + `service_info.token`, accepts single or batched payloads, returns Session-style `{ success, removed }` responses, and now also cryptographically verifies Session-style `UNSUBSCRIBE` signatures for verifiable identities.
- Push `/unsubscribe` reuses Session numeric error shape and validates a stricter 24-hour signature age window for unregister operations.
- Push delivery now uses an internal compat notify hop from storage to push, records deduplicated delivery artifacts for active subscriptions in `push-deliveries.json`, dispatches to configured provider endpoints via `PUSH_PROVIDER_{APNS|FIREBASE|HUAWEI}_URL` or `PUSH_PROVIDER_BASE_URL`, supports provider proxy auth via `PUSH_PROVIDER_{APNS|FIREBASE|HUAWEI}_AUTH_HEADER`, `PUSH_PROVIDER_AUTH_HEADER`, or bearer-token variants, and exposes delivery/provider status through the existing diagnostic `/subscriptions/{pubkey}` response as `deliveries`.
- `GET /stats` now also reports queued push delivery inventory via `pushDeliveries`, provider inventory via `pushProviderDelivered`/`pushProviderFailed`/`pushProviderNotConfigured`, and counters for internal notify requests/queued deliveries/provider attempts.
- Dedicated `push-service` now serves the same push contract from its own runtime module instead of importing `compat-service.mjs`, while preserving the same `push.json` state contract and internal notify path used by `storage-service`.
- Dedicated `push-service` now also has focused standalone runtime coverage for persisted subscription reload, persisted provider delivery reload across restart, and post-restart notify delivery behavior.
- Compatibility services expose `GET /stats` with per-route counters, in-memory inventory (`storageMessages`, `files`, `avatars`, `subscriptions`), and active state file paths for quick diagnostics.

Documented contract deviations vs upstream implementations:

- Services are equivalent contract implementations, not upstream binaries; persistence backend is file-based state snapshots for deterministic local/CI runs.
- Authentication/crypto internals are not delegated to Oxen runtime components; only externally visible HTTP contract behavior is guaranteed by compatibility tests.

Migration plan and completion checklist: `deep-devops/docs/D1_MIGRATION_PLAN.md`.
Messenger-node production rehearsal runbook: `deep-devops/docs/MESSENGER_NODE_PRODUCTION_RUNBOOK.md`.
Production xnode host runbook: `deep-devops/docs/PRODUCTION_NODE_RUNBOOK.md`.

## Useful Commands

```powershell
.\deep-devops\scripts\up.cmd
.\deep-devops\scripts\down.cmd
powershell -ExecutionPolicy Bypass -File .\deep-devops\scripts\test-env.ps1 -Suite full
powershell -ExecutionPolicy Bypass -File .\deep-devops\scripts\test-env.ps1 -Suite smoke -BackendMode external
docker compose -f .\deep-devops\docker-compose.yml --profile storage-external up --build -d --wait storage-service file push
powershell -ExecutionPolicy Bypass -File .\deep-devops\scripts\test-env.ps1 -Suite full -BackendMode external
docker compose -f .\deep-devops\docker-compose.yml --profile storage-external down --volumes --remove-orphans
$env:DEEP_STORAGE_PUSH_NOTIFY_URL='http://push-service:8080'; $env:DEEP_STORAGE_URL='http://host.docker.internal:19100'; $env:DEEP_FILE_URL='http://host.docker.internal:19101'; $env:DEEP_PUSH_URL='http://host.docker.internal:19102'; $env:DEEP_CALL_SIGNALING_BASE_URL='http://host.docker.internal:19103'; $env:DEEP_STORAGE_STATS_URL='http://127.0.0.1:19100/stats'; $env:DEEP_FILE_STATS_URL='http://127.0.0.1:19101/stats'; $env:DEEP_PUSH_STATS_URL='http://127.0.0.1:19102/stats'; $env:DEEP_CALL_STATS_URL='http://127.0.0.1:19103/stats'; docker compose -f .\deep-devops\docker-compose.yml --profile backend-external up --build -d --wait storage-service file-service push-service calls-service
powershell -ExecutionPolicy Bypass -File .\deep-devops\scripts\test-env.ps1 -Suite full -BackendMode external
docker compose -f .\deep-devops\docker-compose.yml --profile backend-external down --volumes --remove-orphans
powershell -ExecutionPolicy Bypass -File .\deep-devops\scripts\test-env.ps1 -Suite smoke -BackendMode external -ManagedExternalProfile backend-external
powershell -ExecutionPolicy Bypass -File .\deep-devops\scripts\test-env.ps1 -Suite smoke -BackendMode external -ManagedExternalProfile backend-external -RequireRouterNoMock
powershell -ExecutionPolicy Bypass -File .\deep-devops\scripts\test-env.ps1 -Suite full -BackendMode external -ManagedExternalProfile backend-external
powershell -ExecutionPolicy Bypass -File .\deep-devops\scripts\test-env.ps1 -Suite full -BackendMode external -ManagedExternalProfile backend-external -RequireRouterNoMock
powershell -ExecutionPolicy Bypass -File .\deep-devops\scripts\multi-node-rehearsal.ps1
$env:PUSH_PROVIDER_FIREBASE_URL='https://provider-proxy.example.invalid/firebase'; $env:PUSH_PROVIDER_FIREBASE_AUTH_HEADER='Authorization: Bearer <secret>'; powershell -ExecutionPolicy Bypass -File .\deep-devops\scripts\test-env.ps1 -Suite smoke -BackendMode external -ManagedExternalProfile backend-external -RequirePushProviderCanary
node .\deep-devops\scripts\security-gate.mjs
node .\deep-devops\scripts\rollback-drill.mjs
node .\deep-devops\scripts\observability-gate.mjs
node .\deep-devops\scripts\session-infra-guard.mjs
node .\deep-devops\scripts\release-gate-contracts.mjs
node .\deep-devops\scripts\release-evidence-gate.mjs --require-rollback-drill
$env:DEEP_ATTACHED_CI_MANIFEST='C:\path\to\attached-ci-artifacts.json'
node .\deep-devops\scripts\attached-ci-manifest.mjs --input C:\path\to\attached-ci-source.json --release-candidate deep-messenger-rc.1
node .\deep-devops\scripts\release-artifact-bundle.mjs --release-candidate deep-messenger-rc.1
node .\deep-devops\scripts\release-evidence-gate.mjs --require-attached-ci --require-rollback-drill --require-staging-provider-canary
node .\deep-devops\scripts\client-device-acceptance-gate.mjs
node .\deep-devops\scripts\ops-deployment-evidence-gate.mjs
node .\deep-devops\scripts\security-audit-signoff-gate.mjs
node .\deep-devops\scripts\ga-decision-gate.mjs
node .\deep-devops\scripts\production-readiness-gate.mjs
node .\deep-devops\scripts\production-readiness-status.mjs
node .\deep-devops\scripts\production-readiness-status.mjs --run-gates --strict-release --release-candidate deep-messenger-rc.1
node .\deep-devops\scripts\production-readiness-status.mjs --run-gates --strict-release --release-candidate deep-messenger-rc.1 --allow-blocked-exit-zero
powershell -ExecutionPolicy Bypass -File .\deep-devops\scripts\collect-artifacts.ps1
powershell -ExecutionPolicy Bypass -File .\deep-devops\scripts\runtime-snapshot.ps1
node --test .\deep-devops\tools\compat-services\compat-service.test.mjs
node --test .\deep-devops\tools\file-service\file-service-runtime.test.mjs
node --test .\deep-devops\tools\storage-service\storage-service-runtime.test.mjs
node --test .\deep-devops\tools\calls-service\calls-service-runtime.test.mjs
node --test .\deep-devops\tools\push-service\push-service-runtime.test.mjs
```

The artifact collector writes only a redacted Compose topology, a recursively
redacted runtime snapshot, and a zero-finding secret-scan summary. It never
writes resolved Compose configuration or unrestricted container logs. See
`deep-devops/docs/SECRET_SAFE_EVIDENCE.md`.

Local test and rehearsal scripts generate matching ephemeral node identities in
memory and clear the generated process variables during cleanup. For a direct
manual Compose invocation, copy `.env.example` to the ignored `.env` and
replace every placeholder with a fresh local-only value.

Host ports:

- registry: `http://127.0.0.1:18080`
- router: `http://127.0.0.1:18081`
- multi-node routers: `http://127.0.0.1:19281`, `http://127.0.0.1:19282`, `http://127.0.0.1:19283`
- staking backend: `http://127.0.0.1:18082`
- storage product service: `http://127.0.0.1:18100`
- file product service: `http://127.0.0.1:18101`
- push compatibility service: `http://127.0.0.1:18102`
- calls product service: `http://127.0.0.1:18103`
- contracts devnet: `http://127.0.0.1:18545`

## Recovery Runbook (devnet/non-production)

1. Stop stack: `./deep-devops/scripts/down.cmd`.
2. Preserve diagnostics: `powershell -ExecutionPolicy Bypass -File ./deep-devops/scripts/collect-artifacts.ps1`.
3. Reset service state when needed: use `docker compose ... down --volumes` for compose-managed runs, or delete the configured local state directory for direct Node runs.
4. Reset registry/staking snapshots if they became inconsistent:
	- `deep-registry-api/.../artifacts/registry-state.json` (or configured `Registry:StatePath`)
	- `xpoint-staking-backend/.../artifacts/staking-state.json` (or configured `Contracts:StatePath`)
5. Start stack: `./deep-devops/scripts/up.cmd`.
6. Verify health and runtime stats:
	- `GET http://127.0.0.1:18080/health/live`
	- `GET http://127.0.0.1:18080/api/nodes/runtime`
	- `GET http://127.0.0.1:18082/health/live`
	- `GET http://127.0.0.1:18082/api/events/stats`
7. Re-run end-to-end smoke: `powershell -ExecutionPolicy Bypass -File ./deep-devops/scripts/test-env.ps1 -Suite full`.
8. When rehearsing cutover to external storage/file/push/calls services, export `DEEP_STORAGE_URL`, `DEEP_FILE_URL`, `DEEP_PUSH_URL`, optional `DEEP_CALL_SIGNALING_BASE_URL`, and optional `DEEP_*_STATS_URL` before invoking `test-env.ps1 -BackendMode external`, or use `-ManagedExternalProfile backend-external` to bootstrap the local dedicated services automatically.
9. If you still manage the dedicated backend profile manually, prefer `docker compose -f .\deep-devops\docker-compose.yml --profile backend-external down --volumes --remove-orphans` before and after the rehearsal so named-volume state does not leak across runs.
