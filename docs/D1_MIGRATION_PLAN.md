# D1 Migration Plan: mock -> compatibility services

## Goal
Replace dev-only mock storage/file/calls/push services with production-profile equivalent product or compatibility services while preserving Session-facing API contracts.

## Scope
- Storage service (`/storage/store`, `/storage/retrieve`)
- File service (`/file`, `/file/{id}`, `/file/{id}/info`, `/avatar/{sessionId}`)
- Calls service (`/api/calls/signal`, `/api/calls/inbox/{recipient}`)
- Push service (`/subscribe`, `/subscriptions/{pubkey}`)

## Migration Steps
1. Baseline contract behavior from existing hardened implementation.
2. Promote implementation into dedicated service runtimes under `tools/*-service`.
3. Switch devops compose wiring to product runtimes for storage/file/calls while preserving push compatibility runtime.
4. Preserve API contract compatibility and behavior semantics:
   - retry/idempotency keys
   - TTL + pruning
   - offline retrieval semantics
   - Session-style subscribe response/error shape
5. Add/keep automated contract tests for retry/idempotency/TTL/offline.
6. Add runtime diagnostics endpoints and health checks in pipeline (`/stats`, runtime gates).
7. Run E2E suite in production-profile stack without mock-path dependencies.
8. Document all deviations from upstream internals.

## Implemented State (2026-05-29)
- Compatibility runtime created: `deep-devops/tools/compat-services/compat-service.mjs`.
- Compose switched from `tools/mock-services` to `tools/compat-services`.
- Contract tests passing: `compat-service.test.mjs` (retry/idempotency/TTL/offline + stats).
- Runtime checks integrated into e2e pipeline and post-suite snapshot gating.
- Upstream deviations documented in `deep-devops/README.md`.
- Production-profile smoke validated in compose stack without mock-path dependencies:
   - `powershell -ExecutionPolicy Bypass -File deep-devops/scripts/test-env.ps1 -Suite smoke` passed
   - `runtime:checks` passed
   - `fixtures:validate` passed
   - `compat` passed
   - `e2e:smoke` passed
   - runtime snapshot failed checks: `0`

## Additional Implemented State (2026-05-30)
- Storage compatibility runtime now supports Session-style `/storage/delete_all` for both default namespace and `namespace: "all"`.
- Storage compatibility runtime now also supports Session-style `/storage/delete` with sorted deleted hashes and `required: true` semantics.
- Storage compatibility runtime now also supports Session-style `/storage/delete_before` with cutoff semantics and future-timestamp guard.
- Storage compatibility runtime now also supports Session-style `/storage/get_expiries` for queried message hashes.
- Storage compatibility runtime now also supports Session-style `/storage/sequence` and `/storage/batch` for ordered or best-effort batched execution across existing storage operations.
- Storage compatibility runtime now also enforces Session-style signature presence for private `/storage/store` namespaces while leaving public-inbox namespaces unauthenticated.
- Storage compatibility runtime now fails closed for every authenticated storage operation: signatures must be cryptographically verified against the exact operation inputs, and standard `05...` pubkeys must include a valid `pubkey_ed25519` companion bound through Ed25519-to-X25519 conversion. Store uses `sig_timestamp` for signature verification when provided; public-inbox stores remain intentionally unauthenticated while retrieve namespace `0` remains authenticated.
- Storage compatibility runtime now also verifies Session-style `subaccount`/`subaccount_sig` authorization across the signed storage lifecycle, enforces upstream read/write/delete/`any_prefix` access flags, and applies the upstream write-only `/storage/expire` rule (`shorten` forbidden without delete access, otherwise implicit extend-only behavior).
- Storage compatibility runtime now also supports Session-style `/storage/revoke_subaccount`, `/storage/unrevoke_subaccount`, and `/storage/revoked_subaccounts`, persists up to the most recent `50` revoked tokens per owner, rejects revoked subaccounts on signed storage endpoints, and preserves the upstream unrevocable retrieve exception for namespaces of the form `-(100n+11)`.
- Storage compatibility runtime now also validates `/storage/store` namespace bounds against the upstream signed int16 range.
- Storage compatibility runtime now also enforces Session-style retrieve auth presence, except for legacy closed-group (`-10`) and public outbox namespaces that remain readable without signatures; signed retrieve requests additionally reject timestamps outside the upstream tolerance window.
- Storage compatibility runtime now also rejects retrieve requests that provide `timestamp` without `signature`, matching the upstream missing-signature request-shape error.
- Storage compatibility runtime now also supports Session-style `/storage/expire_all` with shorten-only semantics and stale-expiry rejection.
- Storage compatibility runtime now also supports Session-style `/storage/expire` with optional `shorten`/`extend`, shared or per-message `expiry` targets, `updated`/`unchanged` response semantics, and upstream-compatible max-TTL clamping.
- File compatibility runtime now enforces upstream-sized upload guards (`0 < size <= 6_000_000`) with Session-style `413` responses.
- File compatibility runtime `POST /file` now returns Session-style `expires` metadata and preserves the original `uploaded` timestamp across duplicate uploads while extending expiry.
- File compatibility runtime now also supports `POST /file/{id}/extend` for existing compat IDs and returns Session-style file metadata on success.
- File compatibility runtime now also supports deprecated `/files` upload/download semantics with numeric legacy IDs, no-dedupe upload behavior, and JSON+base64 retrieval.
- File compatibility runtime now also aligns missing-file responses on `/file/{id}` and `/file/{id}/info` to Session-style `status_code: 404` errors.
- File compatibility runtime now also uses the upstream default expiry window of 3 weeks for new uploads and expiry extensions.
- File compatibility runtime now also uses the upstream salted 33-byte BLAKE2b file-id algorithm (`44`-char base64url output) for `POST /file`.
- File compatibility runtime now also supports upstream-style `X-FS-TTL` overrides for `/file`, deprecated `/files`, and `/file/{id}/extend` when `MAX_FILE_TTL_SECONDS` is configured.
- File compatibility runtime now also provides env-backed compatibility equivalents for deprecated `/session_version` and `/token_info`, including Session-style `404` and `502` outcomes when metadata is invalid or unavailable.
- Push compatibility runtime now also validates optional `subaccount` and `subaccount_sig` fields and preserves them in subscription listing responses.
- Push compatibility runtime now also performs real Session-style `/subscribe` and `/unsubscribe` signature verification for verifiable identities (`03...` and `05...` + `session_ed25519`), including delegated-subaccount read-permission enforcement and Session numeric `ERROR=4` outcomes on bad crypto paths.
- Push compatibility runtime now also forwards storage notifications into the push service via an internal compat hop and records deduplicated delivery artifacts for active subscriptions, making delivery observable in local/CI runs without upstream notifier infrastructure.
- Devops migration harness now also supports `test-env.ps1 -BackendMode external`, so the same smoke/full e2e stack can route storage/file/push traffic through env-supplied external endpoints while preserving the compose-managed router/registry/staking/contracts services.
- Runtime snapshot gating in external mode now also supports separate host-reachable `DEEP_STORAGE_STATS_URL`, `DEEP_FILE_STATS_URL`, and `DEEP_PUSH_STATS_URL` values when the container-visible service URLs differ from the host diagnostics path.
- A first dedicated storage service slice now exists as `tools/storage-service/storage-service.mjs` + `docker/storage-service.Dockerfile` + compose profile `storage-external`; it reuses the validated storage runtime behind a separate service identity and named Docker volume for clean validation runs.
- `test-env.ps1` external mode now correctly starts only router/registry/staking/contracts services; storage/file/push must come from explicitly supplied external endpoints.
- Dedicated `file-service`, `calls-service`, and `push-service` slices now also exist as `tools/file-service/file-service.mjs`, `tools/calls-service/calls-service.mjs`, `tools/push-service/push-service.mjs`, `docker/file-service.Dockerfile`, `docker/calls-service.Dockerfile`, and `docker/push-service.Dockerfile`; compose profile `backend-external` now validates dedicated storage/file/calls/push services behind the external cutover path.
- `storage-service` now also has a standalone runtime module in `tools/storage-service/storage-service-runtime.mjs`, so dedicated storage traffic no longer imports `compat-service.mjs` directly while preserving `storage.json` + `storage-subaccounts.json` persistence, sequence/batch helpers, and the outbound notify hop to `push-service`.
- Dedicated `storage-service` now also has focused standalone runtime tests for persisted message + revoked-subaccount reload across restart.
- `file-service` now also has a standalone runtime module in `tools/file-service/file-service-runtime.mjs`, so dedicated file traffic no longer imports `compat-service.mjs` directly while preserving the same file-state persistence and HTTP contract.
- Dedicated `file-service` now also has focused standalone runtime tests for health/stats, persisted `file.json` reload across restart, legacy `/files` reload, `/file/{id}/extend`, and env-backed `/session_version` + `/token_info` metadata.
- `push-service` now also has a standalone runtime module in `tools/push-service/push-service-runtime.mjs`, so dedicated push traffic no longer imports `compat-service.mjs` directly while preserving the same `push.json` persistence shape, diagnostics, and internal notify contract used by `storage-service`.
- `calls-service` now also has a standalone runtime module in `tools/calls-service/calls-service-runtime.mjs`, so UAT/default call signaling no longer imports `compat-service.mjs` directly while preserving the `/api/calls/signal` and `/api/calls/inbox/{recipient}` contract.
- Dedicated `push-service` now also has focused standalone runtime tests for persisted subscription reload across restart and post-restart notify handling.
- Storage contract coverage now includes private-namespace store auth-presence guards, signed store timestamp-tolerance validation, store `sig_timestamp` validation, real signature verification for verifiable identities across store/retrieve/get_expiries/expire_all/expire/delete/delete_all/delete_before, storage subaccount read/write/delete/`any_prefix` authorization, subaccount revoke/unrevoke/list lifecycle, capped revocation retention, and write-only `/expire` behavior, retrieve auth/noauth exceptions, retrieve request-shape validation, signed retrieve timestamp-tolerance validation, `get_expiries` timestamp-tolerance validation, store namespace-range validation, ordered/best-effort batching, expiry lookup, bulk/targeted scalar+array expiry mutation, selective delete, delete-before, delete-all purge, and stale/future timestamp rejection aligned to upstream `session-storage-server/network-tests/test_batch.py`, `test_deletes.py`, `test_expire.py`, `test_msg_ns.py`, `test_store_retrieve.py`, and `test_subaccount_auth.py`.
- File contract coverage now includes exact salted BLAKE2b file IDs, upstream 3-week expiry defaults, optional `X-FS-TTL` overrides, expiry pruning, empty/oversized upload rejection, upload `expires` metadata, duplicate-upload stability, deprecated `/files` backward-compat behavior, `404`/extend/missing-file semantics, and env-backed `/session_version` + `/token_info` coverage aligned to the compatibility baseline for `session-file-server` lifecycle behavior.
- Push contract coverage now includes real owner/subaccount signature verification for verifiable identities, delegated-subaccount read-permission guards, optional `subaccount`/`subaccount_sig` validation and pass-through listing behavior, storage-triggered delivery queueing, plus subscribe/unsubscribe/idempotency/signature-age coverage.
- Full devops stack validation passed with storage sequence plus delete-all and bulk/targeted expiry mutation flowing through `deep-tests-e2e` full suite:
   - `powershell -ExecutionPolicy Bypass -File deep-devops/scripts/test-env.ps1 -Suite full` passed
   - `runtime:checks` passed
   - `fixtures:validate` passed
   - `compat` passed
   - `e2e:full` passed
   - runtime snapshot failed checks: `0`
- Full devops stack validation now also exercises the storage subaccount revoke lifecycle through `deep-tests-e2e` full suite, including `revoke_subaccount` / `revoked_subaccounts` / `unrevoke_subaccount` and the unrevocable retrieve exception.
- Smoke validation also passed after the file upload guard change:
   - `powershell -ExecutionPolicy Bypass -File deep-devops/scripts/test-env.ps1 -Suite smoke` passed
   - `e2e:smoke` passed
   - runtime snapshot failed checks: `0`
- Smoke and full validation now also exercise live signed push register/unregister/resubscribe paths with generated ed25519 identities.
- Smoke validation now also exercises live storage->push delivery for an active subscription, and full validation remains green with the new delivery hop enabled.
- Smoke validation now also passes in `-BackendMode external` against externally addressed storage/file/push endpoints, while default compat-backed smoke/full validation remains green after the migration-harness change.
- Smoke and full validation now also pass against the dedicated `storage-service` slice in external mode while file/push continue to use external compat endpoints.
- Smoke/full validation now also pass against the dedicated `storage/file/calls/push` service wrappers in `backend-external`, including the storage->push notify hop redirected to `push-service`.
- Smoke/full validation remains green after the `file-service` runtime extraction, so the dedicated backend triad no longer depends on the shared compat runtime for the file slice.
- Smoke/full validation remains green after the `push-service` runtime extraction, so the dedicated backend triad no longer depends on the shared compat runtime for the push slice either.
- Smoke/full validation remains green after the `storage-service` runtime extraction, so the dedicated backend triad no longer depends on the shared compat runtime for the storage slice either.
- Managed `test-env.ps1 -Suite full -BackendMode external -ManagedExternalProfile backend-external` now also performs a host-side `docker compose restart` rehearsal for `storage-service`/`file-service`/`push-service`/`calls-service` and emits `artifacts/test-results/backend-restart-smoke.json` to prove named-volume persistence plus post-restart storage->push delivery and pending call-signal reload.

## Additional Implemented State (2026-06-01)
- File compatibility and dedicated runtimes now expose an explicit avatar lifecycle on `/avatar/{sessionId}` and `/avatar/{sessionId}/info`, backed by the same bounded file storage but with separate `avatar.json` pointer metadata.
- Avatar uploads accept supported image content types (`image/jpeg`, `image/png`, `image/webp`), reject unsupported or empty payloads without state mutation, and return stable metadata (`sessionId`, `fileId`, `contentType`, `size`, `updated`, `expires`) for client/profile publication.
- Dedicated `file-service-runtime.test.mjs` now covers avatar upload/update/fetch/info, restart reload, and invalid avatar payload rejection; the focused dedicated suite is green at `12` tests, and the compatibility suite is green at `79` tests.
- File/avatar state writes are serialized before persisting to disk, closing a stale-`file.json` race found by concurrent `/file/{id}/extend` coverage.
- Managed `test-env.ps1 -Suite full -BackendMode external -ManagedExternalProfile backend-external` now validates avatar upload/update/fetch in full e2e, avatar stats deltas in `backend-load-smoke.json`, and avatar persistence across real compose restart in `backend-restart-smoke.json`.
- Dedicated `push-service` now persists queued delivery artifacts in `push-deliveries.json`, records per-delivery provider status, and can dispatch provider-facing payloads through `PUSH_PROVIDER_{APNS|FIREBASE|HUAWEI}_URL` or `PUSH_PROVIDER_BASE_URL`.
- Dedicated `push-service-runtime.test.mjs` now covers configured provider delivery success, configured provider failure, provider stats/inventory, and provider delivery reload across restart; the focused dedicated push suite is green at `11` tests.
- Push provider release rehearsals now have an executable canary hook: provider proxy auth headers/bearer tokens can be passed through `PUSH_PROVIDER_{APNS|FIREBASE|HUAWEI}_AUTH_HEADER`, `PUSH_PROVIDER_AUTH_HEADER`, or bearer-token variants, and `test-env.ps1 -RequirePushProviderCanary` runs `scripts/push-provider-canary.mjs`, requiring a configured provider delivery artifact at `artifacts/test-results/push-provider-canary.json`.
- Security release rehearsals now have an executable minimum gate: `scripts/security-gate.mjs` emits `secret-scan.json`, `sbom.json`, `dependency-audit.json`, and `security-gate-summary.json`, and devops CI publishes those artifacts from the `security-gate` job.
- Real-Xray router release rehearsals can now set `XNODE_XRAY_SHA256` so `docker/xnode-xray.Dockerfile` verifies the downloaded Xray archive before installing it.
- Managed external full now records push provider inventory in `backend-load-smoke.json` and proves pre-restart push delivery persistence plus post-restart delivery growth in `backend-restart-smoke.json`; `pushDeliveries` survived compose restart (`14 -> 14`) and grew after a new post-restart storage write (`14 -> 15`) in the latest run.

## Deviations vs Upstream
- Equivalent contract implementation, not upstream Oxen service binaries.
- File-based state persistence for deterministic local/CI behavior.
- No dependency on Oxen runtime internals; only HTTP contract parity is guaranteed.

## Exit Criteria
- E2E in production-profile stack runs without mock-path dependencies.
- The shared test harness can validate external storage/file/push endpoints before final production cutover.
- At least one dedicated non-default backend slice (`storage-service`) is reproducibly validated behind that cutover path.
- The entire storage/file/push path is now reproducibly validated behind dedicated standalone runtimes, not just wrappers.
- Dedicated backend load evidence now comes from `deep-tests-e2e/test/e2e/deep.load.test.mjs` and `artifacts/test-results/backend-load-smoke.json`, gated by `test-env.ps1 -Suite full -BackendMode external`.
- The same external cutover path is now reproducible in CI/local orchestration through `test-env.ps1 -ManagedExternalProfile backend-external`, which bootstraps the dedicated backend services and tears them down with profile-aware cleanup.
- The managed external full path now also proves compose-level restart recovery, including avatar pointer persistence and persisted push delivery reload, through `artifacts/test-results/backend-restart-smoke.json`, not just steady-state e2e/load behavior.
- Attachment and avatar backend lifecycle evidence is now present in full/load/restart artifacts; MAUI client remote avatar publication now has shared/client transport wiring, while attached device acceptance evidence remains tracked in P3 rather than this backend migration exit.
- Remaining backend work is now production hardening rather than further runtime extraction, missing provider-facing push dispatch mechanics, missing avatar/backend load evidence, or missing compose restart proof; the provider canary hook exists, but credentialed APNs/FCM/Huawei staging credentials and operator sign-off evidence remain outside this migration slice.
- Contract tests for retry/idempotency/TTL/offline are green.
- Deviations from upstream are documented and reviewable.
