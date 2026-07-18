# Session Porting Spec - DevOps And Service Migration

Last updated: 2026-06-10.

## Scope

This document governs migration from upstream Session service infrastructure to Deep reproducible local, CI, staging, and production infrastructure.

It applies to:

- storage service compatibility,
- file/avatar service compatibility,
- call signaling service compatibility,
- push notification compatibility and provider cutover,
- router no-mock production rehearsals,
- registry/staking integration,
- release evidence gates.

## Reference Sources

Local upstream references may include:

- `../source/session-storage-server`
- `../source/session-file-server`
- `../source/session-push-notification-server`
- `../source/session-android`
- `../source/session-ios`
- `../source/session-desktop`

If a source checkout is missing, document the missing source and use checked-in fixtures/e2e tests as the current contract baseline.

## Migration Model

Deep infrastructure has two categories:

- New Deep services: router, registry, staking backend, release gates, readiness scripts, multi-node rehearsal.
- Session-compatible replacement services: storage, file/avatar, calls, and push runtimes that implement externally visible Session/Deep client contracts without requiring the full upstream Oxen/native deployment stack.

Compatibility services must be treated as production-profile contract implementations when they pass fixtures, restart persistence, load smoke, and provider canary gates.

## Porting Workflow

1. Identify the upstream Session HTTP contract or operational behavior.
2. Add or update fixtures in `deep-tests-e2e`.
3. Implement or adjust the compat/dedicated runtime in `tools/*`.
4. Add focused Node tests for route semantics, persistence, and failure behavior.
5. Add compose wiring and runtime stats if needed.
6. Add gate checks and artifact requirements.
7. Update release docs and preflight requirements.

## Required Evidence By Service

Storage:

- per-node service-node storage deployment profile,
- signed store/retrieve/delete/expiry lifecycle,
- fail-closed signature verification for every authenticated operation, including bound `05...`/`pubkey_ed25519` identities,
- namespace access rules,
- subaccount authorization and revocation,
- sequence/batch semantics,
- TTL pruning,
- restart persistence,
- storage-triggered push notification hop.

File/avatar:

- upload/download/info/extend,
- duplicate/idempotent upload semantics,
- avatar upload/update/fetch/info,
- TTL pruning,
- oversized/malformed rejection,
- restart persistence,
- metadata endpoint behavior.

Calls:

- signal enqueue/dequeue via `/api/calls/signal` and `/api/calls/inbox/{recipient}`,
- recipient inbox drain semantics,
- malformed/missing party rejection,
- restart persistence for pending signals,
- runtime stats and health evidence.

Push:

- subscribe/resubscribe/unsubscribe,
- single and batched payloads,
- Session-style signature validation,
- exact `sig_v === 2` dispatch to the LF-terminated, UTF-8 byte-length-prefixed
  `deep.push/{subscribe|unsubscribe}/v2` payload; absent/`1` is legacy compatibility only,
  unknown versions fail closed, and failed v2 verification never falls back to legacy,
- signature-v2 wire fields are validated before canonicalization: timestamps are safe positive
  integer JSON numbers, Session identities are canonical lowercase hex, signed strings retain
  their exact JSON string type, `data` is boolean, and subscribe namespaces are sorted unique
  Int32 JSON numbers (`-2147483648` through `2147483647`),
- the signature-v2 canonicalizer independently rejects coercive, unsorted, duplicate, or
  out-of-domain inputs instead of normalizing them,
- cross-runtime golden vectors in `tools/fixtures/push-signature-v2.golden.json`,
- provider dispatch success/failure recording,
- delivery dedupe and persistence,
- provider canary evidence for staging/prod.

Router:

- no-mock Xray-backed release profile,
- multi-node registration,
- path selection with distinct hops,
- bootstrap document validity,
- readiness semantics.

Registry/staking:

- registry bootstrap/cache recovery drill,
- reconciliation runtime stats,
- staking event replay/idempotency,
- corrupted state quarantine,
- reward/exit/liquidation quorum signing gated by chain-active service nodes and service-node obligation status.

## Session-Parity Authority Model

Upstream Session does not use a trusted central registry as service-node membership authority. Storage servers and client bootstrap flows consume service-node state from the Oxen service-node network/chain, then use node contact information and health/obligation outcomes to decide who can serve traffic or sign network decisions.

Deep follows the same split:

- Arbitrum contracts and the staking indexer are the authority for active service-node membership.
- Service-node obligation status gates reward, exit, and liquidation signatures.
- Router nodes publish signed relay contact manifests with their Ed25519 node id; unsigned or invalid contacts are rejected.
- Registry API is a bootstrap/cache/diagnostic mirror for node metadata, heartbeat, transport status, and signing endpoint URLs. It must not mutate chain state, auto-remediate service nodes, or decide reward quorum membership by itself.
- Push provider delivery remains centralized while Android/iOS depend on FCM/APNs/Huawei gateway infrastructure.

## Staging/Production Secrets

Environment-bound release lanes must preflight at least:

- `DEEP_CI_REPO_TOKEN`,
- push provider URL (`PUSH_PROVIDER_FIREBASE_URL` or `PUSH_PROVIDER_BASE_URL`, plus other provider URLs when enabled),
- push provider auth header or bearer token,
- `DEEP_PUSH_PROVIDER_CANARY_TOKEN`,
- deployment target credentials for the selected infra provider,
- signing/notarization credentials for client artifacts when release packaging is in scope.

Do not store secrets in artifacts. Summaries may include configured/missing booleans only.

## Accepted Deviations

- Local compatibility services use deterministic file-backed state instead of upstream production databases.
- Upstream Oxen/native internals are not required for local CI if externally visible contracts are pinned by fixtures.
- Some provider endpoints may use provider proxies in staging; production must document the final provider and auth path.

## Stop-The-Line Conditions

- Release evidence can be generated without actually running required checks.
- A compatibility endpoint accepts invalid signed payloads that upstream rejects.
- Restart/load evidence is missing for an external backend cutover path.
- Provider canary passes without a configured provider endpoint and auth.
- Artifacts include raw tokens, private keys, recovery phrases, or provider credentials.

## Completion Checklist

For every migrated Session service contract:

- upstream reference recorded,
- fixture or focused test added,
- e2e path passes,
- runtime stats expose enough inventory for gating,
- restart persistence covered,
- release docs updated,
- known deviations documented.
