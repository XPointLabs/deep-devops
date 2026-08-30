# Messenger Node Production Runbook

This runbook is the release rehearsal path for a Deep-owned messenger node stack. It intentionally excludes VPN, exit-node, DNS overlay, and generic IP routing scope.

## Production Boundary

Launch-critical scope:

- router ingress and client bootstrap through Deep-owned registry metadata;
- storage offline store/retrieve/delete/expiry lifecycle;
- file upload/download/info/extend plus avatar upload/update/fetch;
- push subscribe/resubscribe/unsubscribe and provider delivery canary;
- restart persistence, load smoke, no-mock router validation, security artifacts, and rollback evidence.

Pre-release messenger blocker (reviewed 2026-08-30): no-mock Xray readiness is
currently server-side evidence only. The MAUI mailbox client must be bound to
the VLESS/Reality ingress, and a physical run must succeed while direct HTTPS
managed ingress is blocked. Until then this runbook cannot produce an
anti-blocking messenger GO decision.

Deferred scope:

- VPN/TUN/TAP, exit routing, generic TCP/UDP forwarding, Session/Oxen federation, and non-messenger platform extras.

## Minimal Topology

Production rehearsal requires:

- one registry/control-plane endpoint;
- at least three production-capable router nodes for final multi-node sign-off;
- one storage service, one file service, and one push service with persistent volumes;
- provider proxy endpoints for APNs/FCM/Huawei or the provider selected for the release lane;
- artifact storage for `runtime.gate.json`, `backend-load-smoke.json`, `backend-restart-smoke.json`, `mau2-call-result.json`, `push-provider-canary.json`, `registry-recovery.json`, and security gate outputs.

Local single-node rehearsal is allowed only as a preflight. It is not the production sign-off topology.

## Required Environment

Router release rehearsal:

- `DEEP_REQUIRE_ROUTER_NO_MOCK=true`
- `DEEP_MULTI_NODE_REQUIRE_NO_MOCK=true`
- `XNODE_XRAY_VERSION`
- `XNODE_XRAY_DOWNLOAD_URL` when using an approved mirror
- `XNODE_XRAY_SHA256` for an explicitly supplied archive verification override.
  The local no-mock compose pins the upstream `v26.3.27` Linux x64 asset to
  `23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae`
  and Linux arm64 to
  `4d30283ae614e3057f730f67cd088a42be6fdf91f8639d82cb69e48cde80413c`;
  Dockerfile selection is fail-closed on `TARGETARCH`.

Backend triad:

- `DEEP_BACKEND_MODE=external`
- `DEEP_EXTERNAL_PROFILE=backend-external` for local managed rehearsal
- `DEEP_STORAGE_URL`
- `DEEP_FILE_URL`
- `DEEP_PUSH_URL`
- `DEEP_STORAGE_STATS_URL`
- `DEEP_FILE_STATS_URL`
- `DEEP_PUSH_STATS_URL`

Push provider canary:

- `DEEP_REQUIRE_PUSH_PROVIDER_CANARY=true`
- `DEEP_PUSH_PROVIDER_CANARY_LANE=staging`
- `DEEP_PUSH_PROVIDER_CANARY_SERVICE=firebase|apns|huawei`
- `DEEP_PUSH_PROVIDER_CANARY_TOKEN`
- `PUSH_PROVIDER_FIREBASE_URL`, `PUSH_PROVIDER_APNS_URL`, `PUSH_PROVIDER_HUAWEI_URL`, or `PUSH_PROVIDER_BASE_URL`
- provider auth via `PUSH_PROVIDER_*_AUTH_HEADER` or `PUSH_PROVIDER_*_BEARER_TOKEN`

Secrets must come from the deployment secret store or CI secret context. Do not commit provider credentials, Xray private keys, or TLS material.

## Production Staking Contracts

The Arbitrum One staking deployment is complete and committed in
`xpoint-staking-contracts/docs/ARBITRUM_STAKING_PRODUCTION_DEPLOYMENT.md`.
Use the same values in registry, staking backend, staking portal, and node
host env:

| Setting | Value |
| --- | --- |
| Chain ID | `42161` |
| XPNT token | `0x63B2cdb8B0d8774F1Fdca91D24803698582a079F` |
| ServiceNodeRewards proxy | `0xc52284b7aBAebbEF7BdE0E1ca8251B44AeA12F5f` |
| ServiceNodeContributionFactory proxy | `0x289d88A8C06881634Fb619Ec528361C7b88521f1` |
| RewardRatePool proxy | `0xEd894fb5f0BA3b141A562190D4c9941FEd348356` |
| Staking requirement | `25000000000000` atomic (`25,000 XPNT`) |
| Reward pool deposit | `40,000,000 XPNT` |
| Owner / deployer | `0x62174f6e6a25E7D8135Bd172C1053D7ABd7D2750` |
| ServiceNodeRewards started after deploy | `false` |
| Subscription contracts deployed | `false` |

## Release Rehearsal

1. Run the no-mock external smoke gate:

```powershell
powershell -ExecutionPolicy Bypass -File .\deep-devops\scripts\test-env.ps1 -Suite smoke -BackendMode external -ManagedExternalProfile backend-external -RequireRouterNoMock
```

2. Run the full no-mock external gate:

```powershell
powershell -ExecutionPolicy Bypass -File .\deep-devops\scripts\test-env.ps1 -Suite full -BackendMode external -ManagedExternalProfile backend-external -RequireRouterNoMock
```

3. Run the three-node no-mock topology rehearsal:

```powershell
powershell -ExecutionPolicy Bypass -File .\deep-devops\scripts\multi-node-rehearsal.ps1
```

Startup is isolated under compose project
`deep-multi-node-rehearsal`, reports progress every 15 seconds, and fails with
cleanup after the bounded timeout (`DEEP_MULTI_NODE_COMPOSE_TIMEOUT_SECONDS`,
60-1800; default 900).
Every invocation writes only beneath a unique
`artifacts/rehearsals/multi-node/<UTC-run-id>/` directory. Failure collection
and secret scanning are bound to that directory and never rescan historical
rehearsal artifacts.

4. Run the credentialed provider canary:

```powershell
powershell -ExecutionPolicy Bypass -File .\deep-devops\scripts\test-env.ps1 -Suite smoke -BackendMode external -ManagedExternalProfile backend-external -RequirePushProviderCanary
```

5. Run the security gate from the workspace root or from `deep-devops`:

```powershell
node .\deep-devops\scripts\security-gate.mjs
```

6. Run the rollback drill and preserve its MTTR/post-rollback smoke evidence:

```powershell
node .\deep-devops\scripts\rollback-drill.mjs
```

7. Run the registry recovery drill and preserve snapshot/recovery evidence:

```powershell
node .\deep-devops\scripts\registry-recovery-drill.mjs
```

8. Run the observability/SLO gate:

```powershell
node .\deep-devops\scripts\observability-gate.mjs
```

9. Validate release-gate contracts and example evidence schemas:

```powershell
node .\deep-devops\scripts\release-gate-contracts.mjs
```

This is a CI/schema contract check only. It validates the strict release gate
against fixture artifacts, but it does not replace real attached CI, staging
provider, client device, ops, security, or GA evidence.

10. Run the release evidence gate:

```powershell
node .\deep-devops\scripts\release-evidence-gate.mjs --require-rollback-drill
```

For release sign-off, generate attached CI evidence, verify the raw artifact
bundle, then rerun the evidence gate with rollback proof and staging provider
canary proof required:

```powershell
node .\deep-devops\scripts\attached-ci-manifest.mjs --input C:\path\to\attached-ci-source.json --release-candidate deep-messenger-rc.1
node .\deep-devops\scripts\session-infra-guard.mjs
node .\deep-devops\scripts\release-artifact-bundle.mjs --release-candidate deep-messenger-rc.1
node .\deep-devops\scripts\release-evidence-gate.mjs --require-attached-ci --require-rollback-drill --require-staging-provider-canary
```

Attached CI evidence must be recorded in `artifacts/release/attached-ci-artifacts.json` or the path pointed to by `DEEP_ATTACHED_CI_MANIFEST`. See `docs/ATTACHED_CI_EVIDENCE.md` and `docs/templates/attached-ci-artifacts.example.json` for the required manifest lanes and fields.

11. Run the final program-level production readiness gate:

```powershell
node .\deep-devops\scripts\client-device-acceptance-gate.mjs
node .\deep-devops\scripts\ops-deployment-evidence-gate.mjs
node .\deep-devops\scripts\security-audit-signoff-gate.mjs
node .\deep-devops\scripts\ga-decision-gate.mjs
node .\deep-devops\scripts\production-readiness-gate.mjs
node .\deep-devops\scripts\production-readiness-status.mjs
```

This gate requires strict release evidence plus client device acceptance, ops deployment evidence, security audit sign-off, and GA decision artifacts. See `docs/CLIENT_DEVICE_ACCEPTANCE.md` and `docs/PRODUCTION_READINESS_GATE.md`.
The individual ops, security, and GA evidence schemas are documented in
`docs/OPS_DEPLOYMENT_EVIDENCE.md`, `docs/SECURITY_AUDIT_SIGNOFF.md`, and
`docs/GA_DECISION.md`.
`production-readiness-status.mjs` writes a consolidated
`artifacts/release/production-readiness-status.json` blocker report and
`artifacts/release/production-readiness-checklist.json` exit checklist for
release review.

For a release review that must refresh every verifier before writing the status
report, run the strict status command with the named release candidate:

```powershell
node .\deep-devops\scripts\production-readiness-status.mjs --run-gates --strict-release --release-candidate deep-messenger-rc.1
```

The strict status command also runs `release-artifact-bundle.mjs` before the
lower-level gates. The status report records failed gate commands as release
blockers when `--run-gates` is used, which prevents stale summary files from
being treated as fresh GA evidence.

For CI-backed release sign-off, run the manual `production-readiness.yml`
workflow with the named release candidate. Its `production-readiness-artifacts`
upload is post-readiness audit evidence: retain it after a green run and collect
it with `collect-attached-ci-source.mjs --include-production-readiness` for the
final audit package. It is not a prerequisite lane for the strict release
evidence gate, otherwise the first green production-readiness run would require
itself.
The workflow collects prerequisite attached-CI lanes, downloads the retained
integration/nightly/security/router-C3 artifacts it can prove, and runs
`hydrate-release-artifact-bundle.mjs` before the strict preflight; any missing
staging provider, observability, rollback, or P6 sign-off evidence remains
release-blocking in the generated status report.
If a retained `deep-devops` artifact already contains the staged
`push-provider-canary.json`, `rollback-drill.json`,
`registry-recovery.json`, `observability-gate-summary.json`, and/or the four P6 manifests, pass its
workflow run id and artifact name through the optional
`supporting_evidence_run_id` and `supporting_evidence_artifact_name` workflow
inputs so the runner can hydrate that bundle into `artifacts/release` before
strict preflight. Provide both inputs together. When they are present,
`production-readiness.yml` checks the hydration summary and fails early if the
downloaded supporting bundle did not contribute any recognized release artifact,
which catches wrong run IDs, wrong artifact names, and malformed bundle layouts
before the final status report runs.
Generate that retained bundle directly on GitHub by running the manual
`supporting-release-evidence.yml` workflow. It pulls the retained xnode
C3 artifact for the named RC, runs the backend-external no-mock full suite with
the staging push-provider canary enabled, then runs the rollback drill,
registry recovery drill, and observability gate before uploading
`supporting-release-evidence-<rc>`.
Before running that long supporting evidence job, run the manual
`release-secret-preflight.yml` workflow with the same release candidate, release
lane, and push provider service. It validates that the private checkout token,
push-provider canary token, provider URL, and provider auth sources are present
without writing secret values, then uploads `release-secret-preflight-artifacts`
as a retained non-secret readiness artifact. A failed preflight means the supporting
evidence run would fail before producing staging canary evidence.
When the four P6 manifests are already preserved in another retained
`deep-devops` artifact, first run the manual `p6-release-evidence.yml`
workflow with the raw source artifact's `source_run_id` and
`source_artifact_name`. It hydrates the four raw manifests, verifies that each
one matches the named release candidate, runs the client/ops/security/GA P6
gates, and uploads `p6-release-evidence-<rc>` by default with raw manifests plus
verifier summaries. Pass that P6 workflow run id and artifact name as
`p6_evidence_run_id` and `p6_evidence_artifact_name` to
`supporting-release-evidence.yml`; it hydrates the manifests before bundling and
requires the final supporting bundle to contain all seven supporting artifacts.
Generate that retained bundle from an existing artifact root with:

```powershell
node .\deep-devops\scripts\bundle-supporting-release-evidence.mjs --source-root <artifact-root> --output-dir <bundle-dir>
```

Add `--require-all` when the handoff must fail unless the staging
`push-provider-canary.json`, `registry-recovery.json`, `rollback-drill.json`,
`observability-gate-summary.json`, and all four P6 manifests are present.

12. Preserve artifacts:

```powershell
powershell -ExecutionPolicy Bypass -File .\deep-devops\scripts\collect-artifacts.ps1
```

## Verification Notes

On Windows ARM64, `xpoint-staking-contracts` full `pnpm test` is blocked by the upstream Hardhat EDR package set: Hardhat loads `@nomicfoundation/edr-win32-arm64-msvc`, but the active `@nomicfoundation/edr` release line publishes Windows x64, Linux arm64/x64, and macOS binaries, not Windows ARM64. Treat staking-contract full test evidence as a Linux CI or Windows x64 developer-runtime gate until upstream publishes the Windows ARM64 binary.

## Required Artifacts

Release sign-off requires all of these:

- `artifacts/runtime.gate.json` with `requireRouterNoMock=true`, `routerTransportMocked=false`, and no hard gate failures;
- `artifacts/test-results/backend-load-smoke.json` with non-zero storage/file/avatar/push deltas;
- `artifacts/test-results/backend-restart-smoke.json` proving storage/file/avatar/push persistence across restart;
- `artifacts/test-results/mau2-call-result.json` proving authenticated ringing/accept, a selected ICE pair, bidirectional RTP audio, mute/restore, and remote hangup on the physical Android/Windows pair;
- `artifacts/test-results/push-provider-canary.json` with provider status `delivered`, `hasConfiguredUrl=true`, staging release lane, env-sourced canary token, configured provider auth, and non-local provider host for release sign-off;
- the manual `supporting-release-evidence.yml` workflow must fail on staging lanes when the selected provider service lacks a base or service-specific provider URL/auth pair, or when `DEEP_PUSH_PROVIDER_CANARY_TOKEN` is missing; use `release_lane=local`, `dev`, `test`, or `smoke` only for non-release provider-sink smoke runs;
- the selected run's `artifacts/rehearsals/multi-node/<run-id>/test-results/multi-node-topology.json` with three no-mock routers, registry runtime node count `>= 3`, no reconciliation issues for those nodes, and a `select_path` result with three distinct hops;
- `artifacts/test-results/registry-recovery.json` with status `ok`, proving registry snapshot persistence/reload, corrupted snapshot quarantine, runtime recovery counters, and reconciliation job status;
- `artifacts/test-results/rollback-drill.json` with status `ok`, accepted MTTR, and green post-rollback storage/file/avatar/push smoke;
- `artifacts/security/security-gate-summary.json` with status `ok`;
- `artifacts/observability/observability-gate-summary.json` with status `ok`, zero failed SLO checks, dashboard coverage from `observability/deep-messenger-dashboard.json`, and alert routing coverage from `observability/deep-alert-routes.json`;
- `artifacts/release/release-evidence-summary.json` with status `ok`;
- `artifacts/release/client-device-acceptance.json` and `artifacts/release/client-device-acceptance-summary.json` with Android/Windows device-lab evidence; iOS is unverified/non-blocking and not release-supported;
- `artifacts/release/ops-deployment-evidence.json` and `artifacts/release/ops-deployment-evidence-summary.json` with deployed dashboard, tested alert-route, post-deploy verification, backup, and rollback evidence;
- `artifacts/release/security-audit-signoff.json` and `artifacts/release/security-audit-signoff-summary.json` with external audit closure, zero critical/high findings or approved exception, security-gate evidence, and SBOM attestation;
- `artifacts/release/ga-decision.json` and `artifacts/release/ga-decision-summary.json` with go decision, blocker closure, engineering/security/ops approvals, 30/60/90 stabilization owners, and post-GA backlog;
- `artifacts/release/production-readiness-summary.json` with status `ok` for GA sign-off;
- `artifacts/release/production-readiness-status.json` with status `ok` for GA sign-off review;
- `artifacts/release/production-readiness-checklist.json` with every release-exit item `ready`;
- `artifacts/release/release-artifact-bundle-summary.json` with status `ok`;
- router C3 artifacts from `xnode/artifacts/test-results/c3/latest.json` and `latest.md`; copy `latest.json` into the release bundle as `artifacts/router-c3-latest.json` or set `XNODE_C3_ARTIFACT`;
- attached CI manifest for the no-mock integration, nightly, security, release-gate contract, production-readiness, router C3, and MAUI platform-matrix lanes.

The release candidate string must be consistent across attached CI, client
device acceptance, ops deployment evidence, security audit sign-off, GA decision
artifacts, and the verifier summary files generated from those manifests.
Placeholder evidence URLs are accepted only by the isolated release-gate
contract fixture path; release sign-off manifests must link real retained
evidence, including attached CI artifact links.

## Rollback

1. Stop traffic at the ingress/load balancer.
2. Preserve diagnostics and current state volumes.
3. Roll back router image/config first, then storage/file/push images if the data-plane contract changed.
4. Restart the previous known-good stack.
5. Verify `/health/live`, `/health/ready`, `/stats`, registry runtime metadata, and a smoke send/receive path.
6. Re-run the smoke gate and attach the new `runtime.gate.json`.

Rollback is not complete until the post-rollback smoke artifact is green and the incident record links to the preserved failing artifacts.

## Current Exit Status

The local no-mock router rehearsal, backend triad load/restart evidence, multi-node no-mock topology rehearsal, provider canary hook, security gate script, rollback drill, observability/SLO gate, release evidence gate, client/ops/security/GA evidence gates, release-gate contract CI job, and final production readiness gate exist. The latest local observability gate checked 66 SLO/dashboard/alert-route conditions and wrote `artifacts/observability/observability-gate-summary.json` with status `ok`; the latest local release evidence run with `--require-rollback-drill` checked 68 artifact-level conditions and wrote `artifacts/release/release-evidence-summary.json` with status `ok`. Strict release evidence now also has a `--require-staging-provider-canary` mode that rejects local/generated provider canaries and requires staging lane, env token, configured provider auth, non-local provider host evidence, attached CI proof for the release-gate contract lane, and a named release candidate that must match the P6 manifests. Attached CI prerequisite evidence no longer depends on the future `production-readiness.yml` run; that run is retained as post-readiness audit evidence after it turns green. The latest production readiness gate writes `artifacts/release/production-readiness-summary.json` with status `failed` until strict attached CI and staging provider evidence are present, all four P6 evidence manifests are attached for the same release candidate, and `client-device-acceptance-summary.json`, `ops-deployment-evidence-summary.json`, `security-audit-signoff-summary.json`, and `ga-decision-summary.json` are green for the default release artifact paths. The latest local rollback drill wrote `artifacts/test-results/rollback-drill.json` with status `ok`, MTTR `79.098` seconds, and green post-rollback storage/file/avatar/push smoke. The latest local multi-node rehearsal generated `artifacts/test-results/multi-node-topology.json` with three Xray-backed routers, registry node count `3`, no reconciliation issues, and a three-distinct-hop `select_path` proof. Production-ready messenger-node exit still requires attached green CI/release artifacts, credentialed APNs/FCM/Huawei canary evidence from the selected staging provider lane, deployed dashboards/alert routes, and the program-level client/platform/security/release sign-offs tracked in the root delivery docs.
