# Production Readiness Gate

Every release artifact upload is blocked unless
`node .\deep-devops\scripts\secret-scan.mjs` reports zero findings. Resolved
Compose files and unrestricted raw logs are forbidden evidence; follow
`deep-devops/docs/SECRET_SAFE_EVIDENCE.md`.

`scripts/production-readiness-gate.mjs` is the final program-level gate for the
Deep messenger launch. It is intentionally stricter than the local
release preflight: it should pass only when the launch is ready for GA sign-off.
`scripts/production-readiness-status.mjs` reads the release and P6 summaries and
writes a consolidated blocker report plus an exit checklist for release review.

To generate a fresh report from the current artifacts and rerun the lower-level
gates in one command, use:

```powershell
node .\deep-devops\scripts\production-readiness-status.mjs --run-gates
```

Add `--strict-release` to make the status run execute the raw release artifact
bundle preflight, require attached CI, rollback drill evidence, and staging
provider canary evidence before the final readiness gate is evaluated. Add
`--allow-blocked-exit-zero` only for dashboards or CI jobs that must upload the
blocked report as an artifact without failing the job.
When `--run-gates` is used, any failed gate command is recorded as its own
release-blocking item so stale green summary files cannot mask a broken gate
runner.

For release-candidate sign-off, run the manual GitHub workflow
`production-readiness.yml` with the intended `release_candidate` input. Before
running the gates, the workflow collects the prerequisite attached-CI lanes,
downloads the retained integration/nightly/security/router-C3 artifacts it can
prove from GitHub Actions, hydrates them into `deep-devops/artifacts`,
and writes the attached-CI manifest for the named RC. It then runs:

```powershell
node .\deep-devops\scripts\production-readiness-status.mjs --run-gates --strict-release --release-candidate <rc>
```

and uploads `production-readiness-artifacts`. A successful run proves the status
report was regenerated for that named RC; a blocked status fails the workflow.
That uploaded artifact is retained post-readiness audit evidence. It is not an
input to the strict release evidence gate for the same workflow run, because the
first green production-readiness run cannot require its own future artifact.

Before running strict gates, you can verify that the raw release artifact bundle
is present and tied to the intended release candidate:

```powershell
node .\deep-devops\scripts\session-infra-guard.mjs
node .\deep-devops\scripts\release-artifact-bundle.mjs --release-candidate <rc>
```

This writes `artifacts/release/release-artifact-bundle-summary.json` and checks
the raw runtime/load/restart/provider/multi-node/registry-recovery/security/
observability, Session-infra guard, router C3, attached-CI, and P6 manifest
files that the later gates consume.
`scripts/hydrate-release-artifact-bundle.mjs` can materialize part of that raw
bundle from downloaded Actions artifacts before the preflight runs; missing
artifacts remain release-blocking and are surfaced by the preflight/status
reports.
The hydration step now also materializes raw P6 manifests
`client-device-acceptance.json`, `ops-deployment-evidence.json`,
`security-audit-signoff.json`, and `ga-decision.json` when those files are
present in the downloaded evidence bundle, and it can replace a local
`push-provider-canary.json` with retained staging evidence from that bundle.
By default router C3 evidence is expected at `artifacts/router-c3-latest.json`;
set `XNODE_C3_ARTIFACT` if the retained C3 artifact is mounted
elsewhere.
The same preflight is also executed automatically by
`production-readiness-status.mjs --run-gates --strict-release`, and any failure
is reported as the `release-artifact-bundle` checklist item.

The manual `production-readiness.yml` workflow also accepts optional
`supporting_evidence_run_id` and `supporting_evidence_artifact_name` inputs.
Use them when a retained `deep-devops` artifact bundle already contains
the staging push-provider canary, rollback/observability evidence, and/or the
four P6 manifests, so the runner can hydrate those files before strict
preflight instead of copying them onto the workspace manually.
Those inputs must be provided together. If a supporting bundle is supplied, the
workflow also verifies after hydration that the bundle contributed at least one
recognized release artifact before it proceeds to strict preflight; this catches
wrong run IDs, wrong artifact names, and malformed bundle layouts early.

To generate that retained bundle directly on GitHub Actions, run the manual
`supporting-release-evidence.yml` workflow first. It downloads the retained
xnode C3 artifact for the named RC, runs the backend-external no-mock
full suite with `-RequirePushProviderCanary`, runs `rollback-drill.mjs`, runs
`observability-gate.mjs`, and uploads a retained bundle named
`supporting-release-evidence-<rc>` by default.
Before spending a full supporting evidence run, use the manual
`release-secret-preflight.yml` workflow for the same release candidate, lane,
and push provider service. It runs `scripts/release-secret-preflight.mjs` and
uploads `release-secret-preflight-artifacts` with a non-secret summary of the
required source names that are configured. For release lanes, the preflight
requires `DEEP_CI_REPO_TOKEN`, `DEEP_PUSH_PROVIDER_CANARY_TOKEN`,
a base or service-specific provider URL, and provider auth via an auth header or
bearer token; local/dev/test/smoke lanes are marked as non-release smoke paths.
If the four P6 manifests were produced by another retained `deep-devops`
artifact, first run the manual `p6-release-evidence.yml` workflow with the raw
source `source_run_id` and `source_artifact_name`. That workflow downloads the
raw manifests, hydrates them into `artifacts/release`, verifies that each
manifest matches the selected `release_candidate`, runs the four P6 gates, and
uploads `p6-release-evidence-<rc>` by default with both raw manifests and
verifier summaries. Then pass that P6 workflow run id and artifact name as
`p6_evidence_run_id` and `p6_evidence_artifact_name` to
`supporting-release-evidence.yml`; the supporting workflow hydrates those P6
manifests into its own `artifacts/release` and requires the final bundle to
contain the push canary, rollback drill, observability summary, and all four P6
manifests.
For any release lane other than `local`, `dev`, `test`, or `smoke`, the
workflow requires real staging push provider configuration before it starts the
long e2e run: a base provider URL/auth pair or a provider URL/auth pair for
the selected `push_provider_service`, plus
`DEEP_PUSH_PROVIDER_CANARY_TOKEN`. Without those secrets the workflow
must fail instead of publishing a generated/local canary as staging evidence.

To assemble such a retained bundle from an existing artifact root, run:

```powershell
node .\deep-devops\scripts\bundle-supporting-release-evidence.mjs --source-root <artifact-root> --output-dir <bundle-dir>
```

Add `--require-all` when the bundle must contain the staging
`push-provider-canary.json`, `registry-recovery.json`, `rollback-drill.json`,
`observability-gate-summary.json`, and all four P6 manifests.

Run the lower-level release gate first with all strict flags:

```powershell
node .\deep-devops\scripts\session-infra-guard.mjs
node .\deep-devops\scripts\release-evidence-gate.mjs --require-attached-ci --require-rollback-drill --require-staging-provider-canary
node .\deep-devops\scripts\client-device-acceptance-gate.mjs
node .\deep-devops\scripts\ops-deployment-evidence-gate.mjs
node .\deep-devops\scripts\security-audit-signoff-gate.mjs
node .\deep-devops\scripts\ga-decision-gate.mjs
node .\deep-devops\scripts\production-readiness-gate.mjs
node .\deep-devops\scripts\production-readiness-status.mjs
```

The production gate reads these files under `artifacts/release`:

- `release-evidence-summary.json`
- `session-infra-guard-summary.json`
- `client-device-acceptance.json`
- `client-device-acceptance-summary.json`
- `ops-deployment-evidence.json`
- `ops-deployment-evidence-summary.json`
- `security-audit-signoff.json`
- `security-audit-signoff-summary.json`
- `ga-decision.json`
- `ga-decision-summary.json`
- `production-readiness-checklist.json`
- `release-artifact-bundle-summary.json`

The strict `release-evidence-summary.json` must include `releaseCandidate`.
The client device, ops deployment, security audit, and GA decision manifests
and their verifier summaries must use the same `releaseCandidate`; mixed-RC or
stale summary evidence is rejected.

Production evidence must not use placeholder URLs such as `*.invalid`,
`localhost`, `127.*`, `host.docker.internal`, or `example.com`/`example.org`/
`example.net` hosts. `DEEP_ALLOW_PLACEHOLDER_EVIDENCE=true` exists only
for isolated schema/fixture contract tests and must not be used for release
sign-off.
When an evidence reference uses a local `path` instead of a retained URL or
external artifact ID, the referenced file must exist. Relative paths are
resolved from the release artifact root.
Top-level `generatedAt` timestamps on release and P6 evidence must also be
fresh. The default maximum age is 30 days; set
`DEEP_EVIDENCE_MAX_AGE_DAYS` only for an approved release-review policy,
and use `DEEP_EVIDENCE_NOW` only for deterministic contract fixtures.

`deep-devops/.github/workflows/unit.yml` also runs the
`release-gate-contracts` job. That job validates the gate scripts and example
manifest schemas through `scripts/release-gate-contracts.mjs` in an isolated
artifact root, runs the strict release-evidence gate against fixture artifacts,
then uploads `release-gate-contract-artifacts`. Strict attached-CI prerequisite
evidence must include that lane, but the job is a contract check only; it is not
GA evidence by itself.

## Client Device Acceptance

`client-device-acceptance.json` must prove Android, iOS, and Windows acceptance
against the Deep-owned stack, not build-only or synthetic coverage.
Validate it with `scripts/client-device-acceptance-gate.mjs`; see
`docs/CLIENT_DEVICE_ACCEPTANCE.md` for the full schema and template.

Required scenarios:

- `onboarding-recovery`
- `one-to-one-messaging`
- `offline-retrieval`
- `groups-lifecycle`
- `attachments`
- `avatars-profile-image`
- `push-lifecycle`
- `release-no-stub-no-mock-guards`

Each platform and scenario must have `status`, `result`, or equivalent set to
`passed`, `success`, or `ok`, and must link retained evidence through `url`,
`path`, `id`, `artifacts`, or `evidence`.

## Ops Deployment Evidence

`ops-deployment-evidence.json` must prove staging or production deployment
readiness:

- dashboards deployed with UID or URL;
- alert routes tested with retained evidence;
- post-deploy verification passed with retained evidence.

Validate it with `scripts/ops-deployment-evidence-gate.mjs`; see
`docs/OPS_DEPLOYMENT_EVIDENCE.md` for the full schema and template.

## Security Audit Sign-Off

`security-audit-signoff.json` must prove security approval:

- status approved;
- external audit closed, accepted, or formally not required;
- zero critical findings;
- zero high findings, or an approved high-finding exception.

Validate it with `scripts/security-audit-signoff-gate.mjs`; see
`docs/SECURITY_AUDIT_SIGNOFF.md` for the full schema and template.

## GA Decision

`ga-decision.json` must contain:

- `decision: "go"`;
- meeting minutes evidence;
- release blockers closed or formally accepted;
- approvals from engineering, security, and ops;
- 30/60/90 stabilization owners and objectives;
- post-GA backlog.

Validate it with `scripts/ga-decision-gate.mjs`; see `docs/GA_DECISION.md`
for the full schema and template.

If any of these files are missing or use inconsistent release candidates, the gate writes
`artifacts/release/production-readiness-summary.json` with `status: "failed"`.
The status script additionally writes `artifacts/release/production-readiness-status.json`
with grouped release blockers and next commands, plus
`artifacts/release/production-readiness-checklist.json` with release-exit items,
owner roles, required artifacts, commands, and linked blockers.
