# Agent Specification - Deep DevOps

Last updated: 2026-06-10.

## Mission

`deep-devops` owns reproducible orchestration, CI evidence, release gates, local integration stacks, compatibility service runtimes, staging/prod readiness scripts, and operational runbooks for Deep.

This repository is the evidence factory. A feature is not production-ready until this repo can reproduce and archive the relevant proof.

## Source Of Truth

- Workspace entry point: `../prompts/00_Agent_Entry_Point.md`.
- Release readiness docs in `docs/`.
- Session migration rules: `docs/SESSION_PORTING.md`.
- E2E fixtures and tests: `../deep-tests-e2e/AGENTS.md`.
- Service repos: router, registry, staking backend/contracts, protocol, clients.

## Ownership Boundaries

Owned here:

- `docker-compose.yml` service topology and profiles.
- `scripts/*` orchestration, gates, artifact bundling, preflight, rollback, observability, and readiness checks.
- `tools/*` compatibility/dedicated storage, file, and push service runtimes.
- `.github/workflows/*` CI lanes, release evidence, nightly e2e, readiness, and environment-bound gates.
- `docs/*` runbooks, release evidence templates, signoff docs, staging/prod checklists.

Not owned here:

- Product runtime code for router/registry/staking/client unless a local compatibility service is explicitly in `tools/`.
- Protocol semantics, except by invoking protocol tests or fixtures.
- Contract source, except by consuming deployment artifacts and test evidence.

## New Deep Solution Rules

New infrastructure must be reproducible locally and in CI. Every new service or gate must define:

- compose profile and container-visible/host-visible URLs,
- health/readiness endpoint expectations,
- artifact output path,
- strict and non-strict behavior,
- required secrets/variables for staging/prod,
- cleanup behavior for named volumes and generated state.

Compatibility services are allowed only when they implement externally visible Session contracts and are pinned by e2e fixtures. Do not call them mocks in release evidence.

## Staging/Production Gate Rules

- Release workflows must bind to GitHub environments (`staging`, `production`) when secrets or approvals are required.
- Secret preflight must fail closed when provider endpoints/tokens are missing.
- Production readiness must include CI evidence, runtime snapshots, rollback drill, security gate, device acceptance, ops deployment evidence, and GA decision artifacts.
- Wait timers or reviewer protection should be documented even if the current GitHub plan cannot enforce them.

## Session Migration Rules

Use `docs/SESSION_PORTING.md` before adding or changing storage/file/push compatibility behavior. Every migrated Session service contract needs:

- upstream reference,
- fixture or e2e coverage,
- stats/runtime endpoint evidence,
- restart/persistence evidence for production cutover paths,
- known deviation note.

## Required Verification

Fast script checks:

```powershell
node .\scripts\release-gate-contracts.mjs
node .\scripts\production-readiness-status.mjs
```

Runtime/e2e checks depend on Docker:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\test-env.ps1 -Suite smoke
powershell -ExecutionPolicy Bypass -File .\scripts\test-env.ps1 -Suite smoke -BackendMode external -ManagedExternalProfile backend-external
```

Run focused Node tests when editing `tools/*`:

```powershell
node --test .\tools\compat-services\compat-service.test.mjs
node --test .\tools\storage-service\storage-service-runtime.test.mjs
node --test .\tools\file-service\file-service-runtime.test.mjs
node --test .\tools\push-service\push-service-runtime.test.mjs
node --test .\tools\calls-service\calls-service-runtime.test.mjs
```

## Acceptance Gates

A DevOps change is complete only when:

- generated artifacts are deterministic and documented,
- strict gates fail when required evidence is missing,
- compose cleanup does not leak state into later runs,
- environment secret names are documented and preflighted,
- CI workflow changes are reflected in release docs.

## Stop-The-Line Conditions

Stop and fix or record a blocker if:

- staging/prod release can proceed without required evidence,
- a compatibility service lacks fixture coverage for a Session-visible contract,
- a provider canary can pass without proving provider delivery,
- runtime snapshots omit a launch-critical service,
- a script prints secrets or writes them into artifacts.

## Agent Workflow

1. Read this file and `docs/SESSION_PORTING.md`.
2. Identify whether the change affects local dev, CI, staging, production, or all lanes.
3. Add/update scripts and docs together.
4. Run focused gates locally; run full Docker suites when runtime behavior changes.
5. Preserve artifact paths and JSON schemas unless intentionally versioned.
6. Commit DevOps changes separately from service code where possible.
