# Deep DevOps

Reproducible local, UAT and release orchestration for the Deep messenger stack.
This repository owns topology, TLS/PKI, runtime gates, chaos controls and
sanitized release evidence. Product runtime code stays in its service repo.

Deep is pre-production and uses a clean-break model. Historical Session
compatibility labs, stage contracts and migration plans are not supported
release inputs.

## Active environments

- `docker-compose.survival.dev.yml`: persistent loopback development stack.
- `docker-compose.survival-uat-tls.dev.yml`: CA-trusted HTTPS ingress used by
  physical Android/Windows UAT.
- `docker-compose.survival-resend-chaos.dev.yml`: bounded resend/ACK fault
  injection layered on the development stack.
- `docker-compose.uat.yml` and `.env.uat.example`: current UAT deployment.
- `docker-compose.node.prod.yml`: production node topology and operator inputs.
- `docker-compose.client-services.prod.yml`: production client-side service
  dependencies.
- `docker-compose.production-ingress.lab.yml`: isolated production-ingress
  contract rehearsal.
- `docker-compose.staking.prod.local.yml`: production-shaped local staking
  deployment rehearsal.

Use the matching document under `docs/` before running an environment. Never
reuse UAT keys, certificates, volumes or state in production.

## Local development and UAT

Start, verify and stop the persistent development stack through its guarded
launcher:

```powershell
./scripts/survival-dev.ps1 -Action Up
./scripts/survival-dev.ps1 -Action Verify
./scripts/survival-dev.ps1 -Action Down
```

Run the black-box service stack through the lifecycle-owning test harness:

```powershell
./scripts/test-env.ps1 -Suite smoke
./scripts/test-env.ps1 -Suite smoke -BackendMode external `
  -ManagedExternalProfile backend-external -RequireRouterNoMock
```

Physical client UAT is launched from `deep-client-maui/eng`; DevOps supplies
the authenticated HTTPS topology and bounded chaos controls. Do not run raw
fault-injection commands or mutate Docker state outside the owning scripts.

## Release gates

```powershell
node ./scripts/release-gate-contracts.mjs
node ./scripts/production-readiness-status.mjs
```

These checks are evidence contracts, not a production deployment command.
Production publication, deployment and rollout always require separate
authorization.

Key operator references:

- `docs/UAT_DEPLOYMENT.md`
- `docs/SURVIVAL_DEV_STACK.md`
- `docs/SURVIVAL_UAT_TLS.md`
- `docs/PRODUCTION_NODE_RUNBOOK.md`
- `docs/PRODUCTION_NODE_TLS_INGRESS.md`
- `docs/PRODUCTION_CALLS.md`
- `docs/PRODUCTION_PUSH_NOTIFICATIONS.md`
- `docs/PRODUCTION_READINESS_GATE.md`
- `docs/SECRET_SAFE_EVIDENCE.md`

## Secrets and evidence

- Supply secrets through environment bindings or private mounted files only.
- Never commit provider credentials, signing keys, recovery material, tokens or
  production `.env` files.
- Evidence must use the existing bounded, sanitized JSON schemas and scanners.
- Generated artifacts belong under ignored `artifacts/` paths; historical
  stage handoffs are not tracked.
- Cleanup is limited to resources owned by the exact launcher invocation.
