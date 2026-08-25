# Deep DevOps agent rules

The workspace rules in `../AGENTS.md` apply. This file contains only orchestration deltas.

## Owns

- Docker/UAT/release topology, TLS/PKI, HAProxy, coturn and service wiring.
- CI/release gates, chaos controls, preflight, rollback and sanitized evidence bundles.
- Operational scripts and runbooks for reproducible local, UAT and production paths.
- Dedicated storage/file runtime tooling that is still part of the Deep production design.

Product runtime code belongs in its service repository. Historical compatibility tools and
fixtures are reference/test inputs only and must not enter UAT or release topology.

## Repository rules

- UAT must exercise the production architecture: authenticated HTTPS, real services, durable
  state, bounded retry and fail-closed readiness. No mock can satisfy release evidence.
- Call signaling/ICE routes to `deep-registry-api`; do not restore a standalone legacy calls path.
- HAProxy backends must tolerate container restart through bounded Docker DNS re-resolution.
- Every service defines health/readiness, host/container URLs, secrets, state and cleanup behavior.
- Gates fail when evidence, provider delivery, trust inputs or rollback proof is missing.
- Never place secret values, payloads or private evidence paths in logs or bundles.
- Update the exact operator/UAT runbook when topology, ports, config or recovery changes.

## Verify

```powershell
node ./scripts/release-gate-contracts.mjs
node ./scripts/production-readiness-status.mjs
./scripts/test-env.ps1 -Suite smoke
```

Run focused `node --test` files for changed scripts/tools and the relevant managed-external,
TLS, chaos or production-ingress lane when runtime topology changes.
