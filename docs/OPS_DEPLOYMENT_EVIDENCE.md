# Ops Deployment Evidence

`scripts/ops-deployment-evidence-gate.mjs` validates the deployment evidence
that the final production-readiness gate expects at:

```text
artifacts/release/ops-deployment-evidence.json
```

Run it before `production-readiness-gate.mjs`:

```powershell
node .\deep-devops\scripts\ops-deployment-evidence-gate.mjs
```

The manifest must prove that the selected release candidate has been deployed
to staging or production with operational controls attached. Local-only
rehearsal artifacts are not enough for this gate.

Required top-level fields:

- `status`: `passed`, `success`, `ok`, or `approved`
- `generatedAt`
- `releaseCandidate`
- `environment`: `staging` or `production`
- `deployment`: artifact reference through `url`, `path`, `id`, `artifacts`, or `evidence`

Required dashboard evidence:

- `dashboards.deployed: true`
- dashboard `uid` or `url`
- at least one dashboard panel, preferably `Deep Messenger Release Health`
- retained dashboard deployment evidence

Required alert evidence:

- `alerts.routesTested: true`
- tested routes include `critical-release-pager` and `warning-release-watch`
- retained alert test evidence

Required post-deploy evidence:

- `postDeployVerification.status`: `passed`, `success`, `ok`, or `approved`
- `postDeployVerification.runtimeHealth.status: "ok"` or `passed: true`
- retained post-deploy and release-gate evidence

Required recovery evidence:

- `recovery.backupLocation`
- rollback drill evidence linked through `recovery.rollbackDrill`

The generated `ops-deployment-evidence-summary.json` records the manifest
`releaseCandidate`. The final production-readiness gate rejects summaries that
do not match the raw manifest and strict release evidence candidate.
Placeholder evidence URLs such as `*.invalid`, `localhost`, `127.*`, and
`example.*` are rejected outside isolated fixture contract tests.
If retained evidence is linked with a local `path`, that file must exist;
relative paths are resolved from the release artifact root.
The manifest `generatedAt` timestamp must be fresh for release review; the
default maximum age is 30 days.

Use `docs/templates/ops-deployment-evidence.example.json` as the non-secret
shape reference. Do not copy it into `artifacts/release` as-is.
