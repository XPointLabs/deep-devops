# GA Decision Evidence

`scripts/ga-decision-gate.mjs` validates the GA decision manifest that the
final production-readiness gate expects at:

```text
artifacts/release/ga-decision.json
```

Run it before `production-readiness-gate.mjs`:

```powershell
node .\deep-devops\scripts\ga-decision-gate.mjs
```

The manifest must prove that the release has a reproducible go decision from
engineering, security, and ops. It is the program-level evidence for prompt 09
stabilization and GA closure.

Required decision fields:

- `decision: "go"`
- `generatedAt`
- `releaseCandidate`
- retained `meetingMinutes` evidence through `url`, `path`, `id`, `artifacts`, or `evidence`

Required blocker state:

- `releaseBlockers` must be present
- every blocker must have status `closed` or `accepted`

Required approvals:

- one approval each for `engineering`, `security`, and `ops`
- each approval status must be `approved`, `passed`, `success`, or `ok`
- each approval must include `approvedAt` or retained evidence

Required stabilization plan:

- `stabilizationPlan.day30.owner` and `objective`
- `stabilizationPlan.day60.owner` and `objective`
- `stabilizationPlan.day90.owner` and `objective`

Required post-GA backlog:

- `postGaBacklog` must be non-empty
- at least one backlog item must explicitly keep VPN/deferred non-messenger
  scope outside the launch-critical messenger release

The generated `ga-decision-summary.json` records the manifest
`releaseCandidate`. The final production-readiness gate rejects summaries that
do not match the raw manifest and strict release evidence candidate.
Placeholder evidence URLs such as `*.invalid`, `localhost`, `127.*`, and
`example.*` are rejected outside isolated fixture contract tests.
If retained evidence is linked with a local `path`, that file must exist;
relative paths are resolved from the release artifact root.
The manifest `generatedAt` timestamp must be fresh for release review; the
default maximum age is 30 days.

Use `docs/templates/ga-decision.example.json` as the non-secret shape reference.
Do not copy it into `artifacts/release` as-is.
