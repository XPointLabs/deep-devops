# Attached CI Evidence Manifest

`scripts/release-evidence-gate.mjs --require-attached-ci` reads
`artifacts/release/attached-ci-artifacts.json` by default. Override the path
with `DEEP_ATTACHED_CI_MANIFEST`.

The manifest is intentionally small: it records the green workflow run and the
artifact handle for every release-blocking lane that cannot be proven from local
files alone. Use `docs/templates/attached-ci-artifacts.example.json` as the
non-secret shape reference.

To collect the source file directly from GitHub Actions for the required lanes,
set `DEEP_GITHUB_TOKEN`, `GH_TOKEN`, or `GITHUB_TOKEN` to a token that can
read the private release repos, then run:

```powershell
node .\deep-devops\scripts\collect-attached-ci-source.mjs --owner XPointLabs --branch master --release-candidate deep-messenger-rc.1
```

By default this writes `artifacts/release/attached-ci-source.json` and
`artifacts/release/attached-ci-source-summary.json`. The collector records the
latest completed run with the required artifact for each release-prerequisite
lane; the downstream manifest generator remains the release-blocking success
check. Passing `--require-success` makes collection itself fail when a lane has
no green run. After the final `production-readiness.yml` workflow has produced a
green retained artifact, pass `--include-production-readiness` to collect that
post-readiness audit lane as well.

In GitHub Actions, `collect-attached-ci-source.mjs` also writes sanitized
`<lane>_run_id` outputs such as `devops_integration_run_id` and
`node_router_c3_run_id`, allowing `production-readiness.yml` to download and
hydrate retained prerequisite artifacts without hand-copying run IDs.

To normalize a collected CI source file into the canonical manifest, run:

```powershell
node .\deep-devops\scripts\attached-ci-manifest.mjs --input C:\path\to\attached-ci-source.json --release-candidate deep-messenger-rc.1
```

By default this writes `artifacts/release/attached-ci-artifacts.json` and
`artifacts/release/attached-ci-manifest-summary.json`. The source file may use
either the canonical `runs` array shown below or a `lanes` object keyed by lane
name; the generator orders and validates every required lane before writing the
canonical output.

```json
{
  "generatedAt": "2026-06-02T00:00:00.000Z",
  "releaseCandidate": "deep-messenger-rc.1",
  "runs": [
    {
      "name": "devops-integration",
      "repository": "XPointLabs/deep-devops",
      "workflow": "integration.yml",
      "runId": 123456789,
      "runAttempt": 1,
      "headSha": "0123456789abcdef0123456789abcdef01234567",
      "conclusion": "success",
      "htmlUrl": "https://github.com/XPointLabs/deep-devops/actions/runs/123456789",
      "artifacts": [
        {
          "name": "integration-artifacts",
          "id": 987654321,
          "url": "https://github.com/XPointLabs/deep-devops/actions/runs/123456789/artifacts/987654321"
        }
      ]
    }
  ]
}
```

Required lanes:

- `devops-integration`: `deep-devops`, `integration.yml`, artifact `integration-artifacts`
- `devops-nightly-full-e2e`: `deep-devops`, `nightly-full-e2e.yml`, artifact `nightly-e2e-artifacts`
- `devops-security-gate`: `deep-devops`, `unit.yml`, artifact `security-gate-artifacts`
- `devops-release-gate-contracts`: `deep-devops`, `unit.yml`, artifact `release-gate-contract-artifacts`
- `devops-release-secret-preflight`: `deep-devops`, `release-secret-preflight.yml`, artifact `release-secret-preflight-artifacts`
- `xnode-c3`: `xnode`, `ci.yml`, artifact `c3-test-results`
- `client-maui-platform-matrix`: `deep-client-maui`, `ci.yml`, artifact `deep-client-maui-platform-matrix`

For release sign-off, all listed runs must be from the intended release
candidate commits, have `conclusion: "success"`, include a full 40-character
`headSha`, include `runAttempt`, and link to retained artifacts. The manifest
must also include `releaseCandidate` so the final gate can tie the CI runs to a
named release candidate instead of a loose collection of green jobs.
Placeholder artifact URLs such as `*.invalid`, `localhost`, `127.*`,
`host.docker.internal`, and `example.*` are rejected outside isolated contract
fixtures.
If a run or artifact is linked with a local `path`, that file must exist;
relative paths are resolved from the release artifact root.
The manifest `generatedAt` timestamp must be fresh for release review; the
default maximum age is 30 days.

The `devops-production-readiness` lane is intentionally not a prerequisite for
`release-evidence-gate.mjs`; that workflow is the final verifier that consumes
the strict release and P6 evidence. Its `production-readiness-artifacts` upload
should be retained after a green run and can be collected with
`collect-attached-ci-source.mjs --include-production-readiness` for the final
post-run audit package.
