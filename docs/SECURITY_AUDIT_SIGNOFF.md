# Security Audit Sign-Off Evidence

`scripts/security-audit-signoff-gate.mjs` validates the security sign-off
manifest that the final production-readiness gate expects at:

```text
artifacts/release/security-audit-signoff.json
```

Run it before `production-readiness-gate.mjs`:

```powershell
node .\deep-devops\scripts\security-audit-signoff-gate.mjs
```

The manifest must prove that the release candidate has security approval and
that unresolved launch-critical findings are not being hidden behind local
preflight output.

Required top-level fields:

- `status`: `approved`, `passed`, `success`, or `ok`
- `generatedAt`
- `releaseCandidate`
- `approver.name` or `approver.id`

Required audit evidence:

- `externalAudit.status`: `closed`, `accepted`, or `not_required`
- retained external-audit evidence through `url`, `path`, `id`, `artifacts`, or `evidence`

Required finding state:

- `openFindings.critical: 0`
- `openFindings.high: 0`, or `highFindingException.approved: true`
- if high findings remain, the exception must include `owner` and `reviewDate`

Required release security artifacts:

- `securityGate.status`: `approved`, `passed`, `success`, or `ok`
- retained security-gate artifact reference
- `sbom.attested: true`
- retained SBOM artifact reference

The generated `security-audit-signoff-summary.json` records the manifest
`releaseCandidate`. The final production-readiness gate rejects summaries that
do not match the raw manifest and strict release evidence candidate.
Placeholder evidence URLs such as `*.invalid`, `localhost`, `127.*`, and
`example.*` are rejected outside isolated fixture contract tests.
If retained evidence is linked with a local `path`, that file must exist;
relative paths are resolved from the release artifact root.
The manifest `generatedAt` timestamp must be fresh for release review; the
default maximum age is 30 days.

Use `docs/templates/security-audit-signoff.example.json` as the non-secret
shape reference. Do not copy it into `artifacts/release` as-is.
