# Client Device Acceptance Evidence

`scripts/client-device-acceptance-gate.mjs` validates the client evidence that
the final production-readiness gate expects at:

```text
artifacts/release/client-device-acceptance.json
```

Run it before `production-readiness-gate.mjs`:

```powershell
node .\deep-devops\scripts\client-device-acceptance-gate.mjs
```

The first public release manifest must prove Android and Windows acceptance
against the Deep-owned stack. iOS/iPadOS/macOS remain a separate, explicitly
unsupported lane until signing authority and physical evidence are available.
Build-only, synthetic, unit-only, and local-only
evidence types are rejected.

GitHub Actions never controls the physical Android device or the interactive
Windows desktop. Mr. X runs the physical matrix on the local operator
workstation, then retains its sanitized, signed, commit-bound evidence for the
release manifest. "Local-only" above means an unretained assertion without
that evidence; it does not exclude a properly retained local physical run.

Required platforms:

- `android`
- `windows`

Required scenarios:

- `onboarding-recovery`
- `one-to-one-messaging`
- `offline-retrieval`
- `groups-lifecycle`
- `attachments`
- `avatars-profile-image`
- `push-lifecycle`
- `calls-relay-privacy-and-restricted-network`
- `release-no-stub-no-mock-guards`

Each platform and scenario must be `passed`, `success`, `ok`, or `approved`,
must link retained evidence through `url`, `path`, `id`, `artifacts`, or
`evidence`, and must cover both required platforms.

The generated `client-device-acceptance-summary.json` records the manifest
`releaseCandidate`. The final production-readiness gate rejects summaries that
do not match the raw manifest and strict release evidence candidate.
Placeholder evidence URLs such as `*.invalid`, `localhost`, `127.*`, and
`example.*` are rejected outside isolated fixture contract tests.
If retained evidence is linked with a local `path`, that file must exist;
relative paths are resolved from the release artifact root.
The manifest `generatedAt` timestamp must be fresh for release review; the
default maximum age is 30 days.

The manifest must also include release guards:

```json
{
  "releaseGuards": {
    "noStubTransport": true,
    "noSessionEndpoints": true,
    "deepSessionFileUrlRequired": true,
    "deepSessionPushUrlRequired": true
  }
}
```

Use `docs/templates/client-device-acceptance.example.json` as the non-secret
shape reference. Do not copy it into `artifacts/release` as-is.
