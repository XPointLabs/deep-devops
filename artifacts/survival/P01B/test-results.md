# P01B test results

## Final verification

All verification was executed from
`C:\W\deep-survival\wave01b\deep-devops-sec-hardening` on 2026-07-18.

| Check | Result |
|---|---|
| `node --test scripts/metadata-privacy-gate.test.mjs` | PASS — 11 passed, 0 failed, 0 skipped |
| Strict metadata-safe gate against pinned P01/XNode inputs | PASS — 1 artifact file and 1 metric file, 0 findings |
| Deliberately seeded metadata leaks | EXPECTED FAIL — source IP, request target, Session ID, mailbox capability, push handle and correlation ID were rejected without echoing raw values |
| Metric-label mutations | EXPECTED FAIL — identifier, address and request-path labels were rejected |
| Compose-profile mutations | EXPECTED FAIL — wrong profile, unbounded logging, non-local driver, missing label and verbose framework logging were rejected |
| Xray logging mutations | EXPECTED FAIL — access logging and `info` log level were rejected |
| Break-glass mutations | EXPECTED FAIL — open receipt, unverified deletion, raw export, shared key reference and duration over 60 minutes were rejected |
| `docker compose ... config --format json` through the strict gate | PASS — 7 metadata-safe services rendered and validated |
| Focused secret scan | PASS — 258 selected/tracked/artifact text entries, 0 findings |
| `node scripts/release-gate-contracts.mjs` | PASS — 49 commands |
| Full-gate secret scan | PASS — 236 manifested/selected files |
| Full production readiness gate | PASS — 191 checks |

The full release suite also passed its 9 manifest tests, 21 secret-scan
contract tests, 15 artifact-upload tests, 12 node-identity tests and 14 update
trust tests. Both negative client-device fixtures failed as expected.

## Scope and limitations

- No `docker compose up`, live traffic, network call, deployment, blockchain
  transaction or Git push was performed.
- The compose verification is static configuration validation, not runtime
  evidence.
- Docker local-log size rotation is a bounded-size control, not a wall-clock
  deletion guarantee.
- External provider push-log retention and deletion remain unverified.
  Consequently `productionReady` and `providerDeletionGuaranteed` remain
  `false` for this work package even though repository release gates pass.
- Independent review and live deletion evidence remain required before
  production enablement.
