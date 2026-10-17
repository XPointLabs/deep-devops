# Local CLI public-input I/O diagnosis

Strict retained CLI run33 verified bidirectional Store/history/dedup after
exact retries. Fresh-pair run34 then exhausted both Initial Store deadlines;
its original account/contact intent remains retained. No fresh-cycle PASS is
claimed by that failed receipt.

Closed native measurements showed97 and135 lease checks, with authority work
10.5s and14.3s inside the existing25s Store budget. A read-only same-container
comparison of200 reads of the same public record measured700.98ms through the
Windows bind and117.40ms from a disposable Linux copy (ratio5.97). This is an
I/O diagnosis, not a crypto benchmark or evidence of a network deadline fix.
The disposable public copy was removed; protected data was never touched.

The supported publisher now exports public bytes to `public-runtime`; existing
Registry/node verifiers read that volume without any guard bypass. See
[the runbook](DEEP_DEV.md). All private data, key, floor and signer mounts remain.

`artifacts/cli-public-native-20261018/build-01` preserves an intermediate
compile failure. Build02 and probe-build01 passed without compiler diagnostics.
Compose-contracts01 passed30/native0/0skip. After supported publisher-only
Build (deploy20/build native0), native-contracts01 passed8/native0 against that
actual Linux publisher DLL with no network or protected mounts. Those8 cover
exact output, unknown-file exclusion, no rewrite of identical output, ordinary
public-cache rebuild, malformed frame and both link/private-key refusals.

Supported Up completed with native0 in
`artifacts/cli-public-native-20261018/activation-01`. The retained mount receipt
confirms9 services,54→55 mounts: exactly four public-source replacements and
one publisher public-output mount. All50 other mounts are identical; the built
publisher is healthy. A separate read-back compared7 fixed public artifacts
between host output and native output, all byte-identical. No protected state,
account, key or floor was reset and production was not touched.

Measured CLI retry is separate subsequent evidence: run35 resumes the same
run34 pair and original contact intent. This optimization creates no new
service or node and does not replace final source/package, smoke, recovery or
device gates.

The first broad release-contracts01 attempt failed/native1: the secret scanner
correctly rejected a secret-shaped but non-secret canary literal in the native
probe source. The scanner was not weakened or excluded. The probe now appends
a non-secret private-content keyword to a valid public certificate, so removing
the explicit content guard would incorrectly accept the otherwise parseable
certificate. Probe-build02 and native-contracts02 passed again (8/native0).
Release-contracts02 subsequently passed51 commands/native0;01 remains a
failure. Standalone readiness-status01 remains blocked/native1 with10 missing
release/device/ops/security/GA evidence inputs; fixture contract PASS does not
fabricate them. Supported test-env deep-dev-current smoke01 passed/native0,
eventually verifying Registry proof and3 ONION nodes after32s. Two initial
node-2 HTTP-health refusals are retained in its log; uninterrupted readiness
is not claimed. There was no reset or production change.

CLI run35 completed the original fresh pair's contact/text path (24 cold
commands,0 failures, both verified Store/receive/ACK, histories/dedup PASS).
After the separate Node descriptor-key fix and retained deploy21, run36 passed
26 cold commands with0 failures and a new text pair. A separate cold retention
check confirmed both original and new pairs on each client,0 pending. See
[the CLI checkpoint](../../deep-cli/docs/testing/cli-contact-text-2026-10-18.md).
