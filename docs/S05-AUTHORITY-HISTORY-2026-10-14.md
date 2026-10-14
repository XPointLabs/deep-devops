# S05: exact paired authority history in operator bundles

Owner: Mr. X. Status: focused operator source check passed; S05 remains open.
Execution and acceptance belong to the
[single S05 plan](../../docs/architecture/IMPLEMENTATION-PLAN-V1.md#s05--current-issuer-и-автоматический-lifecycle-управляющего-контура).
Operational behavior belongs to [the custody guide](PRODUCTION_AUTHORITY_CUSTODY.md).
No wire, identity, key, suite, signed lifetime or protected floor was changed.

## Source change

The existing successor CLI now verifies its complete paired XNA1/DTS1 source
from the genesis pin and gives terminal authority to the existing DR-0108
producer. It preserves that entire exact pair history in the successor output.
Public NCP2 extension authenticates the candidate pair history and requires
every retained authority/time-policy byte as an exact prefix. Genesis export
still requires exactly one generation-zero pair. Neither mode creates or signs
an authority renewal or treats an inventory as current authority.

Source aggregate input now defaults to the NCP2 byte ceiling; independently
supplied ADH1 is bounded by the canonical record limit. Successor output is
written as one complete public sibling staging directory, then renamed to a
previously absent output. Existing output is never replaced. On Windows, only
access/sharing/lock IO errors5/32/33 can retry that exact move, at most five
delays totaling1550ms, while staging exists and output does not. Persistent
failure still rejects and retains public staging for review. This does not
change OS security settings or fix XNode's separate native MoveFileEx issue.
Power-loss durability and injected mid-write/rename faults are not proved here.

## Matching evidence

The existing operator regression executable compiled in Release with warnings
as errors: native0, **zero warnings/errors**. Its six top-level groups and the
nested paired-history scenario completed, native0. It produces no TRX and is
not a canonical unfiltered repository gate.

Real owned root/witness/node signers author two same-key XNA1/DTS1 renewals,
two offline operational successors and subsequent delegated appends. The actual
writer and public export produce69 retained views/heads under three exact
authority/time-policy pairs, crossing64 without truncation, genesis reset or
replacement identities. Every original byte in all seven history chains is
compared with the next output; latest XND1 bytes match the author's three
descriptors. Delegated steps activate previously announced traffic keys and
author new announcements. SPKI hashes are synthetic signed fixture values,
not an actual TLS deployment or installed private-key rotation.

Hash-correct hostile inventories with missing middle, bad DTS signature,
unpaired history, truncated prefix or a separately valid signed fork reject
without an output. Existing-output rejection preserves its manifest; normal
publication leaves no staging directory. Aggregate overflow rejects before
opening advertised files. Existing argument/source/certificate/public-transport
audit and genesis/successor regressions still execute.

Final run in DevOps: `artifacts/s05-authority-history-20261014/08/`.
Build interval:2026-10-14T04:15:04.4765432Z–2026-10-14T04:15:09.9909462Z.
Executable interval:2026-10-14T04:15:10.1555051Z–2026-10-14T04:15:20.9494772Z.
`operator-tests.log` SHA256:
`428A13FE515FD6D510DE872651FE1DAABE4BD8A88393A4901AF62B3D3CA71964`.
The common TestGate native runner retained build/run exits and logs using
Windows PowerShell5.1 and SDK10.0.301. Empty final stderr is retained.

Run01 failed compilation when a test tried a private codec; exact descriptor
comparison replaced that call, without a widened API. Run02 correctly rejected
a fixture interval beyond the root policy; the positive case stays inside its
unchanged bounds. Run07 stopped on Windows directory-rename denial. Those
failed runs remain separate, not relabelled or converted into evidence.

## Remaining stage boundaries

The historical run08 does not exercise the complete file-custody successor CLI entry point,
author changed-root/witness renewal or add its supported ceremony command,
provide nonce-fresh DID2 authority, install native client/node catch-up beyond64,
or prove production ingress, independent role rotation or retained-volume recovery.
The operational command consumes prepared signed authority pairs. The routine
same-key preparation command is now implemented and checked below; changed-root/
witness authoring, full provisioning and the remaining S05 matrix still need closure.
No production state, private custody or device account was opened. S06 is not
opened; physical contacts/messages/files/groups remain0/4.

## Routine offline command continuation

`--renew-authority-from` now invokes the accepted same-key API with independent
network/genesis and accepted authority/DTS predecessor pins, explicit offline
time/expiry and the existing single-root file custody. It retains all source
records and publishes only a separately marked prepared inventory, which direct
NCP2 export rejects until operational completion. Custody manifest reads are
bounded; generated temporary private-key copies and failed constructor copies
are cleared. The operator guide owns all command/configuration consequences.

The matching final run10 built the complete operator graph with warnings as
errors, native0/zero warnings/errors, then ran the regression executable,
native0. Six top-level groups plus both nested offline-command/paired-history
scenarios completed; this is not a TRX count or canonical full gate.
The real CLI executable created the first prepared renewal. The same command
method then appended a second pair. Wrong accepted hashes reject even after the
owned synthetic root file is moved aside; the actual CLI emits category-only
stderr and exit1, without the private directory/seed path. Invalid overlapping
lifetimes and output reuse reject; original public inventory and root bytes
remain equal. Prepared-only export rejection and the full69-view case still run.
These are owned synthetic file/custody tests, not production secret access.

Run: `artifacts/s05-authority-history-20261014/10/`.
Build:2026-10-14T04:34:38.4976768Z–2026-10-14T04:34:43.4709918Z;
executable:2026-10-14T04:34:43.6209880Z–2026-10-14T04:34:54.9314045Z.
`operator-tests.log` SHA256:
`B4EB12FD657B274BD0B28F69E0BE5B1752A7056ADAF4783BC53BEEEE5D628810`.
The common native runner retains the two exits/logs; no production, physical,
Release/main or S05 full acceptance follows. Complete operational file-custody
provisioning, independent key rotation/CAS and issuer/node/client recovery remain.

## Operational file-custody continuation

Current run16 completes the actual `--successor-from` CLI entry point from an
already prepared authority. It uses the fixture's three retained Ed25519 node
identities, real owned current/next X25519 seed files and matching ECDSA PEM
certificate/private-key files, then the existing public NCP2 exporter. The
completed bundle retains two exact authority pairs and original view/head prefix
with three active node descriptors. The source/identity/traffic/TLS files remain
byte-equal; no machine deployment or OS trust import occurs.

The actual CLI had retained an obsolete Contact/XPK bootstrap-leaf derivation,
while the DID2 genesis command uses the actual DID2 directory-leaf codec. That
product path is removed. Successor arguments now require the exact public DID2;
the codec-derived leaf must match source metadata before private custody opens.
No compatibility hash or optional old path remains. New origin checks require
certificate SAN matches for each configured IP/DNS without wildcard/CN fallback.
Wrong credential and configured origin reject without an output; the real CLI's
failure is exit1 with category-only stderr, not a private pathname.

The first test compilation run11 lacked an Identity namespace import; run12–14
exposed a new public-only PEM reload that incorrectly demanded a private key in
the certificate file. Origin matching now shares the existing matched
certificate/key loader; no crypto/hostname check was removed. Those failures
remain separate. Final run16 compiles with warnings as errors, native0,
zero warnings/errors; the executable ends native0 with all six top-level groups
and three nested command/history scopes, including the genuine69-view case.
It produces no TRX and does not qualify a canonical full stage.

Run: `artifacts/s05-authority-history-20261014/16/`.
Build:2026-10-14T04:58:14.9170550Z–2026-10-14T04:58:21.4592805Z;
executable:2026-10-14T04:58:21.9119806Z–2026-10-14T04:58:36.8420456Z.
`operator-tests.log` SHA256:
`101A9D56F063EC813E1C26F2241CE88ECE0B9AD1FD17DE66E89E4BD944FCE17C`.
The common native runner retains exits/logs and final stderr is empty. This
proves offline artifact authoring/completion, not fresh DTT1, live Registry/node/
client authority or network transport. Source fixture clocks and own local
certificates are not production time/TLS or physical Windows/Android evidence.
Changed-root/witness/role rotation, CAS, runtime renewal/catch-up, retained-volume
restart and the rest of S05 remain open; no S06 or physical result is claimed.

## Registry diagnostic-provider isolation

The disposable PostgreSQL wrapper delegates full qualification unchanged.
Its new `-NativePhaseTrace` switch explicitly enables Registry's optional
whole-process phase listener only in a filtered diagnostic; full rejects it
before provider creation. Ambient test flags, external DB inputs and the phase
flag are cleared/restored, so a saved shell setting cannot enable profiling in
full. No authority, endpoint, assertion or timeout is changed.
`node --test ./scripts/test-registry-postgres.test.mjs` passed14/0, native0,
including opt-in selection, full rejection, native exits0/7, reference/skip arrays,
owned cleanup and environment restoration. This is real-script orchestration
with command doubles, not Docker/TLS/runtime or S05 stage qualification.

## Infrastructure rehearsal attempt

The actual PowerShell7 managed-external smoke ran with `-Suite smoke`,
`-BackendMode external`, `-ManagedExternalProfile backend-external` and
`-RequireRouterNoMock`. Its isolated compose project was `deep-integration`;
the existing `deep-dev` project and production were not targeted. Three real
backend services became healthy, but the Linux engine disappeared during the
current ARM64 Registry/XNode image build. BuildKit returned EOF and the Docker
engine pipe was absent. The native smoke terminal is **exit1**, not PASS.

Run: `artifacts/rehearsals/smoke/s05-current-native-20261014-01/`.
The runtime snapshot captured at2026-10-14T09:53:46.0750632Z has nine failed
request checks; SHA256:
`FC33DB8CEC30D34D4FF4B1FAF9363CF2C98DA9CCE7FE80869CEBAED9C4818AAE`.
Redacted topology collection and both project cleanup calls also failed because
the engine was unavailable. No `runtime.gate.json` or successful suite receipt
exists. Cleanup must be rechecked against that exact project after engine
recovery; never reset Docker/WSL or unrelated volumes. After the user restarted
the engine, label-filtered inspection found only the three exited backend
containers in that project. Its scoped compose cleanup completed exit0, removing
those three containers and their three disposable state volumes/network. The
existing `deep-dev` project was not targeted. A new smoke run uses fresh evidence
at `artifacts/rehearsals/smoke/s05-current-native-20261014-02/`; the first failure
is retained.

The second smoke completed **native0**. All four hard and five soft runtime
checks passed; router transport was `running`, not mocked, with no gate warnings.
The collector's selected topology/snapshot secret scan passed2 files; the
requested push-provider canary was not enabled and is not proven. Gate time:
2026-10-14T09:58:32.7140701Z. SHA256:
`runtime.gate.json` —
`3C91C3D66AEAB36280BFA2259C42D735FACC3F4F41304ACB67F91603361DDD0D`;
`runtime.snapshot.json` —
`697B6C7645D26892F202FE6B7F5726CB46084163D6E05AD28D5EB05247D34655`.
Both scoped cleanup calls completed; label-filtered inspection found no
remaining `deep-integration` containers.

The actual no-mock three-node rehearsal completed **native0** in
`artifacts/rehearsals/multi-node/20261014T095927921Z-077151518159/`.
Its10:00:16.311Z topology receipt records three distinct synthetic registered
identities, three running non-degraded real Xray processes, Registry node count3
and no reconciliation issues. Each privacy-contact request returned503 as
required without verified authority. This is development topology/health and a
fail-closed boundary, not current DID2 provisioning, selected-entry delivery,
production key rotation, process/retained-volume recovery or physical E2E.
`test-results/multi-node-topology.json` SHA256:
`0C14260B867D406D5182D76364E8FF4BB9A2F5EB6E1FEF562666AA47C59F4C28`.
Its selected artifact secret scan passed1 file. Scoped rehearsal cleanup
completed; no project containers or volumes remained. The separate existing
`deep-dev` project's post-engine-restart unhealthy status is not recovered; its
state/keys were not changed or reset to make these receipts pass.

This lane checks infrastructure/real Xray health. Its `ci:smoke` physical-harness
contract tests use command/WebDriver doubles; they do not exercise current DID2
messaging or actual Windows/Android devices. Do not substitute the retired
SessionId smoke for those missing acceptance scenarios.

`node ./scripts/release-gate-contracts.mjs` completed native0 with51 contract
commands (including expected negative evidence tests). Its synthetic template
evidence stays under `artifacts/release-gate-contracts/`, not the real release
evidence directory. The separate actual `production-readiness-status.mjs`
returned native1/blocked with10 missing evidence/sign-off blockers, including
device/deployment acceptance. No mock device PASS or production readiness follows.
Contract summary SHA256:
`A98D0F1B6959EF68E0E24F69F265CE45FEC53541205BD79BAEA7A8D5A23B3524`.

## Retained dev policy expiry diagnosis

Read-only inspection after engine recovery found70 publisher renewal
`ArgumentException` entries and Registry authenticated-time failures classified
`CryptographicException/policy-interval`. The existing Protocol DTS1 canonical
decoder reads the retained public genesis policy interval as
2026-09-29T14:07:08Z–2026-10-06T14:07:38Z. The host UTC clock is past that expiry.
This decode is not independent signature/current-authority acceptance; no trust
claim or floor is minted from it. It corroborates the observed live-policy
rejection. Dev provisioning authors seven-day XNA1/DTS1 scope; the publisher
uses that original bootstrap authority and delegated policy, not an indefinitely
renewable root. Its successor request rejects a lifetime outside that authority.

The next S05 operational slice must add supported signed authority/policy
renewal and its retained-history activation, including expiry warnings and
the dependent origin-certificate lifetime. It must preserve original independent
genesis, node identities, publisher journal, independent DB floor and node/client
protected floors. The production-oriented offline renewal CLI candidate is not
a supported dev activation command. Do not rerun Init/Provision, edit signed
expiry bytes, waive TLS/trusted time or reset custody to restore health.
