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

## DR-0116 source continuation

[Protocol owns](../../deep-protocol/docs/testing/s05-root-continuity-2026-10-14.md)
the frozen root-continuity semantics, explicit successor policy horizon and
source-gate status. The operator's existing offline preparation can now author
an exact post-expiry successor using real supplied observation time, without
backdating/reviving its predecessor. Operational completion additionally requires
`--root-policy-expires-unix`; actual CLI tests check XVP1/PMA2 expiry140000 while
the first operational view remains shorter, and reject a horizon below the
operational interval or above the actual authority. Three retained node identities
and original input bytes are preserved.

Operator run17 failed compilation because its new tests attempted to access
Protocol-internal records/history. Those internals were not exposed: tests use
existing public PMA verification and the existing independent test-only scalar
reader. Run18 built but failed a new upper-bound test:200001 was below its actual
fixture authority ceiling300000. Its input now derives `authority.ExpiresAt+1`;
the rejection assertion remains. Both prior failures are retained. Run19 built
with zero warnings/errors, native0; executable native0 with six top-level and
three nested command/history scopes, including69 views and post-expiry renewal.
`artifacts/s05-authority-history-20261014/19/operator-tests.log` SHA256:
`0EBD345AE6E646638DB4EAF3E6A3AF032D312E63841CACAF1D5BED0FCD383CB9`.
No production custody was opened and no TRX/full-stage acceptance is implied.

The publisher candidate now authenticates the complete paired terminal
authority from its retained journal bundle, takes its actual terminal DTS/PMA,
and warns about offline expiry without mounting root custody or resetting state.
Delegated authoring still verifies the exact XVP1 before callbacks and cannot
extend its policy. Exhausted root/DTS budgets back off60s; other failures retain
their10s backoff. Its normal authenticated NTS observation is not a client proof.
The source topology contracts passed6/0; those are text contracts, not execution
of the Docker publisher. Current publisher build evidence is under
`artifacts/s05-dev-current-authority-20261014/`; it does not recover the still
expired retained network. Supported dev offline preparation/import with original
journal, retained node/Registry floors and TLS certificates remains open.

## Development offline paired-authority preparation

The explicit host-only `PrepareAuthority` command now prepares a same-key
XNA1/DTS1 successor through the existing Protocol author. It authenticates the
full paired history and unchanged original genesis, acquires NTS from the exact
retained signed source policy, and never backdates a renewal into an expired
window. It holds a separate exclusive offline lease, rejects a source change
before signing and again before staging, and completes one public-only candidate
directory by rename. Root seeds are not copied; publisher journal, online public
closure/configuration, TLS keys and independent retained floors remain unchanged.
The output is deliberately a paired-authority candidate, not an NCP2 containing
old policy/PMA under new authority. Operational completion/import remain open.

Focused Windows PowerShell5.1/SDK10.0.301 run05:
`artifacts/s05-dev-offline-authority-20261014/05/`.
Build native0, zero warnings/errors; executable native0 with **20 checks**.
`tests.log` SHA256:
`178CFF9328C7E64BAD816E5A5EF33262F1352F23C8DA0C7CF65B93E7C353EE0B`.
The tests use isolated real root/witness/node signatures and a real native DID2
provider to construct current eight-chain fixture bytes, then execute file
preparation, verify its signed result and compare unchanged source/root bytes.
Wrong root, non-root adapter, corrupt/missing history, backward/overflow time,
unbound digest, outside-dev path, concurrent lease, source mutation and the
retired seven-chain header reject. Fixture observation time is controlled;
this is not NTS acquisition, a running network or device evidence. The temporary
private test fixture was removed by its exact validated cleanup; retained dev
custody was not targeted. Source topology contracts passed **7/0**.

Run01 rejected a fixture with only two witnesses; the fixture now uses the
required three, without weakening the producer. Run02 passed the initial
13-check core scope; run03 added file ceremony coverage and passed20. Run04
additionally verifies unchanged source before root callbacks; prior logs remain.
Run05 retains that20-check PASS after review changed ancestry checks to fresh
`File.GetAttributes`: access/other IO errors propagate rather than masquerading
as missing paths through `File.Exists`. Only actual missing components are ignored.
An initial ordinary-shell build passed but is only a diagnostic, not the named
PowerShell5.1 qualification above.

Actual retained-dev preparation attempt `prepare-01` returned native2 before
observation/signing: its NCP2 is still the pre-cutover **seven-chain** frame,
with610 views/heads/topologies and no eighth PMA history chain. Read-only framing
inspection is not signature or current-authority evidence. This corrects the
earlier diagnosis that policy/TLS expiry was its only obstacle. No candidate was
created, no old decoder/converter was added, and no volume, registered identity,
genesis or floor was reset. The separate current provisioning clean-break and
supported retained-journal activation must be resolved before runtime readiness
can be claimed. Existing infrastructure smoke is not acceptance of this fixture.

## Separate current-only runtime qualification

The supported Compose template now binds either explicit `deep-dev` or
`deep-dev-current` to disjoint custody, named volumes, network/subnet, loopback
ports and image tags. Both run the same current-only code. The original
pre-cutover fixture was not converted, reset or used for current acceptance.
The separate current fixture was created by first-time Init with actual NTS and
eight-chain NCP2, then explicitly provisioned and started. Its own subsequent
checks retain its genesis, keys, publisher journal and independent floors.

Actual startup exposed two provisioning defects, not Docker/TLS failures:
retired ContactAuthority/GroupControlAuthority declarations caused all nodes to
reject before startup; after removing those declarations through the owned
current generator, the observer had no admitted current checkpoint. The new
supported observer-admission command submits its exact retained DGA2 over normal
authenticated HTTPS and checks the operation/network receipt binding. It does
not recreate the account or promote the receipt to freshness. Node verifiers
independently acquire their own current proofs. Both initial readiness attempts
returned native1 and remain failed, not accepted recovery cases.

Windows focused source run07:22 checks, build/executable native0 and zero
warnings/errors, including exact project address separation and unknown-project
rejection. `artifacts/s05-dev-offline-authority-20261014/07/tests.log` SHA256:
`0A1AB112929056DBA5E54943054B76C8908C26F9AFC768CCC90B2E9EA7D2AA93`.
Topology/observer contracts:10/0, including actual Docker Compose rendering of
both project namespaces. These contracts are not transport delivery tests.

Current Linux ARM64 Registry/XNode/publisher images built successfully. The
actual current Up, retained observer replay and Verify returned native0:
Registry proof ready and three independently verified ONION capabilities.
Runtime receipts: `artifacts/s05-dev-current-runtime-20261014/01/`.
`Verify.log` SHA256:
`2A88A767E9485A239D4EEFA76DBDDB047D68C9837E3F03CDDB523984334FBC63`.
One scoped StackFault passed:20seconds offline,14seconds recovery,30seconds
stable current-proof/three-ONION window, identical container IDs, canonical
mount bindings and online-key digests. No whole-engine shutdown or floor reset.
`StackFault.log` SHA256:
`59379E93D4EB3469D45B7BDE65DF7D23204419CDA8D5AB3FE3887383A945E017`.

Real HistoryFault then passed with all three current nodes offline during130
disposable DEV admissions,129 signed head successors, and independent node
catch-up after restart in10seconds. Native0, custodyReset=false; no mocks or
fixture clock supplied to Registry/nodes. Receipt:
`artifacts/s05-dev-current-runtime-20261014/02/HistoryFault.log`, SHA256:
`56535D4C54AFF2DA7001F459A24C4BCB1014DF85D3D8365ABB73573B2A668D8D`.
The explicit current-instance test-env proof/ONION smoke also returned native0.
Real host NTS/offline paired-authority preparation succeeded on this current
fixture; the prepared pair was not imported or activated as an operational root.

New Init also retains independent mailbox issuer seeds rather than discard
them. This current fixture was initialized before that fix; its old issuer
private keys cannot be reconstructed. It needs a properly root-signed role/PMA
successor and protected external signer/journal provisioning. Readiness above
does not prove grant issuance, contact/message/group/blob terminals or carrier
delivery. Root/witness/role/traffic/TLS rotation and protected publisher import
remain S05 work. Physical contacts/messages/files/groups remain0/4; production,
main and GitHub Releases were not changed.

Final DevOps release-contract runner returned native0/51 commands on this
package. Its fixtures live only in `artifacts/release-gate-contracts`; synthetic
device/GA PASS there is not actual acceptance. Actual production-readiness
status separately returned native1 with10 missing evidence blockers.
