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

## Offline operational role/traffic/TLS candidate

The existing current fixture's discarded role keys are now replaced only by a
properly signed offline successor under
[DR-0118](../../docs/survival-program/decisions/DR-0118-offline-mailbox-issuer-rollover.md).
The host producer authenticates complete current history, obtains real NTS,
authors a same-key root/time renewal and offline policy/PMA successor, and stages
new independent issuer seeds, six fresh traffic-key slots, installable TLS leaf
certificates and a fresh CA certificate retaining the original CA key. Node
identity/BLS/role/replay/history/floor custody is not replaced. It emits a complete
eight-chain public candidate plus a publisher journal authenticated by the retained
integrity key, without public/config/secret-volume mutation.

Owner import source validates retained HMAC, exact generation/prior public hash,
all seven retained history prefixes, root chain, signed role policy/projection and
increased grant floor. It rechecks NTS before a new commit, writes its own durable
journal before public distribution, and can finish exactly the same pending commit
without minting another generation. This is distribution ownership, not live
network authority. Coordinated TLS/private/config installation and runtime import
have NOT been executed; do not invoke import alone on a live old-key deployment.

Focused run03:30 checks, Windows PowerShell5.1/SDK10.0.301, native build/test0,
zero warnings/errors. `artifacts/s05-dev-operational-renewal-20261014/03/tests.log`
SHA256: `96C5223B18749D312E643CA80496089D432AE3CADF8493AEA584A77CC18CE5D6`.
Real root/witness/node/DID2 signatures, complete old-prefix retention, new policy
to private role-key binding, installable TLS/SAN, retained-key HMAC, current source
immutability and stale/skipped/corrupt import rejection are checked. Unit time is
a fixed fixture observation, not NTS/runtime evidence. Topology/source contracts
passed11/0; no physical or release acceptance is implied.

Actual current-dev preparation succeeded with real NTS. The first wrapper resumed
publisher after preparation, which immediately produced another delegated view
and invalidated that candidate's exact predecessor. It was not imported. The
corrected wrapper preserves operator-stopped services, restores its own stop on
failure, and on success leaves only the publisher stopped for coordinated
activation. A second complete candidate generation7 exactly matched the retained
public hash. Both private candidates remain under dev offline custody. Latest
candidate has not been activated; no generator reset, registered identity change
or manual signed-record edit occurred. Starting publisher explicitly cancels this
preparation and requires a new candidate, not a compare-exchange bypass.

## Coordinated installation and failed connected acceptance

The sealed host installation package adds exact private-artifact HMAC binding,
PMA role-seed matching, same-identity CA and leaf private/chain/SAN validation,
traffic metadata checks, and a protected before/new installation plan. Only
TLS/traffic/issuer custody, immutable paired-history files and owned config are
replaced. Ed/BLS identities, genesis, replay/entropy protection, passwords and
state/floor volumes are outside the whitelist. Repeating an interrupted plan
requires every target to match its before or after bytes; altered targets reject
before installation. Only candidate/operator is mounted for online CAS import.

Native Windows PowerShell5.1/SDK10.0.301 build/test exits0, zero warnings/errors:
`artifacts/s05-dev-operational-activation-20261014/03`,35 real-signature/file checks,
12 topology/orchestration contracts. Tests SHA256:
`FA7B2D08C221815A83C3F20EDC16760DA719244353F7732272C15336453819BD`.
Final exact-plan whitelist source passed the matching04 build/test with the same
35 checks, native0, zero warnings/errors and the same tests hash. The first test exposed
incorrect public-only PEM loading; its original failure is not activation evidence.

Actual new sealed candidate generation7 was prepared with NTS against the retained
current predecessor. All six scoped owners stopped; private/config installation
and protected publisher import completed; delegated publication resumed at8.
The180-second independent Registry/three-ONION wait **failed native1**. No reset,
floor replacement, registered-identity replacement or signed-byte edit was used.
The retained dev remains running for diagnosis. Production and old deep-dev were
not changed. This is partial operational progress, not activation/device PASS.

Root/DTS handover during the same UTC-day changes the authenticated DTT1 epoch ID
while preserving its number. The nonce ledger rejects that as rollback/fork;
normal TLS/NTS and head renewal can succeed while proof issuance cannot. Registry
readiness now requires a read-only ledger check with a closed diagnostic label.
Coordinate the operational policy ceremony with that retained issuance namespace
before repeating root handover. Do not fix this by deleting quota/markers,
backdating time or policy, waiting silently, or accepting changed same-number IDs.
External grant signers/journals and physical contacts/messages/files/groups remain
unactivated and unqualified. S05/S06/release acceptance is not closed.

Actual updated Registry readiness now returns503/native curl22 with the closed
`issuance-epoch-rollback-or-fork` diagnostic, not a successful-shaped health.
Receipt `artifacts/s05-dev-operational-activation-20261014/04/runtime-registry.log`,
SHA256:`F024E0660EA2735D7E67894F19055F223D554EE0ECC4A7A27D114B2B4634061D`;
three separately captured node health responses report ONION unavailable.
Matching Registry canonical full passed398/0/7,405 mappings and2839 unchanged
inputs; [Registry evidence](../../deep-registry-api/docs/testing/s05-epoch-readiness-2026-10-14.md)
owns its exact receipts. Final source secret scan of15 changed files found0 findings.
The broad raw-artifact upload scan is not accepted: local logs/archives remain
private diagnostic inputs, not a cleared release bundle.

## Same-day lineage-aware recovery

[DR-0119](../../docs/survival-program/decisions/DR-0119-dtt1-same-day-authority-handover.md)
freezes the exact negative anti-replay lineage; no raw allowlist, nonce/quota reset,
signature/wire change or historical-currentness conversion is used. Registry
probes the unchanged HMAC nonce path for every protocol-minted overlapping paired
namespace and retains all same-day markers and aggregate quota. Current signatures
still name only the exact current authority/time/epoch. Older/sibling namespaces
not in the current lineage reject. Readiness remains read-only.

Actual retained current-dev Registry image build and scoped recreation completed
native0. Registry proof and three independent ONION capabilities recovered21s:
`artifacts/s05-same-day-runtime-20261014/01/verify.log`, SHA256
`75A069194B3FFA0F4F941C487E14B6E5629D8E46DAA2DFEDEEB56C6CD859622D`.
No Init/Provision, genesis/key/floor replacement, clock editing, marker deletion
or production write occurred. The original failed activation remains above.

Retained StackFault:20s offline,18s recovery,30s stable, native0, same custody
digests and state/container mount bindings:
`artifacts/s05-same-day-runtime-20261014/02/stack-fault.log`, SHA256
`50EB11C15752EA47B80DE58423CDCB408D4AB6CF5C3E4339DE93E15A863CEDC1`.
This is a real same-day renewal/restart scenario, not a whole-engine fault,
long soak, complete root/witness rotation ceremony, mailbox issuance or physical
contact/message/file/group acceptance. External grant sockets/journals and the
remaining S05 gates are still open.

Matching Registry canonical full accepted401/0/7,408 exact mappings and2842
unchanged inputs, all native stages0; source scopes and hashes are owned by its
[handover checkpoint](../../deep-registry-api/docs/testing/s05-same-day-handover-2026-10-14.md).
Protocol's independent full retains the original S08 package failure; no release
qualification is inferred from this successful development recovery.

## Protected role signer source and engine-resumed smoke

The optional `mailbox-signer-tests` target in `docker/deep-dev.Dockerfile`
executes real Linux ARM64 role custody/signatures and the Unix adapter tests,
without live authority mounts or service ports. Actual21/0/0/native Docker0;
exact source receipt, build copy-retry warnings and remaining deployment gates
are owned by the [Registry checkpoint](../../deep-registry-api/docs/testing/s05-protected-role-signer-2026-10-14.md).
Topology contracts12/0/native0. The normal six-service composition is unchanged;
no role signer service is claimed deployed. A dedicated role-only mount and
explicit independent grant/MGR roots must precede enabling private issuance.

After the operator restarted Docker, `test-env.ps1 -Suite smoke -BackendMode
deep-dev -DeepDevProjectName deep-dev-current` completed native0 through the
isolated native runner: Registry proof ready, three verified ONION nodes,
3-second observation. `artifacts/s05-role-signer-20261014/03/smoke.log`, SHA256
`3B422649935678F8B1158EFE158F91E2BEC41BA2CA6EF1826FB03F43829B7AC1`.
No container/volume/WSL reset, production mutation or role-key signature occurred.
This is retained current-dev control/ONION smoke, not mailbox or device delivery.
Original pre-cutover deep-dev remains separately retained and unhealthy.

## Actual protected mailbox issuer activation

Current-dev now uses the optional eight-service overlay in the
[operator runbook](DEEP_DEV.md#explicit-current-dev-mailbox-issuer-activation).
The existing signed PMA2 role keys were verified with actual NTS and copied to
separate role-only volumes. Registry's replacement secret mount excludes both
role seeds; original custody/volume is preserved. No offline root or node/BLS
identity was mounted to a signer or replaced. Four canonical grant/MGR tables,
one network root and two actual policy/role roots were explicitly initialized
in one PostgreSQL transaction. Runtime performs no DDL or re-enrollment.

Preparation tests38 checks/native0, zero build errors/warnings; final receipt
`artifacts/s05-mailbox-activation-20261014/11/final-preparation-tests.log`, SHA256
`C7899ADF0EEC14BCC920FE509A28098E87EB0DAC99F12ADAA5B724644CB672A6`.
Actual Compose isolation/lifecycle contracts14/0/native0. Explicit provisioning04
native0; initial read-back was network1/scopes2/grant entries0/MGR entries0:
`artifacts/s05-mailbox-activation-20261014/04/provision.log`, SHA256
`A79070311CFB9D76C7CD6C168F4F0E6E0998AD858F1FD32EA8FA4E15615502EC`.
Preparation02 passed; first provisioning03 rejected CryptographicException
before any volume/schema mutation (read-back tables0). That cause is not claimed
fixed by a successful retry; additional closed NTS/policy labels now aid recurrence.
Build05 failed before a native child: Get-Command Docker returned two applications.
The runner now selects the exact verified docker.exe; builds06/09 completed0.

Actual activation07 native0; both sockets/processes became healthy and Registry
committed two signed MGR1 winners, one per role. Direct container checks confirm
neither seed exists in Registry's runtime mount. Receipt
`artifacts/s05-mailbox-activation-20261014/07/activate.log`, SHA256
`4B2AE275E334CFCDEF437DC5022C3DC358C0524A6273E25E1C73B74DC4F7BB63`.
Ordinary renewal subsequently committed generation3 in both retained scopes.

Original restart08 failed native1 during30-second stability, despite eventual
healthy containers. Preserve `artifacts/s05-mailbox-activation-20261014/08/restart.log.stderr`, SHA256
`32D60E4E0863EA65B621C33E8A554DE7A576B88D35CFC92090AE50A8271CC61F`.
The Registry read-only readiness owner now waits within its original deadline;
matching/full source receipts and unchanged security fences belong to the
[Registry checkpoint](../../deep-registry-api/docs/testing/s05-protected-role-signer-2026-10-14.md#actual-dev-activation-and-readiness-contention).
Updated image and retained observer Up10 native0:
`artifacts/s05-mailbox-activation-20261014/10/update.log`, SHA256
`395BB4CB64B4FAB5AD39167B5156AAC64AE7A009BAA28F01E88724B859F1F4E0`.
Node floor enrollment, private XMC2 issuance/client verification/node acceptance,
coordinated future role-volume/journal rollover and physical delivery remain open.
Pre-mailbox rollover commands refuse the enabled contour rather than applying a
partial update. No production/old-dev mutation, reset or release occurred.

Restart12 also failed native1 (Registry HTTP22/28), despite eventual recovery:
`artifacts/s05-mailbox-activation-20261014/12/restart.log.stderr`, SHA256
`8F097DC2E450E57998AAF7E3F4CB762595BCB9314971970496B99B149B0AF85E`.
Six read-only readiness probes measured2319/2345/2533/4245/2433ms with HTTP200,
then HTTP000/native28 at5415ms. A temporary role journal recreated a database
pool each time; Registry now has one authority-owned fixed-config connection
pool, not a cache of verified winners. Matching PostgreSQL17 checks and the
subsequent19-case ownership remediation pass are recorded by Registry; its
original407/2/10 full FAIL remains preserved, not accepted.

Pooled Registry image13 build native0, updated retained composition14 native0;
no schema, seed, floor or winner was replaced. Six later probes returned HTTP200
native0 at3096/2196/2552/2367/2230/3282ms. This small sample is not a performance,
restart, sustained delivery or physical qualification. Remaining S05 gates stay open.

Pooled restart15 still failed its stability window, not accepted:
`artifacts/s05-mailbox-activation-20261014/15/pool-restart.log.stderr`, SHA256
`2C7D5BC4C15A7A4C5C901B01A1EE5507C16F53368B416AF1CB031D4CED15A26B`.
The final source separates refresh single-flight from journal write exclusion:
unchanged proof/read work does not block readiness; actual due work re-reads
state under the owner and keeps it through both roles/final pair verification.
Final matching19/0/0 and canonical full409/0/10,419 exact mappings/2844 unchanged
inputs, all native stages0 and zero build warnings/errors are owned by the
[Registry source receipt](../../deep-registry-api/docs/testing/s05-protected-role-signer-2026-10-14.md#shared-connection-owner-remediation).

Actual build16/update17 native0, then eight-service retained restart18 native0:
20s offline,38s recovery,30s stable current Registry/MGR and three ONION
capabilities; same Registry/node/role custody and all container/state mounts.
`artifacts/s05-mailbox-activation-20261014/18/owner-restart.log`, SHA256
`CD90E40D9079C2EEA06C73865BD9BD86562A98FFCC2AAD723A4465C5A9A1EB26`.
Initial recovery503/timeouts remain in that successful receipt; stable interval
started only after verified recovery. Read-back then found30 signed MGR1 rows,
generation15/entry_count15/committed15 in each existing role scope, no pending.
No deletion, scope reinitialization, identity change, deadline enlargement or
manual signature was used. This is one bounded recovery, not the complete S05
rotation/outage/soak matrix or node/client/device acceptance.

## Actual retained node mailbox enrollment

The supported explicit workflow now prepares current signed scope, provisions
separate empty protection-key volumes, captures exact signed MGR1 records and
invokes XNode's existing `current-mailbox-enroll` command with each stopped
owner's original identity/data roots. It neither synthesizes MGR signatures nor
resets floors. All three actual enrollments07 completed native0; each sanitized
`artifacts/s05-node-enrollment-20261014/07/node-N-enroll.log` has SHA256
`3798D9A256EDA20C2236C416BCFC5BBDE2B9AC28F3D7B89AB309DD9752531D46`.
Activation08 and strict Verify09 completed native0. Verify requires actual
recovered mailbox hosts, not disabled success; its SHA256 is
`DA713D9A2429A86C0720BDDE27695516BFFAF38AAF4ADFF2967EB7F47DB2B194`.

Final operator preparation tests12:48 checks/native0, including signed role
binding and negative response-framing cases. Receipt
`artifacts/s05-node-enrollment-20261014/12/final-preparation-tests.log`, SHA256
`395BC43730BF50920F2F1C56B637DB2A32D75C0F6456F34FF69C5819BED3C695`.
Actual three-overlay Compose contracts15/0/native0; PowerShell AST and diff
checks passed. Final Linux ARM64 operator image build13 native0, zero compiler
warnings/errors, stderr SHA256
`34061AE4FECAAE4F6312066F74F86619050E60545B88784FCFE2C47741B95D3B`.
Release-gate contracts passed51 synthetic commands; actual production-readiness
remains blocked by10 missing evidence inputs, not shipping acceptance. Final exact
control capture15 native0 under TLS/closed framing, SHA256
`F8E2C713EF3C5D29FDF6B0418CB2EC1BBA22F4AC5BA19F3B9314262BD393C22B`.
Windows PowerShell5.1 resumed current-dev smoke15 native0, SHA256
`D9E6EB69E9AF51A664A87255A013F6252ED206CDF2B295B793F8AEC4CCDCD2FC`.
Direct actual reprovision of an existing keyring16 rejected with helper exit2;
in-memory before/after digest comparison confirmed unchanged key bytes.
Its closed stderr SHA256 is
`5548EB026A54EF5F6B1D4B62FF9FCF1C22AEEB871DD8FE1152A23726D740AF6C`.

Preserved attempts05/14 failed closed with IOException during control capture;
read-only refetch06/15 passed. No native floor was replaced by these retries.
Test11 failed because its negative-test helper did not catch InvalidDataException;
the explicit rejection category was added, not an acceptance/assertion weakened.

Retained restart10's log reports20s offline,153s recovery and30s stable current
Registry/ONION/native mailbox hosts, unchanged identity/role/protection-key bytes
and mounts. Receipt SHA256
`CFDD96A04022915655CE4109546BCCC137AE7FEBE5149C38E62463E461A9B14A`.
The original runner's native terminal was lost during context handoff; this
restart remains **diagnostic/unqualified**, not accepted by inferring exit0
from its final JSON. The independent resumed smoke above has a captured exit0.
Long startup control/readiness unavailability is not claimed fixed by eventual
recovery; no deadline, nonce, signature or floor fence was relaxed.

This closes first explicit dev node enrollment, not private XMC2 acquisition
through the owned client, node acceptance of those grants, coordinated later
role/custody rollover or the remaining S05 fault matrix. Physical contacts,
messages, attachments and groups remain0/4. Production, old-dev, main and GitHub
Releases were not changed. Workflow details have one owner:
[DEEP_DEV](DEEP_DEV.md#explicit-current-dev-node-mailbox-enrollment).

## Contact consumers and owned-client issuance attempt

The current-dev operator now explicitly provisions separate resolver key rings
and independent custody, then stops each original node owner and invokes its
existing `contact-resolver-enroll` command with the same retained identity,
data, mailbox and proof state. All three actual enrollment04 commands completed
native0. Each `artifacts/s05-contact-issuer-20261014/04/node-N-enroll.log` has
SHA256 `435859203F315085F2020C21925579FB52AEF0F7A5011E3019F5C74F1E803739`.
Activation05 and verified recovery06 completed0; Verify SHA256
`E9324AB66485095E4A860662C754C234EAC9028D3B3400E3F8513450366CA42C`.
The contact overlay composes actual current pre-key staging/claims, resolver and
private HTTPS grant client, not the unavailable fallback or a mock issuer.

Current coordination preparation verifies genesis/current policy and records
the three existing configured transport keys, not issuance authority. Explicit
provisioning08 atomically created the canonical route/publication journal tables
and two network roots in the independent PostgreSQL database. Existing tables
reject and runtime performs no DDL. Receipt
`artifacts/s05-contact-issuer-20261014/08/coordination-provision.log`, SHA256
`16205CA1268D89A06C18BDE4373AEEDD5A4012E686CB715AEDE69BF0A67564E9`.
Read-only initial counts: route roots1/publication roots1, entries0/0.
Actual activation09 and Verify10 native0, Verify SHA256
`39067090901F9A482098D6AAC0EE7DA126DE6C27A24DD62C40B2C02FC930DDD0`.
The optional overlays retain eight services and existing keys/mounts.

Final operator tests16:54 checks/native0, SHA256
`BC008452CE2D843A228A2C9B04A05FE7D2C79AB7919D836C56C0AF28CBC99138`.
Actual Compose/closed-input contracts18/0/native0 and PowerShell AST passed.
An earlier contract selected a nested action branch instead of the complete
outer branch; its FAIL was fixed by an exact boundary, not weaker assertions.
Final operator build14 native0/zero compiler warnings/errors; a NuGet EOF retry
remains in that log, not a lost or interrupted terminal. Source-only packages
for Node/Registry/Protocol were unchanged and their full gates were not repeated.
Final current-dev smoke17 from Windows PowerShell5.1 native0, SHA256
`E6EB444BBDD3B43B7205789AF927BEBBD5A53E90A2827603661331AA3F08941D`.
Actual existing-contact-key reprovision18 rejected with native exit2; in-memory
before/after digests confirmed unchanged keys. Closed stderr SHA256
`5548EB026A54EF5F6B1D4B62FF9FCF1C22AEEB871DD8FE1152A23726D740AF6C`.

The new supported `ExerciseOwnedMailbox` probe mounts **public bootstrap only**,
creates a disposable real account owner/encrypted database, and invokes the
actual account-owned admission/network/publication/mailbox APIs with normal TLS
and real ONION selection. It injects no signed grant, signer, transport callback
or fixture clock; process monotonic time is real elapsed time. Process-only
secure storage is explicitly disposable and never device/recovery evidence.

Actual attempt13 failed native1 at AccountAdmission after AccountCreate;
classified attempt15 failed again, not accepted. Its closed stderr SHA256 is
`970AC88825AAC3C4CD3F43708B9D62CD973DA0D6BD0325A130A3A3D7D4653C90`:
HttpRequestException / SecureConnectionError / AuthenticationException.
The same public dev leaf/root inspected read-only on Windows with Online
revocation and an explicit private root produced RevocationStatusUnknown;
the leaf has no CRL Distribution Point. Actual curl HTTPS/H2 readiness returned
200/version2, so healthy services and curl do not qualify the strict managed TLS
consumer. Missing dev revocation distribution is the leading concrete PKI
cause; Linux TLS-chain status and a successful corrected runtime retry remain
required before claiming it resolved.

Do not fix this by NoCheck, accepting unknown revocation/chain errors, cleartext
fallback, raw signed grants or another identity/floor reset. The next supported
operator change is signed dev CRL distribution plus correctly issued leaf
certificates, retaining CA/leaf keys and signed SPKI bindings. .NET has built-in
[CRL Distribution Point authoring](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.certificaterevocationlistbuilder.buildcrldistributionpointextension?view=net-10.0);
no additional crypto library is required. This is still S05 connected issuance,
not S06/physical acceptance. Private grants/client verification/node acceptance,
remaining rollover/outage matrix and physical0/4 remain open. Production,
old-dev, main and GitHub Releases were not changed. Workflow owner:
[DEEP_DEV](DEEP_DEV.md#current-dev-contact-and-issuer-connected-client).

## Same-key dev PKI and strict managed admission

2026-10-15: added the explicit supported dev-only TLS ceremony described in
[DEEP_DEV](DEEP_DEV.md#current-dev-tls-revocation-distribution). It retains the
CA certificate/key, every leaf key/SPKI, host/SAN/extensions and validity window.
The CA signs a standard CRL and reissues the existing leaves with a fixed CRL
Distribution Point. A sealed exact whitelist/before-after plan is validated
before stopping owners; partial installs resume the same candidate. Private
CA/leaf keys never become online mounts or artifacts. No signed network bytes,
protocol root, identity, floor, grant scope or journal root changed.

The existing publisher gained only one bounded internal public CRL endpoint,
no new container or published port, no app HTTP path or signing endpoint.
It verifies the CA signature before serving DER bytes and emits no access log.
Actual distribution returned HTTP200/564 bytes. The Linux .NET10 implementation
requires an HTTP CDP; application HTTPS/H2, chain/name/EKU and online revocation
remain enforced. No client trust callback, NoCheck or ignored chain flags was
introduced. Publisher cancellation is linked to its host lifetime; its original
renewal/journal ownership remains unchanged.

Preparation tests02:58 checks/native0, zero compiler warnings/errors; receipt
`artifacts/s05-dev-pki-20261015/02/pki-preparation-tests.log`, SHA256
`09F62B4FBB570B5DAAE01D3E7840986958E157448FE8197C79F3BA04EFC29286`.
Actual signed candidate03 native0, SHA256
`4BCCB180E71DCA0341CEE57001F1116DF5E65DB661F61148FC58251D8BBB605D`.
Final actual Compose/contracts19/0/native0 and PowerShell AST passed. Matching
ARM64 publisher/operator image04 built native0/zero compiler warnings/errors.
Original test01 failed a fixture local-name collision; corrected, not waived.

Original Apply05 completed0, but Verify06 failed1 because the certificate copy
lost PostgreSQL's non-root file owner: server.crt became0:0/mode0600 while the
retained key remained70:70/mode0600. Six closed permission-denied log lines
confirmed the cause. Copy now preserves numeric ownership from the unchanged
TLS key, with assertions against copying key bytes. Same sealed-candidate resume07
native0 repaired ownership to70:70/mode0600; PostgreSQL/floors were not reset.
Resume SHA256 `3DED4FE3E2269AC85CE32C6FDD5592BDC62F640F5CB8F20DCF61458D822F9D60`.
Current capability Verify08 completed0 after156s recovery, all three ONION/native
mailbox/contact terminals recovered; SHA256
`495328960C847984FB2D9AD0D048BFE8A5F32819B72491E58052F02B35015B9E`.
The first failure remains a failure; eventual healthy containers do not qualify it.
Final resumed Windows PowerShell5.1 smoke10 native0, SHA256
`A9CDA4E8A869CEA1486C1AB8589C8BB9AF5AB2BD8596B02FDE8520B479E7A349`.

Strict owned-client09 now completed actual AccountCreate, **AccountAdmission**
and **CurrentNetwork** through the unchanged managed HTTPS client. This resolves
the observed TLS failure; it does not prove grant issuance/node read. Receipt
`artifacts/s05-dev-pki-20261015/09/owned-client.log`, SHA256
`D0CE6618A68A6DED434F53D639BF25D3C0DBE7D23C9917BDF58495723032542C`.
The command still failed1 at PreKeyStage with PlatformNotSupportedException:
the default approved ML-KEM assets/loader support Windows x64/ARM64 and Android
ARM64, not this Linux probe process. Do not broaden shipping crypto approval or
inject fake prekeys solely to make this diagnostic pass. Continue the connected
owned-client path on the supported Windows/Android platforms (or a separately
reviewed genuine Linux crypto-provider qualification). Physical0/4, grant/node
acceptance, remaining S05 lifecycle and shipping gates remain open. No production,
old-dev, main or GitHub Releases mutation occurred.
