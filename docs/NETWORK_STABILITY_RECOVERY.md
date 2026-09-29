# DID2 network recovery: baseline and fault matrix

Observed: 2026-09-29. This is an operational investigation/runbook, not release
approval. Unfinished work has one owner:
[NEXT-SPRINT.md](../../docs/NEXT-SPRINT.md). Protocol/time/history requirements
belong to [the architecture specification](../../docs/architecture/ACCOUNT-DIRECTORY-TRANSPARENCY-V1.md),
[DR-0012](../../docs/survival-program/decisions/DR-0012-protected-network-history.md)
and [DR-0013](../../docs/survival-program/decisions/DR-0013-readonly-directory-issuance-readiness.md).

## Current candidate increment (2026-09-29)

The observations below describe the predecessor, not the current candidate.
[DEEP_DEV.md](DEEP_DEV.md) is the local runbook: only `deep-dev` remains, using
native ARM64, Registry, a real TLS PostgreSQL floor, three nodes and a delegated
publisher. Production was not modified. The owned NTS helper now authenticates
both pinned source families; Registry persists a lower rollback floor and
reacquires fresh bounded time after boot. Historical recovery follows
[DR-0014](../../docs/survival-program/decisions/DR-0014-directory-historical-catchup.md),
and bounded delegated view renewal follows
[DR-0015](../../docs/survival-program/decisions/DR-0015-delegated-operational-renewal.md).
Neither expired historical heads nor stored time restore live authority.

Actual six-service stop/start cases passed (3–27 seconds). A real DEV run with
130 disposable account admissions while all three nodes were offline passed:
all three verified ONION capabilities recovered in 46 seconds, without reset.
Its first attempt timed out on repeated prefix replay; single-pass journal/map
validation fixed that product defect, and the retained journal was reused.
These are not Docker-engine restart, 20-cycle, beyond-TTL, arbitrary key/TLS
rotation, physical message delivery or 72-hour soak evidence. Mr. X runs soak;
the separate device agent owns local Windows/Android device E2E, not CI.

Observed 2026-09-29 (evening): Registry briefly reported `scope-or-quorum` and
DID2 unready for 10-15 seconds at a time. An instrumented observer showed two
causes: an NTS-KE dial to the multi-address `nts.netnod.se` set exceeded its
4 second serial deadline, and one lost NTP datagram (`i/o timeout`) discarded a
healthy session into the 10 second backoff, longer than the signed 10 second
sample age. The observer now races staggered KE dials (at most eight addresses,
same 4 second bound) and retries one lost NTP datagram on the same session;
TLS 1.3, hostname validation, the exact SPKI pin, NTS authentication and the
sample-age bound are unchanged, and other failures still back off. After the
change: 178/178 readiness probes over 13 minutes with no NTS warning, and
two full six-container stop/start cycles on the final build recovered in
15 and 24 seconds without touching custody or volumes. This is a component
result, not the
Docker-engine restart, 20-cycle, long-TTL or 72-hour evidence.

## Predecessor reproducible causes

| Observation | Exact implementation boundary | Consequence |
| --- | --- | --- |
| Stale Registry time anchor | `ContactResolveProductionAuthority.ReadAsync`, protected CRT1/monotonic sample | Head renewal and proof authoring reject; there is no automatic NTS acquisition/reboot re-attestation worker |
| Startup floor outage | Registry `Program.cs`, formerly awaited renewal/readiness before starting hosted workers | Recovery could not run; corrected to live/unready with per-operation verification |
| Health/proof discrepancy | DID2 readiness formerly checked ADA2/head but not current signed XNV1 | Corrected with the shared read-only Protocol issuance-context verifier; health probes do not consume nonce ledger entries |
| Node initial dependency outage | `PrivacyRoutingProductionCapability.StartAsync` formerly required a fresh receive binding | Corrected to unready background recovery for transport/timeouts/expired authority; config/key mismatch remains fatal |
| Lost throttle metadata | Shared proof transport and XNode `HttpsDeepIdV2DirectoryProofArtifactSource` | Typed 429/503 with bounded delta-seconds; node traffic/background refresh share monotonic backoff, not request replay |
| Long-offline catch-up | `DeepIdV2DirectoryProofIssuer` requires a root-authorized forward proof for a gap over one generation; `DeepIdV2ForwardTailCodec` bounds the tail to 64 heads | Routine renewal can outgrow the available checkpoint/tail. Raising the count or online root signing is not a recovery solution |
| Old local container exit | `deep-survival-dev` uses the retired mailbox fixture graph; xnode1 exited 134 on fixture validation | Do not repair it by reviving expired DEV authority or use this graph as DID2 release evidence |

No production host was changed for this investigation. Local host/DI tests use
real signed/PQ artifacts, retained protected state and injected dependency
failure. They are not independent PostgreSQL/TLS, live NTS or physical-device
evidence. The Linux installer shell gate tests generated configuration and
identity preservation, not a running production messaging path.

## Required UAT fault cases

Use a dedicated current-DID2 topology, exact immutable producer/consumer commit
matrix, authenticated HTTPS, an independent durable PostgreSQL floor, retained
node identities and all state/protection volumes. Do not use legacy survival
fixtures, a mock authority or expired-artifact extensions. Record baseline
verified heads, view/key epochs, state revisions and custody equality privately;
publish only sanitized counts/digests allowed by the evidence schema.

| Case | Execution | Required observation |
| --- | --- | --- |
| Each node | 20 operator stop/start cycles per node | Explicit stop stays stopped; remaining processes stay live; exact-three-hop delivery pauses; after start a new verified binding restores readiness with the same identity/state |
| Registry | Stop/restart while nodes stay up | No cascade exit or state reset; returning fresh authority restores nodes without traffic-triggered repair |
| Independent floor | Temporarily unavailable, then restored | Registry live/unready; all dependent mutations remain closed; retained ADA2/floor are verified before readiness |
| Container recreate | Supported installer rerun and force-recreate | Registered keys, key ring, floor/anchor and named data volumes survive; installed traffic key matches the signed descriptor |
| Docker engine | Stop/start the dedicated UAT engine/host | Only scoped UAT resources are affected; retained volumes and DNS re-resolution recover; no volume deletion |
| Longer than operational TTL | Downtime beyond current head/view/time/key windows | Independent authenticated time plus operational renewal restores availability; old expired inputs never authorize traffic |
| Long history | More than 64 successors and 7 days virtual downtime | Bounded verified catch-up advances exact protected lineage without floor edits/genesis/rekey or routine offline-root repair |
| Rotations/crash | Several view/head/key rotations, interruption at each publish/CAS boundary | Retained predecessor/current+next overlap; no fork/rollback acceptance; recover only under the documented crash policy |
| Soak | 72 actual unattended hours after the cases above pass | Timestamped actual duration, bounded retries/storage/ledger, no manual intervention; accelerated/unit time is not a substitute |
| Local clients | Windows and Android reconnect after network outage | Same accounts, protected floors and durable pending operations; physical device evidence, not CI or host mocks |

## Execution boundary

NTS integration must authenticate both key establishment and NTP packets, not
just read an HTTPS `Date` header or sample the OS clock. The two protocol
parts and TLS exporter binding are defined in
[RFC 8915, sections 4–5](https://www.rfc-editor.org/rfc/rfc8915.html).
A candidate such as chrony has explicit
[NTS trust-set configuration](https://chrony-project.org/doc/4.8/chrony.conf.html#ntstrustedcerts),
but enabling it alone does not prove the exact DTS1 SPKI/source-family binding
or durable witness interval required here. This is an integration constraint,
not a deployed provider or an accepted alternate time source.

On 2026-09-29 a read-only TLS probe of the two endpoints in
`tools/production-authority-bootstrap/Program.cs` succeeded with normal platform
certificate validation, TLS 1.3 and negotiated `ntske/1`. Both leaf SPKI SHA-256
values matched that tool's pinned values (`time.cloudflare.com` and
`nts.netnod.se`). This observation validates only those public endpoint/pin inputs
at probe time. It neither audits a deployed DTS1 nor completes NTS-KE records,
authenticates an NTP response, measures a trusted interval or renews CRT1.

Do not start/declare the 72-hour gate on the current legacy local stack or before
automatic trusted-time acquisition, operational view/key renewal and bounded
history catch-up exist in the current DID2 services. A healthy idle process is
not a passing recovery network. Unit/test-host outage recovery may be accepted
as a component result only, with its substituted dependencies explicitly named.

Keep offline root custody offline, retain old registered keys, and never use
`down --volumes`, floor deletion, account reset, trust-all TLS, unsigned latest
state or OS wall-clock time as repair. A corrupt/forked/split floor is a separate
security recovery case, not a retryable loss of connectivity. Bridges and
smart-contract changes are outside this increment.
