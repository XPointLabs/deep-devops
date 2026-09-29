# DID2 network recovery: baseline and fault matrix

Observed: 2026-09-29. This is an operational investigation/runbook, not release
approval. Unfinished work has one owner:
[NEXT-SPRINT.md](../../docs/NEXT-SPRINT.md). Protocol/time/history requirements
belong to [the architecture specification](../../docs/architecture/ACCOUNT-DIRECTORY-TRANSPARENCY-V1.md),
[DR-0012](../../docs/survival-program/decisions/DR-0012-protected-network-history.md)
and [DR-0013](../../docs/survival-program/decisions/DR-0013-readonly-directory-issuance-readiness.md).

## Reproducible causes

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
