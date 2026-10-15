# S05 — actual owned contact publication and authenticated mailbox read

Date: 2026-10-15. Owner: Mr. X. Local current-dev contour only.
Execution order remains [S05](../../docs/architecture/IMPLEMENTATION-PLAN-V1.md#s05--current-issuer-и-автоматический-lifecycle-управляющего-контура).
This extends [the prekey checkpoint](S05-PREKEY-LIFECYCLE-2026-10-15.md), not its
historical receipts or physical/release acceptance.

## Observed defects and coherent fixes

- The primary retained owner now reports the closed `pmt-reference` failure for
  its incomplete XRA. It was not reset, migrated or silently reauthored.
- Raw network distribution uses one in-flight response with no server queue.
  The first diagnostic owner encountered429 during multi-fragment publication.
  The client now retries only rejected identity-neutral public reads, at most
  eight times with jitter and Retry-After, within the original configured total
  timeout. It caches no authority and still requires an independent fresh proof
  for each authority mint. The shorter four-read attempt failed and is retained.
- Repeated physical `Up` tried to allocate the running proxy's static address
  again for an ephemeral preflight. It now validates mounted inputs inside the
  running proxy's private tmpfs, or uses the one-off container only if no ingress
  is running. Ambiguous ownership rejects. No volumes/network were reset.
- The production Program registered the same contact-replica route twice when
  both resolver and inventory staging were active. Actual remote service logs
  recorded `AmbiguousMatchException`; the coordinator reported only one durable
  replica outcome. One current mapping now handles both flags and injects the
  current composite receiver. The redundant mapper and wrapper were removed;
  authentication, placement, replay and durable verification remain unchanged.

The closed server publication diagnostics distinguish reservation, replica-write
and commit-receipt failure; they contain no identity, locator, body or key bytes.
Temporary speculative peer/endpoint diagnostics were removed once the actual
route collision was established. There is no new public endpoint or wire format.

## Runtime receipts

Prefix: `artifacts/s05-contact-diagnostic-20261015/` in this repository.

| Receipt | Actual result |
| --- | --- |
| `first-01/` | Native1; first diagnostic owner stopped at public closure429. |
| `first-02/` | Native1; bounded four-read strategy still encountered429. |
| `first-03/` | Native1; same owner's prekey completed with eight-read backoff, then contact returned XPO status8/mutation2. |
| `images-01/` | Build0; Up1 before activation because the existing ingress already held its static address. |
| `activation-01/` | Up0/Verify0/repeat-Up0/repeat-Verify0 after the script fix; initial recovery29s. |
| `replication-01/` | Native1; separate retained owner received a before-forward rejection. Closed gateway diagnostic: `IssuedLowerBound`. |
| `replication-02/` | Native1; same request after waiting reached replica-write, XPO8/mutation2, one reported durable replica; receiving node recorded ambiguous routing. |
| `images-02/` | Build0/Up0/Verify0, recovery31s, one-route node composition activated. Initial acceptance stopped in contact-object restoration; the exact failing predicate was not classified. |
| `acceptance-reopen-01/` | Native1; same retained acceptance owner verified its exact prekey pair, completed contact publication after one before-forward backoff, then mailbox grant read received a before-forward rejection. |
| `acceptance-reopen-02/` | **Native0**; same retained owner completed contact publication, acquired the owned grant and received an authenticated empty mailbox page from a real node. |
| `acceptance-renewal-01/` | Native0; same owner again completed the flow, verified network view57/contact generation0. Its newly added count-only diagnostic compiled with CS8602; the nullable checkpoint guard was fixed afterwards, so this run is not a zero-warning build receipt. |
| `acceptance-renewal-03/` | Native1; the same retained owner verified view58 and its byte-identical prekey receipt pair, then contact renewal rejected in `RequirePredecessorBindings`. The exact predicate requires the retained route's PMT to equal the current PMT. No account, floor or pending state was reset. |
| `images-03/` | Final source image Build0/Up0/Verify0; retained Registry proof and three ONION capabilities recovered in44s. This rebuild includes the final contact-only retry restriction and nullable-safe count diagnostics. |

The successful JSON explicitly records `deviceEvidence=false`,
`messageDeliveryEvidence=false`, `restartEvidence=false`. It uses actual Windows
production-code account APIs, Registry issuance, three-hop transport, real
replica stores, signatures and node admission; not an in-process fake service.
This does not qualify installed MAUI, contact consent, text, attachment or group
delivery. Physical features remain0/4.

All four explicitly selected Windows test owners retain their separate
DPAPI-protected state. A successful acceptance owner does not reconcile the
earlier owners' incomplete outcomes. The probe retries only typed retryable
before-forward contact rejection within its original cancellation budget;
unknown completion is never automatically retried. The first object-restoration
failure and subsequent successful cold run do not prove a particular time-bound
predicate without further evidence. No clock checks were relaxed or backdated.

## Source checks and remaining qualification

- Node focused02:11/0/0/native0, including both activation flags mapping exactly
  one real endpoint, lost peer response/cold recovery and wrong-pin refusal.
- Shared focused02:27/0/0/native0, including bounded distribution retry, cancellation,
  unchanged timeout semantics, owned mutable scope, Retry-After and existing signed
  publication successors. [Shared scope](../../deep-client-shared/docs/testing/s05-network-closure-backoff-2026-10-15.md).
- Current static topology/contracts:26/0/0. The intermediate new contract test
  selected the wrong earlier switch block and failed; the selector was corrected,
  not the runtime assertion. Actual repeated Up/Verify independently passed.
- Final operator Debug build: native0, zero warnings/errors; executable88 PASS
  and static contracts26/0/0, native0, in `final-01/`. These are tooling checks,
  not service or device acceptance.
- Node canonical full01:1513/0/0, native test0, but qualification1 because the
  DR-0121 prose retirement lacked the required exact arrow binding. Original
  FullAccepted=false remains. The declaration is corrected without changing the
  semantic replacement; the shared gate now checks declarations before build
  as well as at final qualification,49 contracts/native0. A fresh full remains
  independently recorded below.
- Fresh Node canonical full02 accepted1513/0/0,1513 exact mappings and2191
  unchanged inputs; build/preflight/test/qualification all0, FullAccepted=true.
  This closes the single-endpoint source checkpoint only, not S05 lifecycle.
- Final changed-file secret scan selected/scanned25 files, zero findings;
  all five diff checks and three PowerShell AST checks passed.
- Protocol canonical full:2330/1/7,2338 exact mappings,1587 unchanged inputs;
  build/preflight/qualification0, native test1, FullAccepted=false. Only the
  original S08 retired-MAU2 package failure remains, with seven explicit skips.
  [Protocol scope](../../deep-protocol/docs/testing/s05-contact-scope-diagnostic-2026-10-15.md).
- New Shared full is not qualified. Common gate49 contracts passed under both
  Windows PowerShell5.1 and PowerShell7.6.5; these are tooling, not runtime gates.
- Mandatory current-source managed-external no-mock smoke and three-node
  infrastructure rehearsal both finished native0 in `infrastructure-01/`.
  The smoke snapshot has zero failed checks and its selected artifact scan
  passed. Rehearsal's own retained receipt is
  `artifacts/rehearsals/multi-node/20261015T004715851Z-02efdad772fe/`.
  Both disposed their scoped stacks; current-dev custody and production were
  untouched. These are infrastructure checks, not DID2 contact/message delivery.

The last one-line contact-only diagnostic retry restriction and generation-count
logging postdate the images02 Docker context capture. Actual host probes used
these changes; images03 now rebuilds the matching final publisher helper too.
Production, GitHub Releases and main were untouched.

## Next observed lifecycle boundary

The same-owner view57 success does not establish changed-view renewal. Ordinary
delegated publication advances PMT with the view; view58 exposed the explicitly
unimplemented PMT transition from DR-0071/0072/0078. The current rejection is the
required fail-closed behavior, not a reason to remove the exact-PMT check or use
historical route facts as current authority. Completing this S05 boundary needs
an explicitly bounded successor contract spanning authoring, threshold issuance,
protected pending custody, publication and replica/node verification. Earlier
incomplete owners remain a separate reconciliation boundary. The failed local
wrapper preparation for `acceptance-renewal-02/` did not launch the client;
`acceptance-renewal-03/` is the actual subsequent process receipt.
