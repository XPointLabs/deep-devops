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
delegated publication advances PMT with the view; view58 exposed the missing
logical-assignment/current-carriage lifecycle. That original rejection was
fail-closed under its then-current contract. The accepted
[DR-0122](../../docs/survival-program/decisions/DR-0122-logical-mailbox-assignment-carriage.md)
now owns the semantic clean break: preserve the exact original assignment and
independently verify current eligibility, logical-resource validity, issuance
history and fresh operation authority. It does not rewrite saved references,
revive expired routes or redispatch old mutation requests. The source candidate
has matching focused coverage; same-owner current-dev activation and final full
qualification remain open in [NEXT-SPRINT](../../docs/NEXT-SPRINT.md).
The historical receipts above are unchanged. Earlier incomplete owners remain
a separate reconciliation boundary. The failed local
wrapper preparation for `acceptance-renewal-02/` did not launch the client;
`acceptance-renewal-03/` is the actual subsequent process receipt.

## DR-0122 candidate: real opaque consumer and retained-owner retry

The same local project was rebuilt without resetting keys, accounts, volumes,
genesis or floors. Receipts are under `artifacts/s05-logical-assignment-20261015/`:

- `runtime-01/`: Build/Up/Verify/CRL native0; the retained owner reopened its exact
  prekey receipt pair, then got Unauthorized/None from the opaque publication
  consumer. Source review found its obsolete genesis-only/current-PMT checks.
- `runtime-02/`: Build native0. Up started all nine services but observer admission
  failed closed during recovery. This is not a successful Up or client result.
- `runtime-03/`: retry of supported Up native0; Verify native0 with Registry and
  three verified onion nodes, recovery105s; CRL native0. The same Windows owner
  reached view71 and reauthenticated its byte-identical prekey pair. Contact
  renewal stopped before replica dispatch in owned request verification.
- `runtime-04/`: the unchanged account/request retried with only closed diagnostic
  labels added. Native1, `request-window` confirms the original pending publication
  envelope no longer covers current protected time. No request, nonce, scalar,
  permanent generation fence or custody was replaced. No expiry check was waived.

The closed request diagnostic permits only `request-window`,
`request-authority-bound` and `owned-lineage`; it logs no times, identifiers,
capabilities, payloads or caller-supplied strings.

The matched XNode regression in
`xnode/artifacts/s05-logical-assignment-20261015/opaque-successor-03/`
passed19/0/0/native0 after a zero-warning build. It obtains real durable genesis
receipts before authoring the successor, then commits/reopens/replays both stores
and resolves signed generation1. Generation and receipt substitutions reject;
existing one-time tests stay strict. The first fixture attempt hit unchanged
service-expiry containment; the corrected bounded fixture then exposed the actual
genesis-only resolver defect. Both original failed receipts remain in place.
These are signed local source/storage tests, not remote or physical E2E.

The remaining original-intent recovery needs its separate bounded contract; an
unsigned Unauthorized/None result cannot release a permanent issuer fence, and
an expired XPU cannot be redispatched as fresh authority. This is not solved by
creating a fifth owner. Final source qualification, S05 and all physical delivery
claims remain open. Production, Releases and main were untouched.

## DR-0123 connected fresh-lease checkpoint

The target is owned by [DR-0123](../../docs/survival-program/decisions/DR-0123-retained-publication-intent.md).
XPL1 is the sole reusable mutation envelope; its original XPU/request/op/hash
and permanent winner remain unchanged. One-time genesis remains a separate
strict current operation. Neither the node saga nor protected route journal
changes format. No account, key, floor, volume or original intent was reset.

Exact receipts under `artifacts/s05-logical-assignment-20261015/`:

- `publication-lease-runtime-01/`: Build/Up/Verify/CRL native0; current owner
  reached view77 and reauthenticated the byte-identical prekey pair. Private
  coordination failed closed with unknown completion; no success is inferred.
- `publication-lease-runtime-02/`: Build/Up/Verify/CRL native0. The fresh lease
  passed, but publication received a terminal failure. Added closed HTTP/issuer
  diagnostics contain no payload, origin, identity or credential.
- `publication-lease-runtime-03/`: only the supported same-owner exercise, no
  rebuild/reset. The authenticated terminal code was `MalformedRequest`.
  Source review found the external DID2 dispatcher still decoding raw XPU;
  its ordinary complete-interval guard now consumes fresh lease metadata.
- `publication-lease-runtime-04/`: Build/Up/Verify/CRL native0; actual contact
  generation1 committed and was adopted. Owned grant/read returned unknown,
  preserved as a failed whole exercise, not empty-mailbox success.
- `publication-lease-runtime-05/`: supported exercise of the SAME retained
  owner, native0. The byte-identical prekey pair and saved contact generation1
  reauthenticated after reopen, then the current owned grant and node read
  returned an authenticated empty page. No further publication was required.

The existing bounded before-forward backoff remains; no unknown result frees
a fence or rewrites original bytes. Source checks include Shared26, Node57
(including real loopback TLS/H2 peer composition and restart), Protocol138 and
Registry24 with disposable PostgreSQL/TestServer, all without skips/failures in
their focused scopes. These are not installed MAUI or physical message delivery,
full source qualification, operational rollover acceptance or a release. Earlier
reserved-without-winner/expired-inner-resource owners remain separate recovery
work; this checkpoint does not replace them with another account.

## DR-0124 completed-winner read-back candidate

The contract is owned by [DR-0124](../../docs/survival-program/decisions/DR-0124-publication-winner-readback.md).
Physical MAUI020496d profiles passed bootstrap TLS/authority history, then both
reported unknown contact-publication completion. The retained Android retry
rejected its expired original request. Read-only database aggregates were
publication6/completed6/pending0 and route7/completed7/pending0; these counts do
not prove which request belongs to either physical client.

The matched source candidate adds one current signed READ of a completed winner,
not another issuance/mutation or a journal generation. Original requests,
nonces, generation fences, keys, floors and retained accounts stay unchanged.
Focused component receipts under each repo's
`artifacts/s05-winner-readback-20261015/` cover Shared5/0/0, Node23/0/0,
Protocol19/0/0; Registry's wrapper receipt is
`artifacts/s05-winner-readback-20261015/registry-focused-01/provider.log`, linking
its disposable PostgreSQL native3/0/0 run. The temporary test container and tmpfs
were removed by the supported provider; current-dev volumes were not touched.

The previous diagnostics-only runtime at
`artifacts/s05-local-device-20261015/route-diagnostic-runtime-01/` finished
Build/Up/Verify/CacheWindowsDevCrl0. It does NOT include this read-back candidate.
A supported retained rebuild/activation and physical rerun remain required.
No production machine, GitHub Release or main branch was changed by this slice.
