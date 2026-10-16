# S05 — retained prekey publication and Windows owned-client checkpoint

Date: 2026-10-15. Owner: Mr. X. Source candidate, not release/device acceptance.
Semantics: [DR-0121](../../docs/survival-program/decisions/DR-0121-prekey-publication-placement-lifecycle.md).
Operator workflow: [DEEP_DEV](DEEP_DEV.md). No production change was performed.

## Coherent slice

The current-only local contour keeps three original node identities and all
existing sealed keys, CA, signed histories, journals and protected floors.
The physical overlay adds one pinned HAProxy service (nine owners total), not
another node or a direct client fallback. The same signed TLS origins expose
public H2 and authenticated peer paths separately. Public traffic uses the
existing managed H2 listener and exact trusted proxy; peer traffic retains
backend CA/CRL/name verification and application authentication. Management
paths are not exposed. Original TLS leaves are assembled in private tmpfs;
no node identity/BLS/offline-root directories are mounted into the proxy.

Preserved failed attempts diagnosed peer-only listeners returning404, HAProxy
configuration/defaults and DER-CRL loading, HTTPS scheme on cleartext H2 causing
502/refused streams, and forbidden Date/Server response headers. The fixes keep
the signed carrier's request/response checks; they do not relax canonicality.
Installed-image rebuild now validates sealed configuration rather than rewriting
it. The public readiness probe uses exact media headers, strict TLS/H2 and a
bounded response. These are infrastructure results, not message delivery.

Independent actual Windows TLS probes matched every signed node SPKI while the
production HttpClient intermittently rejected a certificate pin. Disabling TLS
session resumption only in the typed signed-entry constructor changed the same
retained client's prekey publication from failure to success. This supports a
resumed-session certificate-binding diagnosis; OS cache internals were not
instrumented. Pin, name, EKU, validity and current entry checks are unchanged.
CA-managed Registry HTTPS is unaffected. Tests inspect the actual configured
handler options, not a source-text assertion.

## Exact receipts

Artifact prefix: `artifacts/s05-prekey-placement-20261015/` in this repository.

| Receipt | Observed outcome |
| --- | --- |
| `image-01/build.log` | Native0; supported current-dev image build, sealed inputs preserved. |
| `connected-14/` | Actual Windows production-code prekey publication completed; both real replica XIC1 verified. Contact publication then rejected before forwarding. |
| `connected-15/` | Same protected prekey pair reauthenticated byte-identically after cold reopen. Contact publication failed `DeepIdV2PublicationCommitVerifier.RequireResult`; its original response status was not captured. |
| `connected-17/` | Native1. Same pair again reauthenticated unchanged; contact now fails `DeepIdV2RouteContext.RequireAdvertisementScope` during retained-threshold verification, before a new successful commit. |
| `qualification-01/verify.log` | Native0 after engine recovery; current Registry proof and three verified nodes, recovery14s. |
| `qualification-01/contracts.log` | Native0;24/0/0, including actual Compose rendering and closed ingress/custody assertions. |
| `qualification-01/operator.log` | Native0;84 PASS checks, no compiler diagnostics. |

The attempted `connected-16` wrapper did not create a runtime receipt and is
not counted as an executed probe. Failed attempts remain preserved. No claim is
made that changing TLS policy fixed contact publication or its pending recovery.

Matching source evidence:

- [Protocol](../../deep-protocol/docs/testing/s05-prekey-placement-2026-10-15.md):
  focused155/0/0; canonical2330/1/7,2338 exact mappings,1588 unchanged inputs,
  existing MAU2 actual-package FAIL and seven original skips retained.
- [Shared](../../deep-client-shared/docs/testing/s05-prekey-tls-2026-10-15.md):
  focused28/0/0/native0; new full not yet qualified.
- [Node](../../xnode/docs/testing/s05-prekey-placement-2026-10-15.md):
  focused118/0/0/native0; new full not yet qualified.

## Next boundary

Keep the same Windows owner, protected inventory, exact unknown publication and
node stores. The original non-commit response needs classification; the later
XRA scope rejection is a separate retained/current-authority recovery boundary,
not evidence that the original response was caused by the same predicate.
Current code renews fully committed phase7 contacts, but that alone does not
recover an incomplete publication. Authenticate/reconcile the original outcome
before authoring any successor; do not reset, re-sign or waive current checks.

Owned grant/node read, S05 acceptance and all physical contacts/messages/files/
groups remain unqualified. The earlier Android-disconnected observation is
historical; the 2026-10-16 read-only check found one authorized USB device.
No GitHub Release or main merge is authorized by this evidence.

## DR-0131 consumer/runtime checkpoint, 2026-10-16

The owned probe now uses the single maintenance/publication command described
in [DEEP_DEV](DEEP_DEV.md), without removed initial-only API aliases. The same
exact XPP1 requires the exact retained receipt pair; genuine renewal is not
misclassified as corrupted retry custody. The explicit route-issuer fixture
authors/stages real signed support and independently verifies it, without
pretending to dispatch an inventory.

`artifacts/s05-prekey-maintenance-20261016/image-15` built all three supported
images, native0 with no compiler warnings/errors. `up-16` exited0 and ran those
exact images on Registry, both role signers, publisher and all three nodes.
Its retained before/after snapshots prove all29 volume bindings unchanged.
The raw25-bind hash comparison failed: Docker inspect alternates Windows drive
paths and Docker Desktop host mappings. A separate bounded mapping check matched
each old hash uniquely using only equivalent drive/separator/Desktop source
representations, with exact destination/type/RW and retained scope. Both results
remain distinct in the preservation receipt; no reset/reprovision was performed.
Supported smoke17 exited0: current Registry proof, all3 verified ONION nodes,
recovery37s within the original bound. Sustained readiness, retained-account
recovery and physical business acceptance are separate requirements;
image/Up/readiness success does not satisfy them.

The26 DevOps contracts passed. Registry consumer14 passed3 actual PQ/PostgreSQL
route/recovery cases/native0, no failures/skips; its earlier consumer12 wrapper
failure and consumer13 fixture compile error are not passes. Windows QA
CompileOnly11 passed0 warnings/errors but did not publish, install or launch.
Neither production nor GitHub Releases/main was changed.
