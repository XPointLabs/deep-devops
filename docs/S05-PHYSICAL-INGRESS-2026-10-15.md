# S05 retained current-dev physical ingress

This checkpoint covers local development maintenance only. Production was not
changed. S05 remains active; physical contacts/text/files/groups remain 0/4 and
this is not release acceptance. Operational instructions belong to
[DEEP_DEV](DEEP_DEV.md); the producer contract belongs to
[DR-0120](../../docs/survival-program/decisions/DR-0120-signed-operational-origin-relocation.md).

## Implemented and activated

`PreparePhysicalIngress` seals an exact current-dev LAN maintenance candidate.
`ApplyPhysicalIngress` validates the candidate and current signed authority before
stopping services, installs only whitelisted same-key certificate/configuration
images, and publishes the exact signed origin successor through the retained
publisher journal. Only its public online intent/result directory enters that
one-shot publisher; the offline CA/private plan never do. The existing PKI guard
is unchanged. No client endpoint translation or permissive TLS callback is used.

The original CA, eight leaf private keys, node identities/BLS/onion custody,
genesis, volumes and protected floors are retained. Installation has resumable
before/after images while maintenance is incomplete. Once installed, validation
requires every after image: a predecessor image cannot silently restart. A sealed
publication result resumes exact bytes without another authoring operation;
later ordinary signed publisher successors preserve the relocated origins.

## Actual evidence

Receipts are under `artifacts/s05-physical-ingress-20261015/` in this repository.
These are local operator/infrastructure receipts, not shipping/device evidence.

| Receipt | Observed scope |
| --- | --- |
| `prepare-01/prepare.log` | Native0, sealed retained-custody candidate. |
| `apply-01/` | Native1, CryptographicException during prevalidation, before stop/copy. Cause remains unclassified; retained, not represented as fixed. |
| `apply-02/apply.log` | Same candidate, native0; exact signed origin publication and eight-service activation. |
| `verify-01/` | Native0; Registry proof and three verified ONION/contact-capable nodes. |
| `strict-tls-01/` | Native0; Windows strict custom-root/name/EKU/online-revocation validation, HTTP/2 ALPN and announced SPKI match on all three actual signed LAN origins. No trust-store root installation. |
| `resume-01/resume.log` | Already-installed branch completed and eight owners running. Original native session terminal was unavailable after handoff; log alone is not a qualified native0 receipt. |
| `focused-03/operator-tests.log` | Native0, 84 PASS checks including same-key SAN/CDP, sealed intent/result, exact pending-result resume, and installed predecessor-image rejection. |
| `focused-03/contracts.log` | Native0, 22/0/0 Node tests; actual Compose render, eight owners, retained volumes, exact listeners and no private CA/plan mount. |
| `focused-03/verify.log` | Native0 after engine recovery; current Registry/three ONION nodes, recovery9s. |
| `current-smoke-02/smoke.log` | Native0; `test-env.ps1 -Suite smoke -DeepDevProjectName deep-dev-current`. |
| `current-smoke-02/resume.log` | Native0; completed-install validation and retained-volume restart, no re-authoring. |
| `repository-checks-01/release-contracts.log` | Native0, 51 contract commands. The template fixture PASS is not actual release acceptance. |
| `repository-checks-01/readiness-status.log.stderr` | Native1, actual release blocked by ten missing evidence/sign-off inputs. Not waived. |
| `repository-checks-01/smoke.log.stderr` | Native1; default old-dev scope lacks required project metadata. Invocation error for this slice; corrected with explicit current-dev above. Old dev left untouched. |

Final focused log SHA256 values, respectively:

- operator: `F7691DE7C09AB8E2310C092A4C195906682A43ED7B2309ACC0B2FBD714884A8F`
- contracts: `FD5F870B695BB7E5F18D45A36D00F3DC96B2D09DBAE1C50CD51C5FE550D2F91C`
- Verify: `EB8982089D8EF7634F0A93046FC7CC6CF7918431A18F2B3FE3C65DAF331E8D24`

Independent read-only runtime/host comparisons after recovery matched retained
Ed25519, BLS, current/next onion and TLS private custody on all three nodes;
only boolean outcomes were emitted. PowerShell AST parsing passed. Android ADB
currently reports zero online devices; no Android physical result is claimed.

## Next lifecycle defect, not a remaining TLS diagnosis

The preserved Windows owned-client probe completed account restore, admission,
current network, initial prekey staging and onion custody. `windows-03/` then
failed at PreKeyPublication with the closed code `prekey-placement-changed`:
the immutable staged aggregate binds its original placement, but the transport
requires the current placement. The latter commits the exact current view/PMT
and therefore changes during ordinary operational renewal even when replica
ranking is unchanged. This is not an account/private-key or Docker TLS failure.

The account, exact inventory, unknown publication intent and floors remain
preserved. Do not reset/restage/re-sign to get a green probe, drop the comparison,
or treat the original publication as current authority. Resolve the lifecycle in
the normative ContactResolver owner together with the affected producer,
durable holder, replica and receipt-verifier paths, including interrupted and
already-committed cases. Then repeat the owned-client exchange before claiming
issuance/client/node acceptance or opening S06.

The prior Node full1508/0/0 and infrastructure smoke/rehearsal remain their
original scope. The subsequent Protocol canonical full completed2327/1/7,
2335 exact mappings and1587 unchanged inputs; build/preflight/qualification0,
test1 and FullAccepted=false. The sole failure remains the independent S08
retired-MAU2 package graph rejection; seven existing skips were preserved.
[Exact source receipt](../../deep-protocol/docs/testing/s05-origin-relocation-2026-10-15.md#integrated-source-qualification-after-the-operator-slice).
