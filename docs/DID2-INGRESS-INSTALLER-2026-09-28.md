# DID2 installer/H2 prerequisite — 2026-09-28

This is local implementation/transport evidence, not production peer TLS,
two-replica publication, device messaging or release approval. Seed1–seed3
remain production infrastructure with Mr. X's pre-user testing authorization.

## Implemented boundary

- XNode has independent exact-IP proxy trust for managed ingress and h2c
  privacy-peer listeners. Missing/invalid scheme headers reject before dispatch;
  managed proxy trust cannot authorize peer ingress. Ordinary API/RPC listeners
  never promote forwarded schemes; native peer TLS does not use forwarded trust.
- The canonical production compose and standalone installer asset select H2
  backends for the existing managed/privacy/replica routes. HAProxy strips
  caller forwarding headers and supplies only the consumed HTTPS marker.
  It no longer injects the supplemental host header rejected by the frozen
  managed-ingress contract. Protocol/header validation was not relaxed.
- Installer 0.8.0 accepts an explicitly prepared DID2 bundle, validates custody
  before selecting an immutable owner-only version, and retains the selection
  on rerun. Original registered Ed25519/BLS/Reality files and the production
  state volume remain unchanged. Diagnostic state is not imported. V1 contact
  and group authority activation is absent from this composition.
- The candidate explicitly selects the `UAT` diagnostic software profile on
  production hosts. Production activation remains guarded. Optional-terminal
  health is not a claim of publication/claim/message/group readiness.

Normative authority belongs to [DR-0012](../../docs/survival-program/decisions/DR-0012-protected-network-history.md)
and [the frozen ingress contract](../../deep-protocol/docs/deep-extension-managed-ingress-h2-v1.md).
Operator configuration is described in [the ingress runbook](PRODUCTION_NODE_TLS_INGRESS.md).

## Local checks

- XNode source-cutover Release: integration 451, core 262, profile generator
  107 passed; focused proxy/strict-header subset 63 passed. The first parallel
  integration invocation had one C3 failure; the unchanged focused C3 and
  two subsequent full integration invocations passed. No SLO threshold was
  modified; this observation is not a proof that timing flakiness is eliminated.
- Preparation/staging/static-ingress Node tests: 9 passed; static security
  contract: 34 checks. Structural signed-record fixtures do not mint authority.
- Real TLS/HAProxy lab passed at `2026-09-28T09:29:45Z`, including dedicated
  managed and privacy/replica H2 backends, caller-header sanitation, denied
  admin/quorum routes, exact served SPKI, stale attestation refusal and refresh.
  Echo backends are not XNode authority. Application/device verification fields
  are explicitly false. Exact isolated Docker/directory cleanup passed.
- The fresh-install environment example is now tracked as an exact allowed
  asset (it had been accidentally ignored). It contains placeholders rather
  than private deployment addresses and no retired fixed-role/compat setting.
  Installer tests check that fresh preparation and rerun retain the template.
- Three-node real-Xray rehearsal passed with `requireNoMock=true`, while
  unavailable privacy authority stayed fail-closed. This development lane is
  not authenticated DID2 delivery evidence.
- Public documentation rendered 20 Russian pages and passed 241 checks;
  dependency audit reported zero vulnerabilities. The npm wrapper had a local
  command-resolution error; its exact build/verification commands passed when
  run directly. Selected source/release-contract artifact secret scan passed.
- The required backend-external smoke was attempted but its artifact collector
  scanned the shared historical scratch root and rejected unrelated generated
  binaries. That invocation is **not passed**. An isolated artifact/project
  lane remains required before it can be release evidence; no scan exception
  was added to hide those findings.

## Retained-input and owner-CI checkpoint

- Owner CI run `36405059531`, attempt 2, completed successfully from DevOps
  `4467b09` with XNode `d4b7f2c`. Attempt 1 failed writing a Buildx layer
  (`not_found`); rerunning the same source succeeded. The candidate is
  `ghcr.io/xpointlabs/xnode@sha256:ed29ff6501e6d4e468d14fa9902f2e1d57c9bc35f7ab16c8954385552ec5ff4a`.
  It is not a GitHub Release or `latest` publication.
- Real private-input staging rejected the old origin certificates: DNS SAN
  was present but the signed IPv4 origin had no typed IP SAN. No failed bundle
  was deployed. The offline operator now supports the exclusive
  `--reissue-rollover-certificates true` mode with authority/rollover roots,
  three existing node roots and a fresh private output directory. It reissues
  current/next certificates with both exact origins while retaining private
  keys, SPKI pins, onion seeds and the original validity interval byte-for-byte
  where applicable. Existing output, redirected paths and mismatched keys/pins
  reject; no signer, network-history or registered-identity change is performed.
- Five bootstrap test groups passed, including complete six-certificate reissue,
  negative missing-IP-SAN, mismatched-key and existing-output cases. All three
  real node bundles then passed bounded custody staging and strict ingress
  preflight without the lab-certificate exception. These remain local input
  checks, not served TLS or device-delivery evidence.

Next: deploy the immutable reviewed image through the
supported installer preserving keys/floors, verify actual signed-origin peer
TLS, then complete two-replica publication/claim and Windows↔Android delivery.
No GitHub Release or `latest` publication is authorized by these local checks.
