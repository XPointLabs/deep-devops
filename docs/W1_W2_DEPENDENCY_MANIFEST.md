# W1 contract closure and W2 dependency gate

Accountable human: Mr. X.

The local dependency boundary is:

- `release/manifests/survival-v2.1.0-w1w2-gate.detached.local.json`;
- `release/contracts/survival-compatibility-v2.1.0-w1w2-gate.json`;
- `release/evidence/w1w2-dependency-closure.json`.

This boundary closes only the accepted W1 contract identities needed for
subsequent design work. It does not complete W2, approve P05, activate P04
runtime crypto, deploy a service or make a production-readiness claim.

## Detached carrier

The manifest pins DevOps carrier
`524c5796aa868fa3d057fbf7eaa13cfea2e0d19c`. The compatibility contract is
read as raw Git bytes from that commit and has SHA-256
`c45f66f7a688cbd70b7ca57a777851962ce2ab59eb37a3304d9b4bf7e4c55719`.
The contract's DevOps runtime base is the carrier's exact first parent,
`1eb9a2a40ce01ce0f8c924e9dafaf3752b197d31`. The detached manifest therefore
does not require a self-referential hash.

The manifest itself is distributed by raw SHA-256:
`920b24bb5bcfcc8b4f91aef56ed210127246ec9fd2d49178ed9856c8555d0b93`.

## Producer evidence

P04 is pinned as a reviewed contract package, with source, reviewed evidence,
final evidence, package version, package manifest and all three NuGet package
hashes recorded independently. P04 runtime activation remains blocked because
there is no approved production signature adapter, durable trust state, key
ceremony or external cryptographic review.

P05 is pinned as `design-review-go-proposed-not-approved`. Its source/design
commit, exact reviewed evidence and final evidence are distinct pins. The ADR
continues to carry `NOT-APPROVED`; no package exists and
`runtimeAuthorized=false`. P08 and P09A/P09B/P09C remain blocked.

Strict verification reads every listed producer artifact from the exact Git
evidence commit as binary bytes, verifies byte length and SHA-256, and proves
source -> reviewed evidence -> final evidence ancestry. A local source map is
an execution input only. It contains machine-local paths, is ignored, and must
never be committed or included in evidence.

The strict closure gate is mandatory in the release-contract suite. Missing
`DEEP_W1W2_PRODUCER_SOURCE_MAP` fails the suite; there is no shape-only green
path for this closure. Producer Git inspection clears repository-selection,
object-database, replacement and injected config environment, disables
replacement objects and fsmonitor, and rejects replace refs, grafts, object
alternates and shallow repositories before checking ancestry or bytes.

Example local-only verification:

```powershell
node .\scripts\pinned-integration-manifest.mjs `
  --manifest .\release\manifests\survival-v2.1.0-w1w2-gate.detached.local.json `
  --producer-source-map .\artifacts\local-w1w2-producer-source-map.json `
  --verify-producer-artifacts `
  --validate-only

node .\scripts\w1w2-dependency-closure-gate.mjs
```

## Gate interpretation

`release-gate-contracts.mjs` uses synthetic placeholder inputs to test release
gate behavior. A green result from that script is not real release evidence.
The actual production-readiness status remains blocked until real device,
operations, security, GA and deployment evidence exists.

All work is offline/local-only. Network restore, external package publication,
Git push, Docker execution and deployment are forbidden for this closure.
