# Pinned multi-repository integration

## Purpose

The survival release is reproducible only from the exact repository commits in
`release/manifests/survival-v2.0.0.json`. Branch names are informational. They
are never accepted as integration evidence.

Mr. X is the accountable human owner for accepting a new program revision,
compatibility artifact, repository matrix, or release handoff. Automation and
agents may prepare evidence but cannot silently move any pinned value.

## Files

- `release/manifests/survival-v2.0.0.json` pins all repository URLs and SHAs.
- `release/contracts/survival-compatibility-v2.0.0.json` is the immutable
  compatibility contract referenced by name, version, and SHA256 from every
  repository entry.
- `release/manifests/survival-v2.0.1-i01b.local.json` is the immutable,
  local-only I01B integration matrix. Its changed branch names describe local
  branches and do not assert that those branches or commits were pushed.
- `release/contracts/survival-compatibility-v2.0.1-i01b.json` is the immutable
  I01B compatibility contract. The manifest records its exact SHA256.
- `artifacts/survival/I01B/integration-review.json` records the accepted local
  review results and the external scenarios that remain not run.
- `release/pinned-program-revision.json` is the accepted P00A program revision.
- `release/local-feed-policy.json` forbids network restore and external package
  publication. The local feed is `artifacts/packages/survival-v2.0.0`.
- `release/schemas/` contains the manifest, evidence, and handoff contracts.

## Local validation

Validation has no package dependencies and performs no network access:

```powershell
node .\scripts\pinned-integration-manifest.mjs --validate-only
node .\scripts\pinned-integration-manifest.mjs `
  --manifest .\release\manifests\survival-v2.0.1-i01b.local.json `
  --validate-only
node --test .\scripts\pinned-integration-manifest.test.mjs
```

The validator fails closed for a branch-only ref, an unaccepted program
revision, a modified contract artifact, an incompatible repository matrix, or
an external package-feed policy.

## Exact isolated checkout

Prepare a local source directory containing one clean Git worktree per
manifest repository. Every worktree must have the manifest URL as `origin` and
must already contain the pinned commit object. The command does not fetch:

```powershell
node .\scripts\pinned-integration-manifest.mjs `
  --source-root C:\Work\DeepSession\XPointLabs `
  --checkout-root C:\W\deep-survival\integration-v2 `
  --evidence C:\W\deep-survival\evidence\pinned-integration.json `
  --handoff C:\W\deep-survival\evidence\pinned-handoff.json
```

The checkout root must be absent or empty and must not be inside the source
root. Each repository is cloned locally without hardlinks, checked out
detached at the exact SHA, then verified clean. Evidence contains both the
expected and actual SHA for every repository.

The source worktree is rejected if it is missing, dirty, has a different
origin, or does not contain the pinned object. A partially populated checkout
is not release evidence.

## Package policy

Dependencies intended for this release must be staged in the local immutable
feed before integration. Network restore and publication to NuGet, npm, GitHub
Packages, or another external registry are outside P00B and explicitly
forbidden by the checked-in policy.

## Handoff and rollback

Successful execution writes schema-validated integration evidence and a
handoff with no blockers. The generated checkout is isolated from every source
repository; rollback is deletion of only the explicitly supplied checkout
root. Never delete or reset the source worktrees.

Changing any pinned SHA requires a new compatibility artifact, its new SHA256,
an updated manifest, a new accepted program revision when product scope
changes, and Mr. X review.

The I01B matrix remains `local-reviewed/unpublished`. The manifest schema only
allows `pinned` or `verified` per repository, so publication state is recorded
in the I01B review artifact rather than overloaded into `evidenceStatus`.
Neither a valid local manifest nor a green synthetic gate authorizes UAT
restart or establishes production readiness.
