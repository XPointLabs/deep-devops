# Production-like update key ceremony

Accountable human: Mr. X.

Status: ceremony-grade TEST-only dry-run implemented. Production activation is
`BLOCKED`; production signing and publication are `NOT-RUN`.

This runbook operationalizes the update-trust design in
`docs/adr/0001-update-trust-offline-distribution.md` without claiming that the
current repository has production custodians, hardware keys, independently
controlled builders or publication authority.

## Stop-the-line production blockers

Production activation requires all of the following external facts:

1. At least three named independent human root custodians. Mr. X is the
   accountable owner but does not count as three independent people.
2. Reviewed production HSM/offline-device provisioning and retained public
   attestation evidence.
3. Explicit production publication authorization.
4. Retained independently controlled build attestations proving reproducibility.
5. Independent security review of the implementation and ceremony evidence.

The TEST-only evaluator always returns `BLOCKED/NOT-RUN`, even if a caller
passes names, booleans and plausible-looking hashes. Production readiness
requires a separately implemented verifier for a signed
`deep.external-security-review-attestation.v1`; this dry-run deliberately
cannot produce `READY-FOR-INDEPENDENT-AUTHORIZATION`.

Those facts do not currently exist. The machine summary must therefore retain:

```text
activationStatus = BLOCKED
activationRun = NOT-RUN
productionPublication = NOT-RUN
productionHsmVerified = false
independentCustodyVerified = false
reproducibleBuildVerified = false
```

Changing those fields from CI output, TEST signatures or Mr. X's sole approval
is prohibited.

## Production root ceremony design

The planned root ceremony is 2-of-3:

- three named independent custodians use separate offline hardware devices;
- each custodian verifies the canonical raw root payload hash on a separate
  trusted display;
- no device exports key material;
- two custodians sign the same exact canonical payload through the offline/HSM
  interface;
- a separate verification station checks key IDs, signatures, role thresholds,
  version increment and expiry;
- root rotation must satisfy both old and new thresholds over identical bytes;
- only public root metadata, hashes and redacted attendance evidence leave the
  room.

Targets and `android-release` use separate 2-of-3 signer sets. Snapshot and
timestamp each use a distinct 1-of-2 role: one online primary plus one sealed
offline recovery signer. The recovery drill signs fresh metadata with the
recovery signer, rotates the root to install a new primary while retaining the
recovery signer, accepts the replacement primary, then rejects both revoked
old primaries. A same-root 1-of-1 replacement is not accepted as recovery.
Lowering a threshold because a key or person is unavailable is not a recovery
procedure.

The current dry-run simulates these threshold shapes with ephemeral Ed25519
TEST keys in one process. It does not simulate independent people, separate
devices or an HSM.

## Offline/HSM interface

`scripts/update-ceremony.mjs` signs through a handle-only adapter:

```text
sign({ keyHandle, canonicalPayloadBytes }) -> signatureBytes
```

Ceremony orchestration receives the public key, key ID and opaque handle. It
does not receive seed bytes, a private-key export or an environment variable
containing key material. The dry-run adapter generates Ed25519 TEST keys in
memory, accepts only `TEST-ONLY:` handles and clears its handle map on exit.
TEST key material is not written to the output directory or Git.

A production adapter must replace this implementation with a reviewed HSM or
offline-device transport. Merely renaming the TEST adapter is not production
evidence.

## Delegated online release request boundary

Ordinary CI may request a release but cannot sign root or delegated targets.
The canonical `deep.delegated-release-request.v1` contains only:

- request ID and TEST-only/non-production flags;
- source commit and resilient-program revision hash;
- three sorted public target descriptions: Android artifact, CycloneDX SBOM
  and build-evidence provenance;
- exact byte lengths, SHA-256 hashes and media types;
- a digest of the complete canonical request body.

Unknown properties, changed hashes, production authorization, key/seed fields
or extra authority fail closed. Offline/delegated signers independently read
the target bytes and construct canonical targets metadata; the request is not
itself signing authority.

## Canonical metadata and distribution trees

The dry-run generates exact canonical raw metadata compatible with the P02B
verifier:

- sequential root v1 and cross-signed root v2;
- top-level targets and terminating `android-release` delegation;
- snapshot descriptions bound to exact metadata bytes;
- timestamp bound to exact snapshot bytes;
- artifact, SBOM and build-evidence target descriptions.

Two local mirror trees and one offline bundle are generated from the same byte
map. Metadata paths contain the SHA-256 of the exact raw metadata bytes.
Target paths contain the target SHA-256. `release-index.json` maps signed role
and target names to addressed paths. The verifier compares the complete sorted
path/length/hash inventory and checks that every content-address matches. It
then reloads the exact bytes independently from mirror A, mirror B and the
offline bundle, follows each index, parses the canonical raw metadata again,
and feeds each reconstructed bundle through the P02B metadata plus
SBOM/provenance verifier.

The TEST Android payload is a text descriptor, not an APK and never an install
candidate. The two TEST builder labels satisfy the P02B contract fixture but
are not independently controlled build attestations; reproducibility therefore
remains unverified.

## Required drills

Every dry-run must prove:

- root v2 is accepted with both old and new 2-of-3 thresholds, while executed
  old-only, new-only and one-old/one-new insufficient variants are rejected;
- recovery-signed snapshot and timestamp metadata is accepted, root v3 installs
  replacement primaries, and both revoked old primaries are rejected;
- a changed mirror byte causes complete-tree comparison to fail;
- trusted-version rollback is rejected;
- expired timestamp/freeze metadata is rejected;
- restored mirror trees and offline bundle are byte-identical;
- P02B metadata and SBOM/build-evidence verification passes.

These are TEST contract drills. They are not production publication, custody,
HSM or real builder evidence.

## Commands

Focused dry-run:

```powershell
node --test .\scripts\update-ceremony.test.mjs
$out = Join-Path $env:TEMP "deep-p02c-dry-run"
New-Item -ItemType Directory -Path $out
node .\scripts\update-ceremony.mjs dry-run --output-root $out
```

Repository contract evidence:

```powershell
node .\scripts\update-ceremony-contracts.mjs `
  --artifact-dir .\artifacts\generated\P02C
node .\scripts\secret-scan.mjs `
  --artifacts .\artifacts\generated\P02C `
  --summary .\artifacts\generated\P02C-secret-scan.json
```

No command contacts a mirror, blockchain, signing service or HSM. All mirrors
are local directories. Do not publish the generated TEST metadata.

The contract runner accepts only a path below `artifacts` that contains a
distinct `generated` segment, rejects the historical `artifacts/survival`
namespace, checks the boundary before cleanup, and only replaces that narrow
ignored directory.

## Cleanup

Delete the dry-run output directory after review. The runner destroys its
in-memory TEST-key handle map in `finally`. If any private-key representation,
seed phrase or production credential appears in output, stop the line, preserve
only the finding metadata and delete the unsafe dry-run directory.
