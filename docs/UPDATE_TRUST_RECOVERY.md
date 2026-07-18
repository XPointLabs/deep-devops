# Update trust operations and recovery

This runbook applies to the P02 update-trust design in
`docs/adr/0001-update-trust-offline-distribution.md`. It never authorizes
production key import into CI. Mr. X performs every human step.

## Normal offline release

1. Start from a clean, manifest-pinned source checkout.
2. Produce the APK twice on independently controlled builders with the same
   build definition and `SOURCE_DATE_EPOCH`.
3. Stop if the APK hashes differ.
4. Generate CycloneDX SBOM and reproducibility provenance, then bind all three
   target hashes in delegated `android-release` metadata.
5. Meet the delegated targets threshold on isolated signing devices.
6. Emit every metadata file as its exact canonical POUF bytes. Reject BOM,
   whitespace, alternate key ordering, and alternate numeric representations.
   Generate snapshot descriptions over the exact raw target-metadata files.
7. Generate a fresh timestamp. Never extend an expiry merely to pass a gate.
8. On an offline verification station, start from a previously trusted root and
   run the verifier with the Android SDK `apksigner` whose exact executable hash
   is pinned in a protected local tool policy, not copied from release media.
9. Copy only public metadata, target files, and redacted verification summaries
   to distribution media.
10. Run the secret scan over the exact media manifest before handoff.

The verifier state must contain the trusted-root version and SHA-256 of the
exact raw trusted-root file plus the `timestamp`, `snapshot`, `targets`, and
delegated-role versions. The CLI refuses to start when the supplied trusted
root does not exactly match that binding. Each accepted root rotation is
atomically persisted before timestamp processing; final role versions are
atomically replaced after the complete cycle. Deleting or editing state to make
an older/different bundle acceptable is rollback.

## Suspected CI compromise

1. Stop publication and preserve immutable logs. Do not use the suspect CI
   runner to declare itself clean.
2. Mr. X identifies every key and signing service reachable from CI.
3. Root and targets keys should be unreachable by design. If they were exposed,
   stop the line and rotate the affected role through an offline root ceremony.
4. Rotate snapshot and timestamp keys even when exposure is uncertain.
5. Rebuild from a reviewed commit on two clean builders.
6. Publish a sequentially versioned root that is signed by both old and new root
   thresholds. Do not skip a root version.
7. Publish fresh targets, snapshot, and timestamp metadata. Root rotation of
   snapshot/timestamp roles invalidates cached metadata for those roles.
8. Verify that old online keys now fail as unknown signers.
9. Distribute the public recovery chain out of band and retain the drill
   summary. CI recovery is not self-approved; Mr. X records the decision and an
   independent reviewer must later confirm it.

If a threshold of root keys may be compromised, ordinary in-band root rotation
is no longer sufficient. Suspend updates and recover through an independently
authenticated out-of-band root shipped with a trusted application or physical
ceremony. Assume clients updated under the compromised threshold may already be
lost.

## Lost or compromised online key

The checked-in drill models a lost timestamp key:

1. Disable the signing endpoint and preserve its public key ID.
2. Prepare root version `N+1` removing that key and adding the replacement.
3. Meet the old root threshold over the exact canonical `N+1` document.
4. Independently meet the new root threshold over that same document. Test
   old-only and new-only signature sets; both must fail.
5. Verify every root version from the last trusted root through `N+1`, then
   atomically persist `N+1` and its exact raw-file SHA-256.
6. Delete cached timestamp/snapshot state when those role keys change.
7. Sign a fresh snapshot/timestamp with the replacement key.
8. Prove that replacement metadata is accepted and metadata signed only by the
   revoked key is rejected.
9. Archive only public metadata and the redacted result under
   `artifacts/survival/P02`.

For a lost targets key below threshold, rotate it in new root metadata and sign
new target metadata. For a lost root key below threshold, use the remaining old
threshold to authorize a new root set. Never lower a threshold merely because a
key is unavailable.

## Expiry and outage drill

1. Fix update-start time once at the beginning of verification.
2. Verify a current offline bundle succeeds with networking disabled.
3. Advance the test clock beyond timestamp expiry and prove the same bundle
   fails as frozen.
4. Use the sealed timestamp/snapshot recovery signer to create fresh public
   metadata without changing target bytes.
5. Prove the new timestamp is accepted and the prior trusted version is not.
6. Restore the signer to protected storage and scan the public evidence.

This drill does not solve an untrusted or badly wrong device clock. A trusted
time source or monotonic secure time policy is required before a mobile client
implementation can claim freeze protection.

## Prototype commands

Run contract fixtures and produce ignored public evidence:

```powershell
node --test .\scripts\update-trust.test.mjs
node .\scripts\update-trust-contracts.mjs
node .\scripts\secret-scan.mjs `
  --artifacts .\artifacts\survival\P02 `
  --summary .\artifacts\survival\P02\secret-scan-summary.json
```

Expected public outputs:

- `update-trust-summary.json`
- `negative-scenarios.json`
- `root-rotation-drill.json`
- `lost-online-key-drill.json`
- `offline-android-verification.json`
- `sbom-reproducibility-contract.json`
- `public-test-metadata/*.json`
- `secret-scan-summary.json`

The synthetic APK payload exists only in a temporary test directory and is
deleted. It is never published or copied into the evidence directory.

The production-like, still TEST-only multiperson ceremony design and delegated
release-request boundary are specified in `docs/UPDATE_KEY_CEREMONY.md`.
Production activation remains blocked until every external custody, HSM,
publication, reproducibility and independent-review prerequisite in that
runbook is independently evidenced.
