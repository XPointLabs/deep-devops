# P02C handoff

Accountable human: Mr. X.

Independent reviewer checklist:

1. Confirm production activation remains `BLOCKED/NOT-RUN` and no evidence file
   names independent custodians or claims a production HSM.
2. Confirm TEST Ed25519 keys are generated at runtime, retained only behind
   opaque `TEST-ONLY:` handles and never written to disk.
3. Mutate the release request with key/seed fields, extra authority, changed
   hashes and production authorization; each must fail.
4. Verify executed old-only, new-only and one-old/one-new root-v2 variants
   reject while the four-signature cross-signed variant passes.
5. Verify distinct snapshot and timestamp roles are each 1-of-2
   primary-plus-sealed-recovery; recovery signatures pass, root v3 installs
   replacement primaries, and both revoked old primaries fail.
6. Verify mirror byte mutation, rollback and freeze drills reject; mutate the
   async negative-drill helper so an accepted path proves the helper fails.
7. Compare both local mirrors and offline bundle as complete byte-identical
   content-addressed trees, then reload exact indexed bytes from all three.
8. Confirm each reloaded tree passes the P02B metadata plus
   SBOM/build-evidence verifier and binds actual Git HEAD plus the executed
   ceremony-program SHA-256.
9. Confirm TEST builder labels are not described as independent or reproducible
   build proof.
10. Run the focused tests, full release gates and secret scanner. Inspect both
    file names and content for key material.
11. Confirm the runner rejects `artifacts/survival/P02C`, writes only below a
    distinct `artifacts/**/generated` path, and preserves the tracked handoff.

No push, network publication, Docker stack, blockchain action, HSM call or
production signing is authorized by this handoff.
