# P02C handoff

Accountable human: Mr. X.

Independent reviewer checklist:

1. Confirm production activation remains `BLOCKED/NOT-RUN` and no evidence file
   names independent custodians or claims a production HSM.
2. Confirm TEST Ed25519 keys are generated at runtime, retained only behind
   opaque `TEST-ONLY:` handles and never written to disk.
3. Mutate the release request with key/seed fields, extra authority, changed
   hashes and production authorization; each must fail.
4. Verify root rotation needs old and new 2-of-3 signatures over identical
   canonical bytes.
5. Verify the replacement timestamp key succeeds and the revoked key fails.
6. Verify mirror byte mutation, rollback and freeze drills reject.
7. Compare both local mirrors and offline bundle as complete byte-identical
   content-addressed trees.
8. Confirm P02B metadata plus SBOM/build-evidence verification passes.
9. Confirm TEST builder labels are not described as independent or reproducible
   build proof.
10. Run the focused tests, full release gates and secret scanner. Inspect both
    file names and content for key material.

No push, network publication, Docker stack, blockchain action, HSM call or
production signing is authorized by this handoff.
