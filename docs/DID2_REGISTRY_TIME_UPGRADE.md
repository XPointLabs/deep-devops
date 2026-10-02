# Existing DID2 Registry automatic-time transition

Normative owner: [DR-0068](../../docs/survival-program/decisions/DR-0068-manual-to-nts-protected-floor-upgrade.md).
Registry commands and report semantics: [candidate operator guide](../../deep-registry-api/docs/DID2_DIRECTORY_CANDIDATE.md).

`scripts/upgrade-did2-registry-time.cjs` is a narrow Linux Docker operator:
it runs only `provision-nts-floor`, `observe-trusted-time` or `refresh-current-head` in a disposable
candidate container. It does not promote/restart Registry, alter ingress,
reset state or floor, rotate keys, or touch other Docker services. Preserve the
new floor and its fence with the retained custody backups.

Require explicit deployment authorization, a retained protected manual-anchor
backup authenticated with its independent integrity key, its exact SHA-256,
the running source container's exact image ID, and the locally verified candidate
image ID/revision. Load that image using a verified archive before invoking:

```text
node scripts/upgrade-did2-registry-time.cjs --mode provision --container <exact-running-container> --source-image sha256:<source-id> --image sha256:<candidate-id> --revision <40-hex-commit> --manual-sha256 <retained-64-hex-hash>
```

Repeat with `--mode observe` to acquire real NTS under the exact signed policy.
After retaining a current ADA2/floor backup, `--mode renew` acquires NTS, proposes
a bounded head window, then invokes `refresh-current-head` under a second fresh
acquisition. Registry verifies the complete journal and independent PostgreSQL
floor, preserves content and atomically advances that floor before ADA2. This
mode does mutate the current signed head; it never resets account content,
genesis, registered keys or any rollback floor. It is not application promotion.
The script preserves the exact source environment except the three automatic
time settings, all bind mounts and their read/write flags. Provisioning has no
network; observation has the retained Docker network but no published ports.
Neither command grants application readiness or reusable freshness evidence.

For the DR-0069 DID2-only source image, use `--mode observe-did2` or
`--mode renew-did2`. These explicit modes omit only the three retired directory
configuration sections, and only when each present section is explicitly
disabled. Active or ambiguous old authority configuration rejects. No legacy
value is translated, no retained file is deleted, and every current DID2
credential, independent floor, ledger, mount and network setting is preserved.
The ordinary modes remain unchanged for the preceding diagnostic image.
This prepares a disposable operator only; it still does not promote Registry.

The floor uses the existing explicit path, or a new separate sibling of ADA2
named `nts-lower-floor.state` for a manual-only composition. Scope, duplicate
keys, mount aliases, source-image CAS and candidate revision are checked before
the owned command runs. Registry independently verifies cryptography and custody.
The temporary environment is mode 0600, outside repository artifacts; no values
or Docker stderr are printed. Disposable cleanup never removes mounted state.
An interrupted/pending transition must be resumed using the exact retained
manual hash, never repaired by deleting its fence or re-provisioning ADA2.

Verify script changes with `node --test scripts/upgrade-did2-registry-time.test.cjs`.
Synthetic script tests do not prove NTS, production activation or physical E2E.
