# Secret-safe UAT and release evidence

Program revision SHA256:
`ca5ad9f0c9d4dfb509dedcbf8133524c15867fce5534816da21ff86a07057383`.

Mr. X is the accountable human owner for credential rotation, UAT reactivation,
and evidence upload approval. Automation must fail closed and must never print,
hash into a report, archive, or upload a secret value.

## Mandatory irreversible UAT rotation

The previously tracked UAT mnemonic, three Ed25519 private seeds, and three BLS
private scalars are compromised. Deleting them from the current Git tree is not
revocation and does not remove them from history.

Mr. X must complete these steps in order:

1. Keep the current UAT stack stopped. Preserve only allowlisted, redacted
   evidence; delete local resolved Compose files and unrestricted raw logs.
2. Create a fresh UAT deployer wallet in an approved secret manager or offline
   wallet. Never type its recovery phrase into chat, source, a command line,
   shell history, CI variables, or an evidence manifest.
3. From a trusted wallet, transfer any required UAT ownership, roles, test
   assets, and gas away from the retired deployer. If a contract role cannot be
   transferred with confidence, redeploy the UAT contract set under the new
   wallet and treat all old addresses as retired.
4. Submit exits/revocations for retired service-node contract IDs 4, 5, and 6
   and verify final on-chain state. A local configuration change is not proof
   of revocation.
5. Generate three new Ed25519 identities and three new BLS keys independently.
   Do not derive or rotate them from the compromised values.
6. Store the new mnemonic and node keys in protected files created from
   `secret-templates/uat/`. Update `.env.uat` with secret-file paths and new
   public identities only.
7. Register the new public identities, verify proof of possession and on-chain
   membership, then validate registry/router mapping without printing private
   values.
8. Create a Mr. X-signed offline chain-verification attestation that binds the
   checked-in retired public fingerprint manifest, every retired contract node
   ID, every replacement operator/router/BLS public fingerprint, and exact
   transaction, contract, block, log, and finality metadata. Run
   `node scripts/uat-rotation-preflight.mjs --receipt <receipt.json> --secret-dir
   .secrets/uat --trusted-signer-sha256 <Mr-X-public-signing-key-sha256>`.
9. Run `node scripts/secret-scan.mjs`. The offline attestation gate does not
   call a trusted RPC and is not independent on-chain proof; it always reports
   `uatRestartAuthorized: false`. Keep UAT stopped until a separate reviewed
   chain verifier or Mr. X-approved independent chain review closes that
   blocker. Neither gate reads or records old secret values.

This rotation is intentionally irreversible. Rollback means returning to a
stopped UAT stack and removing the newly created local secret files; it never
means restoring a compromised key.

## Windows ACL procedure

Create `.secrets/uat` under this repository only on an encrypted workstation.
After copying the templates and filling values locally, Mr. X must restrict
each file to the current Windows account and `SYSTEM`:

```powershell
$secretDir = Resolve-Path .secrets/uat
icacls $secretDir /inheritance:r
icacls $secretDir /grant:r "$env:USERNAME:(OI)(CI)F" "SYSTEM:(OI)(CI)F"
icacls $secretDir /remove:g "Users" "Authenticated Users" "Everyone"
icacls $secretDir /T
```

Review the final ACL output by principal and permission only. Never display file
contents. On Linux, use owner-only directory mode and owner read/write file
mode. Backups must be encrypted and managed by the same secret owner.

## Evidence allowlist

`scripts/collect-artifacts.ps1` may collect only:

- `compose.topology.redacted.json`, containing service/name/state/health and
  public port numbers;
- `runtime.snapshot.json`, projected through a per-endpoint schema allowlist;
- `security/secret-scan-summary.json`, containing rule IDs and relative paths
  only.

The collector never runs resolved Compose output and never captures unrestricted
container logs. `compose.resolved.yml`, `compose.log`, private key files, local
environment files, crash dumps, databases, and shell transcripts are forbidden
release artifacts.

Every CI upload is prepared and scanned as an exact immutable set:

```powershell
node .\scripts\artifact-upload-manifest.mjs `
  --root .\artifacts\release `
  --require production-readiness-status.json `
  --staging <clean-staging-directory> `
  --manifest <upload-manifest.json>
node .\scripts\artifact-upload-gate.mjs `
  --manifest <upload-manifest.json> `
  --staging-root <clean-staging-directory> `
  --summary <fresh-scan-summary.json>
```

The manifest records required files, relative path, media type, extension,
size, and SHA256 for every subsequently uploaded file. Empty selections and
missing lane-required evidence fail before staging. The gate validates the
inspect-only schema and hashes before scanning, binds the fresh scanner result
to the exact manifest, then validates the unchanged manifest and staged file
hashes again. Scanner crash, timeout, non-zero exit, missing manifest/result,
policy-field mutation, file mutation, or staging mismatch prevents upload.

The scanner checks normalized relative file and archive-entry names, treats
unknown binary/non-text input as blocking, and recursively inspects ZIP, TAR,
GZ, APK, AAB, and MSIX entries with traversal, expanded-size, entry-count, and
depth limits. Raw UI bitmaps and arbitrary logs are never uploadable by
default. Opaque executable binaries and all `hash-only` handling are blocked.
They remain blocked until a separate cryptographically signed approval format,
pinned signer policy, and independent review are implemented.

Placeholder matching is exact. A credential literal that merely contains words
such as `REDACTED` or `NOT_COMMITTED` is still a finding. Artifact and archive
entry names normalized with Unicode NFKC and punctuation folding are rejected
when they represent mnemonic, seed, private-key, credential, wallet, keystore,
dump, database, or `.env` material.

## Rotation attestation boundary

`uat-rotation-preflight.mjs` verifies an Ed25519 signature whose public-key
fingerprint is supplied through the protected Mr. X procedure. The signed
version-2 payload must map contract node IDs 4, 5, and 6 to unique successful
exit/revocation transaction and log evidence. It must separately map each node
to a unique replacement contract ID, operator address, router public ID, BLS
public-key SHA256 fingerprint, registration transaction/log, and at least 12
confirmations relative to the attested finalized block.

This is explicitly a human-signed offline attestation. The script performs no
network request and cannot prove that the referenced chain data exists. Unit
tests use synthetic hashes only as fixtures; synthetic receipts are never
release evidence.

## No-secret rollback

This change does not rewrite Git history. Reverting the code commit does not
make retired credentials safe, and a wholesale Git revert would restore
compromised literals from the parent tree. Never revert this security commit as
a unit. Use a forward corrective commit that keeps every secret deletion,
ignore rule, and scanner control. A safe operational rollback keeps UAT
stopped, removes only newly created local secret files and evidence that failed
scanning, and re-provisions fresh credentials through the procedure above.
