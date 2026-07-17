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
$owner = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
$system = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18')
$allow = [System.Security.AccessControl.AccessControlType]::Allow
$full = [System.Security.AccessControl.FileSystemRights]::FullControl
$inherit = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'
$noneInherit = [System.Security.AccessControl.InheritanceFlags]::None
$nonePropagate = [System.Security.AccessControl.PropagationFlags]::None

$dirAcl = [System.Security.AccessControl.DirectorySecurity]::new()
$dirAcl.SetOwner($owner)
$dirAcl.SetAccessRuleProtection($true, $false)
$dirAcl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(
  $owner, $full, $inherit, $nonePropagate, $allow))
$dirAcl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(
  $system, $full, $inherit, $nonePropagate, $allow))
Set-Acl -LiteralPath $secretDir -AclObject $dirAcl

Get-ChildItem -LiteralPath $secretDir -File | ForEach-Object {
  $fileAcl = [System.Security.AccessControl.FileSecurity]::new()
  $fileAcl.SetOwner($owner)
  $fileAcl.SetAccessRuleProtection($true, $false)
  $fileAcl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(
    $owner, $full, $noneInherit, $nonePropagate, $allow))
  $fileAcl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(
    $system, $full, $noneInherit, $nonePropagate, $allow))
  Set-Acl -LiteralPath $_.FullName -AclObject $fileAcl
}
```

Review the final ACL by SID and permission only. The gate requires a protected,
non-inherited ACL containing exactly the current owner SID and `SYSTEM`, both
with full control; no third principal is accepted. Never display file contents.
On Linux, the directory must be exactly `0700` and every file exactly `0600`.
Backups must be encrypted and managed by the same secret owner.

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
  --summary <fresh-scan-summary.json> `
  --bundle <sealed-evidence.json>
```

The manifest records required files, relative path, media type, extension,
size, and SHA256 for every subsequently uploaded file. Empty selections and
missing lane-required evidence fail before staging. The gate validates the
inspect-only schema and hashes before scanning, binds the fresh scanner result
to the exact manifest, then validates the unchanged manifest and staged file
hashes again. Scanner crash, timeout, non-zero exit, missing manifest/result,
policy-field mutation, file mutation, or staging mismatch prevents upload.
The gate emits one sealed JSON bundle outside the staging root. CI uploads
exactly that single file, downloads the same artifact to a fresh directory,
and verifies the bundle SHA256, embedded raw manifest and scan summary, every
payload hash, and the Actions artifact ID/digest metadata. These receipts
remain explicitly non-production and untrusted until independent publication
policy accepts the Actions archive-digest semantics.
Downstream release workflows first verify the self-seal, embedded hashes,
producer Actions run ID, and source commit/tree, then extract into a new empty
directory. They do not accept an unverified raw-artifact fallback.

The scanner checks normalized relative file and archive-entry names and treats
unknown binary/non-text input as blocking. Every archive, container, and
application-package format is currently blocked by extension and file magic,
including ZIP, TAR, GZIP/TGZ, 7z, RAR, APK, AAB, and MSIX. Parsers still inspect
recognized formats defensively to report embedded findings, but even a clean
archive cannot be uploaded. Raw UI bitmaps and arbitrary logs are also never
uploadable by default. Opaque executable binaries and all `hash-only` handling
remain blocked until a separate cryptographically signed approval format,
pinned signer policy, complete metadata parser, and independent review are
implemented.

Placeholder matching is exact. A credential literal that merely contains words
such as `REDACTED` or `NOT_COMMITTED` is still a finding. Artifact and archive
entry names normalized with Unicode NFKC and punctuation folding are rejected
when they represent mnemonic, seed, private-key, credential, wallet, keystore,
dump, database, or `.env` material.

## Rotation attestation boundary

`uat-rotation-preflight.mjs` verifies an Ed25519 signature whose public-key
fingerprint is supplied through the protected Mr. X procedure. The signed
version-2 payload must map contract node IDs 4, 5, and 6 to unique successful
`ServiceNodeExit` or `ServiceNodeLiquidated` transaction and log evidence using
the exact ABI-derived topic and decoded identity arguments. It must separately map each node
to a unique replacement contract ID, operator address, router public ID, BLS
public-key SHA256 fingerprint, registration transaction/log, and at least 12
confirmations relative to the attested finalized block.

This is explicitly a human-signed offline attestation. The script performs no
network request and cannot prove that the referenced chain data exists. It
does not consume raw receipt/log bytes for local ABI decoding or independently
recompute BLS event material from a trusted RPC. Therefore it always returns
`uatRestartAuthorized: false`; restart still requires a reviewed raw-log
verifier or an independent Mr. X chain review. Unit tests use synthetic hashes
only as fixtures; synthetic receipts are never release evidence.

## No-secret rollback

This change does not rewrite Git history. Reverting the code commit does not
make retired credentials safe, and a wholesale Git revert would restore
compromised literals from the parent tree. Never revert this security commit as
a unit. Use a forward corrective commit that keeps every secret deletion,
ignore rule, and scanner control. A safe operational rollback keeps UAT
stopped, removes only newly created local secret files and evidence that failed
scanning, and re-provisions fresh credentials through the procedure above.
