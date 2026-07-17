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
8. Run `node scripts/secret-scan.mjs`. Reactivate UAT only after it reports zero
   findings and Mr. X records the rotation transaction IDs and new public IDs
   in a separate secret-free evidence manifest.

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
- `runtime.snapshot.json`, with sensitive property names recursively redacted;
- `security/secret-scan-summary.json`, containing rule IDs and relative paths
  only.

The collector never runs resolved Compose output and never captures unrestricted
container logs. `compose.resolved.yml`, `compose.log`, private key files, local
environment files, crash dumps, databases, and shell transcripts are forbidden
release artifacts.

Before every upload, run:

```powershell
node .\scripts\secret-scan.mjs
```

The scanner covers tracked files and the artifact tree, reports no matched
value, treats oversized text files as unscannable, and rejects forbidden raw
artifact names. Any finding blocks bundling and upload.

## No-secret rollback

This change does not rewrite Git history. Reverting the code commit does not
make retired credentials safe, and a wholesale Git revert would restore
compromised literals from the parent tree. Never revert this security commit as
a unit. Use a forward corrective commit that keeps every secret deletion,
ignore rule, and scanner control. A safe operational rollback keeps UAT
stopped, removes only newly created local secret files and evidence that failed
scanning, and re-provisions fresh credentials through the procedure above.
