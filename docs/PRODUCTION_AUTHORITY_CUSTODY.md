# Production authority custody

Until explicitly changed by the owner, all production authority roles are
operated by **Mr. X**. The operator boundary is temporary; cryptographic roles
remain separate so a later multi-operator ceremony does not require reusing one
key across protocols.

Provision once into the protected workspace secret root:

```powershell
node .\scripts\production-authority-provision.mjs `
  --out-dir C:\Work\DeepSession\secrets\prod\authority
```

The operation fails on a non-empty target and stages the complete set before an
atomic directory rename. Private files are raw 32-byte Ed25519 seeds or raw
32-byte integrity keys. Public keys, role IDs, custody-domain hashes, thresholds,
and the generated production network ID are recorded in
`public/custody-manifest.v1.json`.
New custody includes a separate 32-byte account-directory integrity key;
it is not derived from any signer seed.

The `offline-root-1` private seed is local-only and must never be copied to a
registry or node host. Registry DTT signers use a logical 2-of-3 policy even
while one person holds all three custody boundaries. MSG evidence, Contact/XPK,
Group GSR1/DCR1, and the mailbox deposit/retrieve issuers each have distinct
keys. Release signing credentials remain separate from protocol authorities.

An existing pre-mailbox authority directory must **not** be regenerated or
rotated. After reviewing the exact ten-role Mr. X manifest and protecting its
offline root, add the two new mailbox roles once:

```powershell
node .\scripts\production-authority-provision.mjs --augment-mailbox `
  --authority-root C:\Work\DeepSession\secrets\prod\authority
```

The command validates every existing seed against its public key, role ID and
custody domain, refuses partial/replayed augmentation, stages new independent
keys, retains the original public manifest as
`custody-manifest.pre-mailbox.v1.json`, and atomically replaces only the public
manifest. It never rotates existing keys. A leftover augmentation lock or
staging directory means the transaction needs manual review; do not retry by
deleting it. The offline root remains local-only.
