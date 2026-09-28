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

`tools/production-authority-bootstrap` is a one-time genesis author, not an
operational renewal tool. It no longer accepts `--previous-bootstrap-root`:
that path retained the old XNA1/DTS1 pin while re-authoring XVP1/XND1/XNV1/XNH1
as generation zero, which cannot advance an already protected operational
head. A live network must use a separately verified, strictly monotonic
successor ceremony; do not run genesis again to repair an expired view. The
bootstrap binds the distinct mailbox deposit and retrieve public keys from
the custody manifest when constructing PMA2.

For a strictly monotonic operational successor, the same tool accepts
`--successor-from` together with an exact source artifact directory, the
independently protected XNH1 core hash and PMT2 artifact hash, the current
ADH1 bytes and independently protected ADH1 core hash, and a separate
`--rollover-root`. Each of its `seed1`, `seed2`, and `seed3` subdirectories must
already contain `current.x25519.seed`, `next.x25519.seed`,
`current-origin.cer`, `current-origin.key`, `next-origin.cer`, and
`next-origin.key`. Both certificate/key pairs must match and cover the
new interval; their SPKI pins and both onion public keys must differ from the
previous descriptor. The registered Ed25519 node identities are unchanged.
The command reads existing custody, verifies the source inventory and pinned
genesis, and writes only a new, previously absent output directory. It does
not generate keys, alter nodes, publish to Registry, advance protected floors,
or issue a nonce-fresh DTT1/ADP1. Certificate private keys and onion seeds must
be installed on the intended nodes and checked against the signed descriptor
before any network cutover. The source artifact directory alone is never an
independent protected pin; the three expected hashes must be obtained from
their separately protected current-state authorities.

Before that ceremony, `--prepare-rollover true` with `--authority-root`,
`--observed-unix`, and the three `--seedN-root` inputs creates a new
`private/rollover-<observed-unix>` directory inside existing protected custody.
It generates independent current/next X25519 seeds and matching self-issued
TLS certificate/private-key pairs bound to the node hosts in the backed-up
environments. It refuses an existing output directory, does not rotate
registered node identities, and does not modify certbot or remote machines.
The private directory must retain the custody ACL; never include it in public
artifacts. Preparation is not deployment or proof of device readiness.

Run the synthetic offline operator-input gate without opening real custody:

```powershell
dotnet run --project tools/production-authority-bootstrap-tests/ProductionAuthority.Bootstrap.Tests.csproj
```
