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

## Offline same-key authority preparation

The existing tool's `--renew-authority-from` mode implements the routine
same-key producer from [DR-0108](../../docs/survival-program/decisions/DR-0108-current-authority-operational-successor.md).
Run it locally with the existing protected custody, not on a Registry/node host.
It does not change root/witness keys or thresholds. The current command uses the
existing single offline root; an unsupported threshold fails, never collapses.

```powershell
dotnet run --project tools/production-authority-bootstrap/ProductionAuthority.Bootstrap.csproj -- `
  --renew-authority-from .\accepted-public `
  --authority-root C:\Work\DeepSession\secrets\prod\authority `
  --network-id-hex $networkId --genesis-core-hash $genesisHash `
  --protected-authority-core-hash $acceptedAuthorityHash `
  --protected-dts1-policy-hash $acceptedDtsHash `
  --observed-unix $observedUnix --authority-expires-unix $authorityExpires `
  --time-policy-expires-unix $timePolicyExpires --output .\prepared-authority
```

The network/genesis pins and both accepted predecessor hashes must come from
independently accepted operator state, not the proposed inventory. Public scope
and predecessor checks run before opening the root file. Explicit offline time
and expiry inputs must satisfy Protocol's non-regressing time/horizon bounds
under [DR-0116](../../docs/survival-program/decisions/DR-0116-offline-root-continuity-after-expiry.md);
the command is not NTS acquisition or an automatic online signing service.
The key must match the existing custody manifest and predecessor root metadata.
Source files, private root and host floors are not overwritten or reset.

The new directory is a **prepared operator inventory**, marked
`deep-production-prepared-authority-renewal.v1`. This is an administrative JSON
state, not a new network protocol, capability or release-active authority.
It retains every original source byte and appends only the verified XNA1/DTS1
pair. Its generic directory publisher is the same no-overwrite staging/rename
path as operational output. The existing `--successor-from` mode can consume it
to finish the operational closure with actual node traffic-key custody and
independent XNH1/PMT2/ADH1 pins. Direct genesis/NCP2 export rejects this prepared
state; only completed operational output is distribution input.

Offline authoring creates a reviewable candidate; it does not select or commit
a competing candidate, provide freshness, publish/deploy or advance a protected
floor. Do not self-pin candidate hashes as accepted state. The remaining S05
provisioning/CAS/rotation/recovery checks still precede activation. CLI failures
report a coarse category and nonzero exit, not private paths or key material.

## Genesis and operational completion

The genesis mode of `tools/production-authority-bootstrap` is one-time authoring,
not operational renewal. Use its explicit successor mode for an initialized
network. It no longer accepts `--previous-bootstrap-root`:
that path retained the old XNA1/DTS1 pin while re-authoring XVP1/XND1/XNV1/XNH1
as generation zero, which cannot advance an already protected operational
head. A live network must use a separately verified, strictly monotonic
successor ceremony; do not run genesis again to repair an expired view. The
bootstrap binds the distinct mailbox deposit and retrieve public keys from
the custody manifest when constructing PMA2. The clean-break mode additionally
requires `--requested-did2-path` containing one exact public 2052-byte DID2
credential. It first signs a non-authoritative network candidate, then separately
authors the exact V2 empty directory genesis and nonce-bound absence proof for
that credential, independently verifies them, and completes network authoring
under [DR-0070](../../docs/survival-program/decisions/DR-0070-did2-operational-genesis-proof-order.md).
The resulting inventory requires reader 2; neither an arbitrary bootstrap leaf
nor a V1 proof is accepted. The supplied observed-time snapshot is offline
ceremony evidence, not NTS acquisition, live readiness, account admission or
permission to overwrite existing floors. The historical checkpoint audit also
requires this exact DID2 input and rejects retired reader-1 inventories.

For a strictly monotonic operational successor, the same tool accepts
`--successor-from` together with an exact source artifact directory, the
independently protected XNH1 core hash and PMT2 artifact hash, the current
ADH1 bytes and independently protected ADH1 core hash, the exact public
`--requested-did2-path` credential used by the source's directory-leaf binding, and a separate
`--rollover-root`. Each of its `seed1`, `seed2`, and `seed3` subdirectories must
already contain `current.x25519.seed`, `next.x25519.seed`,
`current-origin.cer`, `current-origin.key`, `next-origin.cer`, and
`next-origin.key`. Both certificate/key pairs must match and cover the
new interval and match each node's exact configured IP/DNS origins without
wildcard/common-name fallback; their SPKI pins and both onion public keys must differ from the
previous descriptor. The registered Ed25519 node identities are unchanged.
The command reads existing custody and verifies the source inventory plus the
complete paired XNA1/DTS1 history from its genesis pin. The operational author
uses terminal verified authority; historical predecessor records keep their own
original authority. The output preserves all exact authority/time-policy records,
not merely generation zero. This command does not author an XNA1/DTS1 renewal or
root/witness-key rotation; those signed inputs must already exist from their
authorized offline ceremony, including the explicit preparation above. Routine same-key renewal follows
[DR-0108](../../docs/survival-program/decisions/DR-0108-current-authority-operational-successor.md).
It additionally requires `--root-policy-expires-unix`: the actual offline
XVP1/PMA2 delegation expiry, covering the new operational interval, no later
than terminal authority and within30days. XND1/XNV1/XNH1/PMT2 keep their existing
24-hour scope. A root renewal can thus authorize later delegated short views
without loading root custody online. Neither an expired predecessor nor the
prepared root successor restores current authority before operational completion
and independent current runtime verification. Use actual observation time;
never backdate it to fit an expired authority.
The DID2 directory leaf is derived by the existing Protocol codec. The retired
Contact/XPK bootstrap-leaf hash is not accepted and cannot select a successor
path; missing/mismatched DID2 input rejects before opening signer custody.
It writes only a new, previously absent output directory. The complete public
inventory is staged beside that directory and published by one directory rename;
an existing output is never replaced. A failed `.deep-successor-*` staging
directory is retained for explicit review, not consumed as the named bundle.
Windows access/sharing/lock rename failures can retry the same move under a
bounded1550ms backoff, only while output remains absent. Persistent denial or
existing output still fails; no copy/overwrite or OS-security bypass is used.
The source inventory has the existing NCP2 aggregate byte bound; the independently
supplied ADH1 is read under the existing canonical record bound. It does
not generate keys, alter nodes, publish to Registry, advance protected floors,
or issue a nonce-fresh DTT1/ADP1. Certificate private keys and onion seeds must
be installed on the intended nodes and checked against the signed descriptor
before any network cutover. The source artifact directory alone is never an
independent protected pin; the three expected hashes must be obtained from
their separately protected current-state authorities.

For an already initialized XNode, the supported
[offline network-floor audit](../../xnode/docs/operator.md#offline-accepted-network-checkpoint-audit)
authenticates a read-only snapshot of its floor, independent anchor and matching
existing Data Protection key ring. It exports the exact unchanged DNH2; it neither
creates a writer lease nor renews keys. Its scope uses the reader's **directory
genesis ADH1** pin and registered node ID, not the network-genesis XNA1 hash.
Capture both protected records consistently and retain the copies inside operator
custody. An export is historical local-custody evidence, not fresh authority or a
global anti-rollback floor. Review the retained head reference and exact PMT against
the complete signed predecessor, and keep full NCP2 history for the successor.
Never substitute candidate-manifest hashes for this independently accepted state.

Before that ceremony, `--prepare-rollover true` with `--authority-root`,
`--observed-unix`, and the three `--seedN-root` inputs creates a new
`private/rollover-<observed-unix>` directory inside existing protected custody.
It generates independent current/next X25519 seeds and matching self-issued
TLS certificate/private-key pairs bound to the node hosts in the backed-up
environments. It refuses an existing output directory, does not rotate
registered node identities, and does not modify certbot or remote machines.
The private directory must retain the custody ACL; never include it in public
artifacts. Preparation is not deployment or proof of device readiness.

`--audit-genesis-source` verifies a historical generation-zero bootstrap using
an independently configured genesis/network pin and the exact XNV1 artifact
hash observed on the intended UAT runtime. It checks the signed snapshot and
complete network/placement closure and writes a new audit report only; no
signer seeds or remote state are opened. This report is explicitly historical,
not current-time/readiness evidence and not permission to replace an existing
protected LKG. An initial UAT checkpoint can be reviewed and retained separately
in operator custody before authoring its first successor. Existing readers'
protected heads still take precedence; a mismatched accepted head must never
be reset or self-pinned from the candidate manifest.

For distribution to DID2 clients, `--export-network-genesis <public-source>`
with independently configured `--network-id-hex`, `--genesis-core-hash` and
`--output <new-file>` exports the exact public genesis records into NCP2.
For each operational successor, use `--extend-network-closure <prior-ncp2>`
with `--network-successor-source <public-source>`, the same independent pins,
and a new output file. Extension requires the successor's complete XNV1 prefix
to match the retained bundle exactly and to add one view. Prior XNH1, XVP1 and
PMT2 records remain in the bundle; missing history is never synthesized.
Both modes check the pinned genesis, bounded canonical inventory hashes and
public path containment, refuse output replacement and open no signer keys.
Genesis export still requires one exact generation-zero pair. Successor export
accepts complete paired XNA1/DTS1 history only after its actual signatures and
successor links verify from the original pin. Every prior authority/time-policy
byte must remain an exact prefix of the candidate; missing intermediates,
truncation and a different valid fork reject. It does not sign a renewal, rotate
keys or turn that inventory into current authority. The
[local regression](S05-AUTHORITY-HISTORY-2026-10-14.md) covers two same-key renewals
and69 retained views with delegated traffic-key rotation, not changed-root/
witness custody, native client catch-up or physical acceptance.
The output contains only the Protocol-owned eight public chains, including
the exact root-signed mailbox issuer policy, not historical
account proof/time snapshots from the source directory. This is distribution,
not live verification, floor advancement or permission to deploy. Clients still
require their own nonce-fresh DID2 proof and complete network verification.
Mount only the resulting public file read-only using the
[Registry distribution runbook](../../deep-registry-api/docs/NETWORK_CLOSURE_DISTRIBUTION.md).
After ingress cutover, `--audit-network-distribution <https-origin/>` with
`--network-id-hex` and an independently exported `--expected-bundle-sha256`
checks the Protocol-generated request, exact bounded public response, no-store,
and rejection of a wrong network, query, media type and malformed envelope.
The operator uses normal TLS certificate validation and refuses redirects.
It does not issue an account proof, verify current network authority or satisfy
device E2E; the account-owned client must still perform those checks.
The exact transport envelope is owned by
[XPOINT-NETWORK-V1 section 8.1](../../docs/architecture/XPOINT-NETWORK-V1.md#81-identity-neutral-network-closure-distribution-ncq2ncp2).

There is currently no separate remote UAT environment. The `UAT` name below is
an isolated diagnostic software profile on production infrastructure, not a
different fleet. Mr. X authorizes production testing until he explicitly reports
that users exist. Keep diagnostics isolated from existing registered node state,
ingress, certificate renewal and the staking portal; do not label these hosts UAT.

For the DID2-only XNode diagnostic host, `--export-xnode-did2-assets <complete-ncp2>`
requires the independently retained `--expected-bundle-sha256`,
`--network-id-hex`, `--genesis-core-hash`, `--genesis-head-path`,
`--genesis-head-core-hash`, a canonical `--registry-origin <https-origin/>`,
`--observer-contact-file <two-line-contact-file>` and `--output <new-directory>`.
The observer input is the existing compact descriptor followed by its exact
public DID2 in hexadecimal. Its commitment must match; only the public DID2
is exported, never the descriptor/read capability, account/device keys or phrase.
No signer keys are opened. Inputs are bounded and reject ancestor links.

The complete eight NCP2 chains, separately pinned reader-V2 genesis head,
public observer and `xnode.did2.json` fragment are installed as one new directory.
An existing output is never replaced. Mount this directory read-only at
`/run/did2-network`; configure only a closed UAT host, disable its V1 contact
authority and retain the registered node identities and all protected floors.
The fragment does not configure listener, carrier, private onion custody or peer
transport and is not a standalone production deployment file.

This export verifies the independent bundle digest, pinned XNA1/DTS1 chain,
signed DID2 genesis head and observer binding. Operational chain authentication
and freshness remain the runtime Protocol verifier's job. A latest-only successor
inventory cannot replace the full NCP2 history. Neither an export nor its enabled
configuration flags prove current authority, two-replica publication or device E2E.
The host must acquire its own nonce-fresh proof and verify its installed onion key
before releasing receive capability; see
[DR-0012](../../docs/survival-program/decisions/DR-0012-protected-network-history.md).

The installer stager treats a changed signed-history path list as a new immutable
bundle, not an exact rerun. It does not demand successor-only files in the previous
bundle. All new inputs and retained node/state custody are still validated before
staging; only runtime Protocol verification can advance an existing network floor.
An unchanged configuration with missing retained public files still rejects.

`scripts/prepare-xnode-did2-uat.cjs` prepares one separate canary bundle from
`--assets <export-directory>`, all three existing `--seed1/--seed2/--seed3
<deployment-candidate>` roots, the already authored `--rollover <directory>`,
`--node <seed1|seed2|seed3>` and `--output <new-absolute-directory>`.
It checks public-file hashes, observer/config integrity, registered Ed25519
seed/public binding, distinct peers, current origin key/SPKI and bounded seeds.
It copies only the selected existing Ed25519 seed, rollover onion seed, origin
key and state-protection secret; source files are not changed and no identity
or signer is generated. The resulting directory contains private custody and
must stay in the protected environment root, never a CI artifact or Git.
On Windows it inherits the protected parent's ACL; on the Linux host retain
owner-only directory/file permissions before starting the process.

The preparation deliberately disables VLESS/Reality and every V1 contact/group
authority. `docker-compose.did2-xnode-uat.yml` mounts this separate bundle and
fresh canary state, binds only loopback, uses bounded logs and requires the
verified immutable image digest. Set `DEEP_DID2_UAT_ROOT` to the prepared root
and `XNODE_IMAGE` to that digest; run compose with a unique explicit project name.
The supported production installer remains the later rollout owner; this
isolated compose must not replace its existing node, ingress or volumes.
Require a successful preparation exit and inspect current Registry time/head
inputs before startup. Registry HTTP readiness alone is not proof freshness.
Successful authenticated canary startup can establish its nonce-fresh DID2 host
authority and installed-key binding, not peer TLS, real carrier or message delivery.
Preserve its new directory/network floor, independent anchors and Data Protection
key ring together for a same-image restart; do not reset them to obtain readiness.

Run the synthetic offline operator-input gate without opening real custody:

```powershell
dotnet run --project tools/production-authority-bootstrap-tests/ProductionAuthority.Bootstrap.Tests.csproj
```
