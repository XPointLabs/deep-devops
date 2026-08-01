# DEV-LOCAL-ONLY MAUI mailbox grants

`scripts/survival-dev-mailbox-provision.ps1` is host-only and never starts or
recreates Docker containers. It accepts two device holder public keys; holder
private keys remain in Android/Windows `SessionIdentityProvider`.

Pre-create the output and secret roots as operator-owned directories. On Unix
they must be mode `0700`; mailbox secret files are mode `0600`. On Windows each
root and secret must have a protected, non-inherited DACL owned by the current
identity SID. The exact allowlist is the current identity, Local System
(`S-1-5-18`), and built-in Administrators (`S-1-5-32-544`), all with full
control; every other SID (including Users and Everyone), deny ACE, inherited
ACE, localized account alias, or partial allowlist DACL is rejected.

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\survival-dev-mailbox-provision.ps1 `
  -AndroidHolderPublicKey <64-lowercase-hex> `
  -WindowsHolderPublicKey <64-lowercase-hex> `
  -AuthoritySha256 <trusted-64-lowercase-hex> `
  -ExpectedIssuerPublicKey <trusted-64-lowercase-hex>
```

The wrapper uses only the exported XNode snapshot at pinned commit
`c6c5113c7e77fb9e6577a493e2cc57144cc0de91` with manifest SHA-256
`68027e628e81230c8c26aca5724e477e6c1bd6ca76f60a4315ef7e55a4489d40`.
It rejects every file not present in that manifest, including extra `.cs`,
`.props`, `.targets`, and `Directory.Build.*` inputs. The four driver inputs
are separately hash-pinned. XNode and driver bytes are copied with source
write/delete sharing denied into a protected isolated tree; ambient
`Directory.Build.*` discovery is disabled. The tree is rehashed before and
after a single publish, and source plus published binaries remain read-locked
and replacement-protected through both provision and verification. The build
therefore completes before any secret-bearing command begins.
The physical development HTTP coordinator is exactly
`http://192.168.1.44:41801`; arbitrary HTTP is rejected. HTTPS may be used only
when the exact URL is supplied together with the independently trusted
authority hash and issuer public key.

The provisioner strictly revalidates every MIP1/RIP1 proof, all six descriptors
and endpoints, both membership roots, the exact 30 placement selections, the
E/E+1 windows, and the exact xnode-1/xnode-2 client replicas before signing.
Each device bundle contains E/E+1 retrieve/ACK grants for its own mailbox,
E/E+1 deposit grants for the peer mailbox, and separate E/E+1 deposit grants
for its own mailbox so the existing sender/self E2EE copy can be stored without
sharing the peer holder. All three grant sets are holder-bound and use distinct
serials. This additive development-only field remains schema version 1 because
the pair format has not shipped as a compatibility contract.

## Atomic pair layout

The output root contains:

```text
current-generation.json
generations/<generation>/
  android.mailbox-credentials.v1.json
  windows.mailbox-credentials.v1.json
  pair-manifest.v1.json
```

Both bundles and the pair manifest are flushed in a same-volume staging
directory. Publication orders required barriers as: staged files, staged
directory, generation rename, `generations/` directory, pointer temporary file,
pointer parent, atomic pointer replacement, and output parent. The pointer is
never renamed before the promoted generation's parent barrier succeeds.
Readers must resolve that pointer once and verify the pair manifest and both
file hashes; they must not combine files from different generations.

`verify-provision` requires the pair root, trusted authority file and SHA-256,
trusted issuer public key, and both expected holder public keys. This rejects a
valid but substituted whole pair.

On Windows the implementation opens each directory with native `CreateFileW`,
`GENERIC_WRITE`, and `FILE_FLAG_BACKUP_SEMANTICS`, then requires
`FlushFileBuffers` to succeed. It revalidates every parent and leaf for reparse
points, uses exclusive/write-through file handles, and uses same-volume atomic
renames. Unix uses file flushes plus directory `fsync`. Residual risk remains
below the OS durability contract: storage firmware that falsely acknowledges
flushes, removable/network filesystems with weaker semantics, and physical
media failure can still lose acknowledged writes. The tool fails closed when a
required directory barrier is unavailable; operator ACL isolation remains part
of the local threat boundary.

Never package `.secrets/survival-dev/maui-mailbox-grants`, copy it into an APK,
or attach it to evidence.

## Physical Android/Windows runtime issuance

`survival-dev.ps1 -Action Up -LanHost 192.168.1.44` now creates two distinct
authority files during the same one-shot issuance:

- `mailbox-peer-authority.public.json` is the rich XNode authority containing
  the canonical MIP1/RIP1 proofs and placement matrix used by the six nodes;
- `mailbox-client-authority.public.json` is its byte-deterministic minimized
  client projection. It retains only independently required semantic pins and
  has empty `selections` and empty epoch `replicas` arrays.

The DEV E/E+1 windows are bounded to eight and twelve hours. This is long
enough for one physical build/install/test session, but it is not a durable
production authority. Always run `Up` before issuance; `mailbox-issue` fails
when the prepared authority is stale or has less than 30 minutes remaining.

After both apps have exported valid Ed25519 holder public keys, issue the
runtime pair with:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\scripts\survival-dev-mailbox-issue.ps1
```

The issuer reads only the exact protected holder records
`C:\Work\DeepSession\secrets\mailbox-bootstrap\holders\android.holder.v1.json`
and `windows.holder.v1.json`; holder values are never printed by the script.

The command creates a fresh atomic pair, a bounded four-hour empty revocation
snapshot, and separate `android` and `windows` roots below
`C:\Work\DeepSession\secrets\mailbox-bootstrap\runtime`. Each root
contains the minimized authority, exact pair generation, revocation snapshot,
platform activation, and an Ed25519-signed semantic policy. The policy pins
both holders and derived `05...` Session IDs, ownership `user-managed`, issuer,
authority, pair generation/manifest, revocation snapshot, and platform.

Only the DEV software-held key files
`mr-x-dev-private-key.bin`/`mr-x-dev-public-key.bin` from that protected lab
root are accepted by the wrapper. The private key is read only by the already
built, hash-pinned and read-locked driver; it is zeroed after signing and is
never copied, printed, committed, mounted into Docker, or included in evidence.
These keys have no UAT or production authority.

Runtime publication requires the exact protected DACL described above (or
mode `0700` on Unix), stages both platform trees on the same volume, validates
the lab key pair by signing and verifying each semantic payload, and swaps each
completed tree into place. Repeating the command safely replaces the previous
DEV runtime rather than accumulating alternate generations or repository
copies. No UAT contract or seed is read or changed.
