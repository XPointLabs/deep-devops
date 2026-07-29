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
`f2bdb1178a52b6258f5664e72629a5659b44e518` with manifest SHA-256
`0ae0a297f1e7a6b494198c52964a46727e2c802d828335ba702313bc810868e8`.
It rejects every file not present in that manifest, including extra `.cs`,
`.props`, `.targets`, and `Directory.Build.*` inputs. The three driver inputs
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
