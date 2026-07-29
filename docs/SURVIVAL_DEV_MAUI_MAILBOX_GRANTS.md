# DEV-LOCAL-ONLY MAUI mailbox grants

`scripts/survival-dev-mailbox-provision.ps1` is host-only and never starts or
recreates Docker containers. It accepts two device holder public keys; holder
private keys remain in Android/Windows `SessionIdentityProvider`.

Pre-create the output and secret roots as operator-owned directories. On Unix
they must be mode `0700`; mailbox secret files are mode `0600`. On Windows the
tool rejects broad write ACLs and reparse-point traversal.

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\survival-dev-mailbox-provision.ps1 `
  -AndroidHolderPublicKey <64-lowercase-hex> `
  -WindowsHolderPublicKey <64-lowercase-hex> `
  -AuthoritySha256 <trusted-64-lowercase-hex> `
  -ExpectedIssuerPublicKey <trusted-64-lowercase-hex>
```

The wrapper uses only the exported XNode snapshot at pinned commit
`132fae59ec834e2986703103ccc233a8d51352ea` and verifies its manifest hash.
The physical development HTTP coordinator is exactly
`http://192.168.1.44:41801`; arbitrary HTTP is rejected. HTTPS may be used only
when the exact URL is supplied together with the independently trusted
authority hash and issuer public key.

The provisioner strictly revalidates every MIP1/RIP1 proof, all six descriptors
and endpoints, both membership roots, the exact 30 placement selections, the
E/E+1 windows, and the exact xnode-1/xnode-2 client replicas before signing.

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
directory. The complete directory is renamed into `generations/`, then one
`current-generation.json` pointer is atomically replaced. Readers must resolve
that pointer once and verify the pair manifest and both file hashes; they must
not combine files from different generations.

`verify-provision` requires the pair root, trusted authority file and SHA-256,
trusted issuer public key, and both expected holder public keys. This rejects a
valid but substituted whole pair.

Windows does not expose a portable managed no-follow open or directory-fsync
primitive. The implementation revalidates every parent and leaf for reparse
points immediately before and after each open, uses exclusive/write-through
file handles, and same-volume atomic renames. Operator ACL isolation remains a
required part of the local threat boundary. Unix additionally fsyncs staged and
parent directories.

Never package `.secrets/survival-dev/maui-mailbox-grants`, copy it into an APK,
or attach it to evidence.
