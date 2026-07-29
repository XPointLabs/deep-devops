# DEV-LOCAL-ONLY MAUI mailbox grants

`scripts/survival-dev-mailbox-provision.ps1` is host-only: it neither starts nor recreates Docker containers. It signs two schema-v1 bundles using the local issuer seed while holder private keys remain on Android and Windows in `SessionIdentityProvider`.

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\survival-dev-mailbox-provision.ps1 `
  -AndroidHolderPublicKey <64-lowercase-hex> `
  -WindowsHolderPublicKey <64-lowercase-hex>
```

The physical development coordinator is exactly `http://192.168.1.44:41801`; HTTP is accepted only by the explicitly development-only provisioner. The command requires authority schema v2, two distinct nonzero holders, exactly E/E+1 overlapping windows, and exactly two distinct `xnode-1`/`xnode-2` replica public keys.

It emits `android.mailbox-credentials.v1.json` and `windows.mailbox-credentials.v1.json` under `artifacts/survival-dev/maui-mailbox-grants`. Each has its owner's retrieve/ack grants and only a public route plus deposit grants for the counterpart mailbox. The issuer seed and per-identity mailbox secrets stay in `.secrets/survival-dev/maui-mailbox-grants`; do not package that directory, copy it into an APK, or attach it to evidence. The secret directory must remain operator-owned; the provisioner rejects Windows ACLs with broad write access and any reparse-point path.

Validate delivered bundles without contacting Docker or the network:

```powershell
dotnet run --project .\tools\survival-mailbox-driver\SurvivalMailboxDriver.csproj `
  -p:XNodeSource=..\xnode -- verify-provision `
  --android-bundle .\artifacts\survival-dev\maui-mailbox-grants\android.mailbox-credentials.v1.json `
  --windows-bundle .\artifacts\survival-dev\maui-mailbox-grants\windows.mailbox-credentials.v1.json
```
