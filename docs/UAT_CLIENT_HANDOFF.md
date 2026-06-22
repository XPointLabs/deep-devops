# UAT Client Handoff

Last updated: 2026-06-18.

This file captures the client-side UAT state before pausing MAUI client work.
Use it as the cross-chat handoff for Android/Windows QA work.

## Latest Client Commits

Repository: `C:\Work\Deep\deep-client-maui`

```text
c51bf3c Dismiss keyboard before opening chat screens
1f9b7cc Make UAT chat and settings flows functional
```

Both commits were pushed to `XPointLabs/deep-client-maui` on
`master`.

## Current Build Artifacts

```text
Android signed APK:
C:\Work\Deep\deep-client-maui\src\Deep.Client.Maui\bin\Release\net10.0-android\publish\org.deep.client-Signed.apk

Windows ARM64 executable:
C:\Work\Deep\deep-client-maui\src\Deep.Client.Maui\bin\Release\net10.0-windows10.0.19041.0\win-arm64\publish\Deep.Client.Maui.exe
```

Release builds embed the UAT LAN endpoints in `deep.release.env`:

```text
XNODE_URLS=http://192.168.1.44:29281;http://192.168.1.44:29282;http://192.168.1.44:29283
DEEP_CALL_SIGNALING_BASE_URL=http://192.168.1.44:28103
DEEP_FILE_URL=http://192.168.1.44:28101
DEEP_PUSH_URL=http://192.168.1.44:28102
```

## Verified On Android

Device visible during the last pass:

```text
192.168.1.45:41181 product:beyond0lteser model:SM_G970F
```

Verified on the signed Release APK:

- App starts on the Conversations screen without startup parameter prompts.
- `+` opens the Session-like start conversation flow.
- `Join Community` is not shown while community transport is not implemented.
- New group creation opens a working group chat.
- Keyboard is dismissed before opening one-to-one and group chats, so the chat
  composer keeps real bounds instead of being hidden under the IME.
- Group message send was verified with body `grp9097`.
- One-to-one message send was verified with body `dm6745`.
- Settings rows no longer show UAT placeholder alerts; they navigate to
  `SettingsDetail` sections.
- Settings Path opens a real endpoint/status screen.

## Verification Commands

Run from `C:\Work\Deep\deep-client-maui`:

```powershell
dotnet test tests\Deep.Client.Maui.ViewModels.Tests\Deep.Client.Maui.ViewModels.Tests.csproj --configuration Release -m:1 -nodeReuse:false
dotnet test tests\Deep.Client.Maui.SmokeTests\Deep.Client.Maui.SmokeTests.csproj --configuration Release -m:1 -nodeReuse:false
dotnet build src\Deep.Client.Maui\Deep.Client.Maui.csproj -f net10.0-android -c Release -m:1 -nodeReuse:false
dotnet build src\Deep.Client.Maui\Deep.Client.Maui.csproj -f net10.0-windows10.0.19041.0 -c Release -m:1 -nodeReuse:false
```

Publish commands:

```powershell
dotnet publish src\Deep.Client.Maui\Deep.Client.Maui.csproj -f net10.0-android -c Release -p:AndroidPackageFormat=apk -m:1 -nodeReuse:false
dotnet publish src\Deep.Client.Maui\Deep.Client.Maui.csproj -f net10.0-windows10.0.19041.0 -c Release -p:PublishSingleFile=false -m:1 -nodeReuse:false
```

## Deferred Client Work

- Two-device Android E2E was not completed because the second Android device was
  not visible in ADB during the last pass.
- Calls are intentionally deferred.
- Some Settings toggles currently persist locally and should be wired into
  runtime defaults/backend behavior when client work resumes.
- Visual parity with upstream Session still needs a focused UI pass.
