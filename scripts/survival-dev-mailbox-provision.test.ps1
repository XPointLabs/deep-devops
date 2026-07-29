$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$root = [IO.Path]::GetFullPath((Split-Path $PSScriptRoot -Parent))
$xnode = [IO.Path]::GetFullPath((Join-Path $root '..\xnode'))
$temporary = Join-Path ([IO.Path]::GetTempPath()) ('deep-mailbox-provision-' + [Guid]::NewGuid().ToString('N'))

function Invoke-Driver([string[]]$DriverArguments, [switch]$ExpectFailure) {
    if ($ExpectFailure) {
        & dotnet run --project (Join-Path $root 'tools\survival-mailbox-driver\SurvivalMailboxDriver.csproj') "-p:XNodeSource=$xnode" -- @DriverArguments 2>$null | Out-Null
    } else {
        & dotnet run --project (Join-Path $root 'tools\survival-mailbox-driver\SurvivalMailboxDriver.csproj') "-p:XNodeSource=$xnode" -- @DriverArguments
    }
    if ($ExpectFailure) {
        if ($LASTEXITCODE -eq 0) { throw 'Expected mailbox provision command to fail.' }
        return
    }
    if ($LASTEXITCODE -ne 0) { throw 'Mailbox provision command failed.' }
}

try {
    $secrets = Join-Path $temporary 'secrets'
    $output = Join-Path $temporary 'output'
    $hostSecrets = Join-Path $temporary 'host-secrets'
    New-Item -ItemType Directory -Path $secrets -Force | Out-Null
    foreach ($index in 1..6) {
        [IO.File]::WriteAllText((Join-Path $secrets "xnode-$index-ed25519.seed"), ('{0:x64}' -f $index) + "`n")
    }
    $issuer = Join-Path $secrets 'mailbox-client-issuer.seed'
    [IO.File]::WriteAllText($issuer, ('{0:x64}' -f 1001) + "`n")
    $authority = Join-Path $temporary 'authority.json'
    Invoke-Driver @('authority', '--secrets-dir', $secrets, '--output-env', (Join-Path $temporary 'authority.env'), '--output-client-env', (Join-Path $temporary 'client.env'), '--output-public', $authority, '--coordinator-url', 'http://192.168.1.44:41801')

    $android = '0101010101010101010101010101010101010101010101010101010101010101'
    $windows = '0202020202020202020202020202020202020202020202020202020202020202'
    $provision = @('provision', '--development-only', '--allow-http', '--physical-dev', '--authority-public', $authority, '--issuer-seed-path', $issuer, '--output-directory', $output, '--mailbox-secret-directory', $hostSecrets, '--coordinator-url', 'http://192.168.1.44:41801', '--android-holder-public-key', $android, '--windows-holder-public-key', $windows)
    Invoke-Driver $provision
    $androidBundle = Join-Path $output 'android.mailbox-credentials.v1.json'
    $windowsBundle = Join-Path $output 'windows.mailbox-credentials.v1.json'
    Invoke-Driver @('verify-provision', '--android-bundle', $androidBundle, '--windows-bundle', $windowsBundle)

    $firstHashes = @((Get-FileHash $androidBundle -Algorithm SHA256).Hash, (Get-FileHash $windowsBundle -Algorithm SHA256).Hash)
    Invoke-Driver $provision
    $secondHashes = @((Get-FileHash $androidBundle -Algorithm SHA256).Hash, (Get-FileHash $windowsBundle -Algorithm SHA256).Hash)
    if (-not [Linq.Enumerable]::SequenceEqual([string[]]$firstHashes, [string[]]$secondHashes)) { throw 'Provision output was not deterministic for stable host secrets.' }

    $androidJson = Get-Content -Raw $androidBundle | ConvertFrom-Json
    $windowsJson = Get-Content -Raw $windowsBundle | ConvertFrom-Json
    if ($androidJson.peerMailboxRoute.blindedMailboxId -ne $windowsJson.ownMailbox.blindedMailboxId -or $androidJson.ownMailbox.blindedMailboxId -eq $windowsJson.ownMailbox.blindedMailboxId) { throw 'Android peer route is not the Windows public route.' }
    if ($windowsJson.peerMailboxRoute.blindedMailboxId -ne $androidJson.ownMailbox.blindedMailboxId) { throw 'Windows peer route is not the Android public route.' }
    if ($androidJson.ownMailbox.retrieveAndAcknowledgeGrants[0].canonicalGrant -eq $windowsJson.ownMailbox.retrieveAndAcknowledgeGrants[0].canonicalGrant) { throw 'Android must not receive a Windows retrieve grant.' }
    $issuerText = (Get-Content -Raw $issuer).Trim()
    foreach ($file in @($androidBundle, $windowsBundle)) {
        $content = Get-Content -Raw $file
        if ($content -match '(?i)(issuerseed|privatekey|privateseed|sessionid|mailboxsecret)' -or $content.ToLowerInvariant().Contains($issuerText.ToLowerInvariant())) { throw 'Private material leaked into a bundle.' }
    }

    Invoke-Driver (@('provision', '--development-only', '--allow-http', '--physical-dev', '--authority-public', $authority, '--issuer-seed-path', $issuer, '--output-directory', (Join-Path $temporary 'duplicate'), '--mailbox-secret-directory', (Join-Path $temporary 'duplicate-host'), '--coordinator-url', 'http://192.168.1.44:41801', '--android-holder-public-key', $android, '--windows-holder-public-key', $android)) -ExpectFailure
    $tamperedAuthority = Join-Path $temporary 'tampered-authority.json'
    $authorityObject = Get-Content -Raw $authority | ConvertFrom-Json
    $authorityObject.epochs[0].placementCommitment = ('0' * 64)
    $authorityObject | ConvertTo-Json -Depth 12 | Set-Content -NoNewline $tamperedAuthority
    Invoke-Driver (@('provision', '--development-only', '--allow-http', '--physical-dev', '--authority-public', $tamperedAuthority, '--issuer-seed-path', $issuer, '--output-directory', (Join-Path $temporary 'tampered'), '--mailbox-secret-directory', (Join-Path $temporary 'tampered-host'), '--coordinator-url', 'http://192.168.1.44:41801', '--android-holder-public-key', $android, '--windows-holder-public-key', $windows)) -ExpectFailure

    $tamperedBundle = Join-Path $temporary 'tampered-android.json'
    $tampered = Get-Content -Raw $androidBundle | ConvertFrom-Json
    $tampered.holderPublicKey = $windows
    $tampered | ConvertTo-Json -Depth 12 | Set-Content -NoNewline $tamperedBundle
    Invoke-Driver @('verify-provision', '--android-bundle', $tamperedBundle, '--windows-bundle', $windowsBundle) -ExpectFailure

    foreach ($mutation in @(
        @{ Name = 'epoch'; Offset = 31; Value = 3 },
        @{ Name = 'placement'; Offset = 80; Value = 255 }
    )) {
        $grantTamper = Get-Content -Raw $androidBundle | ConvertFrom-Json
        $bytes = [Convert]::FromBase64String($grantTamper.ownMailbox.retrieveAndAcknowledgeGrants[0].canonicalGrant)
        $bytes[$mutation.Offset] = [byte]$mutation.Value
        $grantTamper.ownMailbox.retrieveAndAcknowledgeGrants[0].canonicalGrant = [Convert]::ToBase64String($bytes)
        $hasher = [Security.Cryptography.SHA256]::Create()
        try { $sha = $hasher.ComputeHash($bytes) } finally { $hasher.Dispose() }
        $grantTamper.ownMailbox.retrieveAndAcknowledgeGrants[0].sha256 = ([BitConverter]::ToString($sha).Replace('-', '')).ToLowerInvariant()
        $path = Join-Path $temporary ("tampered-$($mutation.Name).json")
        $grantTamper | ConvertTo-Json -Depth 12 | Set-Content -NoNewline $path
        Invoke-Driver @('verify-provision', '--android-bundle', $path, '--windows-bundle', $windowsBundle) -ExpectFailure
    }
    Write-Output 'survival-dev mailbox MAUI grant provision tests passed.'
}
finally {
    Remove-Item -LiteralPath $temporary -Recurse -Force -ErrorAction SilentlyContinue
}
