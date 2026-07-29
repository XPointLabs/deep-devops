$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$root = [IO.Path]::GetFullPath((Split-Path $PSScriptRoot -Parent))
$xnode = Join-Path $root 'artifacts\survival-dev\build-contexts\xnode'
$sourceManifest = Join-Path $xnode '.survival-source-manifest.json'
$temporary = Join-Path ([IO.Path]::GetTempPath()) ('deep-mailbox-provision-' + [Guid]::NewGuid().ToString('N'))
$script:ExpectedFailures = 0

function Get-LowerSha256([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function New-ProtectedDirectory([string]$Path) {
    New-Item -ItemType Directory -Path $Path -Force | Out-Null
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT -and
        (Get-Command chmod -ErrorAction SilentlyContinue)) {
        & chmod 700 $Path
        if ($LASTEXITCODE -ne 0) { throw "Unable to protect test directory: $Path" }
    }
}

function Invoke-Driver([string[]]$DriverArguments, [switch]$ExpectFailure) {
    $project = Join-Path $root 'tools\survival-mailbox-driver\SurvivalMailboxDriver.csproj'
    if ($ExpectFailure) {
        $savedPreference = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try {
            $ignored = @(& dotnet run --project $project "-p:XNodeSource=$xnode" -- @DriverArguments 2>&1)
            $exitCode = $LASTEXITCODE
        } finally {
            $ErrorActionPreference = $savedPreference
        }
        if ($exitCode -eq 0) { throw 'Expected mailbox provision command to fail.' }
        $script:ExpectedFailures++
        return
    }
    & dotnet run --project $project "-p:XNodeSource=$xnode" -- @DriverArguments
    if ($LASTEXITCODE -ne 0) { throw 'Mailbox provision command failed.' }
}

function Get-CurrentPair([string]$PairRoot) {
    $pointer = Get-Content -Raw -LiteralPath (Join-Path $PairRoot 'current-generation.json') | ConvertFrom-Json
    $directory = Join-Path (Join-Path $PairRoot 'generations') $pointer.generation
    return [pscustomobject]@{
        Generation = [string]$pointer.generation
        Directory = $directory
        Android = Join-Path $directory 'android.mailbox-credentials.v1.json'
        Windows = Join-Path $directory 'windows.mailbox-credentials.v1.json'
        Manifest = Join-Path $directory 'pair-manifest.v1.json'
    }
}

try {
    if (-not (Test-Path -LiteralPath $sourceManifest -PathType Leaf)) {
        throw 'Pinned exported XNode source snapshot is missing.'
    }
    $source = Get-Content -Raw -LiteralPath $sourceManifest | ConvertFrom-Json
    if ($source.sourceCommit -ne '132fae59ec834e2986703103ccc233a8d51352ea' -or
        (Get-FileHash -LiteralPath $sourceManifest -Algorithm SHA256).Hash -ne
            'D32FA4D17EE9CD4D2C4DDEC5167FEED30D710113680DB5342795EC2DF93A5B38') {
        throw 'Tests require the exact clean exported XNode source snapshot.'
    }
    foreach ($file in $source.files) {
        $candidate = [IO.Path]::GetFullPath((Join-Path $xnode ([string]$file.path)))
        if (-not (Test-Path -LiteralPath $candidate -PathType Leaf) -or
            (Get-Item -LiteralPath $candidate).Length -ne [long]$file.bytes -or
            (Get-FileHash -LiteralPath $candidate -Algorithm SHA256).Hash.ToLowerInvariant() -ne
                [string]$file.sha256) {
            throw "Test XNode snapshot file mismatch: $($file.path)"
        }
    }

    New-ProtectedDirectory $temporary
    $secrets = Join-Path $temporary 'authority-secrets'
    New-ProtectedDirectory $secrets
    foreach ($index in 1..6) {
        [IO.File]::WriteAllText((Join-Path $secrets "xnode-$index-ed25519.seed"),
            ('{0:x64}' -f $index) + "`n")
    }
    $issuer = Join-Path $secrets 'mailbox-client-issuer.seed'
    [IO.File]::WriteAllText($issuer, ('{0:x64}' -f 1001) + "`n")
    $authority = Join-Path $temporary 'authority.json'
    Invoke-Driver @(
        'authority', '--secrets-dir', $secrets,
        '--output-env', (Join-Path $temporary 'authority.env'),
        '--output-client-env', (Join-Path $temporary 'client.env'),
        '--output-public', $authority,
        '--coordinator-url', 'http://192.168.1.44:41801')
    $authorityHash = Get-LowerSha256 $authority
    $authorityObject = Get-Content -Raw -LiteralPath $authority | ConvertFrom-Json
    $issuerPublicKey = [string]$authorityObject.issuerPublicKey

    $output = Join-Path $temporary 'output'
    $hostSecrets = Join-Path $temporary 'host-secrets'
    New-ProtectedDirectory $output
    New-ProtectedDirectory $hostSecrets
    $android = '0101010101010101010101010101010101010101010101010101010101010101'
    $windows = '0202020202020202020202020202020202020202020202020202020202020202'
    $trust = @(
        '--development-only', '--allow-http', '--physical-dev',
        '--authority-public', $authority,
        '--expected-authority-sha256', $authorityHash,
        '--expected-issuer-public-key', $issuerPublicKey,
        '--coordinator-url', 'http://192.168.1.44:41801')
    $common = $trust + @(
        '--android-holder-public-key', $android,
        '--windows-holder-public-key', $windows)
    $provision = @(
        'provision') + $common + @(
        '--issuer-seed-path', $issuer,
        '--output-directory', $output,
        '--mailbox-secret-directory', $hostSecrets)
    $verify = @('verify-provision') + $common + @('--pair-directory', $output)

    Invoke-Driver $provision
    Invoke-Driver $verify
    $first = Get-CurrentPair $output
    Invoke-Driver $provision
    $second = Get-CurrentPair $output
    if ($first.Generation -ne $second.Generation) {
        throw 'Stable authority, holders, and host secrets must produce the same generation.'
    }

    $androidJson = Get-Content -Raw -LiteralPath $first.Android | ConvertFrom-Json
    $windowsJson = Get-Content -Raw -LiteralPath $first.Windows | ConvertFrom-Json
    if ($androidJson.peerMailboxRoute.blindedMailboxId -ne $windowsJson.ownMailbox.blindedMailboxId -or
        $androidJson.ownMailbox.blindedMailboxId -eq $windowsJson.ownMailbox.blindedMailboxId -or
        $windowsJson.peerMailboxRoute.blindedMailboxId -ne $androidJson.ownMailbox.blindedMailboxId) {
        throw 'Counterpart public mailbox routing is invalid.'
    }
    if ($androidJson.ownMailbox.retrieveAndAcknowledgeGrants[0].canonicalGrant -eq
        $windowsJson.ownMailbox.retrieveAndAcknowledgeGrants[0].canonicalGrant) {
        throw 'Android must not receive the Windows retrieve grant.'
    }
    $issuerText = (Get-Content -Raw -LiteralPath $issuer).Trim()
    foreach ($file in @($first.Android, $first.Windows, $first.Manifest,
        (Join-Path $output 'current-generation.json'))) {
        $content = Get-Content -Raw -LiteralPath $file
        if ($content -match '(?i)(issuerseed|privatekey|privateseed|sessionid|mailboxsecret)' -or
            $content.ToLowerInvariant().Contains($issuerText.ToLowerInvariant())) {
            throw 'Private material leaked into published output.'
        }
    }

    # Duplicate holders are rejected before any pair is advertised.
    $duplicateRoot = Join-Path $temporary 'duplicate'
    $duplicateSecrets = Join-Path $temporary 'duplicate-secrets'
    New-ProtectedDirectory $duplicateRoot
    New-ProtectedDirectory $duplicateSecrets
    Invoke-Driver (@('provision') + $trust + @(
        '--android-holder-public-key', $android,
        '--windows-holder-public-key', $android,
        '--issuer-seed-path', $issuer,
        '--output-directory', $duplicateRoot,
        '--mailbox-secret-directory', $duplicateSecrets)) -ExpectFailure

    # A modified authority is rejected even when the attacker supplies its new hash.
    $tamperedAuthority = Join-Path $temporary 'tampered-authority.json'
    $tamperedAuthorityObject = Get-Content -Raw -LiteralPath $authority | ConvertFrom-Json
    $proofBytes = [Convert]::FromBase64String(
        $tamperedAuthorityObject.epochs[0].replicas[0].canonicalRip1)
    $mipBytes = [Convert]::FromBase64String(
        $tamperedAuthorityObject.epochs[0].replicas[0].canonicalMip1)
    $proofOffset = -1
    for ($candidate = 0; $candidate -le $mipBytes.Length - $proofBytes.Length; $candidate++) {
        $matches = $true
        for ($index = 0; $index -lt $proofBytes.Length; $index++) {
            if ($mipBytes[$candidate + $index] -ne $proofBytes[$index]) {
                $matches = $false
                break
            }
        }
        if ($matches) {
            $proofOffset = $candidate
            break
        }
    }
    if ($proofOffset -lt 0) { throw 'Canonical MIP1 did not contain its exact RIP1.' }
    $lastProofByte = $proofBytes.Length - 1
    $proofBytes[$lastProofByte] = $proofBytes[$lastProofByte] -bxor 1
    $mipBytes[$proofOffset + $lastProofByte] = $proofBytes[$lastProofByte]
    $tamperedAuthorityObject.epochs[0].replicas[0].canonicalRip1 =
        [Convert]::ToBase64String($proofBytes)
    $tamperedAuthorityObject.epochs[0].replicas[0].canonicalMip1 =
        [Convert]::ToBase64String($mipBytes)
    $tamperedAuthorityObject | ConvertTo-Json -Depth 14 | Set-Content -NoNewline $tamperedAuthority
    $tamperedRoot = Join-Path $temporary 'tampered-authority-output'
    $tamperedSecrets = Join-Path $temporary 'tampered-authority-secrets'
    New-ProtectedDirectory $tamperedRoot
    New-ProtectedDirectory $tamperedSecrets
    Invoke-Driver (@(
        'provision', '--development-only', '--allow-http', '--physical-dev',
        '--authority-public', $tamperedAuthority,
        '--expected-authority-sha256', (Get-LowerSha256 $tamperedAuthority),
        '--expected-issuer-public-key', $issuerPublicKey,
        '--coordinator-url', 'http://192.168.1.44:41801',
        '--android-holder-public-key', $android,
        '--windows-holder-public-key', $windows,
        '--issuer-seed-path', $issuer,
        '--output-directory', $tamperedRoot,
        '--mailbox-secret-directory', $tamperedSecrets)) -ExpectFailure

    # HTTP can never be enabled for an arbitrary LAN endpoint.
    $lanAuthority = Join-Path $temporary 'lan-authority.json'
    $lanObject = Get-Content -Raw -LiteralPath $authority | ConvertFrom-Json
    $lanObject.coordinatorUrl = 'http://192.168.1.45:41801'
    $lanObject | ConvertTo-Json -Depth 14 | Set-Content -NoNewline $lanAuthority
    Invoke-Driver (@(
        'provision', '--development-only', '--allow-http',
        '--authority-public', $lanAuthority,
        '--expected-authority-sha256', (Get-LowerSha256 $lanAuthority),
        '--expected-issuer-public-key', $issuerPublicKey,
        '--coordinator-url', 'http://192.168.1.45:41801',
        '--android-holder-public-key', $android,
        '--windows-holder-public-key', $windows,
        '--issuer-seed-path', $issuer,
        '--output-directory', $tamperedRoot,
        '--mailbox-secret-directory', $tamperedSecrets)) -ExpectFailure

    # Fault injection proves the advertised pointer never observes a mixed pair.
    $atomicRoot = Join-Path $temporary 'atomic-output'
    $atomicSecrets = Join-Path $temporary 'atomic-secrets'
    New-ProtectedDirectory $atomicRoot
    New-ProtectedDirectory $atomicSecrets
    $atomicBase = @('provision') + $common + @(
        '--issuer-seed-path', $issuer,
        '--output-directory', $atomicRoot,
        '--mailbox-secret-directory', $atomicSecrets)
    Invoke-Driver $atomicBase
    $oldGeneration = (Get-CurrentPair $atomicRoot).Generation
    $androidTwo = '0303030303030303030303030303030303030303030303030303030303030303'
    $windowsTwo = '0404040404040404040404040404040404040404040404040404040404040404'
    $atomicNew = @('provision') + $trust + @(
        '--android-holder-public-key', $androidTwo,
        '--windows-holder-public-key', $windowsTwo,
        '--issuer-seed-path', $issuer,
        '--output-directory', $atomicRoot,
        '--mailbox-secret-directory', $atomicSecrets)
    Invoke-Driver ($atomicNew + '--fail-after-stage') -ExpectFailure
    if ((Get-CurrentPair $atomicRoot).Generation -ne $oldGeneration) {
        throw 'Failure after stage changed the advertised generation.'
    }
    Invoke-Driver (@('verify-provision') + $common + @('--pair-directory', $atomicRoot))
    Invoke-Driver ($atomicNew + '--fail-after-promotion') -ExpectFailure
    if ((Get-CurrentPair $atomicRoot).Generation -ne $oldGeneration) {
        throw 'Failure after promotion changed the advertised generation.'
    }
    Invoke-Driver (@('verify-provision') + $common + @('--pair-directory', $atomicRoot))

    # Whole-pair substitution with valid signatures but unexpected holders fails.
    $substituteRoot = Join-Path $temporary 'substitute-output'
    $substituteSecrets = Join-Path $temporary 'substitute-secrets'
    New-ProtectedDirectory $substituteRoot
    New-ProtectedDirectory $substituteSecrets
    Invoke-Driver (@('provision') + $trust + @(
        '--android-holder-public-key', $androidTwo,
        '--windows-holder-public-key', $windowsTwo,
        '--issuer-seed-path', $issuer,
        '--output-directory', $substituteRoot,
        '--mailbox-secret-directory', $substituteSecrets))
    Invoke-Driver (@('verify-provision') + $common + @('--pair-directory', $substituteRoot)) -ExpectFailure

    # Pair member tampering fails the pair manifest before grant verification.
    $pairTamperRoot = Join-Path $temporary 'pair-tamper'
    Copy-Item -LiteralPath $output -Destination $pairTamperRoot -Recurse
    $pairTamper = Get-CurrentPair $pairTamperRoot
    $tamperedBundle = Get-Content -Raw -LiteralPath $pairTamper.Android | ConvertFrom-Json
    $tamperedBundle.holderPublicKey = $windows
    $tamperedBundle | ConvertTo-Json -Depth 14 | Set-Content -NoNewline $pairTamper.Android
    Invoke-Driver (@('verify-provision') + $common + @('--pair-directory', $pairTamperRoot)) -ExpectFailure

    # Even after recomputing the unauthenticated pair hashes, signed epoch and
    # placement mutations fail against the trusted issuer and authority.
    foreach ($mutation in @(
        @{ Name = 'epoch'; Offset = 31; Value = 3 },
        @{ Name = 'placement'; Offset = 80; Value = 255 }
    )) {
        $grantTamperRoot = Join-Path $temporary ("grant-tamper-$($mutation.Name)")
        Copy-Item -LiteralPath $output -Destination $grantTamperRoot -Recurse
        $grantPair = Get-CurrentPair $grantTamperRoot
        $grantDocument = Get-Content -Raw -LiteralPath $grantPair.Android | ConvertFrom-Json
        $grantBytes = [Convert]::FromBase64String(
            $grantDocument.ownMailbox.retrieveAndAcknowledgeGrants[0].canonicalGrant)
        $grantBytes[$mutation.Offset] = [byte]$mutation.Value
        $grantDocument.ownMailbox.retrieveAndAcknowledgeGrants[0].canonicalGrant =
            [Convert]::ToBase64String($grantBytes)
        $hasher = [Security.Cryptography.SHA256]::Create()
        try { $grantHash = $hasher.ComputeHash($grantBytes) } finally { $hasher.Dispose() }
        $grantDocument.ownMailbox.retrieveAndAcknowledgeGrants[0].sha256 =
            ([BitConverter]::ToString($grantHash).Replace('-', '')).ToLowerInvariant()
        $grantDocument | ConvertTo-Json -Depth 14 | Set-Content -NoNewline $grantPair.Android
        $manifestDocument = Get-Content -Raw -LiteralPath $grantPair.Manifest | ConvertFrom-Json
        $manifestDocument.files.android = Get-LowerSha256 $grantPair.Android
        $manifestDocument | ConvertTo-Json -Depth 14 | Set-Content -NoNewline $grantPair.Manifest
        $pointerDocument = Get-Content -Raw -LiteralPath (
            Join-Path $grantTamperRoot 'current-generation.json') | ConvertFrom-Json
        $pointerDocument.pairManifestSha256 = Get-LowerSha256 $grantPair.Manifest
        $pointerDocument | ConvertTo-Json -Depth 14 | Set-Content -NoNewline (
            Join-Path $grantTamperRoot 'current-generation.json')
        Invoke-Driver (@('verify-provision') + $common + @(
            '--pair-directory', $grantTamperRoot)) -ExpectFailure
    }

    if ($script:ExpectedFailures -ne 9) {
        throw "Expected nine negative paths, executed $script:ExpectedFailures."
    }
    Write-Output 'survival-dev mailbox MAUI grant provision tests passed; expected-failures=9.'
}
finally {
    Remove-Item -LiteralPath $temporary -Recurse -Force -ErrorAction SilentlyContinue
}
