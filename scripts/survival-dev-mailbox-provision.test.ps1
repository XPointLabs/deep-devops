$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$root = [IO.Path]::GetFullPath((Split-Path $PSScriptRoot -Parent))
$xnode = Join-Path $root 'artifacts\survival-dev\build-contexts\xnode'
$sourceManifest = Join-Path $xnode '.survival-source-manifest.json'
$temporary = Join-Path ([IO.Path]::GetTempPath()) ('deep-mailbox-provision-' + [Guid]::NewGuid().ToString('N'))
$script:ExpectedFailures = 0
$script:BuildInputFailures = 0
. (Join-Path $PSScriptRoot 'survival-dev-mailbox-build-inputs.ps1')

function Get-LowerSha256([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Convert-HexToBytes([string]$Value) {
    if ($Value.Length % 2 -ne 0 -or $Value -cnotmatch '^[0-9a-f]+$') {
        throw 'Test hexadecimal input is not canonical.'
    }
    $bytes = [byte[]]::new($Value.Length / 2)
    for ($index = 0; $index -lt $bytes.Length; $index++) {
        $bytes[$index] = [Convert]::ToByte($Value.Substring($index * 2, 2), 16)
    }
    return $bytes
}

function New-ProtectedDirectory([string]$Path) {
    New-Item -ItemType Directory -Path $Path -Force | Out-Null
    if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
        Set-WindowsExclusiveAcl $Path $true
    } elseif (
        (Get-Command chmod -ErrorAction SilentlyContinue)) {
        & chmod 700 $Path
        if ($LASTEXITCODE -ne 0) { throw "Unable to protect test directory: $Path" }
    }
}

function Set-WindowsExclusiveAcl([string]$Path, [bool]$IsDirectory) {
    $current = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $system = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $administrators = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    $security = if ($IsDirectory) {
        [Security.AccessControl.DirectorySecurity]::new()
    } else {
        [Security.AccessControl.FileSecurity]::new()
    }
    $security.SetOwner($current)
    $security.SetAccessRuleProtection($true, $false)
    foreach ($identity in @($current, $system, $administrators)) {
        $inheritance = if ($IsDirectory) {
            [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
                [Security.AccessControl.InheritanceFlags]::ObjectInherit
        } else {
            [Security.AccessControl.InheritanceFlags]::None
        }
        $security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            $identity,
            [Security.AccessControl.FileSystemRights]::FullControl,
            $inheritance,
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow))
    }
    if ($IsDirectory) {
        ([IO.DirectoryInfo](Get-Item -Force -LiteralPath $Path)).SetAccessControl($security)
    } else {
        ([IO.FileInfo](Get-Item -Force -LiteralPath $Path)).SetAccessControl($security)
    }
}

function Protect-TestSecret([string]$Path) {
    if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
        Set-WindowsExclusiveAcl $Path $false
    } elseif (Get-Command chmod -ErrorAction SilentlyContinue) {
        & chmod 600 $Path
        if ($LASTEXITCODE -ne 0) { throw "Unable to protect test secret: $Path" }
    }
}

function Add-WindowsAclRule(
    [string]$Path,
    [string]$Sid,
    [Security.AccessControl.FileSystemRights]$Rights) {
    $security = ([IO.DirectoryInfo](Get-Item -Force -LiteralPath $Path)).GetAccessControl()
    $security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        [Security.Principal.SecurityIdentifier]::new($Sid),
        $Rights,
        [Security.AccessControl.AccessControlType]::Allow))
    ([IO.DirectoryInfo](Get-Item -Force -LiteralPath $Path)).SetAccessControl($security)
}

function Assert-BuildInputFailure([scriptblock]$Action) {
    try {
        & $Action
    } catch {
        $script:BuildInputFailures++
        return
    }
    throw 'Expected immutable mailbox build-input materialization to fail.'
}

function Invoke-Driver([string[]]$DriverArguments, [switch]$ExpectFailure) {
    $project = Join-Path $root 'tools\survival-mailbox-driver\SurvivalMailboxDriver.csproj'
    $driverArtifacts = Join-Path $temporary 'driver-build-artifacts'
    if ($ExpectFailure) {
        $savedPreference = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try {
            $ignored = @(& dotnet run --project $project `
                --artifacts-path $driverArtifacts `
                "-p:XNodeSource=$xnode" -- @DriverArguments 2>&1)
            $exitCode = $LASTEXITCODE
        } finally {
            $ErrorActionPreference = $savedPreference
        }
        if ($exitCode -eq 0) { throw 'Expected mailbox provision command to fail.' }
        $script:ExpectedFailures++
        return
    }
    & dotnet run --project $project `
        --artifacts-path $driverArtifacts `
        "-p:XNodeSource=$xnode" -- @DriverArguments
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
    if ($source.sourceCommit -ne 'c6c5113c7e77fb9e6577a493e2cc57144cc0de91' -or
        (Get-FileHash -LiteralPath $sourceManifest -Algorithm SHA256).Hash -ne
            '68027E628E81230C8C26ACA5724E477E6C1BD6CA76F60A4315EF7E55A4489D40') {
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

    $driverSource = Join-Path $root 'tools\survival-mailbox-driver'
    $driverHashes = @{}
    foreach ($name in @(
        'MailboxGrantProvisioner.cs',
        'MailboxRuntimePublisher.cs',
        'Program.cs',
        'SurvivalMailboxDriver.csproj')) {
        $driverHashes[$name] = (Get-FileHash -LiteralPath (
            Join-Path $driverSource $name) -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    $materialize = {
        param([string]$Source, [string]$Driver, [string]$Destination)
        New-SurvivalMailboxIsolatedSource `
            -XNodeSource $Source `
            -DriverSource $Driver `
            -Destination $Destination `
            -ExpectedCommit 'c6c5113c7e77fb9e6577a493e2cc57144cc0de91' `
            -ExpectedManifestSha256 `
                '68027e628e81230c8c26aca5724e477e6c1bd6ca76f60a4315ef7e55a4489d40' `
            -ExpectedDriverSha256 $driverHashes
    }

    foreach ($extra in @(
        @{ Name = 'extra-cs'; Path = 'src\XNode.Core\Injected.cs'; Content = 'class Injected {}' },
        @{ Name = 'extra-targets'; Path = 'Directory.Build.targets'; Content = '<Project />' })) {
        $tamperedSource = Join-Path $temporary $extra.Name
        Copy-Item -LiteralPath $xnode -Destination $tamperedSource -Recurse
        $extraPath = Join-Path $tamperedSource $extra.Path
        [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($extraPath))
        [IO.File]::WriteAllText($extraPath, $extra.Content)
        Assert-BuildInputFailure {
            & $materialize $tamperedSource $driverSource (
                Join-Path $temporary "$($extra.Name)-isolated")
        }
    }

    $tamperedDriver = Join-Path $temporary 'same-name-driver-mutation'
    New-Item -ItemType Directory -Path $tamperedDriver | Out-Null
    foreach ($name in $driverHashes.Keys) {
        Copy-Item -LiteralPath (Join-Path $driverSource $name) -Destination (
            Join-Path $tamperedDriver $name)
    }
    Add-Content -LiteralPath (Join-Path $tamperedDriver 'Program.cs') -Value '// mutation'
    Assert-BuildInputFailure {
        & $materialize $xnode $tamperedDriver (
            Join-Path $temporary 'same-name-driver-isolated')
    }

    $lockedSourcePath = Join-Path $temporary 'locked-isolated'
    $lockedSource = & $materialize $xnode $driverSource $lockedSourcePath
    Set-MailboxTreeReadOnly $lockedSourcePath
    $lockedHandles = Open-MailboxTreeReadLocks $lockedSourcePath
    try {
        Assert-BuildInputFailure {
            [IO.File]::WriteAllText(
                (Join-Path $lockedSourcePath 'driver\Program.cs'),
                '// replacement')
        }
        Assert-BuildInputFailure {
            [IO.File]::WriteAllText(
                (Join-Path $lockedSourcePath 'driver\Directory.Build.targets'),
                '<Project />')
        }
        Assert-SurvivalMailboxIsolatedSource $lockedSource
    } finally {
        foreach ($lock in $lockedHandles) { $lock.Dispose() }
        Set-MailboxTreeWritable $lockedSourcePath
        Remove-Item -LiteralPath $lockedSourcePath -Recurse -Force
    }

    New-ProtectedDirectory $temporary
    $secrets = Join-Path $temporary 'authority-secrets'
    New-ProtectedDirectory $secrets
    foreach ($index in 1..6) {
        $seedPath = Join-Path $secrets "xnode-$index-ed25519.seed"
        [IO.File]::WriteAllText($seedPath, ('{0:x64}' -f $index) + "`n")
        Protect-TestSecret $seedPath
    }
    $issuer = Join-Path $secrets 'mailbox-client-issuer.seed'
    [IO.File]::WriteAllText($issuer, ('{0:x64}' -f 1001) + "`n")
    Protect-TestSecret $issuer
    $authority = Join-Path $temporary 'authority.json'
    $runtimeAuthority = Join-Path $temporary 'runtime-authority.json'
    Invoke-Driver @(
        'authority', '--secrets-dir', $secrets,
        '--output-env', (Join-Path $temporary 'authority.env'),
        '--output-client-env', (Join-Path $temporary 'client.env'),
        '--output-public', $authority,
        '--output-client-public', $runtimeAuthority,
        '--coordinator-url', 'http://192.168.1.44:41801')
    $authorityHash = Get-LowerSha256 $authority
    $runtimeAuthorityHash = Get-LowerSha256 $runtimeAuthority
    $authorityObject = Get-Content -Raw -LiteralPath $authority | ConvertFrom-Json
    $runtimeAuthorityObject = Get-Content -Raw -LiteralPath $runtimeAuthority | ConvertFrom-Json
    if (@($runtimeAuthorityObject.selections).Count -ne 0 -or
        @($runtimeAuthorityObject.epochs | Where-Object { @($_.replicas).Count -ne 0 }).Count -ne 0 -or
        [string]$runtimeAuthorityObject.issuerPublicKey -cne [string]$authorityObject.issuerPublicKey) {
        throw 'Client authority is not the exact minimized semantic projection.'
    }
    $issuerPublicKey = [string]$authorityObject.issuerPublicKey

    $output = Join-Path $temporary 'output'
    $hostSecrets = Join-Path $temporary 'host-secrets'
    New-ProtectedDirectory $output
    New-ProtectedDirectory $hostSecrets
    # Runtime publication derives canonical 05 Session IDs, so holders must be
    # valid Ed25519 points rather than arbitrary 32-byte provision fixtures.
    $android = [string]$authorityObject.replicaSigningPublicKeys[0]
    $windows = [string]$authorityObject.replicaSigningPublicKeys[1]
    $trust = @(
        '--development-only', '--allow-http', '--physical-dev',
        '--authority-public', $authority,
        '--expected-authority-sha256', $authorityHash,
        '--runtime-authority-public', $runtimeAuthority,
        '--expected-runtime-authority-sha256', $runtimeAuthorityHash,
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

    if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
        foreach ($aclCase in @(
            @{ Name = 'users-read'; Sid = 'S-1-5-32-545' },
            @{ Name = 'everyone-read'; Sid = 'S-1-1-0' },
            @{ Name = 'arbitrary-read'; Sid = 'S-1-5-21-111111111-222222222-333333333-4444' })) {
            $aclRoot = Join-Path $temporary ("acl-" + $aclCase.Name)
            $aclSecrets = Join-Path $temporary ("acl-secrets-" + $aclCase.Name)
            New-ProtectedDirectory $aclRoot
            New-ProtectedDirectory $aclSecrets
            Add-WindowsAclRule `
                $aclRoot `
                $aclCase.Sid `
                ([Security.AccessControl.FileSystemRights]::ReadAndExecute)
            Invoke-Driver (@('provision') + $common + @(
                '--issuer-seed-path', $issuer,
                '--output-directory', $aclRoot,
                '--mailbox-secret-directory', $aclSecrets)) -ExpectFailure
        }

        $inheritedParent = Join-Path $temporary 'acl-inherited-parent'
        $inheritedSecrets = Join-Path $temporary 'acl-inherited-secrets'
        New-ProtectedDirectory $inheritedParent
        New-ProtectedDirectory $inheritedSecrets
        $parentDirectory = [IO.DirectoryInfo](
            Get-Item -Force -LiteralPath $inheritedParent)
        $parentSecurity = $parentDirectory.GetAccessControl()
        $parentSecurity.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new('S-1-5-32-545'),
            [Security.AccessControl.FileSystemRights]::ReadAndExecute,
            [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
                [Security.AccessControl.InheritanceFlags]::ObjectInherit,
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow))
        $parentDirectory.SetAccessControl($parentSecurity)
        $inheritedRoot = Join-Path $inheritedParent 'child'
        New-Item -ItemType Directory -Path $inheritedRoot | Out-Null
        Invoke-Driver (@('provision') + $common + @(
            '--issuer-seed-path', $issuer,
            '--output-directory', $inheritedRoot,
            '--mailbox-secret-directory', $inheritedSecrets)) -ExpectFailure
    }

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
    foreach ($bundle in @($androidJson, $windowsJson)) {
        if (@($bundle.ownMailbox.depositGrants).Count -ne 2 -or
            @($bundle.ownMailbox.retrieveAndAcknowledgeGrants).Count -ne 2 -or
            @($bundle.peerMailboxRoute.depositGrants).Count -ne 2 -or
            $bundle.ownMailbox.depositGrants[0].canonicalGrant -eq
                $bundle.peerMailboxRoute.depositGrants[0].canonicalGrant -or
            $bundle.ownMailbox.depositGrants[0].canonicalGrant -eq
                $bundle.ownMailbox.retrieveAndAcknowledgeGrants[0].canonicalGrant) {
            throw 'Each client must receive distinct E/E+1 own-copy deposit, retrieve, and peer deposit grants.'
        }
    }

    # Publish both platform-specific runtime roots from the minimized authority,
    # bounded empty revocations, and a public RFC 8032 synthetic test key.
    $runtimeParent = Join-Path $temporary 'runtime-output'
    New-ProtectedDirectory $runtimeParent
    $testPrivateKey = Join-Path $temporary 'synthetic-mr-x.private'
    $testPublicKey = Join-Path $temporary 'synthetic-mr-x.public'
    $testSeed = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'
    $testPublic = 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a'
    [IO.File]::WriteAllBytes($testPrivateKey, (Convert-HexToBytes ($testSeed + $testPublic)))
    [IO.File]::WriteAllBytes($testPublicKey, (Convert-HexToBytes $testPublic))
    Protect-TestSecret $testPrivateKey
    Protect-TestSecret $testPublicKey
    $publishRuntime = @(
        'publish-runtime', '--development-only',
        '--runtime-authority-public', $runtimeAuthority,
        '--expected-runtime-authority-sha256', $runtimeAuthorityHash,
        '--pair-directory', $output,
        '--android-runtime-root', (Join-Path $runtimeParent 'android'),
        '--windows-runtime-root', (Join-Path $runtimeParent 'windows'),
        '--android-holder-public-key', $android,
        '--windows-holder-public-key', $windows,
        '--mr-x-private-key', $testPrivateKey,
        '--mr-x-public-key', $testPublicKey,
        '--revocation-ttl-seconds', '3600')
    Invoke-Driver $publishRuntime
    Invoke-Driver $publishRuntime
    foreach ($platform in @('android', 'windows')) {
        $published = Join-Path $runtimeParent $platform
        $activation = Get-Content -Raw (Join-Path $published 'activation.v1.json') | ConvertFrom-Json
        $revocations = Get-Content -Raw (Join-Path $published 'revocations.v1.json') | ConvertFrom-Json
        if ([string]$activation.platform -cne $platform -or
            [string]$activation.authoritySha256 -cne $runtimeAuthorityHash -or
            @($revocations.revoked).Count -ne 0 -or
            (Get-Item (Join-Path $published 'mr-x-mailbox-policy.signature')).Length -ne 64) {
            throw "Published $platform runtime is not the exact bounded signed schema."
        }
    }
    $badPublicKey = Join-Path $temporary 'synthetic-mr-x.bad-public'
    [IO.File]::WriteAllBytes($badPublicKey, [byte[]](1..32))
    Protect-TestSecret $badPublicKey
    $badPublish = @($publishRuntime)
    $badPublish[[Array]::IndexOf($badPublish, '--mr-x-public-key') + 1] = $badPublicKey
    Invoke-Driver $badPublish -ExpectFailure
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
    foreach ($barrier in @('stage', 'generation-parent', 'pointer-temp-parent')) {
        Invoke-Driver ($atomicNew + @(
            '--fail-after-durability-barrier', $barrier)) -ExpectFailure
        if ((Get-CurrentPair $atomicRoot).Generation -ne $oldGeneration) {
            throw "Failure after $barrier durability barrier changed the advertised generation."
        }
        Invoke-Driver (@('verify-provision') + $common + @('--pair-directory', $atomicRoot))
    }
    Invoke-Driver ($atomicNew + @(
        '--fail-after-durability-barrier', 'pointer-parent')) -ExpectFailure
    $committedAfterPointerBarrier = Get-CurrentPair $atomicRoot
    if ($committedAfterPointerBarrier.Generation -eq $oldGeneration) {
        throw 'The pointer-parent barrier fault did not occur after atomic pointer publication.'
    }
    Invoke-Driver (@('verify-provision') + $trust + @(
        '--android-holder-public-key', $androidTwo,
        '--windows-holder-public-key', $windowsTwo,
        '--pair-directory', $atomicRoot))

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

    # A cryptographically valid own-copy deposit grant for the other holder
    # cannot be substituted even after all unauthenticated pair hashes change.
    $ownDepositTamperRoot = Join-Path $temporary 'own-deposit-tamper'
    Copy-Item -LiteralPath $output -Destination $ownDepositTamperRoot -Recurse
    $ownDepositPair = Get-CurrentPair $ownDepositTamperRoot
    $ownDepositAndroid = Get-Content -Raw -LiteralPath $ownDepositPair.Android | ConvertFrom-Json
    $ownDepositWindows = Get-Content -Raw -LiteralPath $ownDepositPair.Windows | ConvertFrom-Json
    $ownDepositAndroid.ownMailbox.depositGrants =
        $ownDepositWindows.ownMailbox.depositGrants
    $ownDepositAndroid | ConvertTo-Json -Depth 14 | Set-Content -NoNewline (
        $ownDepositPair.Android)
    $ownDepositManifest = Get-Content -Raw -LiteralPath $ownDepositPair.Manifest | ConvertFrom-Json
    $ownDepositManifest.files.android = Get-LowerSha256 $ownDepositPair.Android
    $ownDepositManifest | ConvertTo-Json -Depth 14 | Set-Content -NoNewline (
        $ownDepositPair.Manifest)
    $ownDepositPointerPath = Join-Path $ownDepositTamperRoot 'current-generation.json'
    $ownDepositPointer = Get-Content -Raw -LiteralPath $ownDepositPointerPath | ConvertFrom-Json
    $ownDepositPointer.pairManifestSha256 = Get-LowerSha256 $ownDepositPair.Manifest
    $ownDepositPointer | ConvertTo-Json -Depth 14 | Set-Content -NoNewline (
        $ownDepositPointerPath)
    Invoke-Driver (@('verify-provision') + $common + @(
        '--pair-directory', $ownDepositTamperRoot)) -ExpectFailure

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

    # Exercise the operator wrapper itself: exact source+driver materialization,
    # protected publish, and both secret-bearing commands use only locked bytes.
    $wrapperOutput = Join-Path $temporary 'wrapper-output'
    $wrapperSecrets = Join-Path $temporary 'wrapper-secrets'
    New-ProtectedDirectory $wrapperOutput
    New-ProtectedDirectory $wrapperSecrets
    & powershell -ExecutionPolicy Bypass -File (
        Join-Path $PSScriptRoot 'survival-dev-mailbox-provision.ps1') `
        -AndroidHolderPublicKey $android `
        -WindowsHolderPublicKey $windows `
        -AuthoritySha256 $authorityHash `
        -ExpectedIssuerPublicKey $issuerPublicKey `
        -AuthorityPublic $authority `
        -RuntimeAuthorityPublic $runtimeAuthority `
        -RuntimeAuthoritySha256 $runtimeAuthorityHash `
        -IssuerSeedPath $issuer `
        -OutputDirectory $wrapperOutput `
        -MailboxSecretDirectory $wrapperSecrets `
        -CoordinatorUrl 'http://192.168.1.44:41801'
    if ($LASTEXITCODE -ne 0) {
        throw 'The immutable operator wrapper smoke failed.'
    }

    $expectedDriverFailures = if (
        [Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) { 19 } else { 15 }
    if ($script:ExpectedFailures -ne $expectedDriverFailures) {
        throw "Expected $expectedDriverFailures driver negative paths, executed $script:ExpectedFailures."
    }
    if ($script:BuildInputFailures -ne 5) {
        throw "Expected five immutable build-input failures, executed $script:BuildInputFailures."
    }
    Write-Output (
        "survival-dev mailbox MAUI grant provision tests passed; " +
        "driver-expected-failures=$expectedDriverFailures; build-input-failures=5.")
}
finally {
    Set-MailboxTreeWritable $temporary
    Remove-Item -LiteralPath $temporary -Recurse -Force -ErrorAction SilentlyContinue
}
