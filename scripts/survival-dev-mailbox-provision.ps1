[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{64}$')][string]$AndroidHolderPublicKey,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{64}$')][string]$WindowsHolderPublicKey,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{64}$')][string]$AuthoritySha256,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{64}$')][string]$ExpectedIssuerPublicKey,
    [string]$AuthorityPublic = '',
    [ValidatePattern('^$|^[0-9a-f]{64}$')][string]$RuntimeAuthoritySha256 = '',
    [string]$RuntimeAuthorityPublic = '',
    [string]$IssuerSeedPath = '',
    [string]$OutputDirectory = '',
    [string]$MailboxSecretDirectory = '',
    [Parameter(Mandatory)][string]$CoordinatorUrl,
    [switch]$PublishRuntime,
    [ValidateRange(1800,14400)][int]$RevocationTtlSeconds = 14400,
    [string]$RuntimeOutputParent = ''
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$root = [IO.Path]::GetFullPath((Split-Path $PSScriptRoot -Parent))
$buildHelper = Join-Path $PSScriptRoot 'survival-dev-mailbox-build-inputs.ps1'
$expectedBuildHelperSha256 =
    'db657dc0a596a197bc0258c00f1a81f4fe84978efe3d2535c8fc44dd31f22bc3'
if (((Get-Item -Force -LiteralPath $buildHelper).Attributes -band
    [IO.FileAttributes]::ReparsePoint)) {
    throw 'The mailbox immutable-build helper cannot be a reparse point.'
}
$helperStream = [IO.FileStream]::new(
    $buildHelper,
    [IO.FileMode]::Open,
    [IO.FileAccess]::Read,
    [IO.FileShare]::Read)
try {
    if ($helperStream.Length -gt 1024 * 1024) {
        throw 'The mailbox immutable-build helper exceeds its exact size bound.'
    }
    $helperBytes = [byte[]]::new([int]$helperStream.Length)
    $helperOffset = 0
    while ($helperOffset -lt $helperBytes.Length) {
        $read = $helperStream.Read(
            $helperBytes,
            $helperOffset,
            $helperBytes.Length - $helperOffset)
        if ($read -eq 0) {
            throw 'The mailbox immutable-build helper changed while it was read.'
        }
        $helperOffset += $read
    }
} finally {
    $helperStream.Dispose()
}
$helperHasher = [Security.Cryptography.SHA256]::Create()
try {
    $actualBuildHelperSha256 = ([BitConverter]::ToString(
        $helperHasher.ComputeHash($helperBytes)).Replace('-', '')).ToLowerInvariant()
} finally {
    $helperHasher.Dispose()
}
if ($actualBuildHelperSha256 -cne $expectedBuildHelperSha256) {
    throw 'The mailbox immutable-build helper does not match its exact reviewed hash.'
}
. ([ScriptBlock]::Create([Text.Encoding]::UTF8.GetString($helperBytes)))
[Array]::Clear($helperBytes, 0, $helperBytes.Length)
if ([string]::IsNullOrWhiteSpace($AuthorityPublic)) { $AuthorityPublic = Join-Path $root 'artifacts\survival-dev\mailbox-peer-authority.public.json' }
if ([string]::IsNullOrWhiteSpace($IssuerSeedPath)) { $IssuerSeedPath = Join-Path $root '.secrets\survival-dev\mailbox-client-issuer.seed' }
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) { $OutputDirectory = Join-Path $root 'artifacts\survival-dev\maui-mailbox-grants' }
if ([string]::IsNullOrWhiteSpace($MailboxSecretDirectory)) { $MailboxSecretDirectory = Join-Path $root '.secrets\survival-dev\maui-mailbox-grants' }

# This wrapper intentionally does not call Docker or export the issuer seed.
$expectedXNodeCommit = '00280a643cfdc1e0780147eceb1da5c7b6fd2799'
$expectedXNodeManifestSha256 =
    'bd8cb5a16fb1d396716adc14d0adf95b005c0cccdf476cffd1cd65e5938aa102'
$expectedDriverSha256 = @{
    'MailboxGrantProvisioner.cs' =
        '884a6670230d36333adbdad37358d082ca84740fef2d5c6e13776500a37b8d53'
    'MailboxRuntimePublisher.cs' =
        'aa725b67ddfd48193a3e5cc3f39f529130e589e05fa14b1569123c8a8cf42866'
    'PrivateCrossProcessState.cs' =
        '651d8256822d41b9a7bceab1e6d6bb45740026cac00f487a564befe7777f272b'
    'Program.cs' =
        '5763c4556c96dbe2bd798dc79cfa1c97129adfd82691f1283734c06ee49a6562'
    'ProductionMailboxUatPublisher.cs' =
        '966c6be6cfe71317c10e66265bbad30ab61736e722a120304b8ce035fb056bc7'
    'SurvivalMailboxDriver.csproj' =
        '4db436d69ea88ac3ff16f08c161b61cc0c048bad84cb7e529b2208fa569eafbe'
}
$xnodeSource = Join-Path $root 'artifacts\survival-dev\build-contexts\xnode'
foreach ($path in @($OutputDirectory, $MailboxSecretDirectory)) {
    if (-not (Test-Path -LiteralPath $path)) {
        [void][IO.Directory]::CreateDirectory($path)
        Set-MailboxDirectoryExclusiveWritable $path
    }
    if (-not (Test-Path -LiteralPath $path -PathType Container)) {
        throw "Operator-protected root must already exist: $path"
    }
}

$work = Join-Path ([IO.Path]::GetTempPath()) (
    'deep-mailbox-driver-' + [Guid]::NewGuid().ToString('N'))
$sourceRoot = Join-Path $work 'source'
$artifactsRoot = Join-Path $work 'artifacts'
$publishRoot = Join-Path $work 'publish'
$sourceLocks = $null
$publishLocks = $null
try {
    [void][IO.Directory]::CreateDirectory($work)
    Set-MailboxDirectoryExclusiveWritable $work
    $isolated = New-SurvivalMailboxIsolatedSource `
        -XNodeSource $xnodeSource `
        -DriverSource (Join-Path $root 'tools\survival-mailbox-driver') `
        -Destination $sourceRoot `
        -ExpectedCommit $expectedXNodeCommit `
        -ExpectedManifestSha256 $expectedXNodeManifestSha256 `
        -ExpectedDriverSha256 $expectedDriverSha256
    Set-MailboxTreeReadOnly $sourceRoot
    $sourceLocks = Open-MailboxTreeReadLocks $sourceRoot
    Assert-SurvivalMailboxIsolatedSource $isolated

    # Build once, before any secret-bearing command is started. All project
    # sources are the protected exact allowlist above; outputs live elsewhere.
    & dotnet publish $isolated.DriverProject `
        --configuration Release `
        --output $publishRoot `
        --artifacts-path $artifactsRoot `
        --no-self-contained `
        "-p:UseAppHost=false" `
        "-p:XNodeSource=$($isolated.XNode)" `
        "-p:ImportDirectoryBuildProps=false" `
        "-p:ImportDirectoryBuildTargets=false" `
        "-p:DirectoryPackagesPropsPath=$(Join-Path $isolated.XNode 'Directory.Packages.props')"
    if ($LASTEXITCODE -ne 0) {
        throw 'The protected exact mailbox driver build failed.'
    }
    Assert-SurvivalMailboxIsolatedSource $isolated
    Set-MailboxTreeReadOnly $publishRoot
    $publishLocks = Open-MailboxTreeReadLocks $publishRoot
    $driver = Join-Path $publishRoot 'SurvivalMailboxDriver.dll'
    if (-not (Test-Path -LiteralPath $driver -PathType Leaf)) {
        throw 'The protected mailbox driver publication is incomplete.'
    }

    $arguments = @(
        $driver, 'provision',
        '--development-only', '--allow-http', '--physical-dev',
        '--android-holder-public-key', $AndroidHolderPublicKey,
        '--windows-holder-public-key', $WindowsHolderPublicKey,
        '--authority-public', ([IO.Path]::GetFullPath($AuthorityPublic)),
        '--expected-authority-sha256', $AuthoritySha256,
        '--expected-issuer-public-key', $ExpectedIssuerPublicKey,
        '--issuer-seed-path', ([IO.Path]::GetFullPath($IssuerSeedPath)),
        '--output-directory', ([IO.Path]::GetFullPath($OutputDirectory)),
        '--mailbox-secret-directory', ([IO.Path]::GetFullPath($MailboxSecretDirectory)),
        '--coordinator-url', $CoordinatorUrl)
    if (-not [string]::IsNullOrWhiteSpace($RuntimeAuthorityPublic) -or
        -not [string]::IsNullOrWhiteSpace($RuntimeAuthoritySha256)) {
        if ([string]::IsNullOrWhiteSpace($RuntimeAuthorityPublic) -or
            [string]::IsNullOrWhiteSpace($RuntimeAuthoritySha256)) {
            throw 'Runtime authority path and SHA-256 must be supplied together.'
        }
        $arguments += @(
            '--runtime-authority-public', ([IO.Path]::GetFullPath($RuntimeAuthorityPublic)),
            '--expected-runtime-authority-sha256', $RuntimeAuthoritySha256)
    }
    & dotnet @arguments
    if ($LASTEXITCODE -ne 0) {
        throw 'DEV-LOCAL-ONLY MAUI mailbox grant provisioning failed.'
    }

    $verifyArguments = @(
        $driver, 'verify-provision',
        '--development-only', '--allow-http', '--physical-dev',
        '--pair-directory', ([IO.Path]::GetFullPath($OutputDirectory)),
        '--authority-public', ([IO.Path]::GetFullPath($AuthorityPublic)),
        '--expected-authority-sha256', $AuthoritySha256,
        '--expected-issuer-public-key', $ExpectedIssuerPublicKey,
        '--coordinator-url', $CoordinatorUrl,
        '--android-holder-public-key', $AndroidHolderPublicKey,
        '--windows-holder-public-key', $WindowsHolderPublicKey)
    if (-not [string]::IsNullOrWhiteSpace($RuntimeAuthorityPublic)) {
        $verifyArguments += @(
            '--runtime-authority-public', ([IO.Path]::GetFullPath($RuntimeAuthorityPublic)),
            '--expected-runtime-authority-sha256', $RuntimeAuthoritySha256)
    }
    & dotnet @verifyArguments
    if ($LASTEXITCODE -ne 0) {
        throw 'Published DEV-LOCAL-ONLY mailbox pair verification failed.'
    }
    if ($PublishRuntime) {
        if ([string]::IsNullOrWhiteSpace($RuntimeAuthorityPublic) -or
            [string]::IsNullOrWhiteSpace($RuntimeAuthoritySha256)) {
            throw 'Runtime publication requires the minimized runtime authority and its SHA-256.'
        }
        $deepSessionRoot = [IO.Path]::GetFullPath((Split-Path (Split-Path $root -Parent) -Parent))
        $labRoot = Join-Path $deepSessionRoot 'secrets\android-lab-dev'
        $expectedRuntimeParent = Join-Path $deepSessionRoot 'secrets\mailbox-bootstrap\runtime'
        if ([string]::IsNullOrWhiteSpace($RuntimeOutputParent)) {
            $RuntimeOutputParent = $expectedRuntimeParent
        }
        $runtimeParent = [IO.Path]::GetFullPath($RuntimeOutputParent)
        if (-not $runtimeParent.Equals(
            [IO.Path]::GetFullPath($expectedRuntimeParent),
            [StringComparison]::OrdinalIgnoreCase)) {
            throw 'DEV runtime outputs must use the canonical protected mailbox-bootstrap runtime root.'
        }
        [void][IO.Directory]::CreateDirectory($runtimeParent)
        Set-MailboxDirectoryExclusiveWritable $runtimeParent
        $privateKey = Join-Path $labRoot 'mr-x-dev-private-key.bin'
        $publicKey = Join-Path $labRoot 'mr-x-dev-public-key.bin'
        foreach ($key in @($privateKey, $publicKey)) {
            if (-not (Test-Path -LiteralPath $key -PathType Leaf)) {
                throw 'The software-held DEV-only Mr. X key pair is incomplete.'
            }
        }
        $privacyRoutesRoot = Join-Path $root 'artifacts\survival-dev'
        $androidPrivacyRoutes = Join-Path $privacyRoutesRoot 'privacy-routes.android.v1.json'
        $windowsPrivacyRoutes = Join-Path $privacyRoutesRoot 'privacy-routes.windows.v1.json'
        foreach ($privacyRoutes in @($androidPrivacyRoutes, $windowsPrivacyRoutes)) {
            if (-not (Test-Path -LiteralPath $privacyRoutes -PathType Leaf)) {
                throw 'The generated DEV privacy-route inventory is missing.'
            }
        }
        & dotnet $driver publish-runtime `
            --development-only `
            --runtime-authority-public ([IO.Path]::GetFullPath($RuntimeAuthorityPublic)) `
            --expected-runtime-authority-sha256 $RuntimeAuthoritySha256 `
            --pair-directory ([IO.Path]::GetFullPath($OutputDirectory)) `
            --android-runtime-root (Join-Path $runtimeParent 'android') `
            --windows-runtime-root (Join-Path $runtimeParent 'windows') `
            --android-holder-public-key $AndroidHolderPublicKey `
            --windows-holder-public-key $WindowsHolderPublicKey `
            --mr-x-private-key $privateKey `
            --mr-x-public-key $publicKey `
            --android-privacy-routes $androidPrivacyRoutes `
            --windows-privacy-routes $windowsPrivacyRoutes `
            --revocation-ttl-seconds $RevocationTtlSeconds
        if ($LASTEXITCODE -ne 0) {
            throw 'DEV-LOCAL-ONLY Android/Windows mailbox runtime publication failed.'
        }
    }
} finally {
    if ($null -ne $publishLocks) {
        foreach ($lock in $publishLocks) { $lock.Dispose() }
    }
    if ($null -ne $sourceLocks) {
        foreach ($lock in $sourceLocks) { $lock.Dispose() }
    }
    Set-MailboxTreeWritable $work
    Remove-Item -Force -Recurse -LiteralPath $work -ErrorAction SilentlyContinue
}
