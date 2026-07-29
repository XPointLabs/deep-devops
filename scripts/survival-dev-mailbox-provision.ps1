[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{64}$')][string]$AndroidHolderPublicKey,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{64}$')][string]$WindowsHolderPublicKey,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{64}$')][string]$AuthoritySha256,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{64}$')][string]$ExpectedIssuerPublicKey,
    [string]$AuthorityPublic = '',
    [string]$IssuerSeedPath = '',
    [string]$OutputDirectory = '',
    [string]$MailboxSecretDirectory = '',
    [string]$CoordinatorUrl = 'http://192.168.1.44:41801'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$root = [IO.Path]::GetFullPath((Split-Path $PSScriptRoot -Parent))
$buildHelper = Join-Path $PSScriptRoot 'survival-dev-mailbox-build-inputs.ps1'
$expectedBuildHelperSha256 =
    'fa1b87b7928b47f4b4ffa603f02b52d46e4fc2419ee9812bf09737c6d878e872'
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
$expectedXNodeCommit = 'a5318f6ea5091e0e8ab2e4ac6e2cd47135857524'
$expectedXNodeManifestSha256 =
    '0411615b8e6c04b975fc655088d3294aaa2eb89dae2f93dfd7367fcae64feaae'
$expectedDriverSha256 = @{
    'MailboxGrantProvisioner.cs' =
        '845aa8070304c6b0d81bca7c6ffa4a12fdd1c3255d45b0ea31f09abf2cb3461d'
    'Program.cs' =
        '05942710fbdd314ce5bed39c3adfd02f5868fefd39b29834ded38a390aa4aee5'
    'SurvivalMailboxDriver.csproj' =
        'd1ec23d0022a77b2fa818bca1e8a088baeb72208dbccf356ccefa16166e89c63'
}
$xnodeSource = Join-Path $root 'artifacts\survival-dev\build-contexts\xnode'
foreach ($path in @($OutputDirectory, $MailboxSecretDirectory)) {
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
    & dotnet @verifyArguments
    if ($LASTEXITCODE -ne 0) {
        throw 'Published DEV-LOCAL-ONLY mailbox pair verification failed.'
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
