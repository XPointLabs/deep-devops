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
if ([string]::IsNullOrWhiteSpace($AuthorityPublic)) { $AuthorityPublic = Join-Path $root 'artifacts\survival-dev\mailbox-peer-authority.public.json' }
if ([string]::IsNullOrWhiteSpace($IssuerSeedPath)) { $IssuerSeedPath = Join-Path $root '.secrets\survival-dev\mailbox-client-issuer.seed' }
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) { $OutputDirectory = Join-Path $root 'artifacts\survival-dev\maui-mailbox-grants' }
if ([string]::IsNullOrWhiteSpace($MailboxSecretDirectory)) { $MailboxSecretDirectory = Join-Path $root '.secrets\survival-dev\maui-mailbox-grants' }

# This wrapper intentionally does not call Docker or export the issuer seed.
$xnodeSource = Join-Path $root 'artifacts\survival-dev\build-contexts\xnode'
$sourceManifest = Join-Path $xnodeSource '.survival-source-manifest.json'
if (-not (Test-Path -LiteralPath $sourceManifest -PathType Leaf)) {
    throw 'The pinned exported XNode source snapshot is missing. Run the existing Prepare action first.'
}
$source = Get-Content -Raw -LiteralPath $sourceManifest | ConvertFrom-Json
if ($source.sourceCommit -ne '132fae59ec834e2986703103ccc233a8d51352ea' -or
    (Get-FileHash -LiteralPath $sourceManifest -Algorithm SHA256).Hash -ne
        'D32FA4D17EE9CD4D2C4DDEC5167FEED30D710113680DB5342795EC2DF93A5B38') {
    throw 'The exported XNode source snapshot does not match the exact pinned revision and manifest.'
}
foreach ($file in $source.files) {
    $candidate = [IO.Path]::GetFullPath((Join-Path $xnodeSource ([string]$file.path)))
    $snapshotPrefix = [IO.Path]::GetFullPath($xnodeSource).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    if (-not $candidate.StartsWith(
            $snapshotPrefix,
            [StringComparison]::OrdinalIgnoreCase) -or
        -not (Test-Path -LiteralPath $candidate -PathType Leaf) -or
        (Get-Item -LiteralPath $candidate).Length -ne [long]$file.bytes -or
        (Get-FileHash -LiteralPath $candidate -Algorithm SHA256).Hash.ToLowerInvariant() -ne
            [string]$file.sha256) {
        throw "Pinned exported XNode file mismatch: $($file.path)"
    }
}
foreach ($path in @($OutputDirectory, $MailboxSecretDirectory)) {
    if (-not (Test-Path -LiteralPath $path -PathType Container)) {
        throw "Operator-protected root must already exist: $path"
    }
}
$arguments = @(
    'run', '--project', (Join-Path $root 'tools\survival-mailbox-driver\SurvivalMailboxDriver.csproj'),
    "-p:XNodeSource=$([IO.Path]::GetFullPath($xnodeSource))", '--', 'provision',
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
if ($LASTEXITCODE -ne 0) { throw 'DEV-LOCAL-ONLY MAUI mailbox grant provisioning failed.' }

$verifyArguments = @(
    'run', '--project', (Join-Path $root 'tools\survival-mailbox-driver\SurvivalMailboxDriver.csproj'),
    "-p:XNodeSource=$([IO.Path]::GetFullPath($xnodeSource))", '--', 'verify-provision',
    '--development-only', '--allow-http', '--physical-dev',
    '--pair-directory', ([IO.Path]::GetFullPath($OutputDirectory)),
    '--authority-public', ([IO.Path]::GetFullPath($AuthorityPublic)),
    '--expected-authority-sha256', $AuthoritySha256,
    '--expected-issuer-public-key', $ExpectedIssuerPublicKey,
    '--coordinator-url', $CoordinatorUrl,
    '--android-holder-public-key', $AndroidHolderPublicKey,
    '--windows-holder-public-key', $WindowsHolderPublicKey)
& dotnet @verifyArguments
if ($LASTEXITCODE -ne 0) { throw 'Published DEV-LOCAL-ONLY mailbox pair verification failed.' }
