[CmdletBinding()]
param(
    [string]$AndroidHolderPath = '',
    [string]$WindowsHolderPath = '',
    [string]$CoordinatorUrl = 'http://192.168.1.44:41801',
    [ValidateRange(1800,14400)][int]$RevocationTtlSeconds = 14400,
    [string]$RuntimeOutputParent = ''
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$root = [IO.Path]::GetFullPath((Split-Path $PSScriptRoot -Parent))
$deepSessionRoot = [IO.Path]::GetFullPath((Split-Path (Split-Path $root -Parent) -Parent))
$bootstrapRoot = Join-Path $deepSessionRoot 'secrets\mailbox-bootstrap'
$expectedAndroidHolder = Join-Path $bootstrapRoot 'holders\android.holder.v1.json'
$expectedWindowsHolder = Join-Path $bootstrapRoot 'holders\windows.holder.v1.json'
if ([string]::IsNullOrWhiteSpace($AndroidHolderPath)) { $AndroidHolderPath = $expectedAndroidHolder }
if ([string]::IsNullOrWhiteSpace($WindowsHolderPath)) { $WindowsHolderPath = $expectedWindowsHolder }
if ([IO.Path]::GetFullPath($AndroidHolderPath) -cne [IO.Path]::GetFullPath($expectedAndroidHolder) -or
    [IO.Path]::GetFullPath($WindowsHolderPath) -cne [IO.Path]::GetFullPath($expectedWindowsHolder)) {
    throw 'Physical issuance accepts only the canonical protected Android/Windows holder records.'
}

function Assert-ProtectedHolderFile([string]$Path) {
    $item = Get-Item -Force -LiteralPath $Path
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Canonical holder record cannot be a reparse point.'
    }
    if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
        $current = [Security.Principal.WindowsIdentity]::GetCurrent().User
        $allowed = @($current.Value, 'S-1-5-18', 'S-1-5-32-544') | Sort-Object
        $security = ([IO.FileInfo]$item).GetAccessControl()
        $rules = @($security.GetAccessRules($true, $true,
            [Security.Principal.SecurityIdentifier]) | ForEach-Object {
                if ($_.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
                    ($_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -ne
                        [Security.AccessControl.FileSystemRights]::FullControl) {
                    throw 'Canonical holder record has a non-full-control or deny ACE.'
                }
                ([Security.Principal.SecurityIdentifier]$_.IdentityReference).Value
            } | Sort-Object)
        if (-not $security.AreAccessRulesProtected -or
            -not $security.AreAccessRulesCanonical -or
            $security.GetOwner([Security.Principal.SecurityIdentifier]).Value -cne $current.Value -or
            ($rules -join ',') -cne ($allowed -join ',')) {
            throw 'Canonical holder record does not have the exact protected owner/DACL.'
        }
    } elseif ([IO.File]::GetUnixFileMode($Path) -ne
        ([IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite)) {
        throw 'Canonical holder record must have Unix mode 0600.'
    }
}

function Read-CanonicalHolder([string]$Path, [string]$Platform) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Canonical $Platform holder record is missing."
    }
    Assert-ProtectedHolderFile $Path
    $holder = Get-Content -Raw -LiteralPath $Path | ConvertFrom-Json
    $properties = @($holder.PSObject.Properties.Name | Sort-Object)
    if (($properties -join ',') -cne
        'developmentOnly,ed25519PublicKey,platform,schemaVersion,sessionId' -or
        $holder.schemaVersion -ne 1 -or -not $holder.developmentOnly -or
        [string]$holder.platform -cne $Platform -or
        [string]$holder.sessionId -cnotmatch '^05[0-9a-f]{64}$' -or
        [string]$holder.ed25519PublicKey -cnotmatch '^[0-9a-f]{64}$') {
        throw "Canonical $Platform holder record has an invalid schema."
    }
    return [string]$holder.ed25519PublicKey
}

$AndroidHolderPublicKey = Read-CanonicalHolder $AndroidHolderPath 'android'
$WindowsHolderPublicKey = Read-CanonicalHolder $WindowsHolderPath 'windows'
if ($AndroidHolderPublicKey -ceq $WindowsHolderPublicKey) {
    throw 'Android and Windows holder identities must be distinct.'
}
$sourceAuthority = Join-Path $root 'artifacts\survival-dev\mailbox-peer-authority.public.json'
$runtimeAuthority = Join-Path $root 'artifacts\survival-dev\mailbox-client-authority.public.json'
$issuerSeed = Join-Path $root '.secrets\survival-dev\mailbox-client-issuer.seed'
$pairRoot = Join-Path $bootstrapRoot 'provisioning\pair'
$pairSecrets = Join-Path $bootstrapRoot 'provisioning\host-secrets'

foreach ($path in @($sourceAuthority, $runtimeAuthority, $issuerSeed)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Prepared Survival authority input is missing: $path. Run survival-dev.ps1 -Action Up first."
    }
}
$authority = Get-Content -Raw -LiteralPath $sourceAuthority | ConvertFrom-Json
$runtime = Get-Content -Raw -LiteralPath $runtimeAuthority | ConvertFrom-Json
$now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
if ([long]$authority.issuerValidFromUnixSeconds -gt $now -or
    [long]$authority.issuerValidUntilUnixSeconds -lt ($now + 1800) -or
    [string]$authority.coordinatorUrl -cne $CoordinatorUrl) {
    throw 'Prepared source authority is expired, too close to expiry, or bound to another coordinator. Run Survival Up for this LAN host.'
}
if ([string]$runtime.issuerPublicKey -cne [string]$authority.issuerPublicKey -or
    [long]$runtime.issuerValidUntilUnixSeconds -ne [long]$authority.issuerValidUntilUnixSeconds -or
    @($runtime.selections).Count -ne 0 -or
    @($runtime.epochs | Where-Object { @($_.replicas).Count -ne 0 }).Count -ne 0) {
    throw 'Prepared runtime authority is not the minimized projection of the live source authority.'
}

$sourceHash = (Get-FileHash -LiteralPath $sourceAuthority -Algorithm SHA256).Hash.ToLowerInvariant()
$runtimeHash = (Get-FileHash -LiteralPath $runtimeAuthority -Algorithm SHA256).Hash.ToLowerInvariant()
$arguments = @(
    '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File',
    (Join-Path $PSScriptRoot 'survival-dev-mailbox-provision.ps1'),
    '-AndroidHolderPublicKey', $AndroidHolderPublicKey,
    '-WindowsHolderPublicKey', $WindowsHolderPublicKey,
    '-AuthoritySha256', $sourceHash,
    '-ExpectedIssuerPublicKey', ([string]$authority.issuerPublicKey),
    '-AuthorityPublic', $sourceAuthority,
    '-RuntimeAuthoritySha256', $runtimeHash,
    '-RuntimeAuthorityPublic', $runtimeAuthority,
    '-IssuerSeedPath', $issuerSeed,
    '-OutputDirectory', $pairRoot,
    '-MailboxSecretDirectory', $pairSecrets,
    '-CoordinatorUrl', $CoordinatorUrl,
    '-PublishRuntime',
    '-RevocationTtlSeconds', $RevocationTtlSeconds)
if (-not [string]::IsNullOrWhiteSpace($RuntimeOutputParent)) {
    $arguments += @('-RuntimeOutputParent', [IO.Path]::GetFullPath($RuntimeOutputParent))
}
& powershell @arguments
if ($LASTEXITCODE -ne 0) { throw 'Physical DEV mailbox runtime issuance failed.' }

$effectiveRuntimeParent = if ([string]::IsNullOrWhiteSpace($RuntimeOutputParent)) {
    Join-Path $bootstrapRoot 'runtime'
} else { [IO.Path]::GetFullPath($RuntimeOutputParent) }
[pscustomobject]@{
    schemaVersion = 1
    developmentOnly = $true
    sourceAuthoritySha256 = $sourceHash
    runtimeAuthoritySha256 = $runtimeHash
    issuerPublicKey = [string]$authority.issuerPublicKey
    validUntilUnixSeconds = [long]$authority.issuerValidUntilUnixSeconds
    androidRuntimeRoot = Join-Path $effectiveRuntimeParent 'android'
    windowsRuntimeRoot = Join-Path $effectiveRuntimeParent 'windows'
    mrXPublicKeySha256 = (Get-FileHash -LiteralPath (
        Join-Path $deepSessionRoot 'secrets\android-lab-dev\mr-x-dev-public-key.bin') `
        -Algorithm SHA256).Hash.ToLowerInvariant()
} | ConvertTo-Json
