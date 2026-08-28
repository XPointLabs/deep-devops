[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)')]
    [string]$LanHost,
    [Parameter(Mandatory)]
    [ValidatePattern('^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$')]
    [string]$PublicHost,
    [Parameter(Mandatory)]
    [string]$TlsSecretRoot,
    [Parameter(Mandatory)]
    [string]$MailboxSecretRoot,
    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9a-f]{64}$')]
    [string]$AndroidSigningCertificateSha256,
    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9a-f]{64}$')]
    [string]$AndroidBuildArtifactSha256,
    [Parameter(Mandatory)]
    [ValidateSet('network.xpoint.deep.e2e')]
    [string]$AndroidApplicationId,
    [Parameter(Mandatory)]
    [ValidatePattern('^[1-9][0-9]*$')]
    [string]$AndroidVersionCode,
    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9a-f]{64}(\|[0-9a-f]{64}){0,31}$')]
    [string]$AndroidSignerLineageSha256,
    [string]$WindowsSigningCertificateSha256,
    [string]$WindowsBuildArtifactSha256,
    [string]$PreviousTrustFloorBundle,
    [string]$PreviousAuthorityArtifact,
    [string]$XNodeRepository,
    [string]$OutputDirectory
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$root = [IO.Path]::GetFullPath((Split-Path $PSScriptRoot -Parent))
if ([string]::IsNullOrWhiteSpace($XNodeRepository)) {
    $XNodeRepository = Join-Path $root '..\xnode'
}
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $root 'artifacts\survival-dev\production-mailbox-uat'
}
$xnode = [IO.Path]::GetFullPath($XNodeRepository)
$tls = [IO.Path]::GetFullPath($TlsSecretRoot)
$private = [IO.Path]::GetFullPath($MailboxSecretRoot)
$output = [IO.Path]::GetFullPath($OutputDirectory)
$repositoryPrefix = $root.TrimEnd(
    [IO.Path]::DirectorySeparatorChar,
    [IO.Path]::AltDirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
if ($private.StartsWith($repositoryPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'UAT production-mailbox private material must stay outside the repository.'
}
if ((Test-Path -LiteralPath $private) -and
    (Get-Item -LiteralPath $private -Force).Attributes.HasFlag(
        [IO.FileAttributes]::ReparsePoint)) {
    throw 'UAT production-mailbox secret root must not be a reparse point.'
}
[void][IO.Directory]::CreateDirectory($private)
[void][IO.Directory]::CreateDirectory($output)

function Invoke-Checked([string]$File, [string[]]$Arguments) {
    & $File @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$File failed with exit code $LASTEXITCODE." }
}

function Protect-PrivatePath([string]$Path, [switch]$Directory) {
    if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
        $owner = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        $inheritance = if ($Directory) { '(OI)(CI)F' } else { 'F' }
        & icacls.exe $Path '/inheritance:r' '/grant:r' `
            "*$owner`:$inheritance" '*S-1-5-18:F' '*S-1-5-32-544:F' `
            '/q' | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Unable to protect UAT private material.' }
    }
    else {
        Invoke-Checked chmod @($(if ($Directory) { '700' } else { '600' }), $Path)
    }
}

function New-ProtectedSeed([string]$Name) {
    $path = Join-Path $private $Name
    if (Test-Path -LiteralPath $path -PathType Leaf) {
        $item = Get-Item -LiteralPath $path -Force
        if ($item.Attributes.HasFlag([IO.FileAttributes]::ReparsePoint) -or
            $item.Length -ne 32) {
            throw "Protected UAT seed '$Name' is invalid."
        }
        Protect-PrivatePath $path
        return
    }
    $temporary = "$path.$([Guid]::NewGuid().ToString('N')).tmp"
    $bytes = [byte[]]::new(32)
    try {
        [Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
        [IO.File]::WriteAllBytes($temporary, $bytes)
        Protect-PrivatePath $temporary
        Move-Item -LiteralPath $temporary -Destination $path
    }
    finally {
        [Array]::Clear($bytes, 0, $bytes.Length)
        Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
    }
}

Protect-PrivatePath $private -Directory
foreach ($name in @(
    'issuer.seed',
    'mrx.seed',
    'closure-publisher.seed',
    'owner-control.seed',
    'route-state-hmac.key')) {
    New-ProtectedSeed $name
}

$xnodeSecrets = Join-Path $root '.secrets\survival-dev'
$authorityState = Join-Path $xnodeSecrets 'mailbox-authority-state.v1.json'
$currentCertificate = Join-Path $tls 'server.crt'
$nextCertificate = Join-Path $tls 'next-server.crt'
foreach ($path in @($authorityState, $currentCertificate, $nextCertificate)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Required UAT bootstrap input is missing: $([IO.Path]::GetFileName($path))."
    }
}
foreach ($index in 1..6) {
    if (-not (Test-Path -LiteralPath (
            Join-Path $xnodeSecrets "xnode-$index-ed25519.seed") -PathType Leaf)) {
        throw 'Prepare the survival XNode identity secrets before UAT mailbox bootstrap.'
    }
}

$successorInputs = @($PreviousTrustFloorBundle, $PreviousAuthorityArtifact) |
    Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
if ($successorInputs.Count -notin @(0, 2)) {
    throw 'UAT successor bootstrap requires both previous trust floor and authority artifact.'
}
$publisherCommand = if ($successorInputs.Count -eq 2) {
    'publish-production-uat-successor'
} else {
    'publish-production-uat'
}
$successorArguments = if ($successorInputs.Count -eq 2) {
    @(
        '--previous-trust-floor', ([IO.Path]::GetFullPath($PreviousTrustFloorBundle)),
        '--previous-authority', ([IO.Path]::GetFullPath($PreviousAuthorityArtifact)))
} else { @() }
$windowsInputs = @(
    @($WindowsSigningCertificateSha256, $WindowsBuildArtifactSha256) |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
if ($successorInputs.Count -eq 0 -and $windowsInputs.Count -ne 2) {
    throw 'Initial UAT bootstrap requires exact Windows signing and build hashes.'
}
if ($windowsInputs.Count -notin @(0, 2) -or
    ($windowsInputs.Count -eq 2 -and
     ($WindowsSigningCertificateSha256 -cnotmatch '^[0-9a-f]{64}$' -or
      $WindowsBuildArtifactSha256 -cnotmatch '^[0-9a-f]{64}$'))) {
    throw 'UAT Windows approval rotation requires both exact signing and build hashes.'
}
$windowsArguments = if ($windowsInputs.Count -eq 2) {
    @(
        '--windows-signing-certificate-sha256', $WindowsSigningCertificateSha256,
        '--windows-build-artifact-sha256', $WindowsBuildArtifactSha256)
} else { @() }

$project = Join-Path $root 'tools\survival-mailbox-driver\SurvivalMailboxDriver.csproj'
$publisherArguments = @(
    'run', '--project', $project, '--configuration', 'Release',
    "-p:XNodeSource=$xnode", '--',
    $publisherCommand,
    '--secrets-dir', $xnodeSecrets,
    '--private-dir', $private,
    '--output-dir', $output,
    '--authority-state', $authorityState,
    '--lan-host', $LanHost,
    '--public-host', $PublicHost,
    '--current-certificate', $currentCertificate,
    '--next-certificate', $nextCertificate,
    '--android-signing-certificate-sha256', $AndroidSigningCertificateSha256,
    '--android-build-artifact-sha256', $AndroidBuildArtifactSha256,
    '--android-application-id', $AndroidApplicationId,
    '--android-version-code', $AndroidVersionCode,
    '--android-signer-lineage-sha256', $AndroidSignerLineageSha256) +
    $windowsArguments + $successorArguments
Invoke-Checked dotnet $publisherArguments

$runtimePath = Join-Path $output 'runtime-public.json'
$runtime = Get-Content -Raw -LiteralPath $runtimePath | ConvertFrom-Json
if ($runtime.schemaVersion -ne 1 -or $runtime.scope -cne 'DEVELOPMENT-UAT-ONLY') {
    throw 'Generated UAT production-mailbox public runtime is invalid.'
}
function Write-PublicEnvironment([string]$Path, [string[]]$Lines) {
    foreach ($line in $Lines) {
        if ($line -notmatch '^[A-Za-z][A-Za-z0-9_]*=[A-Za-z0-9_./:\-]+$') {
            throw 'Refusing a non-canonical UAT public environment value.'
        }
    }
    [IO.File]::WriteAllText(
        $Path,
        ($Lines -join "`n") + "`n",
        [Text.UTF8Encoding]::new($false))
}

Write-PublicEnvironment (Join-Path $output 'registry.env') @(
    'ProductionMailbox__Enabled=true',
    'ProductionMailbox__UseDevelopmentInMemoryState=true',
    'ProductionMailbox__AuthorityPath=/run/deep-production-mailbox/authority.pma1',
    'ProductionMailbox__RevocationPath=/run/deep-production-mailbox/revocations.pmr1',
    'ProductionMailbox__TopologyPath=/run/deep-production-mailbox/topology.pmt1',
    'ProductionMailbox__MembershipProofDirectory=/run/deep-production-mailbox/proofs',
    "ProductionMailbox__PinnedMrXPublicKeySha256=$($runtime.mrXPublicKeySha256)",
    "ProductionMailbox__ExpectedNetworkId=$($runtime.networkId)",
    "ProductionMailbox__PreviousAuthorityGeneration=$($runtime.previousAuthorityGeneration)",
    "ProductionMailbox__PreviousAuthorityHash=$($runtime.previousAuthorityHash)",
    "ProductionMailbox__PreviousRevocationGeneration=$($runtime.previousRevocationGeneration)",
    "ProductionMailbox__PreviousRevocationHeadHash=$($runtime.previousRevocationHeadHash)",
    "ProductionMailbox__PreviousRevocationSnapshotHash=$($runtime.previousRevocationSnapshotHash)",
    "ProductionMailbox__PreviousTopologyGeneration=$($runtime.previousTopologyGeneration)",
    "ProductionMailbox__PreviousTopologyHash=$($runtime.previousTopologyHash)",
    'ProductionMailbox__ClockSkewSeconds=60',
    'ProductionMailbox__SelectionLifetimeSeconds=900',
    'ProductionMailbox__ChallengeLifetimeSeconds=300',
    'ProductionMailbox__ProofOfWorkLeadingZeroBits=12',
    'ProductionMailbox__MaximumChallengesPerWindow=4096',
    'ProductionMailbox__ChallengeWindowSeconds=60',
    'ProductionMailbox__DevelopmentSoftwareSignerSeedPath=/run/secrets/production-mailbox-issuer',
    'ProductionMailbox__DevelopmentClosurePublisherSeedPath=/run/secrets/production-mailbox-closure-publisher',
    'ProductionMailbox__DevelopmentOwnerControlSeedPath=/run/secrets/production-mailbox-owner-control',
    "ProductionMailbox__ClosurePublisherEd25519PublicKey=$($runtime.closurePublisherEd25519PublicKey)",
    'ProductionMailbox__RouteStateHmacKeyPath=/run/secrets/production-mailbox-route-state-hmac',
    'ProductionMailbox__ArtifactCatalogDirectory=/state/production-mailbox-artifact-catalog')

Write-PublicEnvironment (Join-Path $output 'xnode.env') @(
    'DevelopmentUatPrivatePeerAddresses__Scope=DEVELOPMENT-UAT-ONLY',
    "DevelopmentUatPrivatePeerAddresses__Addresses__0=$LanHost",
    'MailboxClient__Enabled=true',
    'MailboxClient__DevelopmentFixture__Enabled=false',
    'MailboxClientAdapter__Enabled=true',
    "MailboxClientAdapter__CurrentMembershipCommitment=$($runtime.currentMembershipCommitment)",
    "MailboxClientAdapter__NextMembershipCommitment=$($runtime.nextMembershipCommitment)",
    "MailboxClientAdapter__CurrentEpoch=$($runtime.currentEpoch)",
    "MailboxClientAdapter__NextEpoch=$($runtime.nextEpoch)",
    "MailboxClientAdapter__CurrentNotBeforeUnixSeconds=$($runtime.currentNotBeforeUnixSeconds)",
    "MailboxClientAdapter__NextNotBeforeUnixSeconds=$($runtime.nextNotBeforeUnixSeconds)",
    "MailboxClientAdapter__CurrentExpiresAtUnixSeconds=$($runtime.currentExpiresAtUnixSeconds)",
    "MailboxClientAdapter__NextExpiresAtUnixSeconds=$($runtime.nextExpiresAtUnixSeconds)",
    'MailboxClientProductionAuthority__Enabled=true',
    'MailboxClientProductionAuthority__ArtifactPath=/state/production-mailbox-artifacts/authority.pma1',
    'MailboxClientProductionAuthority__RevocationArtifactPath=/state/production-mailbox-artifacts/revocations.pmr1',
    'MailboxClientProductionAuthority__TopologyArtifactPath=/state/production-mailbox-artifacts/topology.pmt1',
    'MailboxClientProductionAuthority__SelectionArtifactDirectory=/state/production-mailbox-artifacts/selections',
    "MailboxClientProductionAuthority__ReadinessBlindedPlacementId=$($runtime.readinessBlindedPlacementId)",
    "MailboxClientProductionAuthority__ReadinessSelectionInputCommitment=$($runtime.readinessSelectionInputCommitment)",
    'MailboxClientProductionAuthority__ArtifactTrustRoot=/state/production-mailbox-artifacts',
    'MailboxClientProductionAuthority__LastKnownGoodPath=/state/production-mailbox/authority-lkg.pml3',
    'MailboxClientProductionAuthority__ClosureDirectory=/state/production-mailbox/closures',
    'MailboxClientProductionAuthority__ClosureStateHmacKeyPath=/state/production-mailbox/closure-state-hmac.key',
    "MailboxClientProductionAuthority__ClosurePublisherEd25519PublicKey=$($runtime.closurePublisherEd25519PublicKey)",
    "MailboxClientProductionAuthority__PinnedMrXPublicKeySha256=$($runtime.mrXPublicKeySha256)",
    "MailboxClientProductionAuthority__ExpectedNetworkId=$($runtime.networkId)",
    'MailboxClientProductionAuthority__ClockSkewSeconds=60')

[pscustomobject]@{
    schema = 'deep-survival-uat-production-mailbox.v1'
    scope = 'DEVELOPMENT-UAT-ONLY'
    outputDirectory = $output
    trustFloor = (Join-Path $output 'trust-floor.json')
    privateMaterialIncluded = $false
    caPrivateKeyMounted = $false
}
