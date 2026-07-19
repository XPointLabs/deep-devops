$ErrorActionPreference = 'Stop'

$script = Join-Path $PSScriptRoot 'p15-compat-lab.ps1'
if (-not (Test-Path -LiteralPath $script -PathType Leaf)) {
    throw 'P15A driver is missing (expected RED).'
}

$source = Get-Content -LiteralPath $script -Raw
$required = @(
    'Assert-SourceLock',
    'Assert-DockerEnvironment',
    'Assert-EmptyProjectNamespace',
    'Invoke-ScopedCleanup',
    'Assert-ZeroResidualResources',
    'InjectFailureAfterUp',
    'InjectFailureAfterBuild',
    'InjectValidationFailureAfterBuild',
    'InjectSemanticLabelDriftAfterBuild',
    'Remove-OwnedRunImage',
    'Assert-EmptyImageReference',
    'New-P15OwnershipNonce',
    'Get-MinimalOwnedRunImageId',
    'P15_OWNERSHIP_NONCE',
    'Invoke-P15CleanupStages',
    '--volumes',
    '--remove-orphans',
    'finally'
)

foreach ($token in $required) {
    if ($source -notmatch [regex]::Escape($token)) {
        throw "P15A driver is missing required lifecycle token: $token"
    }
}

if ($source -match 'docker\s+(system|container|network|volume|image)\s+prune') {
    throw 'P15A driver contains a prohibited global prune command.'
}

$sourceIndex = $source.IndexOf('Assert-SourceLock', [StringComparison]::Ordinal)
$dockerIndex = $source.IndexOf('Assert-DockerEnvironment', [StringComparison]::Ordinal)
if ($sourceIndex -lt 0 -or $dockerIndex -lt 0 -or $sourceIndex -ge $dockerIndex) {
    throw 'Source lock must be checked before Docker preflight.'
}

$verification = Join-Path $PSScriptRoot 'verify-p15-compat-lab.ps1'
if (-not (Test-Path -LiteralPath $verification -PathType Leaf)) {
    throw 'P15A mandatory verification gate is missing.'
}
$verificationSource = Get-Content -LiteralPath $verification -Raw
foreach ($requiredTest in @(
    'p15-cleanup-state.test.ps1',
    'p15-compat-lab.integration.test.ps1'
)) {
    if ($verificationSource -notmatch [regex]::Escape($requiredTest)) {
        throw "P15A mandatory verification gate omits $requiredTest."
    }
}

Write-Output 'P15A PowerShell lifecycle contract: PASS'
