[CmdletBinding()]
param(
    [string] $SecretRoot = 'C:\Work\DeepSession\secrets\prod',
    [Parameter(Mandatory)][string] $AuthorityArtifactRoot,
    [ValidatePattern('^deployment-candidate-v[1-9][0-9]*$')]
    [string] $CandidateName = 'deployment-candidate-v1',
    [string] $RegistryImage = 'ghcr.io/xpointlabs/deep-registry-api@sha256:f58c2a4bcfd2c0f2efc71e04dd5cdbcc2795ec72adf065b9a9a0c1ca95df6494'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Require-RegularFile([string] $Path, [long] $ExactLength = -1) {
    $full = [IO.Path]::GetFullPath($Path)
    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) {
        throw "Required production input is missing: $full"
    }
    $item = Get-Item -LiteralPath $full -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Production inputs must not be reparse points.'
    }
    if ($ExactLength -ge 0 -and $item.Length -ne $ExactLength) {
        throw 'A production authority key has an invalid length.'
    }
    return $full
}

function Require-RegularDirectory([string] $Path) {
    $full = [IO.Path]::GetFullPath($Path)
    if (-not (Test-Path -LiteralPath $full -PathType Container)) {
        throw "Required production directory is missing: $full"
    }
    $item = Get-Item -LiteralPath $full -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Production inputs must not be reparse points.'
    }
    return $full
}

function Require-LowerHex([string] $Value, [int] $Bytes, [string] $Name) {
    if ($Value -cnotmatch "^[0-9a-f]{$($Bytes * 2)}$" -or $Value -match '^0+$') {
        throw "$Name is not canonical nonzero lowercase hexadecimal data."
    }
}

function Write-Utf8New([string] $Path, [string] $Value) {
    $stream = [IO.File]::Open($Path, [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $writer = [IO.StreamWriter]::new($stream, [Text.UTF8Encoding]::new($false))
        try { $writer.Write($Value); $writer.Flush(); $stream.Flush($true) }
        finally { $writer.Dispose() }
    } finally { $stream.Dispose() }
}

$root = Require-RegularDirectory $SecretRoot
$authorityRoot = Require-RegularDirectory (Join-Path $root 'authority')
$artifactSource = Require-RegularDirectory $AuthorityArtifactRoot
$custodyPath = Require-RegularFile (Join-Path $authorityRoot 'public\custody-manifest.v1.json')
$publicManifestPath = Require-RegularFile (Join-Path $artifactSource 'public-manifest.v1.json')
$inventoryPath = Require-RegularFile (Join-Path $artifactSource 'bootstrap\inventory.json')

if ($RegistryImage -cnotmatch '^ghcr\.io/xpointlabs/deep-registry-api@sha256:[0-9a-f]{64}$') {
    throw 'RegistryImage must be an exact GHCR sha256 digest reference.'
}

$custody = Get-Content -Raw -LiteralPath $custodyPath | ConvertFrom-Json
$publicManifest = Get-Content -Raw -LiteralPath $publicManifestPath | ConvertFrom-Json
$inventory = Get-Content -Raw -LiteralPath $inventoryPath | ConvertFrom-Json
if ([string]$custody.schema -cne 'deep-production-authority-custody.v1' -or
    [string]$custody.environment -cne 'prod' -or
    [string]$custody.authorityOwner -cne 'Mr. X' -or
    [string]$publicManifest.schema -cne 'deep-production-authority-bootstrap.v1' -or
    [string]$publicManifest.authorityOwner -cne 'Mr. X' -or
    [string]$inventory.format -cne 'deep-contact-resolve-readonly-v1') {
    throw 'The authority inputs do not belong to the approved Mr. X production boundary.'
}

$network = [string]$custody.networkIdHex
$genesis = [string]$publicManifest.genesisAuthorityCoreHashHex
$directoryLeaf = [string]$publicManifest.directoryLeafKeyHex
Require-LowerHex $network 16 'Network ID'
Require-LowerHex $genesis 32 'Genesis authority core hash'
Require-LowerHex $directoryLeaf 32 'Directory leaf key'
if ([string]$publicManifest.networkIdHex -cne $network -or
    [string]$inventory.networkIdHex -cne $network -or
    [string]$inventory.genesisAuthorityCoreHashHex -cne $genesis) {
    throw 'The custody, public bootstrap and artifact inventory bindings differ.'
}
$now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
if ([long]$publicManifest.notBeforeUnixSeconds -gt $now + 300 -or
    [long]$publicManifest.expiresAtUnixSeconds -lt $now + 3600) {
    throw 'The selected operational authority window is not currently deployable.'
}

$privateRoot = Require-RegularDirectory (Join-Path $authorityRoot 'private')
$privateFiles = [ordered]@{
    'trusted-time-integrity.key' = 'trusted-time-integrity.key'
    'request-ledger-integrity.key' = 'request-ledger-integrity.key'
    'artifact-state-integrity.key' = 'artifact-state-integrity.key'
    'registry-dtt-signer-1.ed25519.seed' = 'witness-1-ed25519.seed'
    'registry-dtt-signer-2.ed25519.seed' = 'witness-2-ed25519.seed'
    'registry-dtt-signer-3.ed25519.seed' = 'witness-3-ed25519.seed'
}
foreach ($name in $privateFiles.Keys) {
    [void](Require-RegularFile (Join-Path $privateRoot $name) 32)
}

$witnessIds = 1..3 | ForEach-Object {
    $roleName = "registry-dtt-signer-$_"
    $role = @($custody.roles | Where-Object { [string]$_.role -ceq $roleName })
    if ($role.Count -ne 1 -or [long]$role[0].keyGeneration -ne 0) {
        throw "The custody manifest does not contain one generation-zero $roleName role."
    }
    $id = [string]$role[0].authorityIdHex
    Require-LowerHex $id 32 "$roleName authority ID"
    $id
}
if (@($witnessIds | Sort-Object -Unique).Count -ne 3) {
    throw 'Registry DTT witness IDs must be distinct.'
}

$registryRoot = Join-Path $root 'registry'
$target = Join-Path $registryRoot $CandidateName
if (Test-Path -LiteralPath $target) {
    throw 'The production Registry deployment candidate already exists; review it before retrying.'
}
$staging = Join-Path $registryRoot ".deployment-candidate-$([guid]::NewGuid().ToString('N'))"
try {
    [IO.Directory]::CreateDirectory($staging) | Out-Null
    $candidatePrivate = Join-Path $staging 'private'
    $candidateArtifacts = Join-Path $staging 'artifacts'
    [IO.Directory]::CreateDirectory($candidatePrivate) | Out-Null
    [IO.Directory]::CreateDirectory($candidateArtifacts) | Out-Null
    foreach ($entry in $privateFiles.GetEnumerator()) {
        Copy-Item -LiteralPath (Join-Path $privateRoot $entry.Key) `
            -Destination (Join-Path $candidatePrivate $entry.Value)
    }
    foreach ($item in Get-ChildItem -LiteralPath $artifactSource -Force) {
        Copy-Item -LiteralPath $item.FullName -Destination $candidateArtifacts -Recurse
    }

    $remoteRoot = '/opt/xpoint-prod/deep-devops/secrets/contact-resolve-v1'
    $environment = @(
        "DEEP_REGISTRY_IMAGE=$RegistryImage"
        "DEEP_XPOINT_NETWORK_ID_HEX=$network"
        "DEEP_XPOINT_GENESIS_PIN_HEX=$genesis"
        "DEEP_XPOINT_DIRECTORY_LEAF_KEY_HEX=$directoryLeaf"
        "DEEP_CONTACT_RESOLVE_ARTIFACT_ROOT=$remoteRoot/artifacts"
        "DEEP_CONTACT_RESOLVE_TRUSTED_TIME_KEY_FILE=$remoteRoot/private/trusted-time-integrity.key"
        "DEEP_CONTACT_RESOLVE_REQUEST_LEDGER_KEY_FILE=$remoteRoot/private/request-ledger-integrity.key"
        "DEEP_CONTACT_RESOLVE_ARTIFACT_STATE_KEY_FILE=$remoteRoot/private/artifact-state-integrity.key"
        "DEEP_CONTACT_RESOLVE_WITNESS_1_ID_HEX=$($witnessIds[0])"
        "DEEP_CONTACT_RESOLVE_WITNESS_1_SEED_FILE=$remoteRoot/private/witness-1-ed25519.seed"
        "DEEP_CONTACT_RESOLVE_WITNESS_2_ID_HEX=$($witnessIds[1])"
        "DEEP_CONTACT_RESOLVE_WITNESS_2_SEED_FILE=$remoteRoot/private/witness-2-ed25519.seed"
        "DEEP_CONTACT_RESOLVE_WITNESS_3_ID_HEX=$($witnessIds[2])"
        "DEEP_CONTACT_RESOLVE_WITNESS_3_SEED_FILE=$remoteRoot/private/witness-3-ed25519.seed"
    ) -join "`n"
    Write-Utf8New (Join-Path $staging '.env.contact-resolve.prod') ($environment + "`n")

    $artifactFiles = Get-ChildItem -LiteralPath $candidateArtifacts -File -Recurse |
        Sort-Object FullName | ForEach-Object {
            [ordered]@{
                relativePath = [IO.Path]::GetRelativePath($candidateArtifacts, $_.FullName).Replace('\', '/')
                length = $_.Length
                sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
            }
        }
    $deploymentManifest = [ordered]@{
        schema = 'deep-production-registry-candidate.v1'
        environment = 'prod'
        authorityOwner = 'Mr. X'
        networkIdHex = $network
        genesisAuthorityCoreHashHex = $genesis
        directoryLeafKeyHex = $directoryLeaf
        authorityNotBeforeUnixSeconds = [long]$publicManifest.notBeforeUnixSeconds
        authorityExpiresAtUnixSeconds = [long]$publicManifest.expiresAtUnixSeconds
        registryImage = $RegistryImage
        artifactFiles = @($artifactFiles)
    }
    Write-Utf8New (Join-Path $staging 'deployment-manifest.public.json') `
        (($deploymentManifest | ConvertTo-Json -Depth 6) + "`n")
    [IO.Directory]::Move($staging, $target)
} catch {
    if (Test-Path -LiteralPath $staging) {
        Remove-Item -LiteralPath $staging -Recurse -Force
    }
    throw
}

Write-Output 'Production Registry candidate prepared without exporting private values.'
