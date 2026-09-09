[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release',

    [switch]$SkipTests,

    [switch]$RunIntegrationTests,

    [switch]$PackageGraphOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-CheckedCommand {
    param(
        [Parameter(Mandatory = $true)]
        [string]$WorkingDirectory,

        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    Push-Location -LiteralPath $WorkingDirectory
    try {
        & $FilePath @Arguments
        if ($LASTEXITCODE -ne 0) {
            throw "Command failed with exit code ${LASTEXITCODE}: $FilePath $($Arguments -join ' ')"
        }
    }
    finally {
        Pop-Location
    }
}

function Get-CurrentProtocolFingerprint {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ProtocolRoot
    )

    $trackedInputs = @(
        'src/Deep.Protocol',
        'src/Deep.Protocol.MembershipRoutes',
        'Directory.Build.props',
        'Directory.Build.targets',
        'Directory.Packages.props',
        'global.json',
        'NuGet.Config'
    )

    $relativeFiles = @(& git -C $ProtocolRoot ls-files --cached --others --exclude-standard -- @trackedInputs)
    if ($LASTEXITCODE -ne 0) {
        throw 'Unable to enumerate the dirty deep-protocol package inputs.'
    }

    $relativeFiles = @($relativeFiles | Where-Object {
        -not [string]::IsNullOrWhiteSpace($_) -and
        (Test-Path -LiteralPath (Join-Path $ProtocolRoot $_) -PathType Leaf)
    })
    [Array]::Sort($relativeFiles, [StringComparer]::Ordinal)

    if ($relativeFiles.Count -eq 0) {
        throw 'No deep-protocol package inputs were found.'
    }

    $entries = New-Object System.Collections.Generic.List[object]
    $fingerprintLines = New-Object System.Collections.Generic.List[string]
    foreach ($relativeFile in $relativeFiles) {
        $normalizedPath = $relativeFile.Replace('\', '/')
        $sha256 = (Get-FileHash -LiteralPath (Join-Path $ProtocolRoot $relativeFile) -Algorithm SHA256).Hash.ToLowerInvariant()
        $entries.Add([ordered]@{
            path = $normalizedPath
            sha256 = $sha256
        })
        $fingerprintLines.Add("$normalizedPath=$sha256")
    }

    $bytes = [Text.Encoding]::UTF8.GetBytes([string]::Join("`n", $fingerprintLines))
    $hasher = [Security.Cryptography.SHA256]::Create()
    try {
        $fingerprint = ([BitConverter]::ToString($hasher.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $hasher.Dispose()
    }

    return [ordered]@{
        fingerprint = $fingerprint
        inputs = $entries
    }
}

function Normalize-LocalNuGetPackage {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PackagePath,

        [Parameter(Mandatory = $true)]
        [string]$PackageId
    )

    Add-Type -AssemblyName System.IO.Compression.FileSystem

    $temporaryPath = "$PackagePath.normalized.tmp"
    if (Test-Path -LiteralPath $temporaryPath -PathType Leaf) {
        Remove-Item -LiteralPath $temporaryPath -Force
    }

    $sourceArchive = [IO.Compression.ZipFile]::OpenRead($PackagePath)
    try {
        $targetStream = [IO.File]::Open(
            $temporaryPath,
            [IO.FileMode]::CreateNew,
            [IO.FileAccess]::ReadWrite,
            [IO.FileShare]::None)
        try {
            $targetArchive = New-Object IO.Compression.ZipArchive(
                $targetStream,
                [IO.Compression.ZipArchiveMode]::Create,
                $true)
            try {
                $fixedTimestamp = New-Object DateTimeOffset(1980, 1, 1, 0, 0, 0, [TimeSpan]::Zero)
                $corePrefix = 'package/services/metadata/core-properties/'
                $entries = @($sourceArchive.Entries | Sort-Object {
                    if ($_.FullName.StartsWith($corePrefix, [StringComparison]::Ordinal)) {
                        return "${corePrefix}core-properties.psmdcp"
                    }
                    return $_.FullName
                })

                foreach ($sourceEntry in $entries) {
                    $targetName = $sourceEntry.FullName
                    if ($targetName.StartsWith($corePrefix, [StringComparison]::Ordinal)) {
                        $targetName = "${corePrefix}core-properties.psmdcp"
                    }

                    $targetEntry = $targetArchive.CreateEntry(
                        $targetName,
                        [IO.Compression.CompressionLevel]::Optimal)
                    $targetEntry.LastWriteTime = $fixedTimestamp
                    $targetEntryStream = $targetEntry.Open()
                    try {
                        if ($sourceEntry.FullName -eq '_rels/.rels') {
                            $relationships = @"
<?xml version="1.0" encoding="utf-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Type="http://schemas.microsoft.com/packaging/2010/07/manifest" Target="/$PackageId.nuspec" Id="R0000000000000001" />
  <Relationship Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="/${corePrefix}core-properties.psmdcp" Id="R0000000000000002" />
</Relationships>
"@
                            $relationshipBytes = (New-Object Text.UTF8Encoding($false)).GetBytes($relationships)
                            $targetEntryStream.Write($relationshipBytes, 0, $relationshipBytes.Length)
                        }
                        else {
                            $sourceEntryStream = $sourceEntry.Open()
                            try {
                                $sourceEntryStream.CopyTo($targetEntryStream)
                            }
                            finally {
                                $sourceEntryStream.Dispose()
                            }
                        }
                    }
                    finally {
                        $targetEntryStream.Dispose()
                    }
                }
            }
            finally {
                $targetArchive.Dispose()
            }
        }
        finally {
            $targetStream.Dispose()
        }
    }
    finally {
        $sourceArchive.Dispose()
    }

    Move-Item -LiteralPath $temporaryPath -Destination $PackagePath -Force
}

$xpointLabsRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$protocolRoot = Join-Path $xpointLabsRoot 'deep-protocol'
$xnodeRoot = Join-Path $xpointLabsRoot 'xnode'
$protocolProject = Join-Path $protocolRoot 'src\Deep.Protocol\Deep.Protocol.csproj'
$membershipRoutesProject = Join-Path $protocolRoot 'src\Deep.Protocol.MembershipRoutes\Deep.Protocol.MembershipRoutes.csproj'
$localNuGetConfig = Join-Path $xnodeRoot 'eng\local-current-protocol.NuGet.Config'
$artifactRoot = Join-Path $xnodeRoot 'artifacts\local-protocol-cutover'
$packageRoot = Join-Path $artifactRoot 'packages'
$lockRoot = Join-Path $artifactRoot 'locks'
$manifestPath = Join-Path $artifactRoot 'source-manifest.json'

foreach ($requiredPath in @(
    $protocolProject,
    $membershipRoutesProject,
    $localNuGetConfig,
    (Join-Path $xnodeRoot 'src\XNode\XNode.csproj'),
    (Join-Path $xnodeRoot 'tests\XNode.Tests\XNode.Tests.csproj')
)) {
    if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) {
        throw "Required local cutover input does not exist: $requiredPath"
    }
}

New-Item -ItemType Directory -Path $packageRoot -Force | Out-Null
New-Item -ItemType Directory -Path $lockRoot -Force | Out-Null

if ($PackageGraphOnly -and $SkipTests) {
    throw 'PackageGraphOnly requires the unit-test graph build; do not combine it with SkipTests.'
}
if ($PackageGraphOnly -and $RunIntegrationTests) {
    throw 'Integration tests require the full XNode runtime build.'
}

$legacyUnexpandedLock = Join-Path $lockRoot '$(MSBuildProjectName).packages.lock.json'
if (Test-Path -LiteralPath $legacyUnexpandedLock -PathType Leaf) {
    Remove-Item -LiteralPath $legacyUnexpandedLock -Force
}

$sourceIdentity = Get-CurrentProtocolFingerprint -ProtocolRoot $protocolRoot
$shortFingerprint = $sourceIdentity.fingerprint.Substring(0, 12)
$packageVersion = "0.6.0-local.$shortFingerprint"

foreach ($packageId in @('Deep.Protocol', 'Deep.Protocol.MembershipRoutes')) {
    $sameVersionPackage = Join-Path $packageRoot "$packageId.$packageVersion.nupkg"
    if (Test-Path -LiteralPath $sameVersionPackage -PathType Leaf) {
        Remove-Item -LiteralPath $sameVersionPackage -Force
    }
}

Write-Host "Packing current dirty deep-protocol as $packageVersion"
Invoke-CheckedCommand -WorkingDirectory $protocolRoot -FilePath 'dotnet' -Arguments @(
    'restore', $protocolProject, '--locked-mode'
)
Invoke-CheckedCommand -WorkingDirectory $protocolRoot -FilePath 'dotnet' -Arguments @(
    'restore', $membershipRoutesProject, '--locked-mode'
)

$packProperties = @(
    "-p:PackageVersion=$packageVersion",
    "-p:Version=$packageVersion"
)
Invoke-CheckedCommand -WorkingDirectory $protocolRoot -FilePath 'dotnet' -Arguments (@(
    'pack', $protocolProject,
    '--configuration', 'Release',
    '--output', $packageRoot,
    '--no-restore'
) + $packProperties)
Invoke-CheckedCommand -WorkingDirectory $protocolRoot -FilePath 'dotnet' -Arguments (@(
    'pack', $membershipRoutesProject,
    '--configuration', 'Release',
    '--output', $packageRoot,
    '--no-restore'
) + $packProperties)

$packageFiles = @(
    Join-Path $packageRoot "Deep.Protocol.$packageVersion.nupkg"
    Join-Path $packageRoot "Deep.Protocol.MembershipRoutes.$packageVersion.nupkg"
)
foreach ($packageFile in $packageFiles) {
    if (-not (Test-Path -LiteralPath $packageFile -PathType Leaf)) {
        throw "Expected local package was not produced: $packageFile"
    }
}

Normalize-LocalNuGetPackage -PackagePath $packageFiles[0] -PackageId 'Deep.Protocol'
Normalize-LocalNuGetPackage -PackagePath $packageFiles[1] -PackageId 'Deep.Protocol.MembershipRoutes'

$manifest = [ordered]@{
    schema = 'xpoint.xnode.local-protocol-cutover.v1'
    localOnly = $true
    productionEvidenceEligible = $false
    protocolPackageConfiguration = 'Release'
    xnodeConfiguration = $Configuration
    packageVersion = $packageVersion
    sourceFingerprintSha256 = $sourceIdentity.fingerprint
    inputs = $sourceIdentity.inputs
    packages = @($packageFiles | ForEach-Object {
        [ordered]@{
            file = [IO.Path]::GetFileName($_)
            sha256 = (Get-FileHash -LiteralPath $_ -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    })
}
$manifest | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $manifestPath -Encoding UTF8

# Each participating project redirects its local lock through a conditional
# NuGetLockFilePath. The checked-in production lock files are never rewritten.
$localProperties = @(
    '-p:DeepProtocolLocalCutover=true',
    "-p:DeepProtocolLocalPackageVersion=$packageVersion",
    "-p:RestoreConfigFile=$localNuGetConfig",
    '-p:RestoreLockedMode=false',
    '-p:RestoreForceEvaluate=true'
)

$runtimeProject = Join-Path $xnodeRoot 'src\XNode\XNode.csproj'
$unitTestProject = Join-Path $xnodeRoot 'tests\XNode.Tests\XNode.Tests.csproj'
$integrationTestProject = Join-Path $xnodeRoot 'tests\XNode.IntegrationTests\XNode.IntegrationTests.csproj'

if (-not $SkipTests) {
    Invoke-CheckedCommand -WorkingDirectory $xnodeRoot -FilePath 'dotnet' -Arguments (@(
        'restore', $unitTestProject, '--force-evaluate'
    ) + $localProperties)
    Invoke-CheckedCommand -WorkingDirectory $xnodeRoot -FilePath 'dotnet' -Arguments (@(
        'test', $unitTestProject,
        '--configuration', $Configuration,
        '--no-restore'
    ) + $localProperties)
}

if (-not $PackageGraphOnly) {
    Write-Host 'Restoring and building the full XNode runtime against the isolated local feed'
    Invoke-CheckedCommand -WorkingDirectory $xnodeRoot -FilePath 'dotnet' -Arguments (@(
        'restore', $runtimeProject, '--force-evaluate'
    ) + $localProperties)
    Invoke-CheckedCommand -WorkingDirectory $xnodeRoot -FilePath 'dotnet' -Arguments (@(
        'build', $runtimeProject,
        '--configuration', $Configuration,
        '--no-restore'
    ) + $localProperties)
}

if ($RunIntegrationTests) {
    Invoke-CheckedCommand -WorkingDirectory $xnodeRoot -FilePath 'dotnet' -Arguments (@(
        'restore', $integrationTestProject, '--force-evaluate'
    ) + $localProperties)
    Invoke-CheckedCommand -WorkingDirectory $xnodeRoot -FilePath 'dotnet' -Arguments (@(
        'test', $integrationTestProject,
        '--configuration', $Configuration,
        '--no-restore'
    ) + $localProperties)
}

Write-Host "LOCAL-ONLY XNode protocol cutover passed: $packageVersion"
Write-Host "Manifest: $manifestPath"
Write-Host 'Production PackageReferences, NuGet config, and lock files were not selected or rewritten.'
