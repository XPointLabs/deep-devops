param(
    [string] $ArtifactDir = "",
    [string] $ComposeFile = "",
    [string] $ComposeProjectName = ""
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$DevopsDir = Resolve-Path (Join-Path $ScriptDir "..")

if ([string]::IsNullOrWhiteSpace($ComposeFile)) {
    $ComposeFile = Join-Path $DevopsDir "docker-compose.yml"
}

if ([string]::IsNullOrWhiteSpace($ArtifactDir)) {
    $ArtifactDir = Join-Path $DevopsDir "artifacts"
}

New-Item -ItemType Directory -Force $ArtifactDir | Out-Null

$resolvedArtifactDir = [System.IO.Path]::GetFullPath($ArtifactDir)
$resolvedDevopsDir = [System.IO.Path]::GetFullPath($DevopsDir)
$devopsPrefix = $resolvedDevopsDir.TrimEnd([System.IO.Path]::DirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar
if (-not $resolvedArtifactDir.StartsWith($devopsPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "ArtifactDir must remain inside the deep-devops repository"
}

$topologyArguments = @(
    (Join-Path $ScriptDir "redacted-compose-topology.mjs"),
    '--compose-file', $ComposeFile,
    '--output', (Join-Path $ArtifactDir "compose.topology.redacted.json")
)
if (-not [string]::IsNullOrWhiteSpace($ComposeProjectName)) {
    $topologyArguments += @('--project-name', $ComposeProjectName)
}
& node @topologyArguments
if ($LASTEXITCODE -ne 0) { throw "redacted topology collection failed with exit code $LASTEXITCODE" }
& (Join-Path $ScriptDir "runtime-snapshot.ps1") -ArtifactDir $ArtifactDir
if ($LASTEXITCODE -ne 0) { throw "runtime snapshot collection failed with exit code $LASTEXITCODE" }
& node (Join-Path $ScriptDir "secret-scan.mjs") `
    --root $DevopsDir `
    --no-tracked `
    --artifacts $ArtifactDir `
    --summary (Join-Path $ArtifactDir "security/secret-scan-summary.json")
if ($LASTEXITCODE -ne 0) { throw "isolated rehearsal secret scan failed with exit code $LASTEXITCODE" }

