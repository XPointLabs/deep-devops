param(
    [string] $ArtifactDir = "",
    [string] $ComposeFile = ""
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

node (Join-Path $ScriptDir "redacted-compose-topology.mjs") `
    --compose-file $ComposeFile `
    --output (Join-Path $ArtifactDir "compose.topology.redacted.json")
& (Join-Path $ScriptDir "runtime-snapshot.ps1") -ArtifactDir $ArtifactDir
node (Join-Path $ScriptDir "secret-scan.mjs") `
    --root $DevopsDir `
    --no-tracked `
    --artifacts $ArtifactDir `
    --summary (Join-Path $ArtifactDir "security/secret-scan-summary.json")

