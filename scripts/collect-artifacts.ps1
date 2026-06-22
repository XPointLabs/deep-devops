param(
    [string] $ArtifactDir = "",
    [string] $ComposeFile = ""
)

$ErrorActionPreference = "Continue"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$DevopsDir = Resolve-Path (Join-Path $ScriptDir "..")

if ([string]::IsNullOrWhiteSpace($ComposeFile)) {
    $ComposeFile = Join-Path $DevopsDir "docker-compose.yml"
}

if ([string]::IsNullOrWhiteSpace($ArtifactDir)) {
    $ArtifactDir = Join-Path $DevopsDir "artifacts"
}

New-Item -ItemType Directory -Force $ArtifactDir | Out-Null

docker compose -f $ComposeFile ps --all | Out-File -Encoding utf8 (Join-Path $ArtifactDir "compose.ps.txt")
docker compose -f $ComposeFile logs --no-color | Out-File -Encoding utf8 (Join-Path $ArtifactDir "compose.log")
docker compose -f $ComposeFile config | Out-File -Encoding utf8 (Join-Path $ArtifactDir "compose.resolved.yml")
& (Join-Path $ScriptDir "runtime-snapshot.ps1") -ArtifactDir $ArtifactDir

