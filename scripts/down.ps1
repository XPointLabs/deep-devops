param()

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$DevopsDir = Resolve-Path (Join-Path $ScriptDir "..")

$previousErrorActionPreference = $ErrorActionPreference
$ErrorActionPreference = "Continue"
docker compose -f (Join-Path $DevopsDir "docker-compose.yml") down --volumes --remove-orphans
$composeExit = $LASTEXITCODE
$ErrorActionPreference = $previousErrorActionPreference

if ($composeExit -ne 0) {
    throw "docker compose down failed with exit code $composeExit"
}
