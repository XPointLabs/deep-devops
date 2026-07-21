$ErrorActionPreference = 'Stop'
$script = Join-Path $PSScriptRoot 'p15c-headless-lab.ps1'
$compose = Join-Path (Split-Path $PSScriptRoot -Parent) 'docker-compose.p15c-headless.yml'
if (-not (Test-Path -LiteralPath $script -PathType Leaf)) { throw 'P15C lifecycle implementation is absent' }
if (-not (Test-Path -LiteralPath $compose -PathType Leaf)) { throw 'P15C topology implementation is absent' }

$text = (Get-Content -LiteralPath $script -Raw) + "`n" + (Get-Content -LiteralPath $compose -Raw)
foreach ($forbidden in @('docker system prune', 'docker container prune', '/var/run/docker.sock', 'host-gateway', 'privileged: true')) {
    if ($text -match [regex]::Escape($forbidden)) { throw "forbidden lifecycle construct: $forbidden" }
}
if ($text -notmatch 'down\s+--volumes\s+--remove-orphans') { throw 'exact compose cleanup is absent' }
if ($text -notmatch 'Vless__Enabled:\s*["'']?false') { throw 'VLESS is not explicitly disabled' }
if ($text -notmatch '127\.0\.0\.1:') { throw 'loopback-only host bindings are absent' }
if ($text -notmatch 'internal:\s*true') { throw 'internal runtime bridge is absent' }
Write-Output 'P15C lifecycle static tests passed.'
