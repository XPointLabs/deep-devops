$ErrorActionPreference = 'Stop'
$script = Join-Path $PSScriptRoot 'p15c-headless-lab.ps1'
$compose = Join-Path (Split-Path $PSScriptRoot -Parent) 'docker-compose.p15c-headless.yml'
if (-not (Test-Path -LiteralPath $script -PathType Leaf)) { throw 'P15C lifecycle implementation is absent' }
if (-not (Test-Path -LiteralPath $compose -PathType Leaf)) { throw 'P15C topology implementation is absent' }

$text = (Get-Content -LiteralPath $script -Raw) + "`n" + (Get-Content -LiteralPath $compose -Raw)
foreach ($forbidden in @('docker system prune', 'docker container prune', '/var/run/docker.sock', 'host-gateway', 'privileged: true')) {
    if ($text -match [regex]::Escape($forbidden)) { throw "forbidden lifecycle construct: $forbidden" }
}
foreach ($forbiddenPattern in @('\bUAT\b', 'deep-uat', 'old\s+identity', 'legacy\s+compose', 'mock\s+Xray', 'profile\s+(?:activation|signer)', 'client\s+verifier', 'runtime\s+registration', 'product[- ]?runtime\s*:\s*true')) {
    if ($text -match $forbiddenPattern) { throw "forbidden authority or activation construct: $forbiddenPattern" }
}
if ($text -notmatch 'down\s+--volumes\s+--remove-orphans') { throw 'exact compose cleanup is absent' }
if ($text -notmatch 'Vless__Enabled:\s*["'']?false') { throw 'VLESS is not explicitly disabled' }
if ($text -notmatch '127\.0\.0\.1:') { throw 'loopback-only host bindings are absent' }
if ($text -notmatch 'internal:\s*true') { throw 'internal runtime bridge is absent' }
if ($text -notmatch 'Node__Ed25519PrivateKeyPath') { throw 'XNode file-only identity setting is absent' }
if ($text -match 'Node__Ed25519PrivateKey\s*:') { throw 'XNode private key must never enter environment' }
if ($text -match '(?im)^\s*(?:pull|pull_policy)\s*:\s*(?:always|missing)') { throw 'silent image pull policy is prohibited' }

$planMatch = [regex]::Match($text, '(?m)^# P15C_OPERATION_PLAN: (?<plan>[a-z0-9,-]+)(?=\r?$)')
if (-not $planMatch.Success) { throw 'real orchestrator must export its exact fail-closed operation plan' }
$expectedPlan = 'source-preflight,image-preflight,collision-check,foreign-snapshot,generate-secrets,compose-config,build,up-contracts,deploy-contracts,up-runtime,probe,e2e,labels,cleanup,evidence'
if ($planMatch.Groups['plan'].Value -ne $expectedPlan) { throw 'real orchestrator operation plan is not exact' }
foreach ($requiredCall in @('Assert-P15COperationPlan', 'Invoke-P15CBuild', 'Invoke-P15CUp')) {
    if ($text.IndexOf($requiredCall, [StringComparison]::Ordinal) -lt 0) { throw "real orchestrator call is absent: $requiredCall" }
}
$planCall = $text.LastIndexOf('Assert-P15COperationPlan', [StringComparison]::Ordinal)
$buildCall = $text.LastIndexOf('Invoke-P15CBuild', [StringComparison]::Ordinal)
$upCall = $text.LastIndexOf('Invoke-P15CUp', [StringComparison]::Ordinal)
if ($planCall -ge $buildCall -or $planCall -ge $upCall) { throw 'real orchestrator can Build/Up before validating preflight/collision/snapshot order' }
if ($text -notmatch "eth_chainId" -or $text -notmatch "0x7a69") { throw 'Hardhat readiness must prove exact JSON-RPC chain id' }
if ($text -notmatch 'Clear-P15CEnvironment') { throw 'driver must clear every P15C process environment value' }
if ($text -notmatch 'receipt-retained') { throw 'retained Run must use a distinct no-cleanup/no-evidence plan' }
Write-Output 'P15C lifecycle static tests passed.'
