$ErrorActionPreference = 'Stop'
$script = Join-Path $PSScriptRoot 'p15c-headless-lab.ps1'
$compose = Join-Path (Split-Path $PSScriptRoot -Parent) 'docker-compose.p15c-headless.yml'
if (-not (Test-Path -LiteralPath $script -PathType Leaf)) { throw 'P15C lifecycle implementation is absent' }
if (-not (Test-Path -LiteralPath $compose -PathType Leaf)) { throw 'P15C topology implementation is absent' }

$driverText = Get-Content -LiteralPath $script -Raw
$composeText = Get-Content -LiteralPath $compose -Raw
$text = $driverText + "`n" + $composeText
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
$expectedPlan = 'source-preflight,collision-check,foreign-snapshot,image-preflight,generate-secrets,source-export,compose-config,build,up-contracts,deploy-contracts,up-runtime,probe,e2e,labels,cleanup,evidence'
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
if ($driverText -match '\{\{\.Status\}\}') { throw 'foreign inventory must not use human-formatted Docker status' }
foreach ($stableField in @('.State.Status','.State.Health.Status','.State.StartedAt','.State.FinishedAt','.RestartCount')) {
    if (-not $driverText.Contains($stableField, [StringComparison]::Ordinal)) { throw "stable inspect-derived foreign inventory field is absent: $stableField" }
}
if ($composeText -match '(?m)^\s*# syntax=docker/dockerfile:1\.7\s*$') { throw 'floating Dockerfile frontend is prohibited' }
foreach ($contextName in @('XNODE','E2E','REGISTRY','STAKING','CONTRACTS')) {
    if ($composeText -notmatch "P15C_$($contextName)_CONTEXT") { throw "exact archived build context is absent: $contextName" }
}
if ($composeText -match 'additional_contexts:[^\r\n]*P15C_(?:XNODE|E2E|REGISTRY|STAKING|CONTRACTS)_PATH' -or $driverText -notmatch 'New-ExactSourceExports') { throw 'build contexts can still copy dirty or ignored checkout outputs' }
if ($driverText -notmatch "'--list-sdks'" -or $driverText -notmatch "com\.xpoint\.p15c\.ownership-nonce") { throw 'SDK or transient preflight container ownership accounting is incomplete' }
if ($driverText -match 'function Assert-ReceiptSyntax' -or $driverText -notmatch 'validate-receipt') { throw 'driver and tests must use one canonical receipt validator' }
foreach ($binding in @('manifestSha256','foreignSnapshotSha256','Assert-OwnedProjectRuntimeInventory','Remove-ExclusivelyCreatedFile','Protect-P15CAuthorityFile')) {
    if ($driverText -notmatch $binding) { throw "retained authority or cleanup binding is absent: $binding" }
}
$ownershipGate = $driverText.LastIndexOf('Assert-OwnedProjectRuntimeInventory', [StringComparison]::Ordinal)
$downMutation = $driverText.LastIndexOf('Invoke-ExactDown', [StringComparison]::Ordinal)
if ($ownershipGate -lt 0 -or $downMutation -lt 0 -or $ownershipGate -ge $downMutation) { throw 'same-project resources are not validated before compose down' }

$integration = Join-Path $PSScriptRoot 'p15c-headless-lab.integration.test.ps1'
$integrationText = Get-Content -LiteralPath $integration -Raw
if ($integrationText -notmatch 'NonDockerSequenceRegression' -or $integrationText -notmatch 'P15C_REAL_INTEGRATION\s*=\s*\$env:P15C_REAL_INTEGRATION') { throw 'integration wrapper does not snapshot P15C inputs before the first driver invocation' }
powershell -NoProfile -ExecutionPolicy Bypass -File $integration -NonDockerSequenceRegression *> $null
if ($LASTEXITCODE -ne 0) { throw 'integration wrapper loses snapshotted inputs across sequential in-process driver calls' }
Write-Output 'P15C lifecycle static tests passed.'
