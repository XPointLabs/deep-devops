$ErrorActionPreference = 'Stop'
$bootstrap = Get-Content -Raw -LiteralPath (
    Join-Path $PSScriptRoot 'first-release-local-bootstrap.ps1')
$keygen = Get-Content -Raw -LiteralPath (
    Join-Path $PSScriptRoot 'first-release-local-keygen.mjs')
$blsHelper = Get-Content -Raw -LiteralPath (
    Join-Path $PSScriptRoot '..\tools\first-release-bootstrap\Program.cs')

[void][scriptblock]::Create($bootstrap)
foreach ($required in @(
    "C:\Work\DeepSession\secrets",
    "'first-release-local'",
    'first-release-local.bootstrap-',
    'first-release-local-runtime-provision.ps1',
    'first-release-local-authority-preflight.ps1',
    'TrustedObservedUnixTime',
    'bootstrap never substitutes the OS clock',
    '--locked-mode',
    '--hardfork',
    'prague',
    "-Action Config",
    "-Action ProvisionTime",
    "-Action Up",
    "-Action Verify")) {
    if ($bootstrap.IndexOf($required, [StringComparison]::Ordinal) -lt 0) {
        throw "Bootstrap contract is missing: $required"
    }
}
if ($bootstrap -match '(?i)survival|volume\s+rm|\bdown\b') {
    throw 'Bootstrap must not reference survival, remove volumes, or stop the topology.'
}
if ($bootstrap -match 'FIRST_RELEASE_XNODE_\$\{index\}_VLESS_CLIENT_ID=' -or
    $bootstrap -match 'FIRST_RELEASE_XNODE_\$\{index\}_REALITY_PRIVATE_KEY=') {
    throw 'Bootstrap must never serialize VLESS or REALITY credential values into environment files.'
}
foreach ($requiredSecretPath in @(
    'FIRST_RELEASE_XNODE_${index}_VLESS_CLIENT_ID_FILE=',
    'FIRST_RELEASE_XNODE_${index}_REALITY_PRIVATE_KEY_FILE=',
    'Set-ProtectedFileAcl $vlessClientIdPath',
    'Set-ProtectedFileAcl $realityPrivateKeyPath')) {
    if ($bootstrap.IndexOf($requiredSecretPath, [StringComparison]::Ordinal) -lt 0) {
        throw "Bootstrap secret-file contract is missing: $requiredSecretPath"
    }
}
if ($keygen -notmatch "--network', 'none'" -or
    $keygen -notmatch "--entrypoint', 'xray'" -or
    $keygen -match 'console\.log\(.+(?:private|seed|scalar)') {
    throw 'Identity generator does not satisfy the private/offline Xray contract.'
}
if ($blsHelper -notmatch 'Bls12381RegistrationProofService' -or
    $blsHelper -notmatch 'The bootstrap BLS RPC must be a loopback HTTP endpoint') {
    throw 'BLS helper must use the XNode proof implementation through loopback only.'
}
Write-Output 'First-release local bootstrap source checks passed.'
