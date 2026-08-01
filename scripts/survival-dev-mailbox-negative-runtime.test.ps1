$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$script = Join-Path $PSScriptRoot 'survival-dev-mailbox-negative-runtime.ps1'
$text = Get-Content -Raw -LiteralPath $script

foreach ($required in @(
    "[ValidateSet('Generate', 'Cleanup')]",
    "'tampered-signature'",
    "'missing-authority'",
    "'android-runtime-on-windows'",
    'e2e-runs/<32-hex>',
    'Set-ProtectedTree',
    'Assert-NoReparseTraversal',
    'Canonical issued runtime changed')) {
    if ($text.IndexOf($required, [StringComparison]::Ordinal) -lt 0) {
        throw "Negative runtime generator contract is missing: $required"
    }
}
foreach ($forbidden in @('sessionId =', 'holderPublicKey =', 'credential =', 'capability =',
    'privateKey =', 'seed =')) {
    if ($text.IndexOf($forbidden, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
        throw "Negative runtime generator writes forbidden evidence material: $forbidden"
    }
}

$parseErrors = $null
[void][Management.Automation.Language.Parser]::ParseFile(
    $script, [ref]$null, [ref]$parseErrors)
if ($parseErrors.Count -ne 0) { throw 'Negative runtime generator has PowerShell parse errors.' }

Write-Output 'survival-dev negative mailbox runtime contract: PASS'
