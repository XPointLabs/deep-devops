$ErrorActionPreference = 'Stop'
$script = Join-Path $PSScriptRoot 'p15c-ephemeral-secrets.ps1'
if (-not (Test-Path -LiteralPath $script -PathType Leaf)) { throw 'P15C ephemeral secret implementation is absent' }

$root = Join-Path ([System.IO.Path]::GetTempPath()) ('p15c-secret-test-' + [guid]::NewGuid().ToString('N'))
try {
    & $script -Action Generate -RunDirectory $root
    $files = @(Get-ChildItem -LiteralPath $root -Filter 'node-*.seed' -File)
    if ($files.Count -ne 3) { throw 'exactly three secret files are required' }
    foreach ($file in $files) {
        $value = (Get-Content -LiteralPath $file.FullName -Raw).Trim()
        if ($value -notmatch '^[0-9a-f]{64}$') { throw 'seed shape is invalid' }
        $acl = Get-Acl -LiteralPath $file.FullName
        if (-not $acl.AreAccessRulesProtected) { throw 'secret ACL inheritance must be disabled' }
    }
    & $script -Action Remove -RunDirectory $root
    if (Test-Path -LiteralPath $root) { throw 'secret directory was not removed' }
}
finally {
    if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force }
}
Write-Output 'P15C ephemeral secret tests passed.'
