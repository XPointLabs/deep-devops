$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$root = [IO.Path]::GetFullPath((Split-Path $PSScriptRoot -Parent))
$artifactsRoot = [IO.Path]::GetFullPath((Join-Path $root 'artifacts'))
$testRoot = Join-Path $artifactsRoot (
    'survival-dev-evidence-test-' + [Guid]::NewGuid().ToString('N'))
$evidence = Join-Path $testRoot 'p10e-mailbox-integration.json'
$missingXNode = Join-Path $testRoot 'missing-xnode'
[void][IO.Directory]::CreateDirectory($testRoot)
try {
    [IO.File]::WriteAllText(
        $evidence,
        "{`"schemaVersion`":3,`"passed`":true}`n",
        [Text.UTF8Encoding]::new($false))
    $previousErrorPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        & powershell -NoProfile -ExecutionPolicy Bypass -File `
            (Join-Path $PSScriptRoot 'survival-dev-mailbox.integration.test.ps1') `
            -XNodeRepository $missingXNode `
            -EvidencePath $evidence `
            -BindHost '127.0.0.1' *> $null
        $failedExitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousErrorPreference
    }
    if ($failedExitCode -eq 0) {
        throw 'The forced early mailbox integration failure unexpectedly succeeded.'
    }
    if (Test-Path -LiteralPath $evidence) {
        throw 'A failed mailbox integration left stale green evidence behind.'
    }
    Write-Output 'survival-dev mailbox evidence invalidation contract: PASS'
} finally {
    $resolvedTestRoot = [IO.Path]::GetFullPath($testRoot)
    $artifactsPrefix = $artifactsRoot.TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    if ($resolvedTestRoot.StartsWith($artifactsPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        Remove-Item -LiteralPath $resolvedTestRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}
