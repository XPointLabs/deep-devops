[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

function Invoke-NativeChecked {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [Parameter(Mandatory = $true)]
        [string[]]$ArgumentList
    )

    & $FilePath @ArgumentList
    if ($LASTEXITCODE -ne 0) {
        throw "$FilePath failed with exit code $LASTEXITCODE."
    }
}

Invoke-NativeChecked -FilePath 'node' -ArgumentList @(
    '--test',
    (Join-Path $PSScriptRoot 'p15-compat-contracts.test.mjs'),
    (Join-Path $PSScriptRoot 'p15-evidence-sanitizer.test.mjs')
)

& (Join-Path $PSScriptRoot 'p15-compat-lab.test.ps1')
& (Join-Path $PSScriptRoot 'p15-cleanup-state.test.ps1')
& (Join-Path $PSScriptRoot 'p15-compat-lab.integration.test.ps1')

Write-Output 'P15A mandatory compatibility lab verification: PASS'
