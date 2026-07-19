$ErrorActionPreference = 'Stop'

$module = Join-Path $PSScriptRoot 'p15-cleanup-state.ps1'
if (-not (Test-Path -LiteralPath $module -PathType Leaf)) {
    throw 'P15A cleanup state module is missing (expected RED).'
}
. $module

foreach ($failingStage in @('shutdown', 'image', 'inventory')) {
    $calls = [Collections.Generic.List[string]]::new()
    $failure = $null
    try {
        Invoke-P15CleanupStages `
            -ShutdownProject {
                $calls.Add('shutdown')
                if ($failingStage -eq 'shutdown') {
                    throw 'injected shutdown failure'
                }
            } `
            -RemoveRunImage {
                $calls.Add('image')
                if ($failingStage -eq 'image') {
                    throw 'injected image failure'
                }
            } `
            -AssertResidualInventory {
                $calls.Add('inventory')
                if ($failingStage -eq 'inventory') {
                    throw 'injected inventory failure'
                }
            }
    }
    catch {
        $failure = $_
    }

    if (-not $failure) {
        throw "P15A cleanup stage $failingStage did not fail closed."
    }
    if (($calls -join ',') -ne 'shutdown,image,inventory') {
        throw "P15A cleanup stage $failingStage skipped a later cleanup action."
    }
    if ($failure.Exception.Message -notmatch $failingStage) {
        throw "P15A cleanup failure did not identify stage $failingStage."
    }
}

Write-Output 'P15A independent cleanup stages: PASS'
