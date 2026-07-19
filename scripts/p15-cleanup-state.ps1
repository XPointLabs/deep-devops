function Invoke-P15CleanupStages {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [scriptblock]$ShutdownProject,

        [Parameter(Mandatory = $true)]
        [scriptblock]$RemoveRunImage,

        [Parameter(Mandatory = $true)]
        [scriptblock]$AssertResidualInventory
    )

    $failures = [Collections.Generic.List[object]]::new()
    $stages = [ordered]@{
        shutdown = $ShutdownProject
        image = $RemoveRunImage
        inventory = $AssertResidualInventory
    }
    foreach ($stage in $stages.GetEnumerator()) {
        try {
            & $stage.Value
        }
        catch {
            $failures.Add([pscustomobject]@{
                Stage = $stage.Key
                Error = $_
            })
        }
    }

    if ($failures.Count -ne 0) {
        $summary = $failures |
            ForEach-Object {
                "$($_.Stage): $($_.Error.Exception.Message)"
            }
        throw "P15A finalization failed after all cleanup stages: $($summary -join '; ')"
    }
}
