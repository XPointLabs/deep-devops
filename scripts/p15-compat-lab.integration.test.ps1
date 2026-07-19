$ErrorActionPreference = 'Stop'

$repositoryRoot = [IO.Path]::GetFullPath((Split-Path $PSScriptRoot -Parent))
$driver = Join-Path $PSScriptRoot 'p15-compat-lab.ps1'
$sourceSha = (& git -C $repositoryRoot rev-parse HEAD).Trim()
$sourceTree = (& git -C $repositoryRoot rev-parse 'HEAD^{tree}').Trim()
$dirty = (& git -C $repositoryRoot status --porcelain=v1 --untracked-files=all |
    Out-String).Trim()
if ($dirty) {
    throw 'P15A integration test requires a clean exact source tree.'
}

$baseImage = 'node@sha256:242549cd46785b480c832479a730f4f2a20865d61ea2e404fdb2a5c3d3b73ecf'
$baseImageId = 'sha256:242549cd46785b480c832479a730f4f2a20865d61ea2e404fdb2a5c3d3b73ecf'
$random = [Guid]::NewGuid().ToString('N')
$project = "p15a-$($random.Substring(0, 16))"
$runTag = "local/p15-compat:$project"
$sentinelTag = "local/p15-unrelated-test:$random"
$evidence = Join-Path ([IO.Path]::GetTempPath()) "p15a-$random.json"
$sentinelCreated = $false

function Get-Count {
    param([string[]]$Arguments)
    return @(& docker @Arguments | Where-Object { $_ }).Count
}

try {
    & docker image tag $baseImage $sentinelTag
    if ($LASTEXITCODE -ne 0) {
        throw 'P15A integration test could not create its unrelated sentinel tag.'
    }
    $sentinelCreated = $true

    $failure = $null
    try {
        & $driver `
            -ExpectedSourceSha $sourceSha `
            -ExpectedSourceTree $sourceTree `
            -EvidencePath $evidence `
            -ProjectName $project `
            -InjectSemanticLabelDriftAfterBuild
    }
    catch {
        $failure = $_
    }
    if (-not $failure -or
        $failure.Exception.Message -notmatch 'built image identity') {
        throw 'P15A semantic image-label drift did not fail full validation.'
    }

    $filter = "label=com.docker.compose.project=$project"
    $containers = Get-Count @('ps', '-aq', '--filter', $filter)
    $networks = Get-Count @('network', 'ls', '-q', '--filter', $filter)
    $volumes = Get-Count @('volume', 'ls', '-q', '--filter', $filter)
    $images = Get-Count @('image', 'ls', '-q', '--filter', $filter)
    $runTagExists = (Get-Count @(
        'image', 'ls', '-q', '--filter', "reference=$runTag"
    )) -ne 0
    if ($containers -ne 0 -or $networks -ne 0 -or
        $volumes -ne 0 -or $images -ne 0 -or $runTagExists) {
        throw 'P15A semantic validation failure left a run-owned Docker resource.'
    }

    $sentinelId = (& docker image inspect $sentinelTag --format '{{.Id}}').Trim()
    if ($LASTEXITCODE -ne 0 -or $sentinelId -ne $baseImageId) {
        throw 'P15A cleanup changed an unrelated image tag.'
    }
}
finally {
    if ($sentinelCreated) {
        $sentinelId = (& docker image inspect $sentinelTag --format '{{.Id}}' 2>$null |
            Out-String).Trim()
        if ($LASTEXITCODE -eq 0 -and $sentinelId -eq $baseImageId) {
            & docker image rm $sentinelTag | Out-Null
        }
    }
}

Write-Output 'P15A semantic-label validation cleanup integration: PASS'
