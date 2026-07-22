$ErrorActionPreference = 'Stop'
$driverPath = Join-Path $PSScriptRoot 'p15c-headless-lab.ps1'
$composePath = Join-Path (Split-Path $PSScriptRoot -Parent) 'docker-compose.p15c-headless.yml'
$tokens = $null
$parseErrors = $null
$driverAst = [Management.Automation.Language.Parser]::ParseFile(
    $driverPath,
    [ref]$tokens,
    [ref]$parseErrors
)
if ($parseErrors.Count) { throw 'P15C production driver does not parse.' }
$nativePublicationPath = Join-Path $PSScriptRoot 'P15C.NativePublication.cs'
if (-not (Test-Path -LiteralPath $nativePublicationPath -PathType Leaf)) {
    throw 'P15C production native publication primitive is missing.'
}
Add-Type -Path $nativePublicationPath

function Import-ProductionFunction([string]$Name,[switch]$Optional) {
    $definition = $driverAst.Find({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] `
            -and $node.Name -eq $Name
    }, $true)
    if ($null -eq $definition) {
        if ($Optional) { return }
        throw "P15C production function is missing: $Name"
    }
    $escaped = [regex]::Escape($Name)
    $globalDefinition = $definition.Extent.Text -replace `
        "^function\s+$escaped", `
        "function global:$Name"
    Invoke-Expression $globalDefinition
}

function Get-TestSha256([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Test-OwnedVolumeReplacementRace {
    foreach ($name in @(
        'Get-ResourceKey',
        'Assert-InventoryKeysEqual',
        'Assert-ResourceStillOwned',
        'Remove-ExactOwnedResource',
        'Invoke-OwnedResourceCleanup'
    )) {
        Import-ProductionFunction $name
    }
    $project = 'p15c-0123456789abcdef'
    $nonce = 'd' * 32
    $original = [pscustomobject][ordered]@{
        kind = 'volume'
        id = "$project`_calls-state"
        name = "$project`_calls-state"
        project = $project
        nonce = $nonce
        role = 'calls-state'
    }
    $script:volumeState = $original
    $script:replacementDeleteObserved = $false
    function Get-OwnedResourceInventory { return @($script:volumeState) }
    function Assert-ZeroOwned {}
    function Get-ForeignInventory { return '{"stable":true}' }
    function docker {
        if ($args[0] -eq 'volume' -and $args[1] -eq 'rm') {
            $script:volumeState = [pscustomobject][ordered]@{
                kind = 'volume'
                id = $original.id
                name = $original.name
                project = 'foreign-project'
                nonce = 'e' * 32
                role = 'foreign-state'
            }
            $script:replacementDeleteObserved = $true
            $script:volumeState = $null
        }
        $global:LASTEXITCODE = 0
    }
    $resourcesClean = $false
    try {
        Invoke-OwnedResourceCleanup `
            -Project $project `
            -Nonce $nonce `
            -OwnedImages @() `
            -ForeignBefore '{"stable":true}' `
            -RunDirectory $env:TEMP `
            -ResourcesClean ([ref]$resourcesClean) `
            -AllowPartial
    } catch {
        if ($_.Exception.Message -match 'named volumes?') { return }
        throw
    }
    if ($script:replacementDeleteObserved) {
        throw 'Production cleanup deleted a replacement volume by mutable name.'
    }
}

function Test-OutputParentReplacementRace {
    Import-ProductionFunction 'Publish-OwnedOutput'
    Import-ProductionFunction 'Initialize-P15CNativePublication' -Optional
    $root = Join-Path $env:TEMP ('p15c-output-race-' + [guid]::NewGuid().ToString('N'))
    $run = Join-Path $root 'run'
    $parent = Join-Path $root 'destination'
    $redirect = Join-Path $root 'redirected'
    [void][IO.Directory]::CreateDirectory($run)
    [void][IO.Directory]::CreateDirectory($parent)
    [void][IO.Directory]::CreateDirectory($redirect)
    $stage = Join-Path $run 'evidence.stage.json'
    [IO.File]::WriteAllText($stage, '{"result":"pass"}')
    $record = [pscustomobject]@{
        created = $true
        path = $stage
        expectedSha256 = Get-TestSha256 $stage
    }
    $destination = Join-Path $parent 'evidence.json'
    $script:parentReplaced = $false
    function Assert-OutputOutsideRepositories {}
    function Assert-ProtectedAcl {}
    function Get-FileSha256([string]$Path) {
        $hash = Get-TestSha256 $Path
        if (-not $script:parentReplaced -and $Path -eq $stage) {
            [IO.Directory]::Delete($parent)
            & cmd.exe /d /c mklink /J $parent $redirect *> $null
            if ($LASTEXITCODE -ne 0) { throw 'Unable to create deterministic junction race.' }
            $script:parentReplaced = $true
        }
        return $hash
    }
    try {
        $rejected = $false
        try {
            [void](Publish-OwnedOutput `
                -Record $record `
                -Destination $destination `
                -Sources @{} `
                -RunDirectory $run)
        } catch {
            $rejected = $true
        }
        if (Test-Path -LiteralPath (Join-Path $redirect 'evidence.json')) {
            throw 'Production publication persisted PASS through a replaced parent.'
        }
        if (-not $rejected) {
            throw 'Production publication accepted a replaced parent.'
        }
    } finally {
        if (Test-Path -LiteralPath $parent) {
            [IO.Directory]::Delete($parent)
        }
        if (Test-Path -LiteralPath $root) {
            Remove-Item -LiteralPath $root -Recurse -Force
        }
    }
}

function Test-NoNamedVolumeAuthority {
    $compose = Get-Content -LiteralPath $composePath -Raw
    $driver = Get-Content -LiteralPath $driverPath -Raw
    if ($compose -match '(?m)^volumes:\s*$') {
        throw 'P15C Compose can still produce named volumes.'
    }
    if ($driver -match "'volume'\s*\{[^\r\n]*'volume',\s*'rm'") {
        throw 'P15C cleanup still contains name-addressed volume deletion.'
    }
}

function Test-ExactHandleRollback {
    Import-ProductionFunction 'Initialize-P15CNativePublication'
    Import-ProductionFunction 'Publish-OwnedOutput'
    Import-ProductionFunction 'Remove-ExclusivelyCreatedFile'
    $root = Join-Path $env:TEMP ('p15c-output-rollback-' + [guid]::NewGuid().ToString('N'))
    $run = Join-Path $root 'run'
    $parent = Join-Path $root 'destination'
    [void][IO.Directory]::CreateDirectory($run)
    [void][IO.Directory]::CreateDirectory($parent)
    $stage = Join-Path $run 'evidence.stage.json'
    $destination = Join-Path $parent 'evidence.json'
    $displaced = Join-Path $parent 'displaced.json'
    [IO.File]::WriteAllText($stage, '{"result":"owned"}')
    $record = [pscustomobject]@{
        created = $true
        path = $stage
        expectedSha256 = Get-TestSha256 $stage
    }
    function Assert-OutputOutsideRepositories {}
    function Get-FileSha256([string]$Path) { return Get-TestSha256 $Path }
    try {
        $published = Publish-OwnedOutput `
            -Record $record `
            -Destination $destination `
            -Sources @{} `
            -RunDirectory $run
        [IO.File]::Move($destination, $displaced)
        [IO.File]::WriteAllText($destination, '{"result":"replacement"}')
        Remove-ExclusivelyCreatedFile $published
        if (Test-Path -LiteralPath $displaced) {
            throw 'Exact-handle rollback retained the displaced owned output.'
        }
        if ([IO.File]::ReadAllText($destination) -ne '{"result":"replacement"}') {
            throw 'Exact-handle rollback deleted or changed the path replacement.'
        }
    } finally {
        if (Test-Path -LiteralPath $root) {
            Remove-Item -LiteralPath $root -Recurse -Force
        }
    }
}

$failures = [Collections.Generic.List[Exception]]::new()
foreach ($case in @(
    ${function:Test-OwnedVolumeReplacementRace},
    ${function:Test-OutputParentReplacementRace},
    ${function:Test-NoNamedVolumeAuthority},
    ${function:Test-ExactHandleRollback}
)) {
    try { & $case }
    catch {
        Write-Output "RED: $($_.Exception.Message)"
        Write-Output $_.ScriptStackTrace
        $failures.Add($_.Exception)
    }
}
if ($failures.Count) {
    throw [AggregateException]::new(
        "P15C corrective race fixtures failed: $($failures.Count)",
        $failures.ToArray()
    )
}
Write-Output 'P15C corrective race tests passed.'
