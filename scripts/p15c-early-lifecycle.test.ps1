$ErrorActionPreference = 'Stop'
$driverPath = Join-Path $PSScriptRoot 'p15c-headless-lab.ps1'
$tokens = $null
$parseErrors = $null
$driverAst = [Management.Automation.Language.Parser]::ParseFile(
    $driverPath,
    [ref]$tokens,
    [ref]$parseErrors
)
if ($parseErrors.Count) { throw 'P15C production driver does not parse.' }

function Import-ProductionFunction([string]$Name) {
    $definition = $driverAst.Find({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] `
            -and $node.Name -eq $Name
    }, $true)
    if ($null -eq $definition) {
        throw "P15C production function is missing: $Name"
    }
    $escaped = [regex]::Escape($Name)
    $globalDefinition = $definition.Extent.Text -replace `
        "^function\s+$escaped", `
        "function global:$Name"
    Invoke-Expression $globalDefinition
}

function Test-ComposeModelIsUtf8Json {
    Import-ProductionFunction 'Invoke-DockerCapture'
    Import-ProductionFunction 'Write-NewUtf8File'
    Import-ProductionFunction 'Write-P15CComposeModel'
    $root = Join-Path $env:TEMP ('p15c-compose-encoding-' + [guid]::NewGuid().ToString('N'))
    [void][IO.Directory]::CreateDirectory($root)
    $composeModel = Join-Path $root 'compose.json'
    $project = 'p15c-0123456789abcdef'
    $ComposePath = Join-Path $root 'compose.yml'
    function docker {
        Write-Output '{"name":"p15c","services":{}}'
        $global:LASTEXITCODE = 0
    }
    function Protect-P15CAuthorityFile {}
    function Get-FileSha256 { return 'a' * 64 }
    try {
        [void](Write-P15CComposeModel $project $ComposePath $composeModel)
        $bytes = [IO.File]::ReadAllBytes($composeModel)
        $utf8 = [Text.UTF8Encoding]::new($false,$true).GetString($bytes)
        [void]($utf8 | ConvertFrom-Json)
        & node -e `
            "JSON.parse(require('fs').readFileSync(process.argv[1], 'utf8'))" `
            $composeModel
        if ($LASTEXITCODE -ne 0) {
            throw 'Node could not parse the persisted Compose JSON as UTF-8.'
        }
    } catch {
        throw "RED: production Compose JSON is not persisted as parseable UTF-8: $($_.Exception.Message)"
    } finally {
        if (Test-Path -LiteralPath $root) {
            Remove-Item -LiteralPath $root -Recurse -Force
        }
    }
}

function Test-ZeroOwnedEarlyFailureCleanup {
    Import-ProductionFunction 'Invoke-OwnedResourceCleanup'
    Import-ProductionFunction 'Invoke-FailedRunCleanup'
    $root = Join-Path $env:TEMP ('p15c-early-cleanup-' + [guid]::NewGuid().ToString('N'))
    $run = Join-Path $root 'run'
    $secrets = Join-Path $run 'secrets'
    [void][IO.Directory]::CreateDirectory($secrets)
    $fakeSecretCleanup = Join-Path $root 'remove-secrets.ps1'
    [IO.File]::WriteAllText(
        $fakeSecretCleanup,
        "param([string]`$Action,[string]`$RunDirectory)`r`n" +
        "[IO.Directory]::Delete(`$RunDirectory, `$true)`r`n" +
        "Write-Output 'P15C ephemeral secrets removed.'`r`n"
    )
    $script:zeroOwnedChecks = 0
    $script:foreignChecks = 0
    $script:runRemoved = $false
    function Get-OwnedResourceInventory { return @() }
    function Assert-ZeroOwned {
        $script:zeroOwnedChecks++
    }
    function Get-ForeignInventory {
        $script:foreignChecks++
        return '{"stable":true}'
    }
    function Remove-OwnedRunDirectory([string]$Directory) {
        $script:runRemoved = $true
        [IO.Directory]::Delete($Directory,$true)
    }
    function Join-Path {
        param([string]$Path,[string]$ChildPath)
        if ($ChildPath -eq 'p15c-ephemeral-secrets.ps1') {
            return $fakeSecretCleanup
        }
        return Microsoft.PowerShell.Management\Join-Path `
            -Path $Path `
            -ChildPath $ChildPath
    }
    $outputs = [Collections.Generic.List[object]]::new()
    $primary = [InvalidOperationException]::new('primary compose validation failure')
    $observed = $null
    try {
        try {
            throw $primary
        } catch {
            $operationError = $_.Exception
            $cleanupErrors = @(Invoke-FailedRunCleanup `
                'p15c-0123456789abcdef' `
                ('d' * 32) `
                $run `
                $secrets `
                @() `
                '{"stable":true}' `
                $true `
                $false `
                $outputs)
            if ($cleanupErrors.Count) {
                throw [AggregateException]::new(
                    'P15C operation and cleanup failed; owned state preserved.',
                    @($operationError) + $cleanupErrors
                )
            }
            throw $operationError
        }
    } catch {
        $observed = $_.Exception
    }
    try {
        if ($observed -is [AggregateException] -or
            $observed.Message -ne $primary.Message) {
            throw 'Primary early failure was masked by cleanup.'
        }
        if ($script:zeroOwnedChecks -ne 1 -or $script:foreignChecks -ne 1) {
            throw 'Zero-owned or foreign-invariant cleanup was not verified exactly once.'
        }
        if (-not $script:runRemoved -or
            (Test-Path -LiteralPath $run) -or
            (Test-Path -LiteralPath $secrets)) {
            throw 'Verified early cleanup did not remove secrets and the run directory.'
        }
    } catch {
        throw "RED: production early zero-resource cleanup failed: $($_.Exception.Message)"
    } finally {
        if (Test-Path -LiteralPath $root) {
            Remove-Item -LiteralPath $root -Recurse -Force
        }
    }
}

function Test-CleanupFailureIsTypedAndObservable {
    Import-ProductionFunction 'Invoke-OwnedResourceCleanup'
    Import-ProductionFunction 'Invoke-FailedRunCleanup'
    $root = Join-Path $env:TEMP ('p15c-cleanup-errors-' + [guid]::NewGuid().ToString('N'))
    $run = Join-Path $root 'run'
    $secrets = Join-Path $run 'secrets'
    [void][IO.Directory]::CreateDirectory($secrets)
    $secretSentinel = 'never-emit-this-secret-value'
    [IO.File]::WriteAllText((Join-Path $secrets 'sentinel'),$secretSentinel)
    function Get-OwnedResourceInventory { return @() }
    function Assert-ZeroOwned {}
    function Get-ForeignInventory { return '{"changed":true}' }
    $outputs = [Collections.Generic.List[object]]::new()
    try {
        $cleanupErrors = @(Invoke-FailedRunCleanup `
            'p15c-0123456789abcdef' `
            ('d' * 32) `
            $run `
            $secrets `
            @() `
            '{"stable":true}' `
            $true `
            $false `
            $outputs)
        if ($cleanupErrors.Count -ne 1 -or
            @($cleanupErrors | Where-Object { $_ -isnot [Exception] }).Count) {
            throw 'Cleanup returned non-exception pipeline records.'
        }
        $primary = [InvalidOperationException]::new('primary validation failure')
        $aggregate = [AggregateException]::new(
            'P15C operation and cleanup failed; owned state preserved.',
            @($primary) + $cleanupErrors
        )
        $messages = @($aggregate.InnerExceptions | ForEach-Object Message)
        if ($messages -notcontains $primary.Message -or
            $messages -notcontains 'P15C foreign Docker identity or membership changed.') {
            throw 'Primary and cleanup causes are not both observable.'
        }
        if (($aggregate.ToString()).Contains($secretSentinel)) {
            throw 'Cleanup diagnostics leaked secret content.'
        }
    } finally {
        if (Test-Path -LiteralPath $root) {
            Remove-Item -LiteralPath $root -Recurse -Force
        }
    }
}

$failures = [Collections.Generic.List[Exception]]::new()
foreach ($case in @(
    ${function:Test-ComposeModelIsUtf8Json},
    ${function:Test-ZeroOwnedEarlyFailureCleanup},
    ${function:Test-CleanupFailureIsTypedAndObservable}
)) {
    try { & $case }
    catch {
        Write-Output $_.Exception.Message
        $failures.Add($_.Exception)
    }
}
if ($failures.Count) {
    throw [AggregateException]::new(
        "P15C early lifecycle fixtures failed: $($failures.Count)",
        $failures.ToArray()
    )
}
Write-Output 'P15C early lifecycle tests passed.'
