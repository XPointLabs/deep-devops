$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
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

function Test-DockerProgressIsNotTerminating {
    Import-ProductionFunction 'Invoke-DockerQuiet'
    $source = @'
using System;

public static class FakeDockerProgress
{
    public static int Main(string[] args)
    {
        Console.Error.WriteLine("Dockerfile:7");
        if (Array.IndexOf(args, "fail") >= 0) return 7;
        Console.Out.WriteLine("BuildKit progress");
        return 0;
    }
}
'@
    $root = Join-Path $env:TEMP ('p15c-docker-progress-' + [guid]::NewGuid().ToString('N'))
    [void][IO.Directory]::CreateDirectory($root)
    $dockerPath = Join-Path $root 'docker.exe'
    $logPath = Join-Path $root 'build.log'
    $priorPath = $env:PATH
    try {
        Add-Type `
            -TypeDefinition $source `
            -Language CSharp `
            -OutputAssembly $dockerPath `
            -OutputType ConsoleApplication
        $env:PATH = $root + [IO.Path]::PathSeparator + $priorPath
        try {
            Invoke-DockerQuiet @('compose','build') $logPath
        } catch {
            throw "RED: Docker progress stderr terminated a successful native process: $($_.Exception.Message)"
        }
        $log = [IO.File]::ReadAllText($logPath)
        if ($log -notmatch 'Dockerfile:7' -or $log -notmatch 'BuildKit progress') {
            throw 'P15C Docker log did not retain both native output streams.'
        }
        try {
            Invoke-DockerQuiet @('fail') $logPath
            throw 'P15C failing native Docker process was accepted.'
        } catch {
            if ($_.Exception.Message -match 'remains only in the owned run directory') {
                throw 'RED: Docker failure message claims a log that successful cleanup deletes.'
            }
            if ($_.Exception.Message -ne 'P15C Docker operation failed.') {
                throw
            }
        }
    } finally {
        $env:PATH = $priorPath
        if (Test-Path -LiteralPath $root) {
            Remove-Item -LiteralPath $root -Recurse -Force
        }
    }
}

function Test-BuildIsExplicitlyOffline {
    Import-ProductionFunction 'Invoke-P15CBuild'
    $ComposePath = 'C:\owned\compose.yml'
    $script:buildArguments = @()
    function Invoke-DockerQuiet([string[]]$Arguments,[string]$LogPath) {
        $script:buildArguments = @($Arguments)
    }
    Invoke-P15CBuild 'p15c-0123456789abcdef' 'C:\owned\build.log'
    if ($script:buildArguments -notcontains '--pull=false' -or
        $script:buildArguments -notcontains '--no-cache') {
        throw 'RED: P15C build does not explicitly prohibit base-image pulls.'
    }
}

function Test-EarlyImageNamesAreNotReceiptIds {
    Import-ProductionFunction 'Get-ExpectedImageIds'
    $imageNames = [ordered]@{
        XNode = 'p15c-0123456789abcdef-xnode:exact'
        Storage = 'p15c-0123456789abcdef-storage:exact'
    }
    try {
        $ids = @(Get-ExpectedImageIds $imageNames)
    } catch {
        throw "RED: early cleanup treated image names as receipt IDs: $($_.Exception.Message)"
    }
    if ($ids.Count) {
        throw 'P15C early image-name dictionary produced cleanup IDs.'
    }
}

function Test-MultistageBaseArgsAreGlobal {
    $composePath = Join-Path (Split-Path $PSScriptRoot -Parent) `
        'docker-compose.p15c-headless.yml'
    $compose = Get-Content -LiteralPath $composePath -Raw
    $globalDeclarations = [regex]::Matches(
        $compose,
        '(?m)^\s+ARG SDK_IMAGE\r?\n\s+ARG RUNTIME_IMAGE\r?\n\s+FROM \$\$\{SDK_IMAGE\} AS build$'
    )
    if ($globalDeclarations.Count -ne 3) {
        throw 'RED: multi-stage runtime base ARGs are not globally declared before the first FROM.'
    }
}

$failures = [Collections.Generic.List[Exception]]::new()
foreach ($case in @(
    ${function:Test-DockerProgressIsNotTerminating},
    ${function:Test-BuildIsExplicitlyOffline},
    ${function:Test-EarlyImageNamesAreNotReceiptIds},
    ${function:Test-MultistageBaseArgsAreGlobal}
)) {
    try { & $case }
    catch {
        Write-Output $_.Exception.Message
        $failures.Add($_.Exception)
    }
}
if ($failures.Count) {
    throw [AggregateException]::new(
        "P15C native process fixtures failed: $($failures.Count)",
        $failures.ToArray()
    )
}
Write-Output 'P15C native process tests passed.'
