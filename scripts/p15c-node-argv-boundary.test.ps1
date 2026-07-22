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

$root = Join-Path $env:TEMP ('p15c-node-argv-' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($root)
$probe = Join-Path $root 'probe.mjs'
$input = Join-Path $root 'input.json'
$probeSource = @'
import { readFileSync } from 'node:fs';

const [command, inputPath, expectation] = process.argv.slice(2);
const commands = new Set([
  'validate-compose',
  'validate-receipt',
  'summarize-receipt',
  'validate-runtime-inventory'
]);
if (!commands.has(command) || !inputPath) process.exit(2);
const value = JSON.parse(expectation);
if (value.marker !== command || value.nested?.quoted !== 'exact value') process.exit(3);
readFileSync(inputPath);
'@
[IO.File]::WriteAllText($probe,$probeSource,[Text.UTF8Encoding]::new($false))
[IO.File]::WriteAllText($input,'{}',[Text.UTF8Encoding]::new($false))
Import-ProductionFunction 'Invoke-NodeQuiet'
$failures = [Collections.Generic.List[string]]::new()
try {
    foreach ($command in @(
        'validate-compose',
        'validate-receipt',
        'summarize-receipt',
        'validate-runtime-inventory'
    )) {
        $expectation = [ordered]@{
            marker = $command
            nested = [ordered]@{ quoted = 'exact value' }
        } | ConvertTo-Json -Depth 4 -Compress
        try {
            Invoke-NodeQuiet @($probe,$command,$input,$expectation)
        } catch {
            $failures.Add($command)
        }
    }
    if ($failures.Count) {
        throw "RED: native Node expectation argv failed for $($failures.Count) production command paths: $($failures -join ', ')"
    }
} finally {
    if (Test-Path -LiteralPath $root) {
        Remove-Item -LiteralPath $root -Recurse -Force
    }
}
Write-Output 'P15C Node expectation boundary tests passed.'
