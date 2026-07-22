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

$fakeSource = @'
using System;

public static class FakeDocker
{
    public static int Main(string[] args)
    {
        string command = String.Join(" ", args);
        if (args.Length >= 2 && args[0] == "container" && args[1] == "ls")
        {
            Console.WriteLine(new string('a', 64));
            return 0;
        }
        if (args.Length >= 2 && args[0] == "container" && args[1] == "inspect")
        {
            if (command.Contains("index .Config.Labels") &&
                !command.Contains("\"com.docker.compose.project\""))
            {
                Console.Error.WriteLine("template: :1: function \"com\" not defined");
                return 1;
            }
            if (command.Contains("{{json .}}"))
            {
                Console.WriteLine("{\"Id\":\"" + new string('a', 64) +
                    "\",\"Name\":\"/foreign\",\"Image\":\"sha256:" +
                    new string('b', 64) + "\",\"Config\":{\"Labels\":null}}");
                return 0;
            }
        }
        return 0;
    }
}
'@

$root = Join-Path $env:TEMP ('p15c-native-docker-' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($root)
$dockerPath = Join-Path $root 'docker.exe'
$priorPath = $env:PATH
try {
    Add-Type `
        -TypeDefinition $fakeSource `
        -Language CSharp `
        -OutputAssembly $dockerPath `
        -OutputType ConsoleApplication
    $env:PATH = $root + [IO.Path]::PathSeparator + $priorPath
    Import-ProductionFunction 'Invoke-DockerCapture'
    Import-ProductionFunction 'Get-ForeignInventory'
    try {
        $inventory = Get-ForeignInventory 'p15c-0123456789abcdef'
    } catch {
        throw "RED: production foreign inventory failed through native Docker arguments: $($_.Exception.Message)"
    }
    $value = $inventory | ConvertFrom-Json
    if (@($value.containers).Count -ne 1 -or
        $value.containers[0] -notmatch ('^a{64}\|/foreign\|sha256:b{64}\|$')) {
        throw 'P15C foreign container identity projection is not stable or null-label safe.'
    }
} finally {
    $env:PATH = $priorPath
    if (Test-Path -LiteralPath $root) {
        Remove-Item -LiteralPath $root -Recurse -Force
    }
}
Write-Output 'P15C native foreign inventory test passed.'
