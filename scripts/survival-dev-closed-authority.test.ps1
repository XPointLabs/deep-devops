[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$root = [IO.Path]::GetFullPath((Split-Path $PSScriptRoot -Parent))
$launcher = Join-Path $PSScriptRoot 'survival-dev.ps1'
$work = Join-Path ([IO.Path]::GetTempPath()) (
    'deep-closed-docker-authority-' + [Guid]::NewGuid().ToString('N'))
$approved = Join-Path $work 'approved-docker.cmd'
$pathShimDirectory = Join-Path $work 'path-shim'
$pathShim = Join-Path $pathShimDirectory 'docker.cmd'
$runtimeRoot = Join-Path $work 'runtime-root'
$approvedMarker = Join-Path $work 'approved.txt'
$pathMarker = Join-Path $work 'path.txt'
$originalPath = $env:PATH
$originalDockerPath = $env:DEEP_PHYSICAL_E2E_DOCKER_PATH
$originalDockerSha = $env:DEEP_PHYSICAL_E2E_DOCKER_SHA256
$originalComposePath = $env:DEEP_PHYSICAL_E2E_DOCKER_COMPOSE_PATH
$originalComposeSha = $env:DEEP_PHYSICAL_E2E_DOCKER_COMPOSE_SHA256
$originalRuntimeRoot = $env:DEEP_PHYSICAL_E2E_DEVOPS_RUNTIME_ROOT
$originalNodeImage = $env:SURVIVAL_NODE_IMAGE

function Invoke-LauncherExpect([bool]$Success) {
    $priorPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $output = @(& powershell -NoProfile -ExecutionPolicy Bypass -File $launcher `
            -Action Status 2>&1)
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $priorPreference
    }
    if (($exitCode -eq 0) -ne $Success) {
        throw "Closed Docker authority returned unexpected exit code $exitCode.`n$($output -join "`n")"
    }
    return $output
}

try {
    [void][IO.Directory]::CreateDirectory($pathShimDirectory)
    [void][IO.Directory]::CreateDirectory($runtimeRoot)
    [IO.File]::WriteAllText(
        (Join-Path $runtimeRoot '.env'),
        "SURVIVAL_NODE_IMAGE=attacker.invalid/from-dotenv:latest`nCOMPOSE_FILE=attacker.yml`n",
        [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText(
        $approved,
        "@echo off`r`necho %COMPOSE_DISABLE_ENV_FILE%>$approvedMarker`r`nexit /b 0`r`n",
        [Text.ASCIIEncoding]::new())
    [IO.File]::WriteAllText(
        $pathShim,
        "@echo off`r`necho path>$pathMarker`r`nexit /b 0`r`n",
        [Text.ASCIIEncoding]::new())
    $env:DEEP_PHYSICAL_E2E_DOCKER_PATH = $approved
    $env:DEEP_PHYSICAL_E2E_DOCKER_SHA256 =
        (Get-FileHash -LiteralPath $approved -Algorithm SHA256).Hash.ToLowerInvariant()
    $env:DEEP_PHYSICAL_E2E_DOCKER_COMPOSE_PATH = $approved
    $env:DEEP_PHYSICAL_E2E_DOCKER_COMPOSE_SHA256 =
        $env:DEEP_PHYSICAL_E2E_DOCKER_SHA256
    $env:DEEP_PHYSICAL_E2E_DEVOPS_RUNTIME_ROOT = $runtimeRoot
    $env:PATH = $pathShimDirectory + [IO.Path]::PathSeparator + $originalPath
    Remove-Item Env:SURVIVAL_NODE_IMAGE -ErrorAction SilentlyContinue

    [void](Invoke-LauncherExpect $true)
    if (-not (Test-Path -LiteralPath $approvedMarker -PathType Leaf) -or
        (Get-Content -Raw -LiteralPath $approvedMarker).Trim() -cne 'true' -or
        (Test-Path -LiteralPath $pathMarker)) {
        throw 'Status did not use the exact approved Docker path with .env disabled.'
    }

    Remove-Item -LiteralPath $approvedMarker -Force
    foreach ($hostile in @('SuRvIvAl_NoDe_ImAgE', 'dOcKeR_hOsT', 'CoMpOsE_fIlE')) {
        [Environment]::SetEnvironmentVariable($hostile, 'attacker-controlled')
        $rejected = Invoke-LauncherExpect $false
        [Environment]::SetEnvironmentVariable($hostile, $null)
        if (($rejected -join "`n") -cnotmatch 'rejects inherited variable' -or
            (Test-Path -LiteralPath $approvedMarker) -or
            (Test-Path -LiteralPath $pathMarker)) {
            throw "Inherited override '$hostile' was not rejected before Docker execution."
        }
    }

    $env:DEEP_PHYSICAL_E2E_DOCKER_SHA256 = '0' * 64
    $rejected = Invoke-LauncherExpect $false
    if (($rejected -join "`n") -cnotmatch 'does not match its reviewed SHA-256' -or
        (Test-Path -LiteralPath $approvedMarker)) {
        throw 'Docker byte substitution was not rejected before execution.'
    }
} finally {
    $env:PATH = $originalPath
    $env:DEEP_PHYSICAL_E2E_DOCKER_PATH = $originalDockerPath
    $env:DEEP_PHYSICAL_E2E_DOCKER_SHA256 = $originalDockerSha
    $env:DEEP_PHYSICAL_E2E_DOCKER_COMPOSE_PATH = $originalComposePath
    $env:DEEP_PHYSICAL_E2E_DOCKER_COMPOSE_SHA256 = $originalComposeSha
    $env:DEEP_PHYSICAL_E2E_DEVOPS_RUNTIME_ROOT = $originalRuntimeRoot
    $env:SURVIVAL_NODE_IMAGE = $originalNodeImage
    if (Test-Path -LiteralPath $work) {
        Remove-Item -LiteralPath $work -Recurse -Force
    }
}

'survival-dev-closed-authority-green'
