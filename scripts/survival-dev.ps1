[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('Up','Down','Status','Logs','Build','Restart')]
    [string]$Action,
    [string[]]$Service = @(),
    [string]$LanHost,
    [switch]$Chain,
    [switch]$Reset
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$Root = [IO.Path]::GetFullPath((Split-Path $PSScriptRoot -Parent))
$ComposePath = Join-Path $Root 'docker-compose.survival.dev.yml'
$Project = 'deep-survival-dev'
$baseArguments = @('compose', '-p', $Project, '-f', $ComposePath)
$ContextRoot = Join-Path $Root 'artifacts\survival-dev\build-contexts'

function Invoke-SurvivalDocker([string[]]$Arguments) {
    & docker @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Survival dev Docker command failed with exit code $LASTEXITCODE."
    }
}

function Resolve-SurvivalSource([string]$EnvironmentName,[string]$DefaultRelativePath) {
    $configured = [Environment]::GetEnvironmentVariable($EnvironmentName)
    $candidate = if ([string]::IsNullOrWhiteSpace($configured)) {
        Join-Path $Root $DefaultRelativePath
    } else {
        $configured
    }
    return [IO.Path]::GetFullPath($candidate)
}

function Export-SurvivalContext([string]$Kind,[string]$Source,[string]$Name,[string]$EnvironmentName) {
    $destination = Join-Path $ContextRoot $Name
    & node (Join-Path $PSScriptRoot 'survival-dev-context-export.mjs') $Kind $Source $destination $ContextRoot
    if ($LASTEXITCODE -ne 0) { throw "Survival $Name build context export failed." }
    Set-Item -Path "Env:$EnvironmentName" -Value $destination
}

function Prepare-SurvivalBuildContexts([switch]$IncludeChain) {
    Export-SurvivalContext 'dotnet' (Resolve-SurvivalSource 'SURVIVAL_XNODE_PATH' '..\xnode') 'xnode' 'SURVIVAL_XNODE_BUILD_CONTEXT'
    Export-SurvivalContext 'dotnet' (Resolve-SurvivalSource 'SURVIVAL_REGISTRY_PATH' '..\deep-registry-api') 'registry' 'SURVIVAL_REGISTRY_BUILD_CONTEXT'
    if ($IncludeChain) {
        Export-SurvivalContext 'dotnet' (Resolve-SurvivalSource 'SURVIVAL_STAKING_PATH' '..\xpoint-staking-backend') 'staking' 'SURVIVAL_STAKING_BUILD_CONTEXT'
        Export-SurvivalContext 'contracts' (Resolve-SurvivalSource 'SURVIVAL_CONTRACTS_PATH' '..\xpoint-staking-contracts') 'contracts' 'SURVIVAL_CONTRACTS_BUILD_CONTEXT'
    }
}

function Assert-SurvivalHostEndpoints([string]$HostName) {
    $targets = @(
        "http://$HostName`:41801/api/network/contact",
        "http://$HostName`:41802/api/network/contact",
        "http://$HostName`:41803/api/network/contact",
        "http://$HostName`:41810/health/live",
        "http://$HostName`:41820/health/ready",
        "http://$HostName`:41821/health/ready",
        "http://$HostName`:41822/health/ready",
        "http://$HostName`:41823/health/ready",
        'http://127.0.0.1:41999/health/ready'
    )
    foreach ($target in $targets) {
        $ready = $false
        foreach ($attempt in 1..40) {
            try {
                $response = Invoke-WebRequest -UseBasicParsing -Uri $target -TimeoutSec 3
                if ($response.StatusCode -ge 200 -and $response.StatusCode -lt 300) {
                    $ready = $true
                    break
                }
            } catch {}
            Start-Sleep -Milliseconds 500
        }
        if (-not $ready) { throw "Survival dev endpoint is unreachable: $target" }
    }
}

function Write-ClientEnvironment([string]$HostName,[switch]$IncludeChain) {
    $address = $null
    if (-not [Net.IPAddress]::TryParse($HostName, [ref]$address) -or
        $address.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or
        $address.Equals([Net.IPAddress]::Any)) {
        throw 'LanHost must be an IPv4 address.'
    }
    $outputDirectory = Join-Path $Root 'artifacts\survival-dev'
    [void][IO.Directory]::CreateDirectory($outputDirectory)
    $routerIds = @(
        '4cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29',
        '7422b9887598068e32c4448a949adb290d0f4e35b9e01b0ee5f1a1e600fe2674',
        'f381626e41e7027ea431bfe3009e94bdd25a746beec468948d6c3c7c5dc9a54b'
    )
    foreach ($target in @(
        [pscustomobject]@{ Name = 'client.android.env'; Host = $HostName },
        [pscustomobject]@{ Name = 'client.windows.env'; Host = $HostName }
    )) {
        $hostValue = $target.Host
        $values = @(
            'SURVIVAL_ENV=Development',
            "XNODE_URLS=$($routerIds[0])|http://$hostValue`:41801;$($routerIds[1])|http://$hostValue`:41802;$($routerIds[2])|http://$hostValue`:41803",
            "DEEP_REGISTRY_URL=http://$hostValue`:41810",
            "DEEP_FILE_URL=http://$hostValue`:41821",
            "DEEP_PUSH_URL=http://$hostValue`:41822",
            "DEEP_CALL_SIGNALING_BASE_URL=http://$hostValue`:41823",
            'DEEP_TLS_PINS='
        )
        if ($IncludeChain) {
            $values += "DEEP_STAKING_BACKEND_URL=http://$hostValue`:41811"
            $values += "DEEP_DEVNET_RPC_URL=http://$hostValue`:41545"
        }
        $content = $values -join "`n"
        [IO.File]::WriteAllText(
            (Join-Path $outputDirectory $target.Name),
            $content + "`n",
            [Text.UTF8Encoding]::new($false)
        )
    }
    Write-Output "Client environments: $outputDirectory"
}

switch ($Action) {
    'Up' {
        $advertisedHost = if ([string]::IsNullOrWhiteSpace($LanHost)) { '127.0.0.1' } else { $LanHost }
        Write-ClientEnvironment $advertisedHost -IncludeChain:$Chain
        $env:SURVIVAL_BIND_HOST = $advertisedHost
        Prepare-SurvivalBuildContexts -IncludeChain:$Chain
        $upArguments = @($baseArguments)
        if ($Chain) { $upArguments += @('--profile', 'chain') }
        Invoke-SurvivalDocker ($upArguments + @('up', '-d', '--build', '--wait', '--force-recreate') + $Service)
        Assert-SurvivalHostEndpoints $advertisedHost
        & node (Join-Path $PSScriptRoot 'survival-dev-seed.mjs') '--host' $advertisedHost
        if ($LASTEXITCODE -ne 0) { throw 'Survival relay contact seed failed.' }
        Invoke-SurvivalDocker ($baseArguments + @('restart', 'xnode-1', 'xnode-2', 'xnode-3'))
        Invoke-SurvivalDocker ($baseArguments + @('up', '-d', '--wait', 'xnode-1', 'xnode-2', 'xnode-3'))
        Assert-SurvivalHostEndpoints $advertisedHost
        & node (Join-Path $PSScriptRoot 'survival-dev-verify.mjs') '--host' $advertisedHost
        if ($LASTEXITCODE -ne 0) { throw 'Survival relay contact verification failed.' }
    }
    'Down' {
        $arguments = $baseArguments + @('down')
        if ($Reset) { $arguments += '--volumes' }
        Invoke-SurvivalDocker $arguments
    }
    'Status' { Invoke-SurvivalDocker ($baseArguments + @('ps')) }
    'Logs' { Invoke-SurvivalDocker ($baseArguments + @('logs', '-f', '--tail=200') + $Service) }
    'Build' {
        $includeChainContexts = $Chain -or $Service -contains 'contracts-devnet' -or $Service -contains 'staking-backend'
        Prepare-SurvivalBuildContexts -IncludeChain:$includeChainContexts
        Invoke-SurvivalDocker ($baseArguments + @('build') + $Service)
    }
    'Restart' {
        if ($Service.Count -eq 0) { throw 'Restart requires at least one -Service.' }
        Invoke-SurvivalDocker ($baseArguments + @('restart') + $Service)
    }
}
