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

function Invoke-SurvivalDocker([string[]]$Arguments) {
    & docker @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Survival dev Docker command failed with exit code $LASTEXITCODE."
    }
}

function Assert-SurvivalHostEndpoints {
    $targets = @(
        'http://127.0.0.1:41801/api/network/contact',
        'http://127.0.0.1:41802/api/network/contact',
        'http://127.0.0.1:41803/api/network/contact',
        'http://127.0.0.1:41810/health/live',
        'http://127.0.0.1:41820/health/ready',
        'http://127.0.0.1:41821/health/ready',
        'http://127.0.0.1:41822/health/ready',
        'http://127.0.0.1:41823/health/ready',
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
        [pscustomobject]@{ Name = 'client.windows.env'; Host = '127.0.0.1' }
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
        $env:SURVIVAL_BIND_HOST = if ([string]::IsNullOrWhiteSpace($LanHost)) { '127.0.0.1' } else { '0.0.0.0' }
        $upArguments = @($baseArguments)
        if ($Chain) { $upArguments += @('--profile', 'chain') }
        Invoke-SurvivalDocker ($upArguments + @('up', '-d', '--build', '--wait', '--force-recreate') + $Service)
        Assert-SurvivalHostEndpoints
        & node (Join-Path $PSScriptRoot 'survival-dev-seed.mjs')
        if ($LASTEXITCODE -ne 0) { throw 'Survival relay contact seed failed.' }
        Invoke-SurvivalDocker ($baseArguments + @('restart', 'xnode-1', 'xnode-2', 'xnode-3'))
        Invoke-SurvivalDocker ($baseArguments + @('up', '-d', '--wait', 'xnode-1', 'xnode-2', 'xnode-3'))
        Assert-SurvivalHostEndpoints
        & node (Join-Path $PSScriptRoot 'survival-dev-verify.mjs')
        if ($LASTEXITCODE -ne 0) { throw 'Survival relay contact verification failed.' }
    }
    'Down' {
        $arguments = $baseArguments + @('down')
        if ($Reset) { $arguments += '--volumes' }
        Invoke-SurvivalDocker $arguments
    }
    'Status' { Invoke-SurvivalDocker ($baseArguments + @('ps')) }
    'Logs' { Invoke-SurvivalDocker ($baseArguments + @('logs', '-f', '--tail=200') + $Service) }
    'Build' { Invoke-SurvivalDocker ($baseArguments + @('build') + $Service) }
    'Restart' {
        if ($Service.Count -eq 0) { throw 'Restart requires at least one -Service.' }
        Invoke-SurvivalDocker ($baseArguments + @('restart') + $Service)
    }
}
