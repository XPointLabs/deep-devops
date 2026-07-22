# P15C_OPERATION_PLAN: source-preflight,image-preflight,collision-check,foreign-snapshot,generate-secrets,compose-config,build,up-contracts,deploy-contracts,up-runtime,probe,e2e,labels,cleanup,evidence
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('Run','Verify','Down')][string]$Action,
    [string]$XNodePath,
    [string]$E2EPath,
    [string]$RegistryPath,
    [string]$StakingPath,
    [string]$ContractsPath,
    [string]$NodeImage,
    [string]$DotnetSdkImage,
    [string]$DotnetRuntimeImage,
    [string]$EvidencePath,
    [string]$ReceiptPath,
    [switch]$KeepRunning
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$Expected = [ordered]@{
    XNode = [ordered]@{ Sha = 'cd9d20a8ec8346d171d4cd070dde170aa5f471d7'; Tree = 'e27c1d7c2517bd9d1bcdfbacda8c68c57a2ced59'; Path = 'C:\W\deep-survival\wave09\xnode-p15c-source' }
    E2E = [ordered]@{ Sha = 'da24f530f187dbd81258905bc28feedce0eb23eb'; Tree = '566ee86cd01ec5a32d3ad60d1c9eac9183328c1f'; Path = 'C:\Work\DeepSession\XPointLabs\deep-tests-e2e' }
    Registry = [ordered]@{ Sha = 'fb7ebac6404e7a53241af08bb2f80d8a81022be8'; Tree = 'be7a44e68933fa0773e81f6ad898feebd752a67a'; Path = 'C:\Work\DeepSession\XPointLabs\deep-registry-api' }
    Staking = [ordered]@{ Sha = 'c4638486d1f658f3cda2b5060eb3709e255d7288'; Tree = 'a0dafebbd380425e5b4c5e86bdb3138bf77fa3e0'; Path = 'C:\Work\DeepSession\XPointLabs\xpoint-staking-backend' }
    Contracts = [ordered]@{ Sha = 'd5063212b491b4c7bd649a3ab367491dfed9909f'; Tree = '89f506e9c1c33cce0e1ad928b72602aa533b012c'; Path = 'C:\Work\DeepSession\XPointLabs\xpoint-staking-contracts' }
}
$ExpectedNodeImage = 'node@sha256:242549cd46785b480c832479a730f4f2a20865d61ea2e404fdb2a5c3d3b73ecf'
$ExpectedSdkImage = 'mcr.microsoft.com/dotnet/sdk@sha256:7e964ea8bc6c1e18ea9fbc76ed403da41c9b19aeee2aab6bf9c845f25e891380'
$ExpectedRuntimeImage = 'mcr.microsoft.com/dotnet/aspnet@sha256:e3736b0d423db99c6988e1ddf5ea725c14b12579bb120024e5ff7ff204a14080'
$Root = [System.IO.Path]::GetFullPath((Split-Path $PSScriptRoot -Parent))
$ComposePath = Join-Path $Root 'docker-compose.p15c-headless.yml'
$CommonPlan = @('source-preflight','image-preflight','collision-check','foreign-snapshot','generate-secrets','compose-config','build','up-contracts','deploy-contracts','up-runtime','probe','e2e','labels')
$NormalPlan = @($CommonPlan) + @('cleanup','evidence')
$RetainedPlan = @($CommonPlan) + @('receipt-retained')
$Ports = [ordered]@{ Contracts = 39545; XNode1 = 39801; XNode2 = 39802; XNode3 = 39803; Registry = 39810; Staking = 39811 }

function New-Hex([int]$Bytes) {
    $value = [byte[]]::new($Bytes)
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($value); return (([System.BitConverter]::ToString($value) -replace '-', '').ToLowerInvariant()) }
    finally { $rng.Dispose(); [Array]::Clear($value, 0, $value.Length) }
}

function Get-FileSha256([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Write-NewUtf8File([string]$Path, [string]$Content) {
    $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes($Content)
    $stream = [System.IO.FileStream]::new($Path, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
    try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) }
    finally { $stream.Dispose(); [Array]::Clear($bytes, 0, $bytes.Length) }
}

function Assert-P15COperationPlan([string[]]$Observed, [switch]$Prefix, [switch]$Retained) {
    $expected = if ($Retained) { $RetainedPlan } else { $NormalPlan }
    if ($Prefix) { $expected = @($expected | Select-Object -First $Observed.Count) }
    if ($Observed.Count -ne $expected.Count) { throw 'P15C lifecycle operation plan is incomplete.' }
    for ($index = 0; $index -lt $expected.Count; $index++) {
        if ($Observed[$index] -ne $expected[$index]) { throw 'P15C lifecycle operation order is invalid.' }
    }
}

function Assert-CompletedPlan([string[]]$Observed, [switch]$Retained) {
    & $function:Assert-P15COperationPlan $Observed -Retained:$Retained
}

function Clear-P15CEnvironment {
    foreach ($item in @(Get-ChildItem Env: | Where-Object { $_.Name.StartsWith('P15C_', [StringComparison]::OrdinalIgnoreCase) })) {
        [Environment]::SetEnvironmentVariable($item.Name, $null, 'Process')
    }
}

function Invoke-DockerCapture([string[]]$Arguments) {
    $output = @(& docker @Arguments 2>$null)
    if ($LASTEXITCODE -ne 0) { throw 'P15C Docker query failed.' }
    return $output
}

function Invoke-DockerQuiet([string[]]$Arguments, [string]$LogPath) {
    & docker @Arguments *> $LogPath
    if ($LASTEXITCODE -ne 0) { throw 'P15C Docker operation failed; raw output retained only in the owned run directory.' }
}

function Invoke-NodeQuiet([string[]]$Arguments) {
    & node @Arguments *> $null
    if ($LASTEXITCODE -ne 0) { throw 'P15C validation gate failed.' }
}

function Get-GitValue([string]$Path, [string[]]$Arguments) {
    $value = @(& git -C $Path @Arguments 2>$null)
    if ($LASTEXITCODE -ne 0) { throw 'P15C Git query failed.' }
    return ($value -join "`n").Trim()
}

function Assert-RunInputs {
    $required = @($XNodePath,$E2EPath,$RegistryPath,$StakingPath,$ContractsPath,$NodeImage,$DotnetSdkImage,$DotnetRuntimeImage,$EvidencePath,$ReceiptPath)
    if (@($required | Where-Object { [string]::IsNullOrWhiteSpace($_) }).Count -ne 0) { throw 'P15C Run requires every exact source, image, evidence and receipt input.' }
    if ($NodeImage -ne $ExpectedNodeImage -or $DotnetSdkImage -ne $ExpectedSdkImage -or $DotnetRuntimeImage -ne $ExpectedRuntimeImage) { throw 'P15C image lock differs from the accepted local ARM64 digest.' }
    if (Test-Path -LiteralPath $EvidencePath) { throw 'P15C evidence path already exists.' }
    if (Test-Path -LiteralPath $ReceiptPath) { throw 'P15C receipt path already exists.' }
}

function New-SourceManifest([string]$Path, [System.Collections.IDictionary]$Sources) {
    $items = foreach ($name in $Sources.Keys) {
        $item = $Sources[$name]
        [ordered]@{ name = $name; path = $item.Path; sha = $item.Sha; tree = $item.Tree }
    }
    [System.IO.File]::WriteAllText($Path, (@{ sources = @($items) } | ConvertTo-Json -Depth 8), [System.Text.UTF8Encoding]::new($false))
}

function Assert-SourcePreflight([string]$ManifestPath) {
    Invoke-NodeQuiet @((Join-Path $PSScriptRoot 'p15c-headless-source-preflight.mjs'),'check-sources',$ManifestPath)
}

function Assert-ImageLock([string]$Reference, [string]$Kind) {
    $raw = (Invoke-DockerCapture @('image','inspect',$Reference,'--format','{{json .}}')) -join ''
    $image = $raw | ConvertFrom-Json
    if ($image.Os -ne 'linux' -or $image.Architecture -ne 'arm64' -or $image.Id -notmatch '^sha256:[0-9a-f]{64}$' -or @($image.RepoDigests) -notcontains $Reference) { throw 'P15C local image lock is missing or not Linux ARM64.' }
    if ($Kind -eq 'sdk') {
        $version = (Invoke-DockerCapture @('run','--rm','--pull','never','--platform','linux/arm64',$Reference,'dotnet','--version') -join "`n").Trim()
        if ($version -ne '10.0.301') { throw 'P15C exact SDK 10.0.301 is unavailable.' }
    }
    elseif ($Kind -eq 'runtime') {
        $versions = @((Invoke-DockerCapture @('run','--rm','--pull','never','--platform','linux/arm64',$Reference,'dotnet','--list-runtimes')) | Where-Object { $_ -match '^Microsoft\.(?:AspNetCore|NETCore)\.App ' } | ForEach-Object { ($_ -split ' \[')[0] } | Sort-Object)
        if (($versions -join "`n") -ne "Microsoft.AspNetCore.App 10.0.10`nMicrosoft.NETCore.App 10.0.10") { throw 'P15C exact ASP.NET/Core 10.0.10 runtime is unavailable.' }
    }
    elseif ($Kind -eq 'node') {
        $version = (Invoke-DockerCapture @('run','--rm','--pull','never','--platform','linux/arm64',$Reference,'node','--version') -join '').Trim()
        if ($version -ne 'v24.16.0') { throw 'P15C exact Node 24.16.0 runtime is unavailable.' }
    }
}

function Assert-EngineArchitecture {
    $arch = (Invoke-DockerCapture @('info','--format','{{.Architecture}}') -join '').Trim().ToLowerInvariant()
    if ($arch -notin @('arm64','aarch64')) { throw 'P15C Docker Engine must be ARM64; emulation is not accepted.' }
}

function Assert-NoCollision([string]$Project, [string]$Nonce) {
    $containers = @(Invoke-DockerCapture @('container','ls','-aq','--filter',"label=com.docker.compose.project=$Project"))
    $networks = @(Invoke-DockerCapture @('network','ls','-q','--filter',"label=com.docker.compose.project=$Project"))
    $volumes = @(Invoke-DockerCapture @('volume','ls','-q','--filter',"label=com.docker.compose.project=$Project"))
    $images = @(Invoke-DockerCapture @('image','ls','-q','--filter',"label=com.xpoint.p15c.ownership-nonce=$Nonce"))
    if ($containers.Count + $networks.Count + $volumes.Count + $images.Count -ne 0) { throw 'P15C project/tag/resource collision exists.' }
    $tagCollision = @(Invoke-DockerCapture @('image','ls','-q',"$Project-*"))
    if ($tagCollision.Count -ne 0) { throw 'P15C image tag collision exists.' }
}

function Get-ForeignInventory([string]$Project) {
    $containers = @(Invoke-DockerCapture @('container','ls','-a','--no-trunc','--format','{{.ID}}|{{.Names}}|{{.Image}}|{{.Status}}')) | Where-Object { $_ -notmatch "\|$([regex]::Escape($Project))-" } | Sort-Object
    $images = @(Invoke-DockerCapture @('image','ls','--no-trunc','--digests','--format','{{.ID}}|{{.Repository}}|{{.Tag}}|{{.Digest}}')) | Where-Object { $_ -notmatch "\|$([regex]::Escape($Project))-" } | Sort-Object
    $networks = @(Invoke-DockerCapture @('network','ls','--no-trunc','--format','{{.ID}}|{{.Name}}|{{.Driver}}|{{.Scope}}')) | Where-Object { $_ -notmatch "\|$([regex]::Escape($Project))_" } | Sort-Object
    $volumes = @(Invoke-DockerCapture @('volume','ls','--format','{{.Name}}|{{.Driver}}')) | Where-Object { $_ -notmatch "^$([regex]::Escape($Project))_" } | Sort-Object
    return [ordered]@{ containers = $containers; images = $images; networks = $networks; volumes = $volumes } | ConvertTo-Json -Depth 4 -Compress
}

function Assert-PortAvailable([int]$Port) {
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $Port)
    try { $listener.Start() } catch { throw 'A P15C loopback port is unavailable.' } finally { $listener.Stop() }
}

function Set-ComposeEnvironment([System.Collections.IDictionary]$Context) {
    foreach ($entry in $Context.GetEnumerator()) { [Environment]::SetEnvironmentVariable($entry.Key, [string]$entry.Value, 'Process') }
}

function New-ComposeContext([string]$Project, [string]$Nonce, [string]$SecretDirectory, [System.Collections.IDictionary]$Sources, [System.Collections.IDictionary]$Images, $Contracts) {
    return @{
        P15C_PROJECT_NAME=$Project; P15C_OWNERSHIP_NONCE=$Nonce; P15C_DEVOPS_SHA=$Sources.DevOps.Sha; P15C_DEVOPS_TREE=$Sources.DevOps.Tree
        P15C_XNODE_PATH=$Sources.XNode.Path; P15C_XNODE_SHA=$Sources.XNode.Sha; P15C_XNODE_TREE=$Sources.XNode.Tree
        P15C_E2E_PATH=$Sources.E2E.Path; P15C_E2E_SHA=$Sources.E2E.Sha; P15C_E2E_TREE=$Sources.E2E.Tree
        P15C_REGISTRY_PATH=$Sources.Registry.Path; P15C_REGISTRY_SHA=$Sources.Registry.Sha; P15C_REGISTRY_TREE=$Sources.Registry.Tree
        P15C_STAKING_PATH=$Sources.Staking.Path; P15C_STAKING_SHA=$Sources.Staking.Sha; P15C_STAKING_TREE=$Sources.Staking.Tree
        P15C_CONTRACTS_PATH=$Sources.Contracts.Path; P15C_CONTRACTS_SHA=$Sources.Contracts.Sha; P15C_CONTRACTS_TREE=$Sources.Contracts.Tree
        P15C_NODE_IMAGE=$ExpectedNodeImage; P15C_DOTNET_SDK_IMAGE=$ExpectedSdkImage; P15C_DOTNET_RUNTIME_IMAGE=$ExpectedRuntimeImage
        P15C_XNODE_IMAGE_NAME=$Images.XNode; P15C_CONTRACTS_IMAGE_NAME=$Images.Contracts; P15C_REGISTRY_IMAGE_NAME=$Images.Registry; P15C_STAKING_IMAGE_NAME=$Images.Staking
        P15C_STORAGE_IMAGE_NAME=$Images.Storage; P15C_FILE_IMAGE_NAME=$Images.File; P15C_PUSH_IMAGE_NAME=$Images.Push; P15C_CALLS_IMAGE_NAME=$Images.Calls; P15C_TEST_IMAGE_NAME=$Images.Test
        P15C_SECRET_DIR=$SecretDirectory; P15C_CONTRACTS_PORT=$Ports.Contracts; P15C_XNODE1_PORT=$Ports.XNode1; P15C_XNODE2_PORT=$Ports.XNode2; P15C_XNODE3_PORT=$Ports.XNode3; P15C_REGISTRY_PORT=$Ports.Registry; P15C_STAKING_PORT=$Ports.Staking
        P15C_TOKEN_ADDRESS=if($null -eq $Contracts){''}else{$Contracts.contracts.token}; P15C_REWARDS_ADDRESS=if($null -eq $Contracts){''}else{$Contracts.contracts.serviceNodeRewards}; P15C_FACTORY_ADDRESS=if($null -eq $Contracts){''}else{$Contracts.contracts.serviceNodeContributionFactory}; P15C_POOL_ADDRESS=if($null -eq $Contracts){''}else{$Contracts.contracts.rewardRatePool}
    }
}

function Invoke-P15CBuild([string]$Project, [string]$LogPath) {
    Invoke-DockerQuiet @('compose','-p',$Project,'-f',$ComposePath,'build','--no-cache') $LogPath
}

function Invoke-P15CUp([string]$Project, [string[]]$Services, [string]$LogPath) {
    Invoke-DockerQuiet (@('compose','-p',$Project,'-f',$ComposePath,'up','-d','--no-build') + $Services) $LogPath
}

function Wait-Http([string]$Url, [int]$Seconds = 120) {
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($Seconds)
    do {
        try { $response = Invoke-WebRequest -UseBasicParsing -Uri $Url -TimeoutSec 3; if ($response.StatusCode -ge 200 -and $response.StatusCode -lt 300) { return } } catch {}
        Start-Sleep -Milliseconds 500
    } while ([DateTimeOffset]::UtcNow -lt $deadline)
    throw 'P15C service readiness deadline expired.'
}

function Wait-RpcChain([int]$Seconds = 120) {
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($Seconds)
    $body = @{jsonrpc='2.0';id=1;method='eth_chainId';params=@()} | ConvertTo-Json -Compress
    do {
        try { $response = Invoke-RestMethod -Uri "http://127.0.0.1:$($Ports.Contracts)" -Method Post -ContentType 'application/json' -Body $body -TimeoutSec 3; if ($response.result -eq '0x7a69') { return } } catch {}
        Start-Sleep -Milliseconds 500
    } while ([DateTimeOffset]::UtcNow -lt $deadline)
    throw 'P15C local chain readiness deadline expired.'
}

function Assert-Runtime([string]$Project) {
    Wait-RpcChain
    Wait-Http "http://127.0.0.1:$($Ports.Registry)/health/live"
    Wait-Http "http://127.0.0.1:$($Ports.Staking)/health/live"
    foreach ($port in @($Ports.XNode1,$Ports.XNode2,$Ports.XNode3)) {
        Wait-Http "http://127.0.0.1:$port/health/ready"
        $status = Invoke-RestMethod -Uri "http://127.0.0.1:$port/status" -TimeoutSec 3
        if ($status.xray.enabled -ne $false) { throw 'P15C XNode VLESS-disabled runtime gate failed.' }
    }
    $longRunning = @('contracts-devnet','xnode-1','xnode-2','xnode-3','registry','staking-backend','storage','file','push','calls')
    $running = @(Invoke-DockerCapture @('compose','-p',$Project,'-f',$ComposePath,'ps','--services','--status','running'))
    foreach ($service in $longRunning) {
        if ($running -notcontains $service) { throw 'P15C long-running topology is incomplete.' }
        $containerId = (Invoke-DockerCapture @('compose','-p',$Project,'-f',$ComposePath,'ps','-q',$service) -join '').Trim()
        if ($containerId -notmatch '^[0-9a-f]{12,64}$') { throw 'P15C runtime container identity is invalid.' }
        $state = (Invoke-DockerCapture @('container','inspect',$containerId,'--format','{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{end}}') -join '').Trim()
        if ($state -ne 'running|healthy') { throw "P15C runtime health gate failed for $service." }
    }
}

function Get-ImageReceipt([System.Collections.IDictionary]$Images, [System.Collections.IDictionary]$Sources, [string]$Nonce) {
    $bindings = @(
        @{ Role='xnode'; Tag=$Images.XNode; SourceName='XNode'; SourceLabel='xnode'; Source=$Sources.XNode }, @{ Role='contracts-devnet'; Tag=$Images.Contracts; SourceName='Contracts'; SourceLabel='xpoint-staking-contracts'; Source=$Sources.Contracts },
        @{ Role='registry'; Tag=$Images.Registry; SourceName='Registry'; SourceLabel='deep-registry-api'; Source=$Sources.Registry }, @{ Role='staking-backend'; Tag=$Images.Staking; SourceName='Staking'; SourceLabel='xpoint-staking-backend'; Source=$Sources.Staking },
        @{ Role='storage'; Tag=$Images.Storage; SourceName='DevOps'; SourceLabel='deep-devops'; Source=$Sources.DevOps }, @{ Role='file'; Tag=$Images.File; SourceName='DevOps'; SourceLabel='deep-devops'; Source=$Sources.DevOps },
        @{ Role='push'; Tag=$Images.Push; SourceName='DevOps'; SourceLabel='deep-devops'; Source=$Sources.DevOps }, @{ Role='calls'; Tag=$Images.Calls; SourceName='DevOps'; SourceLabel='deep-devops'; Source=$Sources.DevOps }, @{ Role='test-client'; Tag=$Images.Test; SourceName='E2E'; SourceLabel='deep-tests-e2e'; Source=$Sources.E2E }
    )
    $result = foreach ($binding in $bindings) {
        $raw = (Invoke-DockerCapture @('image','inspect',$binding.Tag,'--format','{{json .}}')) -join ''
        $image = $raw | ConvertFrom-Json
        $labels = $image.Config.Labels
        if ($image.Os -ne 'linux' -or $image.Architecture -ne 'arm64' -or $labels.'org.opencontainers.image.revision' -ne $binding.Source.Sha -or $labels.'org.opencontainers.image.source-tree' -ne $binding.Source.Tree -or $labels.'org.opencontainers.image.source' -ne $binding.SourceLabel -or $labels.'com.xpoint.p15c.role' -ne $binding.Role -or $labels.'com.xpoint.evidence-class' -ne 'headless-harness' -or $labels.'com.xpoint.product-runtime' -ne 'false' -or $labels.'com.xpoint.p15c.ownership-nonce' -ne $Nonce) { throw 'P15C built image label gate failed.' }
        [ordered]@{ role=$binding.Role; source=$binding.SourceName; sha=$binding.Source.Sha; tree=$binding.Source.Tree; id=$image.Id }
    }
    return @($result)
}

function Invoke-ExactDown([string]$Project, [string]$LogPath) {
    # exact cleanup: down --volumes --remove-orphans
    Invoke-DockerQuiet @('compose','-p',$Project,'-f',$ComposePath,'down','--volumes','--remove-orphans') $LogPath
}

function Remove-OwnedImages([object[]]$Images, [string]$LogPath) {
    $ids = @($Images | ForEach-Object { $_.id } | Sort-Object -Unique)
    foreach ($id in $ids) {
        if ($id -notmatch '^sha256:[0-9a-f]{64}$') { throw 'P15C owned image id is invalid.' }
    }
    $failures = [System.Collections.Generic.List[Exception]]::new()
    foreach ($id in $ids) {
        & docker image rm $id *>> $LogPath
        if ($LASTEXITCODE -ne 0) { $failures.Add([InvalidOperationException]::new('P15C exact owned image cleanup failed.')) }
    }
    if ($failures.Count) { throw [System.AggregateException]::new('One or more exact owned image removals failed.', $failures.ToArray()) }
}

function Assert-ZeroOwned([string]$Project, [string]$Nonce) {
    $counts = @(
        @(Invoke-DockerCapture @('container','ls','-aq','--filter',"label=com.docker.compose.project=$Project")).Count,
        @(Invoke-DockerCapture @('network','ls','-q','--filter',"label=com.xpoint.p15c.ownership-nonce=$Nonce")).Count,
        @(Invoke-DockerCapture @('volume','ls','-q','--filter',"label=com.xpoint.p15c.ownership-nonce=$Nonce")).Count,
        @(Invoke-DockerCapture @('image','ls','-q','--filter',"label=com.xpoint.p15c.ownership-nonce=$Nonce")).Count
    )
    if (($counts | Measure-Object -Sum).Sum -ne 0) { throw 'P15C owned Docker resources remain after cleanup.' }
}

function Remove-OwnedRunDirectory([string]$Directory) {
    $base = [System.IO.Path]::GetFullPath((Join-Path $env:LOCALAPPDATA 'Deep\P15C')).TrimEnd('\') + '\'
    $full = [System.IO.Path]::GetFullPath($Directory)
    $marker = Join-Path $full '.p15c-run-owner'
    if (-not $full.StartsWith($base, [StringComparison]::OrdinalIgnoreCase) -or -not (Test-Path -LiteralPath $marker -PathType Leaf) -or [System.IO.File]::ReadAllText($marker) -ne 'deep-p15c-run.v1') { throw 'P15C run directory ownership validation failed.' }
    [System.IO.Directory]::Delete($full, $true)
}

function Assert-RunDirectoryOutsideRepositories([string]$Directory, [System.Collections.IDictionary]$Sources) {
    $full = [System.IO.Path]::GetFullPath($Directory).TrimEnd('\') + '\'
    foreach ($source in $Sources.Values) {
        $repo = [System.IO.Path]::GetFullPath($source.Path).TrimEnd('\') + '\'
        if ($full.StartsWith($repo, [StringComparison]::OrdinalIgnoreCase) -or $repo.StartsWith($full, [StringComparison]::OrdinalIgnoreCase)) { throw 'P15C run directory must remain outside every source repository.' }
    }
}

function Assert-NoReparseOutputPath([string]$Path) {
    $full = [System.IO.Path]::GetFullPath($Path)
    if (Test-Path -LiteralPath $full) {
        $outputItem = Get-Item -LiteralPath $full -Force
        if (($outputItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'P15C output path must not be a reparse point.' }
    }
    $current = [System.IO.Path]::GetDirectoryName($full)
    if ([string]::IsNullOrWhiteSpace($current) -or -not (Test-Path -LiteralPath $current -PathType Container)) { throw 'P15C output parent directory must already exist.' }
    while (-not [string]::IsNullOrWhiteSpace($current)) {
        $item = Get-Item -LiteralPath $current -Force
        if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'P15C output path must not traverse a reparse point.' }
        $parent = [System.IO.Directory]::GetParent($current)
        if ($null -eq $parent) { break }
        $current = $parent.FullName
    }
}

function Assert-OutputOutsideRepositories([string]$Path, [System.Collections.IDictionary]$Sources, [string]$RunDirectory) {
    if (-not [System.IO.Path]::IsPathRooted($Path) -or $Path -match '(?:^|[\\/])\.\.(?:[\\/]|$)') { throw 'P15C output path must be canonical and absolute.' }
    $full = [System.IO.Path]::GetFullPath($Path)
    if (-not $Path.Equals($full, [StringComparison]::OrdinalIgnoreCase)) { throw 'P15C output path must already be in canonical absolute form.' }
    Assert-NoReparseOutputPath $full
    foreach ($source in $Sources.Values) {
        $repo = [System.IO.Path]::GetFullPath($source.Path).TrimEnd('\') + '\'
        if ($full.StartsWith($repo, [StringComparison]::OrdinalIgnoreCase)) { throw 'P15C evidence and receipt outputs must remain outside every source repository.' }
    }
    $run = [System.IO.Path]::GetFullPath($RunDirectory).TrimEnd('\') + '\'
    if ($full.StartsWith($run, [StringComparison]::OrdinalIgnoreCase)) { throw 'P15C evidence and receipt outputs must remain outside the owned run tree.' }
}

function Assert-DistinctOutputPaths([string]$Left, [string]$Right) {
    if ([System.IO.Path]::GetFullPath($Left).Equals([System.IO.Path]::GetFullPath($Right), [StringComparison]::OrdinalIgnoreCase)) { throw 'P15C evidence and receipt paths must be distinct.' }
}

function Assert-ProtectedAcl([string]$Path) {
    $allowedSids = @([System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value, 'S-1-5-18') | Sort-Object
    $acl = Get-Acl -LiteralPath $Path
    $sids = @($acl.Access | ForEach-Object { $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } | Sort-Object -Unique)
    if (-not $acl.AreAccessRulesProtected -or ($sids -join "`n") -ne ($allowedSids -join "`n")) { throw 'P15C retained secret ACL is invalid.' }
}

function Assert-SecretDirectoryOwnership([string]$Directory) {
    $marker = Join-Path $Directory '.p15c-secret-owner'
    if (-not (Test-Path -LiteralPath $marker -PathType Leaf) -or [System.IO.File]::ReadAllText($marker) -ne 'deep-p15c-ephemeral-secrets.v1') { throw 'P15C retained secret marker is invalid.' }
    $expectedNames = @('.p15c-secret-owner','node-1.config.json','node-1.seed','node-2.config.json','node-2.seed','node-3.config.json','node-3.seed') | Sort-Object
    $actualNames = @(Get-ChildItem -LiteralPath $Directory -Force | ForEach-Object Name | Sort-Object)
    if (($actualNames -join "`n") -ne ($expectedNames -join "`n")) { throw 'P15C retained secret directory contains missing or extra entries.' }
    Assert-ProtectedAcl $Directory
    foreach ($path in @($marker) + @(1..3 | ForEach-Object { Join-Path $Directory "node-$_.seed" }) + @(1..3 | ForEach-Object { Join-Path $Directory "node-$_.config.json" })) {
        Assert-ProtectedAcl $path
    }
    $seeds = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $routerIds = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($index in 1..3) {
        $seed = ([System.IO.File]::ReadAllText((Join-Path $Directory "node-$index.seed"))).Trim()
        if ($seed -notmatch '^[0-9a-f]{64}$' -or -not $seeds.Add($seed)) { throw 'P15C retained seed file is malformed or duplicated.' }
        $config = Get-Content -LiteralPath (Join-Path $Directory "node-$index.config.json") -Raw | ConvertFrom-Json
        if ((@($config.psobject.Properties.Name) -join ',') -ne 'Node' -or (@($config.Node.psobject.Properties.Name) -join ',') -ne 'RouterId' -or $config.Node.RouterId -notmatch '^[0-9a-f]{64}$' -or -not $routerIds.Add($config.Node.RouterId)) { throw 'P15C retained public node configuration is malformed or duplicated.' }
    }
}

function Assert-ForeignSnapshot([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw 'P15C retained foreign inventory snapshot is missing.' }
    $raw = [System.IO.File]::ReadAllText($Path)
    $value = $raw | ConvertFrom-Json
    if ((@($value.psobject.Properties.Name | Sort-Object) -join ',') -ne 'containers,images,networks,volumes') { throw 'P15C retained foreign inventory snapshot is malformed.' }
    foreach ($name in @('containers','images','networks','volumes')) {
        if ($null -eq $value.$name) { throw 'P15C retained foreign inventory snapshot is incomplete.' }
    }
    return $raw
}

function New-Evidence([string]$Path) {
    $input = "$Path.input"
    $value = [ordered]@{ schema='deep-p15c-headless-evidence.v1'; evidenceClass='headless-harness'; productRuntime=$false; result='pass'; gates=[ordered]@{ source='pass'; images='pass'; contracts='pass'; runtime='pass'; e2e='pass'; cleanup='pass' }; counts=[ordered]@{ services=11; xnodes=3; localContracts=4 } }
    Write-NewUtf8File $input ($value | ConvertTo-Json -Depth 8)
    try { Invoke-NodeQuiet @((Join-Path $PSScriptRoot 'p15c-evidence-sanitizer.mjs'),'write',$input,$Path) }
    finally { if (Test-Path -LiteralPath $input) { [System.IO.File]::Delete($input) } }
}

function Assert-ReceiptSyntax($Receipt, [string]$ComposeSha, [System.Collections.IDictionary]$Sources) {
    $topKeys = @($Receipt.psobject.Properties.Name | Sort-Object)
    if (($topKeys -join ',') -ne 'composeSha256,images,nonce,project,schema,sources' -or $Receipt.schema -ne 'deep-p15c-ownership.v1' -or $Receipt.project -notmatch '^p15c-[0-9a-f]{16}$' -or $Receipt.nonce -notmatch '^[0-9a-f]{32}$' -or $Receipt.composeSha256 -ne $ComposeSha -or @($Receipt.images).Count -ne 9) { throw 'P15C ownership receipt is invalid.' }
    $sourceKeys = @($Receipt.sources.psobject.Properties.Name | Sort-Object)
    if (($sourceKeys -join ',') -ne 'Contracts,DevOps,E2E,Registry,Staking,XNode') { throw 'P15C ownership receipt source set is invalid.' }
    foreach ($name in $Sources.Keys) {
        $record = $Receipt.sources.$name
        if ((@($record.psobject.Properties.Name | Sort-Object) -join ',') -ne 'sha,tree' -or $record.sha -ne $Sources[$name].Sha -or $record.tree -ne $Sources[$name].Tree) { throw 'P15C ownership receipt source binding is invalid.' }
    }
    $expectedRoleSources = [ordered]@{calls='DevOps';'contracts-devnet'='Contracts';file='DevOps';push='DevOps';registry='Registry';'staking-backend'='Staking';storage='DevOps';'test-client'='E2E';xnode='XNode'}
    $observedRoles = @($Receipt.images | ForEach-Object role | Sort-Object)
    if (($observedRoles -join ',') -ne (($expectedRoleSources.Keys | Sort-Object) -join ',') -or @($Receipt.images | ForEach-Object id | Sort-Object -Unique).Count -ne 9) { throw 'P15C ownership receipt image role/id set is invalid.' }
    foreach ($image in $Receipt.images) {
        if ((@($image.psobject.Properties.Name | Sort-Object) -join ',') -ne 'id,role,sha,source,tree' -or $image.id -notmatch '^sha256:[0-9a-f]{64}$' -or $expectedRoleSources[$image.role] -ne $image.source -or $Receipt.sources.($image.source).sha -ne $image.sha -or $Receipt.sources.($image.source).tree -ne $image.tree) { throw 'P15C ownership receipt image binding is invalid.' }
    }
}

function Get-FailureOwnedImages($Images, [string]$Nonce) {
    $ownedIds = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    if ($null -ne $Images) {
        foreach ($tag in $Images.Values) {
            $id = (Invoke-DockerCapture @('image','ls','-q',$tag) -join '').Trim()
            if ($id -match '^[0-9a-f]{12,64}$') {
                $fullId = (Invoke-DockerCapture @('image','inspect',$tag,'--format','{{.Id}}') -join '').Trim()
                if ($fullId -match '^sha256:[0-9a-f]{64}$') { [void]$ownedIds.Add($fullId) }
            }
        }
    }
    foreach ($id in @(Invoke-DockerCapture @('image','ls','-q','--filter',"label=com.xpoint.p15c.ownership-nonce=$Nonce"))) {
        if ($id -match '^[0-9a-f]{12,64}$') {
            $fullId = (Invoke-DockerCapture @('image','inspect',$id,'--format','{{.Id}}') -join '').Trim()
            if ($fullId -match '^sha256:[0-9a-f]{64}$') { [void]$ownedIds.Add($fullId) }
        }
    }
    return @($ownedIds | ForEach-Object { [pscustomobject]@{id=$_} })
}

function Invoke-FailedRunCleanup([string]$Project, [string]$Nonce, [string]$RunDirectory, [string]$SecretDirectory, $Images, [string]$ForeignBefore, [bool]$MutationStarted, [bool]$ResourcesClean) {
    $failures = [System.Collections.Generic.List[Exception]]::new()
    if ($MutationStarted -and -not $ResourcesClean) {
        try { Invoke-ExactDown $Project (Join-Path $RunDirectory 'failure-down.log') } catch { $failures.Add($_.Exception) }
        try { $owned = @(Get-FailureOwnedImages $Images $Nonce); if ($owned.Count) { Remove-OwnedImages $owned (Join-Path $RunDirectory 'failure-images.log') } } catch { $failures.Add($_.Exception) }
        try { Assert-ZeroOwned $Project $Nonce } catch { $failures.Add($_.Exception) }
        if ($null -ne $ForeignBefore) { try { if ((Get-ForeignInventory $Project) -ne $ForeignBefore) { throw 'P15C foreign Docker inventory changed during failed cleanup.' } } catch { $failures.Add($_.Exception) } }
    }
    if ($failures.Count -eq 0) {
        if (Test-Path -LiteralPath $SecretDirectory) { try { & (Join-Path $PSScriptRoot 'p15c-ephemeral-secrets.ps1') -Action Remove -RunDirectory $SecretDirectory } catch { $failures.Add($_.Exception) } }
        foreach ($path in @($ReceiptPath,$EvidencePath)) {
            if ($failures.Count -eq 0 -and -not [string]::IsNullOrWhiteSpace($path) -and (Test-Path -LiteralPath $path -PathType Leaf)) { try { [System.IO.File]::Delete([System.IO.Path]::GetFullPath($path)) } catch { $failures.Add($_.Exception) } }
        }
        if ($failures.Count -eq 0 -and (Test-Path -LiteralPath $RunDirectory)) { try { Remove-OwnedRunDirectory $RunDirectory } catch { $failures.Add($_.Exception) } }
    }
    return $failures
}

function Invoke-OwnedResourceCleanup([string]$Project, [string]$Nonce, [object[]]$OwnedImages, [string]$ForeignBefore, [string]$RunDirectory) {
    $failures = [System.Collections.Generic.List[Exception]]::new()
    try { Invoke-ExactDown $Project (Join-Path $RunDirectory 'down.log') } catch { $failures.Add($_.Exception) }
    try { Remove-OwnedImages $OwnedImages (Join-Path $RunDirectory 'image-cleanup.log') } catch { $failures.Add($_.Exception) }
    try { Assert-ZeroOwned $Project $Nonce } catch { $failures.Add($_.Exception) }
    try { if ((Get-ForeignInventory $Project) -ne $ForeignBefore) { throw 'P15C foreign Docker inventory changed.' } } catch { $failures.Add($_.Exception) }
    if ($failures.Count) { throw [System.AggregateException]::new('P15C owned resource cleanup failed; retained state and logs were preserved.', $failures.ToArray()) }
}

function Complete-RetainedStateCleanup($Context, [string]$FinalEvidencePath) {
    $stagePath = "$FinalEvidencePath.p15c-stage-$($Context.Receipt.nonce)"
    Assert-OutputOutsideRepositories $stagePath $Context.Sources $Context.RunDirectory
    if (Test-Path -LiteralPath $stagePath) { throw 'P15C staged evidence path already exists.' }
    $receiptBytes = [System.IO.File]::ReadAllBytes([System.IO.Path]::GetFullPath($ReceiptPath))
    New-Evidence $stagePath
    try {
        & (Join-Path $PSScriptRoot 'p15c-ephemeral-secrets.ps1') -Action Remove -RunDirectory $Context.SecretDirectory
        [System.IO.File]::Delete([System.IO.Path]::GetFullPath($ReceiptPath))
        Remove-OwnedRunDirectory $Context.RunDirectory
    }
    catch {
        $stateError = $_.Exception
        $rollbackErrors = [System.Collections.Generic.List[Exception]]::new()
        try { if (Test-Path -LiteralPath $stagePath -PathType Leaf) { [System.IO.File]::Delete($stagePath) } } catch { $rollbackErrors.Add($_.Exception) }
        try { if (-not (Test-Path -LiteralPath $ReceiptPath -PathType Leaf)) { [System.IO.File]::WriteAllBytes([System.IO.Path]::GetFullPath($ReceiptPath), $receiptBytes) } } catch { $rollbackErrors.Add($_.Exception) }
        if ($rollbackErrors.Count) {
            $all = [System.Collections.Generic.List[Exception]]::new(); $all.Add($stateError); foreach ($error in $rollbackErrors) { $all.Add($error) }
            throw [System.AggregateException]::new('P15C retained state cleanup and rollback failed.', $all.ToArray())
        }
        throw $stateError
    }
    try { [System.IO.File]::Move($stagePath, [System.IO.Path]::GetFullPath($FinalEvidencePath)) }
    catch {
        try { if (Test-Path -LiteralPath $stagePath -PathType Leaf) { [System.IO.File]::Delete($stagePath) } } catch {}
        throw
    }
}

function Invoke-Run {
    Assert-RunInputs
    $project = 'p15c-' + (New-Hex 8)
    $nonce = New-Hex 16
    $runDirectory = Join-Path (Join-Path $env:LOCALAPPDATA 'Deep\P15C') "$project-$nonce"
    $secretDirectory = Join-Path $runDirectory 'secrets'
    if (Test-Path -LiteralPath $runDirectory) { throw 'P15C owned run directory collision exists.' }
    [void][System.IO.Directory]::CreateDirectory($runDirectory)
    [System.IO.File]::WriteAllText((Join-Path $runDirectory '.p15c-run-owner'),'deep-p15c-run.v1',[System.Text.UTF8Encoding]::new($false))
    $foreignBefore = $null
    $collisionPassed = $false
    $retained = $false
    $mutationStarted = $false
    $resourcesClean = $false
    $imagesReceipt = @()
    $images = $null
    $operations = [System.Collections.Generic.List[string]]::new()
    try {
        $devopsSha = Get-GitValue $Root @('rev-parse','HEAD')
        $devopsTree = Get-GitValue $Root @('rev-parse','HEAD^{tree}')
        $sources = [ordered]@{
            DevOps=[ordered]@{Sha=$devopsSha;Tree=$devopsTree;Path=$Root}; XNode=[ordered]@{Sha=$Expected.XNode.Sha;Tree=$Expected.XNode.Tree;Path=[System.IO.Path]::GetFullPath($XNodePath)}
            E2E=[ordered]@{Sha=$Expected.E2E.Sha;Tree=$Expected.E2E.Tree;Path=[System.IO.Path]::GetFullPath($E2EPath)}; Registry=[ordered]@{Sha=$Expected.Registry.Sha;Tree=$Expected.Registry.Tree;Path=[System.IO.Path]::GetFullPath($RegistryPath)}
            Staking=[ordered]@{Sha=$Expected.Staking.Sha;Tree=$Expected.Staking.Tree;Path=[System.IO.Path]::GetFullPath($StakingPath)}; Contracts=[ordered]@{Sha=$Expected.Contracts.Sha;Tree=$Expected.Contracts.Tree;Path=[System.IO.Path]::GetFullPath($ContractsPath)}
        }
        foreach ($name in @('XNode','E2E','Registry','Staking','Contracts')) { if ($sources[$name].Path -ne [System.IO.Path]::GetFullPath($Expected[$name].Path)) { throw 'P15C exact source path differs from invocation contract.' } }
        Assert-RunDirectoryOutsideRepositories $runDirectory $sources
        Assert-OutputOutsideRepositories $EvidencePath $sources $runDirectory
        Assert-OutputOutsideRepositories $ReceiptPath $sources $runDirectory
        Assert-DistinctOutputPaths $EvidencePath $ReceiptPath
        $sourceManifest = Join-Path $runDirectory 'sources.json'; New-SourceManifest $sourceManifest $sources; Assert-SourcePreflight $sourceManifest; $operations.Add('source-preflight')

        Assert-EngineArchitecture; Assert-ImageLock $DotnetSdkImage 'sdk'; Assert-ImageLock $DotnetRuntimeImage 'runtime'; Assert-ImageLock $NodeImage 'node'; $operations.Add('image-preflight')
        Assert-NoCollision $project $nonce; $collisionPassed = $true; $operations.Add('collision-check')
        $foreignBefore = Get-ForeignInventory $project; [System.IO.File]::WriteAllText((Join-Path $runDirectory 'foreign-before.json'),$foreignBefore,[System.Text.UTF8Encoding]::new($false)); $operations.Add('foreign-snapshot')

        & (Join-Path $PSScriptRoot 'p15c-ephemeral-secrets.ps1') -Action Generate -RunDirectory $secretDirectory; $operations.Add('generate-secrets')
        foreach ($port in $Ports.Values) { Assert-PortAvailable $port }
        $images = [ordered]@{ XNode="$project-xnode:$($Expected.XNode.Sha.Substring(0,12))"; Contracts="$project-contracts:$($Expected.Contracts.Sha.Substring(0,12))"; Registry="$project-registry:$($Expected.Registry.Sha.Substring(0,12))"; Staking="$project-staking:$($Expected.Staking.Sha.Substring(0,12))"; Storage="$project-storage:$($devopsSha.Substring(0,12))"; File="$project-file:$($devopsSha.Substring(0,12))"; Push="$project-push:$($devopsSha.Substring(0,12))"; Calls="$project-calls:$($devopsSha.Substring(0,12))"; Test="$project-test:$($Expected.E2E.Sha.Substring(0,12))" }
        Set-ComposeEnvironment (New-ComposeContext $project $nonce $secretDirectory $sources $images $null)
        $composeModel = Join-Path $runDirectory 'compose.json'; & docker compose -p $project -f $ComposePath config --format json *> $composeModel; if ($LASTEXITCODE -ne 0) { throw 'P15C Compose configuration failed.' }; Invoke-NodeQuiet @((Join-Path $PSScriptRoot 'p15c-headless-contracts.mjs'),'validate-compose',$composeModel,(@{sha=$devopsSha;tree=$devopsTree}|ConvertTo-Json -Compress)); $operations.Add('compose-config')

        Assert-P15COperationPlan $operations.ToArray() -Prefix
        $mutationStarted = $true
        Invoke-P15CBuild $project (Join-Path $runDirectory 'build.log'); $operations.Add('build')
        Invoke-P15CUp $project @('contracts-devnet') (Join-Path $runDirectory 'up-contracts.log'); Wait-RpcChain; $operations.Add('up-contracts')
        Invoke-DockerQuiet @('compose','-p',$project,'-f',$ComposePath,'exec','-T','contracts-devnet','pnpm','exec','hardhat','run','scripts/deploy-local-devnet.js','--network','localhost') (Join-Path $runDirectory 'deploy.log')
        Invoke-DockerQuiet @('compose','-p',$project,'-f',$ComposePath,'exec','-T','contracts-devnet','pnpm','exec','hardhat','run','scripts/local-devnet-smoke.js','--network','localhost') (Join-Path $runDirectory 'contract-smoke.log')
        $contractContainer = (Invoke-DockerCapture @('compose','-p',$project,'-f',$ComposePath,'ps','-q','contracts-devnet') -join '').Trim(); if ($contractContainer -notmatch '^[0-9a-f]{12,64}$') { throw 'P15C owned contract container id is invalid.' }
        $rawManifest = Join-Path $runDirectory 'localhost.raw.json'; Invoke-DockerQuiet @('cp',"$contractContainer`:/workspace/deployments/localhost.latest.json",$rawManifest) (Join-Path $runDirectory 'copy-manifest.log')
        $localManifest = Join-Path $runDirectory 'localhost.validated.json'; Invoke-NodeQuiet @((Join-Path $PSScriptRoot 'p15c-local-contract-manifest.mjs'),'normalize',$rawManifest,$localManifest,"http://127.0.0.1:$($Ports.Contracts)"); [System.IO.File]::Delete($rawManifest)
        $contracts = Get-Content -LiteralPath $localManifest -Raw | ConvertFrom-Json; $operations.Add('deploy-contracts')

        Set-ComposeEnvironment (New-ComposeContext $project $nonce $secretDirectory $sources $images $contracts)
        Invoke-P15CUp $project @('contracts-devnet','xnode-1','xnode-2','xnode-3','registry','staking-backend','storage','file','push','calls') (Join-Path $runDirectory 'up-runtime.log'); $operations.Add('up-runtime')
        Assert-Runtime $project; $operations.Add('probe')
        Invoke-DockerQuiet @('compose','-p',$project,'-f',$ComposePath,'run','--rm','--no-deps','test-client') (Join-Path $runDirectory 'e2e.log'); $operations.Add('e2e')
        $imagesReceipt = Get-ImageReceipt $images $sources $nonce; $operations.Add('labels')

        if ($KeepRunning) {
            $receiptSources = [ordered]@{}; foreach ($name in $sources.Keys) { $receiptSources[$name] = [ordered]@{sha=$sources[$name].Sha;tree=$sources[$name].Tree} }
            $receipt = [ordered]@{schema='deep-p15c-ownership.v1';project=$project;nonce=$nonce;composeSha256=(Get-FileSha256 $ComposePath);sources=$receiptSources;images=$imagesReceipt}
            Write-NewUtf8File $ReceiptPath ($receipt | ConvertTo-Json -Depth 10)
            $operations.Add('receipt-retained'); Assert-CompletedPlan $operations.ToArray() -Retained; $retained = $true
            return
        }

        Invoke-OwnedResourceCleanup $project $nonce $imagesReceipt $foreignBefore $runDirectory
        $resourcesClean = $true
        & (Join-Path $PSScriptRoot 'p15c-ephemeral-secrets.ps1') -Action Remove -RunDirectory $secretDirectory
        Remove-OwnedRunDirectory $runDirectory
        $operations.Add('cleanup')
        New-Evidence $EvidencePath; $operations.Add('evidence'); Assert-CompletedPlan $operations.ToArray()
    }
    catch {
        $operationError = $_.Exception
        if (-not $retained) {
            $cleanupErrors = @(Invoke-FailedRunCleanup $project $nonce $runDirectory $secretDirectory $images $foreignBefore $mutationStarted $resourcesClean)
            if ($cleanupErrors.Count) {
                $all = [System.Collections.Generic.List[Exception]]::new(); $all.Add($operationError); foreach ($error in $cleanupErrors) { $all.Add($error) }
                throw [System.AggregateException]::new('P15C operation and cleanup failed; owned state preserved.', $all.ToArray())
            }
        }
        throw $operationError
    }
}

function Get-RetainedContext([switch]$ForDown) {
    if ([string]::IsNullOrWhiteSpace($ReceiptPath) -or -not (Test-Path -LiteralPath $ReceiptPath -PathType Leaf)) { throw 'P15C exact ownership receipt is required.' }
    $receipt = Get-Content -LiteralPath $ReceiptPath -Raw | ConvertFrom-Json
    $devopsSha = Get-GitValue $Root @('rev-parse','HEAD'); $devopsTree = Get-GitValue $Root @('rev-parse','HEAD^{tree}')
    $sources = [ordered]@{ DevOps=[ordered]@{Sha=$devopsSha;Tree=$devopsTree;Path=$Root}; XNode=$Expected.XNode; E2E=$Expected.E2E; Registry=$Expected.Registry; Staking=$Expected.Staking; Contracts=$Expected.Contracts }
    Assert-ReceiptSyntax $receipt (Get-FileSha256 $ComposePath) $sources
    $runDirectory = Join-Path (Join-Path $env:LOCALAPPDATA 'Deep\P15C') "$($receipt.project)-$($receipt.nonce)"
    $secretDirectory = Join-Path $runDirectory 'secrets'; $manifestPath = Join-Path $runDirectory 'localhost.validated.json'
    $runMarker = Join-Path $runDirectory '.p15c-run-owner'
    if (-not (Test-Path -LiteralPath $runMarker -PathType Leaf) -or [System.IO.File]::ReadAllText($runMarker) -ne 'deep-p15c-run.v1' -or -not (Test-Path -LiteralPath $manifestPath -PathType Leaf) -or -not (Test-Path -LiteralPath $secretDirectory -PathType Container)) { throw 'P15C retained ownership state is incomplete.' }
    Assert-RunDirectoryOutsideRepositories $runDirectory $sources
    Assert-OutputOutsideRepositories $ReceiptPath $sources $runDirectory
    if ($ForDown) {
        if ([string]::IsNullOrWhiteSpace($EvidencePath)) { throw 'P15C Down requires a final evidence path.' }
        Assert-OutputOutsideRepositories $EvidencePath $sources $runDirectory
        Assert-DistinctOutputPaths $EvidencePath $ReceiptPath
        if (Test-Path -LiteralPath $EvidencePath) { throw 'P15C evidence path already exists.' }
    }
    elseif (-not [string]::IsNullOrWhiteSpace($EvidencePath)) { throw 'P15C Verify does not accept an evidence output path.' }
    Assert-SecretDirectoryOwnership $secretDirectory
    Invoke-NodeQuiet @((Join-Path $PSScriptRoot 'p15c-local-contract-manifest.mjs'),'validate-shape',$manifestPath)
    $verifySources = Join-Path $runDirectory 'verify-sources.json'
    try { New-SourceManifest $verifySources $sources; Assert-SourcePreflight $verifySources }
    finally { if (Test-Path -LiteralPath $verifySources) { [System.IO.File]::Delete($verifySources) } }
    $contracts = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    $foreignBefore = Assert-ForeignSnapshot (Join-Path $runDirectory 'foreign-before.json')
    $project=$receipt.project; $images=[ordered]@{ XNode="$project-xnode:$($Expected.XNode.Sha.Substring(0,12))"; Contracts="$project-contracts:$($Expected.Contracts.Sha.Substring(0,12))"; Registry="$project-registry:$($Expected.Registry.Sha.Substring(0,12))"; Staking="$project-staking:$($Expected.Staking.Sha.Substring(0,12))"; Storage="$project-storage:$($devopsSha.Substring(0,12))"; File="$project-file:$($devopsSha.Substring(0,12))"; Push="$project-push:$($devopsSha.Substring(0,12))"; Calls="$project-calls:$($devopsSha.Substring(0,12))"; Test="$project-test:$($Expected.E2E.Sha.Substring(0,12))" }
    return [ordered]@{Receipt=$receipt;Sources=$sources;RunDirectory=$runDirectory;SecretDirectory=$secretDirectory;Contracts=$contracts;Images=$images;ForeignBefore=$foreignBefore}
}

function Invoke-VerifyOrDown([switch]$Remove) {
    $context = Get-RetainedContext -ForDown:$Remove # complete receipt/source/run validation occurs before the first Docker call
    Set-ComposeEnvironment (New-ComposeContext $context.Receipt.project $context.Receipt.nonce $context.SecretDirectory $context.Sources $context.Images $context.Contracts)
    $observed = Get-ImageReceipt $context.Images $context.Sources $context.Receipt.nonce
    foreach ($expectedImage in $context.Receipt.images) {
        $actual = @($observed | Where-Object { $_.role -eq $expectedImage.role })
        if ($actual.Count -ne 1 -or $actual[0].id -ne $expectedImage.id) { throw 'P15C retained image differs from ownership receipt.' }
    }
    if (-not $Remove) { Assert-Runtime $context.Receipt.project; return }
    Invoke-OwnedResourceCleanup $context.Receipt.project $context.Receipt.nonce @($context.Receipt.images) $context.ForeignBefore $context.RunDirectory
    Complete-RetainedStateCleanup $context $EvidencePath
}

try {
    switch ($Action) {
        'Run' { Invoke-Run }
        'Verify' { if ($KeepRunning) { throw 'KeepRunning is valid only for Run.' }; Invoke-VerifyOrDown }
        'Down' { if ($KeepRunning) { throw 'KeepRunning is valid only for Run.' }; Invoke-VerifyOrDown -Remove }
    }
}
finally { Clear-P15CEnvironment }
