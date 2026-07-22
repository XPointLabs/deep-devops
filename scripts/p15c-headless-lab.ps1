# P15C_OPERATION_PLAN: source-preflight,collision-check,foreign-snapshot,image-preflight,generate-secrets,source-export,compose-config,build,up-contracts,deploy-contracts,up-runtime,probe,e2e,labels,cleanup,evidence
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
    XNode = [ordered]@{ Sha='cd9d20a8ec8346d171d4cd070dde170aa5f471d7'; Tree='e27c1d7c2517bd9d1bcdfbacda8c68c57a2ced59'; Path='C:\W\deep-survival\wave09\xnode-p15c-source' }
    E2E = [ordered]@{ Sha='da24f530f187dbd81258905bc28feedce0eb23eb'; Tree='566ee86cd01ec5a32d3ad60d1c9eac9183328c1f'; Path='C:\Work\DeepSession\XPointLabs\deep-tests-e2e' }
    Registry = [ordered]@{ Sha='fb7ebac6404e7a53241af08bb2f80d8a81022be8'; Tree='be7a44e68933fa0773e81f6ad898feebd752a67a'; Path='C:\Work\DeepSession\XPointLabs\deep-registry-api' }
    Staking = [ordered]@{ Sha='c4638486d1f658f3cda2b5060eb3709e255d7288'; Tree='a0dafebbd380425e5b4c5e86bdb3138bf77fa3e0'; Path='C:\Work\DeepSession\XPointLabs\xpoint-staking-backend' }
    Contracts = [ordered]@{ Sha='d5063212b491b4c7bd649a3ab367491dfed9909f'; Tree='89f506e9c1c33cce0e1ad928b72602aa533b012c'; Path='C:\Work\DeepSession\XPointLabs\xpoint-staking-contracts' }
}
$ExpectedNodeImage = 'node@sha256:242549cd46785b480c832479a730f4f2a20865d61ea2e404fdb2a5c3d3b73ecf'
$ExpectedSdkImage = 'mcr.microsoft.com/dotnet/sdk@sha256:7e964ea8bc6c1e18ea9fbc76ed403da41c9b19aeee2aab6bf9c845f25e891380'
$ExpectedRuntimeImage = 'mcr.microsoft.com/dotnet/aspnet@sha256:e3736b0d423db99c6988e1ddf5ea725c14b12579bb120024e5ff7ff204a14080'
$Root = [System.IO.Path]::GetFullPath((Split-Path $PSScriptRoot -Parent))
$ComposePath = Join-Path $Root 'docker-compose.p15c-headless.yml'
$CommonPlan = @('source-preflight','collision-check','foreign-snapshot','image-preflight','generate-secrets','source-export','compose-config','build','up-contracts','deploy-contracts','up-runtime','probe','e2e','labels')
$NormalPlan = @($CommonPlan) + @('cleanup','evidence')
$RetainedPlan = @($CommonPlan) + @('receipt-retained')
$RuntimeServices = @('contracts-devnet','xnode-1','xnode-2','xnode-3','registry','staking-backend','storage','file','push','calls')
$RuntimeVolumes = @('xnode-1-state','xnode-2-state','xnode-3-state','registry-state','staking-state','storage-state','file-state','push-state','calls-state')
$ImageRoles = @('calls','contracts-devnet','file','push','registry','staking-backend','storage','test-client','xnode')
$Ports = [ordered]@{ Contracts=39545; XNode1=39801; XNode2=39802; XNode3=39803; Registry=39810; Staking=39811 }

function New-Hex([int]$Bytes) {
    $value = [byte[]]::new($Bytes)
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($value); return (([BitConverter]::ToString($value) -replace '-','').ToLowerInvariant()) }
    finally { $rng.Dispose(); [Array]::Clear($value,0,$value.Length) }
}

function Get-FileSha256([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Protect-P15CAuthorityFile([string]$Path, [switch]$Directory) {
    $currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $acl = if ($Directory) { New-Object System.Security.AccessControl.DirectorySecurity } else { New-Object System.Security.AccessControl.FileSecurity }
    $acl.SetAccessRuleProtection($true,$false)
    $inheritance = if ($Directory) { [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit' } else { [System.Security.AccessControl.InheritanceFlags]::None }
    foreach ($sidValue in @($currentSid,'S-1-5-18')) {
        $sid = New-Object System.Security.Principal.SecurityIdentifier($sidValue)
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($sid,[System.Security.AccessControl.FileSystemRights]::FullControl,$inheritance,[System.Security.AccessControl.PropagationFlags]::None,[System.Security.AccessControl.AccessControlType]::Allow)
        [void]$acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Assert-ProtectedAcl([string]$Path) {
    $allowed = @([System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value,'S-1-5-18') | Sort-Object
    $acl = Get-Acl -LiteralPath $Path
    $actual = @($acl.Access | ForEach-Object { $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } | Sort-Object -Unique)
    if (-not $acl.AreAccessRulesProtected -or ($actual -join "`n") -ne ($allowed -join "`n")) { throw 'P15C authority ACL is invalid.' }
}

function Write-NewUtf8File([string]$Path,[string]$Content) {
    $full = [System.IO.Path]::GetFullPath($Path)
    $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes($Content)
    $stream = [System.IO.FileStream]::new($full,[System.IO.FileMode]::CreateNew,[System.IO.FileAccess]::Write,[System.IO.FileShare]::None)
    try { $stream.Write($bytes,0,$bytes.Length); $stream.Flush($true) }
    finally { $stream.Dispose(); [Array]::Clear($bytes,0,$bytes.Length) }
    Protect-P15CAuthorityFile $full
    return [pscustomobject]@{ created=$true; path=$full; expectedSha256=(Get-FileSha256 $full) }
}

function Remove-ExclusivelyCreatedFile($Record) {
    if ($null -eq $Record -or $Record.created -ne $true -or $Record.expectedSha256 -notmatch '^[0-9a-f]{64}$') { throw 'P15C owned output record is invalid.' }
    $full = [System.IO.Path]::GetFullPath([string]$Record.path)
    if ($full -ne [string]$Record.path -or -not (Test-Path -LiteralPath $full -PathType Leaf)) { throw 'P15C owned output no longer names an exact file.' }
    $item = Get-Item -LiteralPath $full -Force
    if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or (Get-FileSha256 $full) -ne $Record.expectedSha256) { throw 'P15C owned output binding changed; refusing deletion.' }
    [System.IO.File]::Delete($full)
}

function Assert-P15COperationPlan([string[]]$Observed,[switch]$Prefix,[switch]$Retained) {
    $expected = if ($Retained) { $RetainedPlan } else { $NormalPlan }
    if ($Prefix) { $expected = @($expected | Select-Object -First $Observed.Count) }
    if ($Observed.Count -ne $expected.Count) { throw 'P15C lifecycle operation plan is incomplete.' }
    for ($index=0; $index -lt $expected.Count; $index++) { if ($Observed[$index] -ne $expected[$index]) { throw 'P15C lifecycle operation order is invalid.' } }
}

function Assert-CompletedPlan([string[]]$Observed,[switch]$Retained) {
    & $function:Assert-P15COperationPlan $Observed -Retained:$Retained
}

function Clear-P15CEnvironment {
    foreach ($item in @(Get-ChildItem Env: | Where-Object { $_.Name.StartsWith('P15C_',[StringComparison]::OrdinalIgnoreCase) })) { [Environment]::SetEnvironmentVariable($item.Name,$null,'Process') }
}

function Invoke-DockerCapture([string[]]$Arguments) {
    $output = @(& docker @Arguments 2>$null)
    if ($LASTEXITCODE -ne 0) { throw 'P15C Docker query failed.' }
    return $output
}

function Invoke-DockerQuiet([string[]]$Arguments,[string]$LogPath) {
    & docker @Arguments *> $LogPath
    if ($LASTEXITCODE -ne 0) { throw 'P15C Docker operation failed; raw output remains only in the owned run directory.' }
}

function Invoke-NodeQuiet([string[]]$Arguments) {
    & node @Arguments *> $null
    if ($LASTEXITCODE -ne 0) { throw 'P15C validation gate failed.' }
}

function Invoke-NodeCapture([string[]]$Arguments) {
    $value = @(& node @Arguments 2>$null)
    if ($LASTEXITCODE -ne 0) { throw 'P15C validation gate failed.' }
    return ($value -join "`n").Trim()
}

function Get-GitValue([string]$Path,[string[]]$Arguments) {
    $value = @(& git -C $Path @Arguments 2>$null)
    if ($LASTEXITCODE -ne 0) { throw 'P15C Git query failed.' }
    return ($value -join "`n").Trim()
}

function Assert-RunInputs {
    $required = @($XNodePath,$E2EPath,$RegistryPath,$StakingPath,$ContractsPath,$NodeImage,$DotnetSdkImage,$DotnetRuntimeImage,$EvidencePath,$ReceiptPath)
    if (@($required | Where-Object { [string]::IsNullOrWhiteSpace($_) }).Count) { throw 'P15C Run requires every exact source, image, evidence and receipt input.' }
    if ($NodeImage -ne $ExpectedNodeImage -or $DotnetSdkImage -ne $ExpectedSdkImage -or $DotnetRuntimeImage -ne $ExpectedRuntimeImage) { throw 'P15C image lock differs from the accepted local ARM64 digest.' }
    if (Test-Path -LiteralPath $EvidencePath) { throw 'P15C evidence path already exists.' }
    if (Test-Path -LiteralPath $ReceiptPath) { throw 'P15C receipt path already exists.' }
}

function New-SourceManifest([string]$Path,[System.Collections.IDictionary]$Sources) {
    $items = foreach ($name in $Sources.Keys) { $item=$Sources[$name]; [ordered]@{name=$name;path=$item.Path;sha=$item.Sha;tree=$item.Tree} }
    return Write-NewUtf8File $Path (@{sources=@($items)} | ConvertTo-Json -Depth 8)
}

function Assert-SourcePreflight([string]$ManifestPath) {
    Invoke-NodeQuiet @((Join-Path $PSScriptRoot 'p15c-headless-source-preflight.mjs'),'check-sources',$ManifestPath)
}

function New-ExactSourceExports([System.Collections.IDictionary]$Sources,[string]$RunDirectory) {
    $root = Join-Path $RunDirectory 'contexts'
    if (Test-Path -LiteralPath $root) { throw 'P15C exact source export root already exists.' }
    [void][System.IO.Directory]::CreateDirectory($root)
    Protect-P15CAuthorityFile $root -Directory
    $contexts = [ordered]@{}
    foreach ($name in $Sources.Keys) {
        $destination = Join-Path $root $name.ToLowerInvariant()
        [void][System.IO.Directory]::CreateDirectory($destination)
        Protect-P15CAuthorityFile $destination -Directory
        $tarPath = Join-Path $RunDirectory ("source-{0}.tar" -f $name.ToLowerInvariant())
        & git -C $Sources[$name].Path archive --format=tar --output=$tarPath $Sources[$name].Sha 2>$null
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $tarPath -PathType Leaf)) { throw 'P15C exact Git archive creation failed.' }
        Protect-P15CAuthorityFile $tarPath
        $tarRecord = [pscustomobject]@{created=$true;path=[System.IO.Path]::GetFullPath($tarPath);expectedSha256=(Get-FileSha256 $tarPath)}
        & tar -xf $tarPath -C $destination
        if ($LASTEXITCODE -ne 0 -or (Test-Path -LiteralPath (Join-Path $destination '.git'))) { throw 'P15C exact Git archive extraction failed.' }
        Remove-ExclusivelyCreatedFile $tarRecord
        $contexts[$name] = [System.IO.Path]::GetFullPath($destination)
    }
    return $contexts
}

function Assert-ExactSourceExports([string]$RunDirectory,[System.Collections.IDictionary]$Sources) {
    $root = Join-Path $RunDirectory 'contexts'
    if (-not (Test-Path -LiteralPath $root -PathType Container)) { throw 'P15C retained source export root is missing.' }
    Assert-ProtectedAcl $root
    $expectedNames = @($Sources.Keys | ForEach-Object { $_.ToLowerInvariant() } | Sort-Object)
    $actualNames = @(Get-ChildItem -LiteralPath $root -Force | ForEach-Object Name | Sort-Object)
    if (($expectedNames -join "`n") -ne ($actualNames -join "`n")) { throw 'P15C retained exact source exports are incomplete.' }
    $contexts = [ordered]@{}
    foreach ($name in $Sources.Keys) {
        $path = Join-Path $root $name.ToLowerInvariant()
        if (-not (Test-Path -LiteralPath $path -PathType Container) -or (Test-Path -LiteralPath (Join-Path $path '.git'))) { throw 'P15C retained source export is invalid.' }
        Assert-ProtectedAcl $path
        $contexts[$name] = [System.IO.Path]::GetFullPath($path)
    }
    return $contexts
}

function Assert-NoCollision([string]$Project,[string]$Nonce) {
    $counts = @(
        @(Invoke-DockerCapture @('container','ls','-aq','--filter',"label=com.docker.compose.project=$Project")).Count,
        @(Invoke-DockerCapture @('network','ls','-q','--filter',"label=com.docker.compose.project=$Project")).Count,
        @(Invoke-DockerCapture @('volume','ls','-q','--filter',"label=com.docker.compose.project=$Project")).Count,
        @(Invoke-DockerCapture @('image','ls','-q','--filter',"label=com.xpoint.p15c.ownership-nonce=$Nonce")).Count,
        @(Invoke-DockerCapture @('image','ls','-q',"$Project-*")).Count
    )
    if (($counts | Measure-Object -Sum).Sum) { throw 'P15C project/tag/resource collision exists.' }
}

function Get-ForeignInventory([string]$Project) {
    $containers = [Collections.Generic.List[string]]::new()
    foreach ($id in @(Invoke-DockerCapture @('container','ls','-aq','--no-trunc'))) {
        if ($id -notmatch '^[0-9a-f]{12,64}$') { throw 'P15C foreign container id is invalid.' }
        $record = (Invoke-DockerCapture @('container','inspect',$id,'--format','{{.Id}}|{{.Name}}|{{.Image}}|{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{end}}|{{.State.StartedAt}}|{{.State.FinishedAt}}|{{.RestartCount}}|{{index .Config.Labels "com.docker.compose.project"}}') -join '').Trim()
        $parts = $record -split '\|',9
        if ($parts.Count -ne 9) { throw 'P15C stable foreign container inventory is invalid.' }
        if ($parts[8] -ne $Project) { $containers.Add($record) }
    }
    $images = @(Invoke-DockerCapture @('image','ls','--no-trunc','--digests','--format','{{.ID}}|{{.Repository}}|{{.Tag}}|{{.Digest}}')) | Where-Object { $_ -notmatch "\|$([regex]::Escape($Project))-" } | Sort-Object
    $networks = [Collections.Generic.List[string]]::new()
    foreach ($id in @(Invoke-DockerCapture @('network','ls','-q','--no-trunc'))) {
        $record = (Invoke-DockerCapture @('network','inspect',$id,'--format','{{.Id}}|{{.Name}}|{{.Driver}}|{{.Scope}}|{{index .Labels "com.docker.compose.project"}}') -join '').Trim()
        $parts = $record -split '\|',5
        if ($parts.Count -ne 5) { throw 'P15C stable foreign network inventory is invalid.' }
        if ($parts[4] -ne $Project) { $networks.Add($record) }
    }
    $volumes = [Collections.Generic.List[string]]::new()
    foreach ($name in @(Invoke-DockerCapture @('volume','ls','-q'))) {
        $record = (Invoke-DockerCapture @('volume','inspect',$name,'--format','{{.Name}}|{{.Driver}}|{{index .Labels "com.docker.compose.project"}}') -join '').Trim()
        $parts = $record -split '\|',3
        if ($parts.Count -ne 3) { throw 'P15C stable foreign volume inventory is invalid.' }
        if ($parts[2] -ne $Project) { $volumes.Add($record) }
    }
    return [ordered]@{containers=@($containers | Sort-Object);images=$images;networks=@($networks | Sort-Object);volumes=@($volumes | Sort-Object)} | ConvertTo-Json -Depth 4 -Compress
}

function Assert-ImageLock([string]$Reference,[string]$Kind,[string]$Project,[string]$Nonce) {
    $raw = (Invoke-DockerCapture @('image','inspect',$Reference,'--format','{{json .}}')) -join ''
    $image = $raw | ConvertFrom-Json
    if ($image.Os -ne 'linux' -or $image.Architecture -ne 'arm64' -or $image.Id -notmatch '^sha256:[0-9a-f]{64}$' -or @($image.RepoDigests) -notcontains $Reference) { throw 'P15C local image lock is missing or not Linux ARM64.' }
    $base = @('run','--rm','--pull','never','--platform','linux/arm64','--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges:true','--label',"com.docker.compose.project=$Project",'--label',"com.docker.compose.service=p15c-preflight-$Kind",'--label',"com.xpoint.p15c.ownership-nonce=$Nonce",$Reference)
    if ($Kind -eq 'sdk') {
        $versions = @(Invoke-DockerCapture ($base + @('dotnet','--list-sdks')) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        if ($versions.Count -ne 1 -or $versions[0] -notmatch '^10\.0\.301 \[[^\]]+\]$') { throw 'P15C SDK inventory is not exactly 10.0.301.' }
    } elseif ($Kind -eq 'runtime') {
        $versions = @(Invoke-DockerCapture ($base + @('dotnet','--list-runtimes')) | Where-Object { $_ -match '^Microsoft\.(?:AspNetCore|NETCore)\.App ' } | ForEach-Object { ($_ -split ' \[')[0] } | Sort-Object)
        if (($versions -join "`n") -ne "Microsoft.AspNetCore.App 10.0.10`nMicrosoft.NETCore.App 10.0.10") { throw 'P15C runtime inventory is not exact.' }
    } else {
        $version = (Invoke-DockerCapture ($base + @('node','--version')) -join '').Trim()
        if ($version -ne 'v24.16.0') { throw 'P15C Node inventory is not exact.' }
    }
}

function Assert-EngineArchitecture {
    $arch = (Invoke-DockerCapture @('info','--format','{{.Architecture}}') -join '').Trim().ToLowerInvariant()
    if ($arch -notin @('arm64','aarch64')) { throw 'P15C Docker Engine must be ARM64; emulation is not accepted.' }
}

function Assert-PortAvailable([int]$Port) {
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback,$Port)
    try { $listener.Start() } catch { throw 'A P15C loopback port is unavailable.' } finally { $listener.Stop() }
}

function Set-ComposeEnvironment([System.Collections.IDictionary]$Context) {
    foreach ($entry in $Context.GetEnumerator()) { [Environment]::SetEnvironmentVariable($entry.Key,[string]$entry.Value,'Process') }
}

function New-ComposeContext([string]$Project,[string]$Nonce,[string]$SecretDirectory,[System.Collections.IDictionary]$Sources,[System.Collections.IDictionary]$Contexts,[System.Collections.IDictionary]$Images,$Contracts) {
    return @{
        P15C_PROJECT_NAME=$Project; P15C_OWNERSHIP_NONCE=$Nonce; P15C_DEVOPS_SHA=$Sources.DevOps.Sha; P15C_DEVOPS_TREE=$Sources.DevOps.Tree; P15C_DEVOPS_CONTEXT=$Contexts.DevOps
        P15C_XNODE_CONTEXT=$Contexts.XNode; P15C_XNODE_SHA=$Sources.XNode.Sha; P15C_XNODE_TREE=$Sources.XNode.Tree
        P15C_E2E_CONTEXT=$Contexts.E2E; P15C_E2E_SHA=$Sources.E2E.Sha; P15C_E2E_TREE=$Sources.E2E.Tree
        P15C_REGISTRY_CONTEXT=$Contexts.Registry; P15C_REGISTRY_SHA=$Sources.Registry.Sha; P15C_REGISTRY_TREE=$Sources.Registry.Tree
        P15C_STAKING_CONTEXT=$Contexts.Staking; P15C_STAKING_SHA=$Sources.Staking.Sha; P15C_STAKING_TREE=$Sources.Staking.Tree
        P15C_CONTRACTS_CONTEXT=$Contexts.Contracts; P15C_CONTRACTS_SHA=$Sources.Contracts.Sha; P15C_CONTRACTS_TREE=$Sources.Contracts.Tree
        P15C_NODE_IMAGE=$ExpectedNodeImage; P15C_DOTNET_SDK_IMAGE=$ExpectedSdkImage; P15C_DOTNET_RUNTIME_IMAGE=$ExpectedRuntimeImage; P15C_SECRET_DIR=$SecretDirectory
        P15C_XNODE_IMAGE_NAME=$Images.XNode; P15C_CONTRACTS_IMAGE_NAME=$Images.Contracts; P15C_REGISTRY_IMAGE_NAME=$Images.Registry; P15C_STAKING_IMAGE_NAME=$Images.Staking
        P15C_STORAGE_IMAGE_NAME=$Images.Storage; P15C_FILE_IMAGE_NAME=$Images.File; P15C_PUSH_IMAGE_NAME=$Images.Push; P15C_CALLS_IMAGE_NAME=$Images.Calls; P15C_TEST_IMAGE_NAME=$Images.Test
        P15C_CONTRACTS_PORT=$Ports.Contracts; P15C_XNODE1_PORT=$Ports.XNode1; P15C_XNODE2_PORT=$Ports.XNode2; P15C_XNODE3_PORT=$Ports.XNode3; P15C_REGISTRY_PORT=$Ports.Registry; P15C_STAKING_PORT=$Ports.Staking
        P15C_TOKEN_ADDRESS=if($Contracts){$Contracts.contracts.token}else{''}; P15C_REWARDS_ADDRESS=if($Contracts){$Contracts.contracts.serviceNodeRewards}else{''}; P15C_FACTORY_ADDRESS=if($Contracts){$Contracts.contracts.serviceNodeContributionFactory}else{''}; P15C_POOL_ADDRESS=if($Contracts){$Contracts.contracts.rewardRatePool}else{''}
    }
}

function Invoke-P15CBuild([string]$Project,[string]$LogPath) { Invoke-DockerQuiet @('compose','-p',$Project,'-f',$ComposePath,'build','--no-cache') $LogPath }
function Invoke-P15CUp([string]$Project,[string[]]$Services,[string]$LogPath) { Invoke-DockerQuiet (@('compose','-p',$Project,'-f',$ComposePath,'up','-d','--no-build','--pull','never') + $Services) $LogPath }

function Wait-Http([string]$Url,[int]$Seconds=120) {
    $until = [DateTime]::UtcNow.AddSeconds($Seconds)
    do { try { $response=Invoke-WebRequest -UseBasicParsing -Uri $Url -TimeoutSec 2; if ($response.StatusCode -ge 200 -and $response.StatusCode -lt 300) { return } } catch {}; Start-Sleep -Milliseconds 500 } while ([DateTime]::UtcNow -lt $until)
    throw 'P15C HTTP readiness timed out.'
}

function Wait-RpcChain([int]$Seconds=120) {
    $until = [DateTime]::UtcNow.AddSeconds($Seconds)
    $body = @{jsonrpc='2.0';id=1;method='eth_chainId';params=@()} | ConvertTo-Json -Compress
    do { try { $value=Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:$($Ports.Contracts)" -ContentType 'application/json' -Body $body -TimeoutSec 2; if ($value.result -eq '0x7a69') { return } } catch {}; Start-Sleep -Milliseconds 500 } while ([DateTime]::UtcNow -lt $until)
    throw 'P15C chain 0x7a69 readiness timed out.'
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
    foreach ($service in $RuntimeServices) {
        $id=(Invoke-DockerCapture @('compose','-p',$Project,'-f',$ComposePath,'ps','-q',$service) -join '').Trim()
        if ($id -notmatch '^[0-9a-f]{12,64}$') { throw 'P15C runtime container identity is invalid.' }
        $state=(Invoke-DockerCapture @('container','inspect',$id,'--format','{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{end}}') -join '').Trim()
        if ($state -ne 'running|healthy') { throw "P15C runtime health gate failed for $service." }
    }
}

function Get-ImageReceipt([System.Collections.IDictionary]$Images,[System.Collections.IDictionary]$Sources,[string]$Nonce) {
    $bindings = @(
        @{Role='xnode';Tag=$Images.XNode;SourceName='XNode';SourceLabel='xnode';Source=$Sources.XNode}, @{Role='contracts-devnet';Tag=$Images.Contracts;SourceName='Contracts';SourceLabel='xpoint-staking-contracts';Source=$Sources.Contracts},
        @{Role='registry';Tag=$Images.Registry;SourceName='Registry';SourceLabel='deep-registry-api';Source=$Sources.Registry}, @{Role='staking-backend';Tag=$Images.Staking;SourceName='Staking';SourceLabel='xpoint-staking-backend';Source=$Sources.Staking},
        @{Role='storage';Tag=$Images.Storage;SourceName='DevOps';SourceLabel='deep-devops';Source=$Sources.DevOps}, @{Role='file';Tag=$Images.File;SourceName='DevOps';SourceLabel='deep-devops';Source=$Sources.DevOps},
        @{Role='push';Tag=$Images.Push;SourceName='DevOps';SourceLabel='deep-devops';Source=$Sources.DevOps}, @{Role='calls';Tag=$Images.Calls;SourceName='DevOps';SourceLabel='deep-devops';Source=$Sources.DevOps}, @{Role='test-client';Tag=$Images.Test;SourceName='E2E';SourceLabel='deep-tests-e2e';Source=$Sources.E2E}
    )
    $result = foreach ($binding in $bindings) {
        $image=((Invoke-DockerCapture @('image','inspect',$binding.Tag,'--format','{{json .}}')) -join '') | ConvertFrom-Json
        $labels=$image.Config.Labels
        if ($image.Os -ne 'linux' -or $image.Architecture -ne 'arm64' -or $image.Id -notmatch '^sha256:[0-9a-f]{64}$' -or $labels.'org.opencontainers.image.revision' -ne $binding.Source.Sha -or $labels.'org.opencontainers.image.source-tree' -ne $binding.Source.Tree -or $labels.'org.opencontainers.image.source' -ne $binding.SourceLabel -or $labels.'com.xpoint.p15c.role' -ne $binding.Role -or $labels.'com.xpoint.evidence-class' -ne 'headless-harness' -or $labels.'com.xpoint.product-runtime' -ne 'false' -or $labels.'com.xpoint.p15c.ownership-nonce' -ne $Nonce) { throw 'P15C built image label gate failed.' }
        [ordered]@{role=$binding.Role;source=$binding.SourceName;sha=$binding.Source.Sha;tree=$binding.Source.Tree;id=$image.Id}
    }
    return @($result)
}

function New-ReceiptExpectation([System.Collections.IDictionary]$Sources,[string[]]$Roles,[string]$Project,[string]$Nonce,[string]$ComposeSha,[string]$ManifestSha,[string]$ForeignSha) {
    $pins=[ordered]@{}; foreach($name in $Sources.Keys){$pins[$name]=[ordered]@{sha=$Sources[$name].Sha;tree=$Sources[$name].Tree}}
    $value=[ordered]@{sources=$pins;roles=@($Roles)}
    if($Project){$value.project=$Project}; if($Nonce){$value.nonce=$Nonce}; if($ComposeSha){$value.composeSha256=$ComposeSha}; if($ManifestSha){$value.manifestSha256=$ManifestSha}; if($ForeignSha){$value.foreignSnapshotSha256=$ForeignSha}
    return ($value | ConvertTo-Json -Depth 8 -Compress)
}

function Invoke-ExactDown([string]$Project,[string]$LogPath) {
    # exact cleanup: down --volumes --remove-orphans
    Invoke-DockerQuiet @('compose','-p',$Project,'-f',$ComposePath,'down','--volumes','--remove-orphans') $LogPath
}

function Get-OwnedProjectRuntimeInventory([string]$Project) {
    $containers=@(); foreach($id in @(Invoke-DockerCapture @('container','ls','-aq','--filter',"label=com.docker.compose.project=$Project"))){
        $raw=(Invoke-DockerCapture @('container','inspect',$id,'--format','{{index .Config.Labels "com.docker.compose.project"}}|{{index .Config.Labels "com.xpoint.p15c.ownership-nonce"}}|{{index .Config.Labels "com.docker.compose.service"}}') -join '').Trim(); $parts=$raw -split '\|',3
        if($parts.Count -ne 3){throw 'P15C owned container inventory is malformed.'}; $containers += [ordered]@{project=$parts[0];nonce=$parts[1];service=$parts[2];labels=[ordered]@{'com.xpoint.p15c.ownership-nonce'=$parts[1]}}
    }
    $networks=@(); foreach($id in @(Invoke-DockerCapture @('network','ls','-q','--filter',"label=com.docker.compose.project=$Project"))){
        $raw=(Invoke-DockerCapture @('network','inspect',$id,'--format','{{index .Labels "com.docker.compose.project"}}|{{index .Labels "com.xpoint.p15c.ownership-nonce"}}|{{index .Labels "com.docker.compose.network"}}') -join '').Trim(); $parts=$raw -split '\|',3
        if($parts.Count -ne 3){throw 'P15C owned network inventory is malformed.'}; $networks += [ordered]@{project=$parts[0];nonce=$parts[1];network=$parts[2];labels=[ordered]@{'com.xpoint.p15c.ownership-nonce'=$parts[1]}}
    }
    $volumes=@(); foreach($name in @(Invoke-DockerCapture @('volume','ls','-q','--filter',"label=com.docker.compose.project=$Project"))){
        $raw=(Invoke-DockerCapture @('volume','inspect',$name,'--format','{{index .Labels "com.docker.compose.project"}}|{{index .Labels "com.xpoint.p15c.ownership-nonce"}}|{{index .Labels "com.docker.compose.volume"}}') -join '').Trim(); $parts=$raw -split '\|',3
        if($parts.Count -ne 3){throw 'P15C owned volume inventory is malformed.'}; $volumes += [ordered]@{project=$parts[0];nonce=$parts[1];volume=$parts[2];labels=[ordered]@{'com.xpoint.p15c.ownership-nonce'=$parts[1]}}
    }
    return [ordered]@{containers=@($containers);networks=@($networks);volumes=@($volumes)}
}

function Assert-OwnedProjectRuntimeInventory([string]$Project,[string]$Nonce,[string]$RunDirectory,[switch]$AllowPartial) {
    $inventory=Get-OwnedProjectRuntimeInventory $Project
    $kind = if ($AllowPartial) { 'partial' } else { 'exact' }
    $path = Join-Path $RunDirectory ("owned-runtime-$kind-$(New-Hex 4).json")
    $record=Write-NewUtf8File $path ($inventory | ConvertTo-Json -Depth 8)
    $services=if($AllowPartial){@($RuntimeServices)+@('test-client','p15c-preflight-sdk','p15c-preflight-runtime','p15c-preflight-node')}else{@($RuntimeServices)}
    $expected=[ordered]@{project=$Project;nonce=$Nonce;services=@($services);networks=@('runtime');volumes=@($RuntimeVolumes);allowPartial=[bool]$AllowPartial}
    try { Invoke-NodeQuiet @((Join-Path $PSScriptRoot 'p15c-headless-contracts.mjs'),'validate-runtime-inventory',$path,($expected|ConvertTo-Json -Depth 6 -Compress)) }
    finally { Remove-ExclusivelyCreatedFile $record }
}

function Remove-OwnedImages([object[]]$Images,[string]$LogPath) {
    $ids=@($Images | ForEach-Object id | Sort-Object -Unique); foreach($id in $ids){if($id -notmatch '^sha256:[0-9a-f]{64}$'){throw 'P15C owned image id is invalid.'}}
    $failures=[Collections.Generic.List[Exception]]::new(); foreach($id in $ids){& docker image rm $id *>> $LogPath; if($LASTEXITCODE -ne 0){$failures.Add([InvalidOperationException]::new('P15C exact owned image cleanup failed.'))}}
    if($failures.Count){throw [AggregateException]::new('One or more exact owned image removals failed.',$failures.ToArray())}
}

function Get-FailureOwnedImages($Images,[string]$Nonce) {
    $ids=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    if($null -ne $Images){foreach($tag in $Images.Values){$short=(Invoke-DockerCapture @('image','ls','-q',$tag) -join '').Trim();if($short -match '^[0-9a-f]{12,64}$'){$id=(Invoke-DockerCapture @('image','inspect',$tag,'--format','{{.Id}}') -join '').Trim();if($id -match '^sha256:[0-9a-f]{64}$'){[void]$ids.Add($id)}}}}
    foreach($short in @(Invoke-DockerCapture @('image','ls','-q','--filter',"label=com.xpoint.p15c.ownership-nonce=$Nonce"))){$id=(Invoke-DockerCapture @('image','inspect',$short,'--format','{{.Id}}') -join '').Trim();if($id -match '^sha256:[0-9a-f]{64}$'){[void]$ids.Add($id)}}
    return @($ids | ForEach-Object {[pscustomobject]@{id=$_}})
}

function Assert-ZeroOwned([string]$Project,[string]$Nonce) {
    $counts=@(@(Invoke-DockerCapture @('container','ls','-aq','--filter',"label=com.docker.compose.project=$Project")).Count,@(Invoke-DockerCapture @('network','ls','-q','--filter',"label=com.xpoint.p15c.ownership-nonce=$Nonce")).Count,@(Invoke-DockerCapture @('volume','ls','-q','--filter',"label=com.xpoint.p15c.ownership-nonce=$Nonce")).Count,@(Invoke-DockerCapture @('image','ls','-q','--filter',"label=com.xpoint.p15c.ownership-nonce=$Nonce")).Count)
    if(($counts|Measure-Object -Sum).Sum){throw 'P15C owned Docker resources remain after cleanup.'}
}

function Invoke-OwnedResourceCleanup([string]$Project,[string]$Nonce,[object[]]$OwnedImages,[string]$ForeignBefore,[string]$RunDirectory,[switch]$AllowPartial) {
    Assert-OwnedProjectRuntimeInventory $Project $Nonce $RunDirectory -AllowPartial:$AllowPartial
    $failures=[Collections.Generic.List[Exception]]::new()
    try { Invoke-ExactDown $Project (Join-Path $RunDirectory 'down.log') } catch { $failures.Add($_.Exception) }
    try { Remove-OwnedImages $OwnedImages (Join-Path $RunDirectory 'image-cleanup.log') } catch { $failures.Add($_.Exception) }
    try { Assert-ZeroOwned $Project $Nonce } catch { $failures.Add($_.Exception) }
    try { if((Get-ForeignInventory $Project) -ne $ForeignBefore){throw 'P15C foreign Docker inventory changed.'} } catch { $failures.Add($_.Exception) }
    if($failures.Count){throw [AggregateException]::new('P15C owned resource cleanup failed; retained state and logs were preserved.',$failures.ToArray())}
}

function Remove-OwnedRunDirectory([string]$Directory) {
    $base=[System.IO.Path]::GetFullPath((Join-Path $env:LOCALAPPDATA 'Deep\P15C')).TrimEnd('\')+'\'; $full=[System.IO.Path]::GetFullPath($Directory); $marker=Join-Path $full '.p15c-run-owner'
    if(-not $full.StartsWith($base,[StringComparison]::OrdinalIgnoreCase) -or -not(Test-Path -LiteralPath $marker -PathType Leaf) -or [IO.File]::ReadAllText($marker) -ne 'deep-p15c-run.v1'){throw 'P15C run directory ownership validation failed.'}
    [IO.Directory]::Delete($full,$true)
}

function Assert-RunDirectoryOutsideRepositories([string]$Directory,[System.Collections.IDictionary]$Sources) {
    $full=[IO.Path]::GetFullPath($Directory).TrimEnd('\')+'\'; foreach($source in $Sources.Values){$repo=[IO.Path]::GetFullPath($source.Path).TrimEnd('\')+'\';if($full.StartsWith($repo,[StringComparison]::OrdinalIgnoreCase)-or $repo.StartsWith($full,[StringComparison]::OrdinalIgnoreCase)){throw 'P15C run directory must remain outside every source repository.'}}
}

function Assert-NoReparseOutputPath([string]$Path) {
    $full=[IO.Path]::GetFullPath($Path); if(Test-Path -LiteralPath $full){$item=Get-Item -LiteralPath $full -Force;if(($item.Attributes-band[IO.FileAttributes]::ReparsePoint)-ne 0){throw 'P15C output path must not be a reparse point.'}}
    $current=[IO.Path]::GetDirectoryName($full);if([string]::IsNullOrWhiteSpace($current)-or-not(Test-Path -LiteralPath $current -PathType Container)){throw 'P15C output parent directory must already exist.'}
    while($current){$item=Get-Item -LiteralPath $current -Force;if(($item.Attributes-band[IO.FileAttributes]::ReparsePoint)-ne 0){throw 'P15C output path must not traverse a reparse point.'};$parent=[IO.Directory]::GetParent($current);if($null-eq$parent){break};$current=$parent.FullName}
}

function Assert-OutputOutsideRepositories([string]$Path,[System.Collections.IDictionary]$Sources,[string]$RunDirectory) {
    if(-not[IO.Path]::IsPathRooted($Path)-or$Path-match'(?:^|[\\/])\.\.(?:[\\/]|$)'){throw 'P15C output path must be canonical and absolute.'};$full=[IO.Path]::GetFullPath($Path);if(-not$Path.Equals($full,[StringComparison]::OrdinalIgnoreCase)){throw 'P15C output path must already be canonical.'};Assert-NoReparseOutputPath $full
    foreach($source in $Sources.Values){$repo=[IO.Path]::GetFullPath($source.Path).TrimEnd('\')+'\';if($full.StartsWith($repo,[StringComparison]::OrdinalIgnoreCase)){throw 'P15C output must remain outside source repositories.'}}
    $run=[IO.Path]::GetFullPath($RunDirectory).TrimEnd('\')+'\';if($full.StartsWith($run,[StringComparison]::OrdinalIgnoreCase)){throw 'P15C output must remain outside the owned run tree.'}
}

function Assert-DistinctOutputPaths([string]$Left,[string]$Right){if([IO.Path]::GetFullPath($Left).Equals([IO.Path]::GetFullPath($Right),[StringComparison]::OrdinalIgnoreCase)){throw 'P15C evidence and receipt paths must be distinct.'}}

function Assert-SecretDirectoryOwnership([string]$Directory) {
    $marker=Join-Path $Directory '.p15c-secret-owner';if(-not(Test-Path -LiteralPath $marker -PathType Leaf)-or[IO.File]::ReadAllText($marker)-ne'deep-p15c-ephemeral-secrets.v1'){throw 'P15C retained secret marker is invalid.'}
    $expectedNames=@('.p15c-secret-owner','node-1.config.json','node-1.seed','node-2.config.json','node-2.seed','node-3.config.json','node-3.seed')|Sort-Object;$actualNames=@(Get-ChildItem -LiteralPath $Directory -Force|ForEach-Object Name|Sort-Object);if(($actualNames-join"`n")-ne($expectedNames-join"`n")){throw 'P15C retained secret directory contains missing or extra entries.'}
    Assert-ProtectedAcl $Directory;foreach($path in @($marker)+@(1..3|ForEach-Object{Join-Path $Directory "node-$_.seed"})+@(1..3|ForEach-Object{Join-Path $Directory "node-$_.config.json"})){Assert-ProtectedAcl $path}
    $seeds=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal);$routers=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach($index in 1..3){$seed=([IO.File]::ReadAllText((Join-Path $Directory "node-$index.seed"))).Trim();if($seed-notmatch'^[0-9a-f]{64}$'-or-not$seeds.Add($seed)){throw 'P15C retained seed is malformed.'};$config=Get-Content -LiteralPath (Join-Path $Directory "node-$index.config.json") -Raw|ConvertFrom-Json;if((@($config.psobject.Properties.Name)-join',')-ne'Node'-or(@($config.Node.psobject.Properties.Name)-join',')-ne'RouterId'-or$config.Node.RouterId-notmatch'^[0-9a-f]{64}$'-or-not$routers.Add($config.Node.RouterId)){throw 'P15C retained public configuration is malformed.'}}
}

function Assert-ForeignSnapshot([string]$Path) {
    if(-not(Test-Path -LiteralPath $Path -PathType Leaf)){throw 'P15C retained foreign snapshot is missing.'};Assert-ProtectedAcl $Path;$raw=[IO.File]::ReadAllText($Path);$value=$raw|ConvertFrom-Json
    if((@($value.psobject.Properties.Name|Sort-Object)-join',')-ne'containers,images,networks,volumes'){throw 'P15C retained foreign snapshot is malformed.'};foreach($name in @('containers','images','networks','volumes')){if($null-eq$value.$name){throw 'P15C retained foreign snapshot is incomplete.'}};return $raw
}

function New-Evidence([string]$Path) {
    $input="$Path.input";$inputRecord=$null;$outputRecord=$null;$sanitizerCreated=$false;$value=[ordered]@{schema='deep-p15c-headless-evidence.v1';evidenceClass='headless-harness';productRuntime=$false;result='pass';gates=[ordered]@{source='pass';images='pass';contracts='pass';runtime='pass';e2e='pass';cleanup='pass'};counts=[ordered]@{services=11;xnodes=3;localContracts=4}}
    try {$inputRecord=Write-NewUtf8File $input ($value|ConvertTo-Json -Depth 8);Invoke-NodeQuiet @((Join-Path $PSScriptRoot 'p15c-evidence-sanitizer.mjs'),'write',$input,$Path);$sanitizerCreated=$true;$outputRecord=[pscustomobject]@{created=$true;path=[IO.Path]::GetFullPath($Path);expectedSha256=(Get-FileSha256 $Path)};Protect-P15CAuthorityFile $Path}
    catch {if($sanitizerCreated -and $null -ne $outputRecord -and (Test-Path -LiteralPath $outputRecord.path -PathType Leaf)){Remove-ExclusivelyCreatedFile $outputRecord};throw}
    finally {if($null-ne$inputRecord -and(Test-Path -LiteralPath $inputRecord.path -PathType Leaf)){Remove-ExclusivelyCreatedFile $inputRecord}}
    return $outputRecord
}

function Invoke-FailedRunCleanup([string]$Project,[string]$Nonce,[string]$RunDirectory,[string]$SecretDirectory,$Images,[string]$ForeignBefore,[bool]$MutationStarted,[bool]$ResourcesClean,[Collections.Generic.List[object]]$OwnedOutputs) {
    $failures=[Collections.Generic.List[Exception]]::new()
    if($MutationStarted-and-not$ResourcesClean){
        $inventoryValid=$true;try{Assert-OwnedProjectRuntimeInventory $Project $Nonce $RunDirectory -AllowPartial}catch{$inventoryValid=$false;$failures.Add($_.Exception)}
        if($inventoryValid){try{Invoke-ExactDown $Project (Join-Path $RunDirectory 'failure-down.log')}catch{$failures.Add($_.Exception)}}
        try{$owned=@(Get-FailureOwnedImages $Images $Nonce);if($owned.Count){Remove-OwnedImages $owned (Join-Path $RunDirectory 'failure-images.log')}}catch{$failures.Add($_.Exception)}
        try{Assert-ZeroOwned $Project $Nonce}catch{$failures.Add($_.Exception)}
        if($null-ne$ForeignBefore){try{if((Get-ForeignInventory $Project)-ne$ForeignBefore){throw 'P15C foreign inventory changed during failed cleanup.'}}catch{$failures.Add($_.Exception)}}
    }
    if($failures.Count-eq 0){if(Test-Path -LiteralPath $SecretDirectory){try{& (Join-Path $PSScriptRoot 'p15c-ephemeral-secrets.ps1') -Action Remove -RunDirectory $SecretDirectory}catch{$failures.Add($_.Exception)}};foreach($record in $OwnedOutputs){if($failures.Count-eq 0-and(Test-Path -LiteralPath $record.path -PathType Leaf)){try{Remove-ExclusivelyCreatedFile $record}catch{$failures.Add($_.Exception)}}};if($failures.Count-eq 0-and(Test-Path -LiteralPath $RunDirectory)){try{Remove-OwnedRunDirectory $RunDirectory}catch{$failures.Add($_.Exception)}}}
    return $failures
}

function Complete-RetainedStateCleanup($Context,[string]$FinalEvidencePath) {
    $stagePath="$FinalEvidencePath.p15c-stage-$($Context.Receipt.nonce)";Assert-OutputOutsideRepositories $stagePath $Context.Sources $Context.RunDirectory;if(Test-Path -LiteralPath $stagePath){throw 'P15C staged evidence path already exists.'}
    $stageRecord=New-Evidence $stagePath;$receiptRecord=[pscustomobject]@{created=$true;path=[IO.Path]::GetFullPath($ReceiptPath);expectedSha256=(Get-FileSha256 $ReceiptPath)}
    try {& (Join-Path $PSScriptRoot 'p15c-ephemeral-secrets.ps1') -Action Remove -RunDirectory $Context.SecretDirectory;Remove-OwnedRunDirectory $Context.RunDirectory;Remove-ExclusivelyCreatedFile $receiptRecord;[IO.File]::Move($stageRecord.path,[IO.Path]::GetFullPath($FinalEvidencePath))}
    catch {$stateError=$_.Exception;if(Test-Path -LiteralPath $stageRecord.path -PathType Leaf){try{Remove-ExclusivelyCreatedFile $stageRecord}catch{throw [AggregateException]::new('P15C retained cleanup failed and staged evidence cleanup also failed.',@($stateError,$_.Exception))}};throw $stateError}
}

function Invoke-Run {
    Assert-RunInputs;$project='p15c-'+(New-Hex 8);$nonce=New-Hex 16;$runDirectory=Join-Path (Join-Path $env:LOCALAPPDATA 'Deep\P15C') "$project-$nonce";$secretDirectory=Join-Path $runDirectory 'secrets'
    if(Test-Path -LiteralPath $runDirectory){throw 'P15C owned run directory collision exists.'};[void][IO.Directory]::CreateDirectory($runDirectory);Protect-P15CAuthorityFile $runDirectory -Directory;$runMarker=Write-NewUtf8File (Join-Path $runDirectory '.p15c-run-owner') 'deep-p15c-run.v1'
    $foreignBefore=$null;$retained=$false;$mutationStarted=$false;$resourcesClean=$false;$images=$null;$imagesReceipt=@();$ownedOutputs=[Collections.Generic.List[object]]::new();$operations=[Collections.Generic.List[string]]::new()
    try {
        $devopsSha=Get-GitValue $Root @('rev-parse','HEAD');$devopsTree=Get-GitValue $Root @('rev-parse','HEAD^{tree}');$sources=[ordered]@{DevOps=[ordered]@{Sha=$devopsSha;Tree=$devopsTree;Path=$Root};XNode=[ordered]@{Sha=$Expected.XNode.Sha;Tree=$Expected.XNode.Tree;Path=[IO.Path]::GetFullPath($XNodePath)};E2E=[ordered]@{Sha=$Expected.E2E.Sha;Tree=$Expected.E2E.Tree;Path=[IO.Path]::GetFullPath($E2EPath)};Registry=[ordered]@{Sha=$Expected.Registry.Sha;Tree=$Expected.Registry.Tree;Path=[IO.Path]::GetFullPath($RegistryPath)};Staking=[ordered]@{Sha=$Expected.Staking.Sha;Tree=$Expected.Staking.Tree;Path=[IO.Path]::GetFullPath($StakingPath)};Contracts=[ordered]@{Sha=$Expected.Contracts.Sha;Tree=$Expected.Contracts.Tree;Path=[IO.Path]::GetFullPath($ContractsPath)}}
        foreach($name in @('XNode','E2E','Registry','Staking','Contracts')){if($sources[$name].Path-ne[IO.Path]::GetFullPath($Expected[$name].Path)){throw 'P15C source path differs from invocation contract.'}}
        Assert-RunDirectoryOutsideRepositories $runDirectory $sources;Assert-OutputOutsideRepositories $EvidencePath $sources $runDirectory;Assert-OutputOutsideRepositories $ReceiptPath $sources $runDirectory;Assert-DistinctOutputPaths $EvidencePath $ReceiptPath
        $sourceManifest=Join-Path $runDirectory 'sources.json';$sourceRecord=New-SourceManifest $sourceManifest $sources;Assert-SourcePreflight $sourceManifest;$operations.Add('source-preflight')
        Assert-NoCollision $project $nonce;$operations.Add('collision-check')
        $foreignPath=Join-Path $runDirectory 'foreign-before.json';$foreignBefore=Get-ForeignInventory $project;$foreignRecord=Write-NewUtf8File $foreignPath $foreignBefore;$operations.Add('foreign-snapshot')
        $mutationStarted=$true;Assert-EngineArchitecture;Assert-ImageLock $DotnetSdkImage 'sdk' $project $nonce;Assert-ImageLock $DotnetRuntimeImage 'runtime' $project $nonce;Assert-ImageLock $NodeImage 'node' $project $nonce;$operations.Add('image-preflight')
        & (Join-Path $PSScriptRoot 'p15c-ephemeral-secrets.ps1') -Action Generate -RunDirectory $secretDirectory;$operations.Add('generate-secrets')
        $contexts=New-ExactSourceExports $sources $runDirectory;$operations.Add('source-export');foreach($port in $Ports.Values){Assert-PortAvailable $port}
        $images=[ordered]@{XNode="$project-xnode:$($Expected.XNode.Sha.Substring(0,12))";Contracts="$project-contracts:$($Expected.Contracts.Sha.Substring(0,12))";Registry="$project-registry:$($Expected.Registry.Sha.Substring(0,12))";Staking="$project-staking:$($Expected.Staking.Sha.Substring(0,12))";Storage="$project-storage:$($devopsSha.Substring(0,12))";File="$project-file:$($devopsSha.Substring(0,12))";Push="$project-push:$($devopsSha.Substring(0,12))";Calls="$project-calls:$($devopsSha.Substring(0,12))";Test="$project-test:$($Expected.E2E.Sha.Substring(0,12))"}
        Set-ComposeEnvironment (New-ComposeContext $project $nonce $secretDirectory $sources $contexts $images $null);$composeModel=Join-Path $runDirectory 'compose.json';& docker compose -p $project -f $ComposePath config --format json *> $composeModel;if($LASTEXITCODE-ne 0){throw 'P15C Compose configuration failed.'};Protect-P15CAuthorityFile $composeModel;Invoke-NodeQuiet @((Join-Path $PSScriptRoot 'p15c-headless-contracts.mjs'),'validate-compose',$composeModel,(@{sha=$devopsSha;tree=$devopsTree}|ConvertTo-Json -Compress));$operations.Add('compose-config')
        Assert-P15COperationPlan $operations.ToArray() -Prefix
        Invoke-P15CBuild $project (Join-Path $runDirectory 'build.log');$operations.Add('build');Invoke-P15CUp $project @('contracts-devnet') (Join-Path $runDirectory 'up-contracts.log');Wait-RpcChain;$operations.Add('up-contracts')
        Invoke-DockerQuiet @('compose','-p',$project,'-f',$ComposePath,'exec','-T','contracts-devnet','pnpm','exec','hardhat','run','scripts/deploy-local-devnet.js','--network','localhost') (Join-Path $runDirectory 'deploy.log');Invoke-DockerQuiet @('compose','-p',$project,'-f',$ComposePath,'exec','-T','contracts-devnet','pnpm','exec','hardhat','run','scripts/local-devnet-smoke.js','--network','localhost') (Join-Path $runDirectory 'contract-smoke.log')
        $contractContainer=(Invoke-DockerCapture @('compose','-p',$project,'-f',$ComposePath,'ps','-q','contracts-devnet')-join'').Trim();if($contractContainer-notmatch'^[0-9a-f]{12,64}$'){throw 'P15C contract container id is invalid.'};$rawManifest=Join-Path $runDirectory 'localhost.raw.json';Invoke-DockerQuiet @('cp',"$contractContainer`:/workspace/deployments/localhost.latest.json",$rawManifest) (Join-Path $runDirectory 'copy-manifest.log');$localManifest=Join-Path $runDirectory 'localhost.validated.json';Invoke-NodeQuiet @((Join-Path $PSScriptRoot 'p15c-local-contract-manifest.mjs'),'normalize',$rawManifest,$localManifest,"http://127.0.0.1:$($Ports.Contracts)");Protect-P15CAuthorityFile $localManifest;[IO.File]::Delete($rawManifest);$contracts=Get-Content -LiteralPath $localManifest -Raw|ConvertFrom-Json;$operations.Add('deploy-contracts')
        Set-ComposeEnvironment (New-ComposeContext $project $nonce $secretDirectory $sources $contexts $images $contracts);Invoke-P15CUp $project $RuntimeServices (Join-Path $runDirectory 'up-runtime.log');$operations.Add('up-runtime');Assert-Runtime $project;$operations.Add('probe');Invoke-DockerQuiet @('compose','-p',$project,'-f',$ComposePath,'run','--rm','--no-deps','test-client') (Join-Path $runDirectory 'e2e.log');$operations.Add('e2e');$imagesReceipt=Get-ImageReceipt $images $sources $nonce;$operations.Add('labels')
        if($KeepRunning){$pins=[ordered]@{};foreach($name in $sources.Keys){$pins[$name]=[ordered]@{sha=$sources[$name].Sha;tree=$sources[$name].Tree}};$receipt=[ordered]@{schema='deep-p15c-ownership.v1';project=$project;nonce=$nonce;composeSha256=(Get-FileSha256 $ComposePath);manifestSha256=(Get-FileSha256 $localManifest);foreignSnapshotSha256=(Get-FileSha256 $foreignPath);sources=$pins;images=$imagesReceipt};$receiptRecord=Write-NewUtf8File $ReceiptPath ($receipt|ConvertTo-Json -Depth 10);$ownedOutputs.Add($receiptRecord);$expectation=New-ReceiptExpectation $sources $ImageRoles $project $nonce (Get-FileSha256 $ComposePath) (Get-FileSha256 $localManifest) (Get-FileSha256 $foreignPath);Invoke-NodeQuiet @((Join-Path $PSScriptRoot 'p15c-headless-contracts.mjs'),'validate-receipt',$ReceiptPath,$expectation);$operations.Add('receipt-retained');Assert-CompletedPlan $operations.ToArray() -Retained;$retained=$true;$ownedOutputs.Clear();return}
        Invoke-OwnedResourceCleanup $project $nonce $imagesReceipt $foreignBefore $runDirectory;$resourcesClean=$true;& (Join-Path $PSScriptRoot 'p15c-ephemeral-secrets.ps1') -Action Remove -RunDirectory $secretDirectory;Remove-OwnedRunDirectory $runDirectory;$operations.Add('cleanup');$evidenceRecord=New-Evidence $EvidencePath;$ownedOutputs.Add($evidenceRecord);$operations.Add('evidence');Assert-CompletedPlan $operations.ToArray();$ownedOutputs.Clear()
    } catch {$operationError=$_.Exception;if(-not$retained){$cleanupErrors=@(Invoke-FailedRunCleanup $project $nonce $runDirectory $secretDirectory $images $foreignBefore $mutationStarted $resourcesClean $ownedOutputs);if($cleanupErrors.Count){$all=[Collections.Generic.List[Exception]]::new();$all.Add($operationError);foreach($error in $cleanupErrors){$all.Add($error)};throw [AggregateException]::new('P15C operation and cleanup failed; owned state preserved.',$all.ToArray())}};throw $operationError}
}

function Get-RetainedContext([switch]$ForDown) {
    if([string]::IsNullOrWhiteSpace($ReceiptPath)-or-not(Test-Path -LiteralPath $ReceiptPath -PathType Leaf)){throw 'P15C exact ownership receipt is required.'};Assert-ProtectedAcl $ReceiptPath
    $devopsSha=Get-GitValue $Root @('rev-parse','HEAD');$devopsTree=Get-GitValue $Root @('rev-parse','HEAD^{tree}');$sources=[ordered]@{DevOps=[ordered]@{Sha=$devopsSha;Tree=$devopsTree;Path=$Root};XNode=$Expected.XNode;E2E=$Expected.E2E;Registry=$Expected.Registry;Staking=$Expected.Staking;Contracts=$Expected.Contracts}
    $summaryRaw=Invoke-NodeCapture @((Join-Path $PSScriptRoot 'p15c-headless-contracts.mjs'),'summarize-receipt',$ReceiptPath,(New-ReceiptExpectation $sources $ImageRoles $null $null (Get-FileSha256 $ComposePath) $null $null));$summary=$summaryRaw|ConvertFrom-Json;$runDirectory=Join-Path (Join-Path $env:LOCALAPPDATA 'Deep\P15C') "$($summary.project)-$($summary.nonce)";$secretDirectory=Join-Path $runDirectory 'secrets';$manifestPath=Join-Path $runDirectory 'localhost.validated.json';$foreignPath=Join-Path $runDirectory 'foreign-before.json';$runMarker=Join-Path $runDirectory '.p15c-run-owner'
    if(-not(Test-Path -LiteralPath $runMarker -PathType Leaf)-or[IO.File]::ReadAllText($runMarker)-ne'deep-p15c-run.v1'-or-not(Test-Path -LiteralPath $manifestPath -PathType Leaf)-or-not(Test-Path -LiteralPath $secretDirectory -PathType Container)){throw 'P15C retained ownership state is incomplete.'};Assert-ProtectedAcl $runDirectory;Assert-ProtectedAcl $runMarker;Assert-ProtectedAcl $manifestPath
    Assert-RunDirectoryOutsideRepositories $runDirectory $sources;Assert-OutputOutsideRepositories $ReceiptPath $sources $runDirectory;if($ForDown){if([string]::IsNullOrWhiteSpace($EvidencePath)){throw 'P15C Down requires evidence path.'};Assert-OutputOutsideRepositories $EvidencePath $sources $runDirectory;Assert-DistinctOutputPaths $EvidencePath $ReceiptPath;if(Test-Path -LiteralPath $EvidencePath){throw 'P15C evidence path already exists.'}}elseif(-not[string]::IsNullOrWhiteSpace($EvidencePath)){throw 'P15C Verify does not accept an evidence path.'}
    Assert-SecretDirectoryOwnership $secretDirectory;Invoke-NodeQuiet @((Join-Path $PSScriptRoot 'p15c-local-contract-manifest.mjs'),'validate-shape',$manifestPath);$sourceManifest=Join-Path $runDirectory 'sources.json';Assert-ProtectedAcl $sourceManifest;Assert-SourcePreflight $sourceManifest;$contexts=Assert-ExactSourceExports $runDirectory $sources;$foreignBefore=Assert-ForeignSnapshot $foreignPath
    $expectation=New-ReceiptExpectation $sources $ImageRoles $summary.project $summary.nonce (Get-FileSha256 $ComposePath) (Get-FileSha256 $manifestPath) (Get-FileSha256 $foreignPath);Invoke-NodeQuiet @((Join-Path $PSScriptRoot 'p15c-headless-contracts.mjs'),'validate-receipt',$ReceiptPath,$expectation);$receipt=Get-Content -LiteralPath $ReceiptPath -Raw|ConvertFrom-Json;$contracts=Get-Content -LiteralPath $manifestPath -Raw|ConvertFrom-Json;$project=$receipt.project;$images=[ordered]@{XNode="$project-xnode:$($Expected.XNode.Sha.Substring(0,12))";Contracts="$project-contracts:$($Expected.Contracts.Sha.Substring(0,12))";Registry="$project-registry:$($Expected.Registry.Sha.Substring(0,12))";Staking="$project-staking:$($Expected.Staking.Sha.Substring(0,12))";Storage="$project-storage:$($devopsSha.Substring(0,12))";File="$project-file:$($devopsSha.Substring(0,12))";Push="$project-push:$($devopsSha.Substring(0,12))";Calls="$project-calls:$($devopsSha.Substring(0,12))";Test="$project-test:$($Expected.E2E.Sha.Substring(0,12))"}
    return [ordered]@{Receipt=$receipt;Sources=$sources;Contexts=$contexts;RunDirectory=$runDirectory;SecretDirectory=$secretDirectory;ManifestPath=$manifestPath;Contracts=$contracts;Images=$images;ForeignBefore=$foreignBefore}
}

function Invoke-VerifyOrDown([switch]$Remove) {
    $context=Get-RetainedContext -ForDown:$Remove # all authority validation precedes the first Docker call
    Set-ComposeEnvironment (New-ComposeContext $context.Receipt.project $context.Receipt.nonce $context.SecretDirectory $context.Sources $context.Contexts $context.Images $context.Contracts);$observed=Get-ImageReceipt $context.Images $context.Sources $context.Receipt.nonce
    foreach($expectedImage in $context.Receipt.images){$actual=@($observed|Where-Object{$_.role-eq$expectedImage.role});if($actual.Count-ne1-or$actual[0].id-ne$expectedImage.id){throw 'P15C retained image differs from receipt.'}}
    if(-not$Remove){Invoke-NodeQuiet @((Join-Path $PSScriptRoot 'p15c-local-contract-manifest.mjs'),'validate',$context.ManifestPath,"http://127.0.0.1:$($Ports.Contracts)");Assert-Runtime $context.Receipt.project;return}
    Invoke-OwnedResourceCleanup $context.Receipt.project $context.Receipt.nonce @($context.Receipt.images) $context.ForeignBefore $context.RunDirectory;Complete-RetainedStateCleanup $context $EvidencePath
}

try {switch($Action){'Run'{Invoke-Run};'Verify'{if($KeepRunning){throw 'KeepRunning is valid only for Run.'};Invoke-VerifyOrDown};'Down'{if($KeepRunning){throw 'KeepRunning is valid only for Run.'};Invoke-VerifyOrDown -Remove}}}
finally {Clear-P15CEnvironment}
