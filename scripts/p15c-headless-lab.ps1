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
    XNode = [ordered]@{ Sha='a8fe6165d2392831c9450c0107fa00efb081ec66'; Tree='ee32782ff810c8b9c4c6f0a893b485ef7edd9396'; Path='C:\Work\DeepSession\XPointLabs\xnode' }
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
$CommonPlan = @(
    'source-preflight', 'collision-check', 'foreign-snapshot', 'image-preflight',
    'generate-secrets', 'source-export', 'compose-config', 'build',
    'up-contracts', 'deploy-contracts', 'up-runtime', 'probe', 'e2e',
    'labels'
)
$NormalPlan = @($CommonPlan) + @('cleanup','evidence')
$RetainedPlan = @($CommonPlan) + @('receipt-retained')
$RuntimeServices = @('contracts-devnet','xnode-1','xnode-2','xnode-3','registry','staking-backend','storage','file','push','calls')
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
        $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
            $sid,
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            $inheritance,
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow
        )
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

function Initialize-P15CNativePublication {
    if ($null -ne ('P15CNativePublication' -as [type])) { return }
    Add-Type -Path (Join-Path $PSScriptRoot 'P15C.NativePublication.cs')
}

function Remove-ExclusivelyCreatedFile($Record) {
    if ($null -eq $Record -or $Record.created -ne $true -or $Record.expectedSha256 -notmatch '^[0-9a-f]{64}$') { throw 'P15C owned output record is invalid.' }
    if ($null -ne $Record.PSObject.Properties['lease'] -and $null -ne $Record.lease) {
        $Record.lease.Rollback()
        $Record.lease = $null
        return
    }
    $full = [System.IO.Path]::GetFullPath([string]$Record.path)
    if ($full -ne [string]$Record.path -or -not (Test-Path -LiteralPath $full -PathType Leaf)) { throw 'P15C owned output no longer names an exact file.' }
    $item = Get-Item -LiteralPath $full -Force
    if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or (Get-FileSha256 $full) -ne $Record.expectedSha256) { throw 'P15C owned output binding changed; refusing deletion.' }
    [System.IO.File]::Delete($full)
}

function Commit-OwnedOutput($Record) {
    if ($null -eq $Record -or $null -eq $Record.PSObject.Properties['lease'] -or $null -eq $Record.lease) {
        throw 'P15C published output lease is absent.'
    }
    $Record.lease.Commit()
    $Record.lease = $null
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
    $wrongImage = $NodeImage -ne $ExpectedNodeImage `
        -or $DotnetSdkImage -ne $ExpectedSdkImage `
        -or $DotnetRuntimeImage -ne $ExpectedRuntimeImage
    if ($wrongImage) {
        throw 'P15C image lock differs from the accepted local ARM64 digest.'
    }
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
        $source = $Sources[$name]
        Invoke-NodeQuiet @(
            (Join-Path $PSScriptRoot 'p15c-source-export.mjs'),
            'export',
            $source.Path,
            $source.Sha,
            $source.Tree,
            $destination,
            $RunDirectory
        )
        if (-not (Test-Path -LiteralPath $destination -PathType Container)) {
            throw 'P15C isolated exact source export is missing.'
        }
        if (Test-Path -LiteralPath (Join-Path $destination '.git')) {
            throw 'P15C isolated exact source export contains Git metadata.'
        }
        Protect-P15CAuthorityFile $destination -Directory
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

function Get-DockerLabelValue($Labels,[string]$Name) {
    if ($null -eq $Labels) { return '' }
    $property = $Labels.PSObject.Properties[$Name]
    if ($null -eq $property -or $null -eq $property.Value) { return '' }
    return [string]$property.Value
}

function Get-ForeignInventory([string]$Project) {
    $containers = [Collections.Generic.List[string]]::new()
    foreach ($id in @(Invoke-DockerCapture @('container','ls','-aq','--no-trunc'))) {
        if ($id -notmatch '^[0-9a-f]{12,64}$') { throw 'P15C foreign container id is invalid.' }
        $raw = (Invoke-DockerCapture @(
            'container', 'inspect', $id, '--format', '{{json .}}'
        ) -join '').Trim()
        $value = $raw | ConvertFrom-Json
        $projectLabel = Get-DockerLabelValue $value.Config.Labels `
            'com.docker.compose.project'
        $record = @(
            [string]$value.Id,
            [string]$value.Name,
            [string]$value.Image,
            $projectLabel
        ) -join '|'
        if ($projectLabel -ne $Project) { $containers.Add($record) }
    }
    $images = @(
        Invoke-DockerCapture @(
            'image', 'ls', '--no-trunc', '--digests', '--format',
            '{{.ID}}|{{.Repository}}|{{.Tag}}|{{.Digest}}'
        ) | Where-Object {
            $_ -notmatch "\|$([regex]::Escape($Project))-"
        } | Sort-Object
    )
    $networks = [Collections.Generic.List[string]]::new()
    foreach ($id in @(Invoke-DockerCapture @('network','ls','-q','--no-trunc'))) {
        $raw = (Invoke-DockerCapture @(
            'network', 'inspect', $id, '--format', '{{json .}}'
        ) -join '').Trim()
        $value = $raw | ConvertFrom-Json
        $projectLabel = Get-DockerLabelValue $value.Labels `
            'com.docker.compose.project'
        $record = @(
            [string]$value.Id,
            [string]$value.Name,
            [string]$value.Driver,
            [string]$value.Scope,
            $projectLabel
        ) -join '|'
        if ($projectLabel -ne $Project) { $networks.Add($record) }
    }
    $volumes = [Collections.Generic.List[string]]::new()
    foreach ($name in @(Invoke-DockerCapture @('volume','ls','-q'))) {
        $raw = (Invoke-DockerCapture @(
            'volume', 'inspect', $name, '--format', '{{json .}}'
        ) -join '').Trim()
        $value = $raw | ConvertFrom-Json
        $projectLabel = Get-DockerLabelValue $value.Labels `
            'com.docker.compose.project'
        $record = @(
            [string]$value.Name,
            [string]$value.Driver,
            $projectLabel
        ) -join '|'
        if ($projectLabel -ne $Project) { $volumes.Add($record) }
    }
    return [ordered]@{
        containers = @($containers | Sort-Object)
        images = $images
        networks = @($networks | Sort-Object)
        volumes = @($volumes | Sort-Object)
    } | ConvertTo-Json -Depth 4 -Compress
}

function Assert-ImageLock([string]$Reference,[string]$Kind,[string]$Project,[string]$Nonce) {
    $raw = (Invoke-DockerCapture @('image','inspect',$Reference,'--format','{{json .}}')) -join ''
    $image = $raw | ConvertFrom-Json
    $invalidImage = $image.Os -ne 'linux' `
        -or $image.Architecture -ne 'arm64' `
        -or $image.Id -notmatch '^sha256:[0-9a-f]{64}$' `
        -or @($image.RepoDigests) -notcontains $Reference
    if ($invalidImage) {
        throw 'P15C local image lock is missing or not Linux ARM64.'
    }
    $base = @(
        'run', '--rm', '--pull', 'never', '--platform', 'linux/arm64',
        '--network', 'none', '--read-only', '--cap-drop', 'ALL',
        '--security-opt', 'no-new-privileges:true',
        '--label', "com.docker.compose.project=$Project",
        '--label', "com.docker.compose.service=p15c-preflight-$Kind",
        '--label', "com.xpoint.p15c.ownership-nonce=$Nonce",
        $Reference
    )
    if ($Kind -eq 'sdk') {
        $versions = @(Invoke-DockerCapture ($base + @('dotnet','--list-sdks')) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        if ($versions.Count -ne 1 -or $versions[0] -notmatch '^10\.0\.301 \[[^\]]+\]$') { throw 'P15C SDK inventory is not exactly 10.0.301.' }
    } elseif ($Kind -eq 'runtime') {
        $versions = @(
            Invoke-DockerCapture ($base + @('dotnet', '--list-runtimes')) |
                Where-Object { $_ -match '^Microsoft\.(?:AspNetCore|NETCore)\.App ' } |
                ForEach-Object { ($_ -split ' \[')[0] } |
                Sort-Object
        )
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

function New-ComposeContext(
    [string]$Project,
    [string]$Nonce,
    [string]$SecretDirectory,
    [System.Collections.IDictionary]$Sources,
    [System.Collections.IDictionary]$Contexts,
    [System.Collections.IDictionary]$Images,
    $Contracts
) {
    return @{
        P15C_PROJECT_NAME = $Project
        P15C_OWNERSHIP_NONCE = $Nonce
        P15C_DEVOPS_SHA = $Sources.DevOps.Sha
        P15C_DEVOPS_TREE = $Sources.DevOps.Tree
        P15C_DEVOPS_CONTEXT = $Contexts.DevOps
        P15C_XNODE_CONTEXT = $Contexts.XNode
        P15C_XNODE_SHA = $Sources.XNode.Sha
        P15C_XNODE_TREE = $Sources.XNode.Tree
        P15C_E2E_CONTEXT = $Contexts.E2E
        P15C_E2E_SHA = $Sources.E2E.Sha
        P15C_E2E_TREE = $Sources.E2E.Tree
        P15C_REGISTRY_CONTEXT = $Contexts.Registry
        P15C_REGISTRY_SHA = $Sources.Registry.Sha
        P15C_REGISTRY_TREE = $Sources.Registry.Tree
        P15C_STAKING_CONTEXT = $Contexts.Staking
        P15C_STAKING_SHA = $Sources.Staking.Sha
        P15C_STAKING_TREE = $Sources.Staking.Tree
        P15C_CONTRACTS_CONTEXT = $Contexts.Contracts
        P15C_CONTRACTS_SHA = $Sources.Contracts.Sha
        P15C_CONTRACTS_TREE = $Sources.Contracts.Tree
        P15C_NODE_IMAGE = $ExpectedNodeImage
        P15C_DOTNET_SDK_IMAGE = $ExpectedSdkImage
        P15C_DOTNET_RUNTIME_IMAGE = $ExpectedRuntimeImage
        P15C_SECRET_DIR = $SecretDirectory
        P15C_XNODE_IMAGE_NAME = $Images.XNode
        P15C_CONTRACTS_IMAGE_NAME = $Images.Contracts
        P15C_REGISTRY_IMAGE_NAME = $Images.Registry
        P15C_STAKING_IMAGE_NAME = $Images.Staking
        P15C_STORAGE_IMAGE_NAME = $Images.Storage
        P15C_FILE_IMAGE_NAME = $Images.File
        P15C_PUSH_IMAGE_NAME = $Images.Push
        P15C_CALLS_IMAGE_NAME = $Images.Calls
        P15C_TEST_IMAGE_NAME = $Images.Test
        P15C_CONTRACTS_PORT = $Ports.Contracts
        P15C_XNODE1_PORT = $Ports.XNode1
        P15C_XNODE2_PORT = $Ports.XNode2
        P15C_XNODE3_PORT = $Ports.XNode3
        P15C_REGISTRY_PORT = $Ports.Registry
        P15C_STAKING_PORT = $Ports.Staking
        P15C_TOKEN_ADDRESS = if ($Contracts) {
            $Contracts.contracts.token
        } else { '' }
        P15C_REWARDS_ADDRESS = if ($Contracts) {
            $Contracts.contracts.serviceNodeRewards
        } else { '' }
        P15C_FACTORY_ADDRESS = if ($Contracts) {
            $Contracts.contracts.serviceNodeContributionFactory
        } else { '' }
        P15C_POOL_ADDRESS = if ($Contracts) {
            $Contracts.contracts.rewardRatePool
        } else { '' }
    }
}

function Invoke-P15CBuild([string]$Project,[string]$LogPath) {
    Invoke-DockerQuiet @(
        'compose', '-p', $Project, '-f', $ComposePath, 'build', '--no-cache'
    ) $LogPath
}

function Invoke-P15CUp([string]$Project,[string[]]$Services,[string]$LogPath) {
    $arguments = @(
        'compose', '-p', $Project, '-f', $ComposePath,
        'up', '-d', '--no-build', '--pull', 'never'
    ) + $Services
    Invoke-DockerQuiet $arguments $LogPath
}

function Wait-Http([string]$Url,[int]$Seconds=120) {
    $until = [DateTime]::UtcNow.AddSeconds($Seconds)
    do {
        try {
            $response = Invoke-WebRequest `
                -UseBasicParsing `
                -Uri $Url `
                -TimeoutSec 2
            if ($response.StatusCode -ge 200 -and $response.StatusCode -lt 300) {
                return
            }
        } catch {}
        Start-Sleep -Milliseconds 500
    } while ([DateTime]::UtcNow -lt $until)
    throw 'P15C HTTP readiness timed out.'
}

function Wait-RpcChain([int]$Seconds=120) {
    $until = [DateTime]::UtcNow.AddSeconds($Seconds)
    $body = @{jsonrpc='2.0';id=1;method='eth_chainId';params=@()} | ConvertTo-Json -Compress
    do {
        try {
            $value = Invoke-RestMethod `
                -Method Post `
                -Uri "http://127.0.0.1:$($Ports.Contracts)" `
                -ContentType 'application/json' `
                -Body $body `
                -TimeoutSec 2
            if ($value.result -eq '0x7a69') { return }
        } catch {}
        Start-Sleep -Milliseconds 500
    } while ([DateTime]::UtcNow -lt $until)
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
        @{
            Role = 'xnode'; Tag = $Images.XNode; SourceName = 'XNode'
            SourceLabel = 'xnode'; Source = $Sources.XNode
        },
        @{
            Role = 'contracts-devnet'; Tag = $Images.Contracts
            SourceName = 'Contracts'; SourceLabel = 'xpoint-staking-contracts'
            Source = $Sources.Contracts
        },
        @{
            Role = 'registry'; Tag = $Images.Registry; SourceName = 'Registry'
            SourceLabel = 'deep-registry-api'; Source = $Sources.Registry
        },
        @{
            Role = 'staking-backend'; Tag = $Images.Staking; SourceName = 'Staking'
            SourceLabel = 'xpoint-staking-backend'; Source = $Sources.Staking
        },
        @{
            Role = 'storage'; Tag = $Images.Storage; SourceName = 'DevOps'
            SourceLabel = 'deep-devops'; Source = $Sources.DevOps
        },
        @{
            Role = 'file'; Tag = $Images.File; SourceName = 'DevOps'
            SourceLabel = 'deep-devops'; Source = $Sources.DevOps
        },
        @{
            Role = 'push'; Tag = $Images.Push; SourceName = 'DevOps'
            SourceLabel = 'deep-devops'; Source = $Sources.DevOps
        },
        @{
            Role = 'calls'; Tag = $Images.Calls; SourceName = 'DevOps'
            SourceLabel = 'deep-devops'; Source = $Sources.DevOps
        },
        @{
            Role = 'test-client'; Tag = $Images.Test; SourceName = 'E2E'
            SourceLabel = 'deep-tests-e2e'; Source = $Sources.E2E
        }
    )
    $result = foreach ($binding in $bindings) {
        $image=((Invoke-DockerCapture @('image','inspect',$binding.Tag,'--format','{{json .}}')) -join '') | ConvertFrom-Json
        $labels=$image.Config.Labels
        $invalid = $image.Os -ne 'linux' `
            -or $image.Architecture -ne 'arm64' `
            -or $image.Id -notmatch '^sha256:[0-9a-f]{64}$' `
            -or $labels.'org.opencontainers.image.revision' -ne $binding.Source.Sha `
            -or $labels.'org.opencontainers.image.source-tree' -ne $binding.Source.Tree `
            -or $labels.'org.opencontainers.image.source' -ne $binding.SourceLabel `
            -or $labels.'com.xpoint.p15c.role' -ne $binding.Role `
            -or $labels.'com.xpoint.evidence-class' -ne 'headless-harness' `
            -or $labels.'com.xpoint.product-runtime' -ne 'false' `
            -or $labels.'com.xpoint.p15c.ownership-nonce' -ne $Nonce
        if ($invalid) { throw 'P15C built image label gate failed.' }
        [ordered]@{role=$binding.Role;source=$binding.SourceName;sha=$binding.Source.Sha;tree=$binding.Source.Tree;id=$image.Id}
    }
    return @($result)
}

function New-ReceiptExpectation([System.Collections.IDictionary]$Sources,[string[]]$Roles,[string]$Project,[string]$Nonce,[string]$ComposeSha,[string]$ManifestSha,[string]$ForeignSha) {
    $pins=[ordered]@{}; foreach($name in $Sources.Keys){$pins[$name]=[ordered]@{sha=$Sources[$name].Sha;tree=$Sources[$name].Tree}}
    $value=[ordered]@{sources=$pins;roles=@($Roles)}
    if ($Project) { $value.project = $Project }
    if ($Nonce) { $value.nonce = $Nonce }
    if ($ComposeSha) { $value.composeSha256 = $ComposeSha }
    if ($ManifestSha) { $value.manifestSha256 = $ManifestSha }
    if ($ForeignSha) { $value.foreignSnapshotSha256 = $ForeignSha }
    return ($value | ConvertTo-Json -Depth 8 -Compress)
}

function Add-DockerIds(
    [Collections.Generic.HashSet[string]]$Set,
    [string[]]$Arguments
) {
    foreach ($id in @(Invoke-DockerCapture $Arguments)) {
        if (-not [string]::IsNullOrWhiteSpace($id)) {
            [void]$Set.Add($id.Trim())
        }
    }
}

function Get-ExpectedImageIds($OwnedImages) {
    if ($null -eq $OwnedImages) { return @() }
    return @(
        $OwnedImages |
            ForEach-Object { $_.id } |
            Where-Object { $_ -match '^sha256:[0-9a-f]{64}$' } |
            Sort-Object -Unique
    )
}

function Get-OwnedResourceInventory(
    [string]$Project,
    [string]$Nonce,
    $OwnedImages,
    [switch]$AllowPartial
) {
    $result = [Collections.Generic.List[object]]::new()
    $containerIds = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    Add-DockerIds $containerIds @(
        'container', 'ls', '-aq', '--no-trunc', '--filter',
        "label=com.docker.compose.project=$Project"
    )
    Add-DockerIds $containerIds @(
        'container', 'ls', '-aq', '--no-trunc', '--filter',
        "label=com.xpoint.p15c.ownership-nonce=$Nonce"
    )
    foreach ($id in $containerIds) {
        $raw = (Invoke-DockerCapture @(
            'container', 'inspect', $id, '--format', '{{json .}}'
        ) -join '')
        $value = $raw | ConvertFrom-Json
        $labels = $value.Config.Labels
        $result.Add([pscustomobject][ordered]@{
            kind = 'container'
            id = [string]$value.Id
            name = [string]$value.Name
            project = [string]$labels.'com.docker.compose.project'
            nonce = [string]$labels.'com.xpoint.p15c.ownership-nonce'
            role = [string]$labels.'com.docker.compose.service'
        })
    }

    $networkIds = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    Add-DockerIds $networkIds @(
        'network', 'ls', '-q', '--no-trunc', '--filter',
        "label=com.docker.compose.project=$Project"
    )
    Add-DockerIds $networkIds @(
        'network', 'ls', '-q', '--no-trunc', '--filter',
        "label=com.xpoint.p15c.ownership-nonce=$Nonce"
    )
    foreach ($id in $networkIds) {
        $raw = (Invoke-DockerCapture @(
            'network', 'inspect', $id, '--format', '{{json .}}'
        ) -join '')
        $value = $raw | ConvertFrom-Json
        $result.Add([pscustomobject][ordered]@{
            kind = 'network'
            id = [string]$value.Id
            name = [string]$value.Name
            project = [string]$value.Labels.'com.docker.compose.project'
            nonce = [string]$value.Labels.'com.xpoint.p15c.ownership-nonce'
            role = [string]$value.Labels.'com.docker.compose.network'
        })
    }

    $volumeNames = @(
        Invoke-DockerCapture @(
            'volume', 'ls', '-q', '--filter',
            "label=com.docker.compose.project=$Project"
        )
    )
    $volumeNames += @(
        Invoke-DockerCapture @(
            'volume', 'ls', '-q', '--filter',
            "label=com.xpoint.p15c.ownership-nonce=$Nonce"
        )
    )
    $volumeNames = @($volumeNames | Where-Object { $_ } | Sort-Object -Unique)
    if ($volumeNames.Count) {
        throw 'P15C named volumes are prohibited and cannot be cleanup targets.'
    }

    $imageIds = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    Add-DockerIds $imageIds @(
        'image', 'ls', '-q', '--no-trunc', '--filter',
        "label=com.xpoint.p15c.ownership-nonce=$Nonce"
    )
    Add-DockerIds $imageIds @(
        'image', 'ls', '-q', '--no-trunc', "$Project-*"
    )
    foreach ($id in @(Get-ExpectedImageIds $OwnedImages)) {
        [void]$imageIds.Add($id)
    }
    foreach ($id in $imageIds) {
        $raw = (Invoke-DockerCapture @(
            'image', 'inspect', $id, '--format', '{{json .}}'
        ) -join '')
        $value = $raw | ConvertFrom-Json
        $labels = $value.Config.Labels
        $result.Add([pscustomobject][ordered]@{
            kind = 'image'
            id = [string]$value.Id
            name = [string]$labels.'com.xpoint.p15c.role'
            project = $Project
            nonce = [string]$labels.'com.xpoint.p15c.ownership-nonce'
            role = [string]$labels.'com.xpoint.p15c.role'
        })
    }

    Assert-OwnedResourceInventory $result.ToArray() $Project $Nonce -AllowPartial:$AllowPartial
    return @($result)
}

function Assert-OwnedResourceInventory(
    [object[]]$Inventory,
    [string]$Project,
    [string]$Nonce,
    [switch]$AllowPartial
) {
    if (-not $AllowPartial -and $Inventory.Count -eq 0) {
        throw 'P15C exact owned resource inventory is empty.'
    }
    $containerRoles = @($RuntimeServices)
    if ($AllowPartial) {
        $containerRoles += @(
            'test-client',
            'p15c-preflight-sdk',
            'p15c-preflight-runtime',
            'p15c-preflight-node'
        )
    }
    $allowed = @{
        container = $containerRoles
        network = @('runtime')
        image = @($ImageRoles)
    }
    $keys = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $roles = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($resource in $Inventory) {
        $key = "$($resource.kind):$($resource.id)"
        $roleKey = "$($resource.kind):$($resource.role)"
        if ($resource.project -ne $Project -or $resource.nonce -ne $Nonce) {
            throw 'P15C owned resource project or nonce binding is invalid.'
        }
        if (-not $allowed.ContainsKey($resource.kind)) {
            throw 'P15C owned resource kind is invalid.'
        }
        if ($resource.role -notin $allowed[$resource.kind]) {
            throw 'P15C injected same-project resource role exists.'
        }
        if (-not $keys.Add($key) -or -not $roles.Add($roleKey)) {
            throw 'P15C duplicate owned resource identity or role exists.'
        }
    }
    if (-not $AllowPartial) {
        foreach ($kind in @('container', 'network', 'image')) {
            $actual = @(
                $Inventory |
                    Where-Object kind -eq $kind |
                    ForEach-Object role |
                    Sort-Object
            )
            $expected = @($allowed[$kind] | Sort-Object)
            if (($actual -join "`n") -ne ($expected -join "`n")) {
                throw 'P15C exact owned resource topology is incomplete.'
            }
        }
    }
}

function Get-ResourceKey($Resource) {
    return "$($Resource.kind):$($Resource.id)"
}

function Assert-InventoryKeysEqual([object[]]$Expected,[object[]]$Actual) {
    $expectedKeys = @($Expected | ForEach-Object { Get-ResourceKey $_ } | Sort-Object)
    $actualKeys = @($Actual | ForEach-Object { Get-ResourceKey $_ } | Sort-Object)
    if (($expectedKeys -join "`n") -ne ($actualKeys -join "`n")) {
        throw 'P15C owned membership changed after cleanup capture.'
    }
}

function Assert-ResourceStillOwned($Expected,[string]$Project,[string]$Nonce) {
    $current = @(Get-OwnedResourceInventory $Project $Nonce @($Expected) -AllowPartial)
    $matching = @(
        $current |
            Where-Object { (Get-ResourceKey $_) -eq (Get-ResourceKey $Expected) }
    )
    if ($matching.Count -ne 1) {
        throw 'P15C exact cleanup resource disappeared or changed identity.'
    }
    foreach ($property in @('kind', 'id', 'name', 'project', 'nonce', 'role')) {
        if ([string]$matching[0].$property -cne [string]$Expected.$property) {
            throw 'P15C cleanup resource ownership changed before removal.'
        }
    }
}

function Remove-ExactOwnedResource($Resource,[string]$LogPath) {
    $arguments = switch ($Resource.kind) {
        'container' { @('container', 'rm', '--force', $Resource.id) }
        'network' { @('network', 'rm', $Resource.id) }
        'image' { @('image', 'rm', $Resource.id) }
        default { throw 'P15C cleanup resource kind is invalid.' }
    }
    & docker @arguments *>> $LogPath
    if ($LASTEXITCODE -ne 0) {
        throw 'P15C exact owned resource removal failed.'
    }
}

function Assert-ZeroOwned([string]$Project,[string]$Nonce) {
    $inventory = @(Get-OwnedResourceInventory $Project $Nonce @() -AllowPartial)
    if ($inventory.Count) {
        throw 'P15C owned Docker resources remain after cleanup.'
    }
}

function Invoke-OwnedResourceCleanup(
    [string]$Project,
    [string]$Nonce,
    [object[]]$OwnedImages,
    [string]$ForeignBefore,
    [string]$RunDirectory,
    [ref]$ResourcesClean,
    [switch]$AllowPartial
) {
    $captured = @(
        Get-OwnedResourceInventory $Project $Nonce $OwnedImages -AllowPartial:$AllowPartial
    )
    if ($captured.Count -eq 0) {
        throw 'P15C cleanup has no captured owned resource evidence.'
    }
    $remaining = [Collections.Generic.List[object]]::new()
    foreach ($resource in $captured) { $remaining.Add($resource) }
    if (@($captured | Where-Object kind -eq 'volume').Count) {
        throw 'P15C named volumes are not removable ownership authority.'
    }
    $order = @{ container = 0; network = 1; image = 2 }
    $logPath = Join-Path $RunDirectory 'exact-resource-cleanup.log'
    foreach ($resource in @(
        $captured | Sort-Object @{ Expression = { $order[$_.kind] } }, kind, id
    )) {
        $current = @(
            Get-OwnedResourceInventory `
                $Project `
                $Nonce `
                $remaining.ToArray() `
                -AllowPartial
        )
        Assert-InventoryKeysEqual $remaining.ToArray() $current
        Assert-ResourceStillOwned $resource $Project $Nonce
        Remove-ExactOwnedResource $resource $logPath
        [void]$remaining.Remove($resource)
    }
    Assert-ZeroOwned $Project $Nonce
    $ResourcesClean.Value = $true
    if ((Get-ForeignInventory $Project) -ne $ForeignBefore) {
        throw 'P15C foreign Docker identity or membership changed.'
    }
}

function Remove-OwnedRunDirectory([string]$Directory) {
    $base = [IO.Path]::GetFullPath(
        (Join-Path $env:LOCALAPPDATA 'Deep\P15C')
    ).TrimEnd('\') + '\'
    $full = [IO.Path]::GetFullPath($Directory)
    $marker = Join-Path $full '.p15c-run-owner'
    if (-not $full.StartsWith($base, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'P15C run directory is outside its owned base.'
    }
    if (-not (Test-Path -LiteralPath $marker -PathType Leaf)) {
        throw 'P15C run directory ownership marker is missing.'
    }
    if ([IO.File]::ReadAllText($marker) -ne 'deep-p15c-run.v1') {
        throw 'P15C run directory ownership marker is invalid.'
    }
    Assert-ProtectedAcl $full
    Assert-ProtectedAcl $marker
    [IO.Directory]::Delete($full, $true)
}

function Assert-RunDirectoryOutsideRepositories(
    [string]$Directory,
    [System.Collections.IDictionary]$Sources
) {
    $full = [IO.Path]::GetFullPath($Directory).TrimEnd('\') + '\'
    foreach ($source in $Sources.Values) {
        $repo = [IO.Path]::GetFullPath($source.Path).TrimEnd('\') + '\'
        if ($full.StartsWith($repo, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'P15C run directory enters a source repository.'
        }
        if ($repo.StartsWith($full, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'P15C run directory contains a source repository.'
        }
    }
}

function Assert-NoReparseOutputPath([string]$Path) {
    $full = [IO.Path]::GetFullPath($Path)
    if (Test-Path -LiteralPath $full) {
        $item = Get-Item -LiteralPath $full -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'P15C output path must not be a reparse point.'
        }
    }
    $current = [IO.Path]::GetDirectoryName($full)
    if ([string]::IsNullOrWhiteSpace($current)) {
        throw 'P15C output parent directory is missing.'
    }
    if (-not (Test-Path -LiteralPath $current -PathType Container)) {
        throw 'P15C output parent directory must already exist.'
    }
    while ($current) {
        $item = Get-Item -LiteralPath $current -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'P15C output path traverses a reparse point.'
        }
        $parent = [IO.Directory]::GetParent($current)
        if ($null -eq $parent) { break }
        $current = $parent.FullName
    }
}

function Assert-OutputOutsideRepositories(
    [string]$Path,
    [System.Collections.IDictionary]$Sources,
    [string]$RunDirectory
) {
    if (-not [IO.Path]::IsPathRooted($Path)) {
        throw 'P15C output path must be absolute.'
    }
    if ($Path -match '(?:^|[\\/])\.\.(?:[\\/]|$)') {
        throw 'P15C output path must not contain parent traversal.'
    }
    $full = [IO.Path]::GetFullPath($Path)
    if (-not $Path.Equals($full, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'P15C output path must already be canonical.'
    }
    Assert-NoReparseOutputPath $full
    foreach ($source in $Sources.Values) {
        $repo = [IO.Path]::GetFullPath($source.Path).TrimEnd('\') + '\'
        if ($full.StartsWith($repo, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'P15C output enters a source repository.'
        }
    }
    $run = [IO.Path]::GetFullPath($RunDirectory).TrimEnd('\') + '\'
    if ($full.StartsWith($run, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'P15C output enters the owned run tree.'
    }
}

function Assert-DistinctOutputPaths([string]$Left,[string]$Right) {
    $leftFull = [IO.Path]::GetFullPath($Left)
    $rightFull = [IO.Path]::GetFullPath($Right)
    if ($leftFull.Equals($rightFull, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'P15C evidence and receipt paths must be distinct.'
    }
}

function Publish-OwnedOutput(
    $Record,
    [string]$Destination,
    [System.Collections.IDictionary]$Sources,
    [string]$RunDirectory
) {
    $destinationFull = [IO.Path]::GetFullPath($Destination)
    $runBoundary = [IO.Path]::GetFullPath($RunDirectory).TrimEnd('\') + '\'
    if (-not $Record.path.StartsWith(
        $runBoundary,
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw 'P15C staged output is outside the protected run tree.'
    }
    for ($pass = 0; $pass -lt 2; $pass++) {
        Assert-OutputOutsideRepositories $destinationFull $Sources $RunDirectory
        if (Test-Path -LiteralPath $destinationFull) {
            throw 'P15C refuses to overwrite an output destination.'
        }
    }
    if ((Get-FileSha256 $Record.path) -ne $Record.expectedSha256) {
        throw 'P15C staged output changed before publication.'
    }
    Initialize-P15CNativePublication
    $lease = [P15CNativePublication]::MoveNoReplaceVerified(
        [string]$Record.path,
        $destinationFull,
        [string]$Record.expectedSha256
    )
    return [pscustomobject]@{
        created = $true
        path = $destinationFull
        expectedSha256 = [string]$Record.expectedSha256
        lease = $lease
    }
}

function Assert-SecretDirectoryOwnership([string]$Directory) {
    $marker = Join-Path $Directory '.p15c-secret-owner'
    if (-not (Test-Path -LiteralPath $marker -PathType Leaf)) {
        throw 'P15C retained secret marker is missing.'
    }
    if ([IO.File]::ReadAllText($marker) -ne 'deep-p15c-ephemeral-secrets.v1') {
        throw 'P15C retained secret marker is invalid.'
    }
    $expectedNames = @(
        '.p15c-secret-owner',
        'node-1.config.json', 'node-1.seed',
        'node-2.config.json', 'node-2.seed',
        'node-3.config.json', 'node-3.seed'
    ) | Sort-Object
    $actualNames = @(
        Get-ChildItem -LiteralPath $Directory -Force |
            ForEach-Object Name |
            Sort-Object
    )
    if (($actualNames -join "`n") -ne ($expectedNames -join "`n")) {
        throw 'P15C retained secret directory has missing or extra entries.'
    }
    Assert-ProtectedAcl $Directory
    Assert-ProtectedAcl $marker
    $seeds = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $routers = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($index in 1..3) {
        $seedPath = Join-Path $Directory "node-$index.seed"
        $configPath = Join-Path $Directory "node-$index.config.json"
        Assert-ProtectedAcl $seedPath
        Assert-ProtectedAcl $configPath
        $seed = ([IO.File]::ReadAllText($seedPath)).Trim()
        if ($seed -notmatch '^[0-9a-f]{64}$' -or -not $seeds.Add($seed)) {
            throw 'P15C retained seed is malformed or duplicated.'
        }
        $config = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
        if ((@($config.psobject.Properties.Name) -join ',') -ne 'Node') {
            throw 'P15C retained public configuration envelope is malformed.'
        }
        if ((@($config.Node.psobject.Properties.Name) -join ',') -ne 'RouterId') {
            throw 'P15C retained router configuration is malformed.'
        }
        if ($config.Node.RouterId -notmatch '^[0-9a-f]{64}$') {
            throw 'P15C retained router identity shape is malformed.'
        }
        if (-not $routers.Add($config.Node.RouterId)) {
            throw 'P15C retained router identity is duplicated.'
        }
    }
}

function Assert-ForeignSnapshot([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw 'P15C retained foreign snapshot is missing.'
    }
    Assert-ProtectedAcl $Path
    $raw = [IO.File]::ReadAllText($Path)
    $value = $raw | ConvertFrom-Json
    $names = @($value.psobject.Properties.Name | Sort-Object) -join ','
    if ($names -ne 'containers,images,networks,volumes') {
        throw 'P15C retained foreign snapshot is malformed.'
    }
    foreach ($name in @('containers', 'images', 'networks', 'volumes')) {
        if ($null -eq $value.$name) {
            throw 'P15C retained foreign snapshot is incomplete.'
        }
    }
    return $raw
}

function New-Evidence([string]$Path) {
    $input = "$Path.input"
    $inputRecord = $null
    $outputRecord = $null
    $value = [ordered]@{
        schema = 'deep-p15c-headless-evidence.v1'
        evidenceClass = 'headless-harness'
        productRuntime = $false
        result = 'pass'
        gates = [ordered]@{
            source = 'pass'
            images = 'pass'
            contracts = 'pass'
            runtime = 'pass'
            e2e = 'pass'
            cleanup = 'pass'
        }
        counts = [ordered]@{
            services = 11
            xnodes = 3
            localContracts = 4
        }
    }
    try {
        $inputRecord = Write-NewUtf8File $input ($value | ConvertTo-Json -Depth 8)
        Invoke-NodeQuiet @(
            (Join-Path $PSScriptRoot 'p15c-evidence-sanitizer.mjs'),
            'write', $input, $Path
        )
        Protect-P15CAuthorityFile $Path
        $outputRecord = [pscustomobject]@{
            created = $true
            path = [IO.Path]::GetFullPath($Path)
            expectedSha256 = Get-FileSha256 $Path
        }
    } catch {
        if ($null -ne $outputRecord -and (Test-Path -LiteralPath $outputRecord.path)) {
            Remove-ExclusivelyCreatedFile $outputRecord
        }
        throw
    } finally {
        if ($null -ne $inputRecord -and (Test-Path -LiteralPath $inputRecord.path)) {
            Remove-ExclusivelyCreatedFile $inputRecord
        }
    }
    return $outputRecord
}

function Invoke-FailedRunCleanup(
    [string]$Project,
    [string]$Nonce,
    [string]$RunDirectory,
    [string]$SecretDirectory,
    $Images,
    [string]$ForeignBefore,
    [bool]$MutationStarted,
    [bool]$ResourcesClean,
    [Collections.Generic.List[object]]$OwnedOutputs
) {
    $failures = [Collections.Generic.List[Exception]]::new()
    $cleanupState = $ResourcesClean
    if ($MutationStarted -and -not $ResourcesClean) {
        try {
            Invoke-OwnedResourceCleanup `
                $Project `
                $Nonce `
                $Images `
                $ForeignBefore `
                $RunDirectory `
                ([ref]$cleanupState) `
                -AllowPartial
        } catch {
            $failures.Add($_.Exception)
        }
    }
    $mayRemoveSecrets = $cleanupState -or -not $MutationStarted
    if ($mayRemoveSecrets -and (Test-Path -LiteralPath $SecretDirectory)) {
        try {
            & (Join-Path $PSScriptRoot 'p15c-ephemeral-secrets.ps1') `
                -Action Remove `
                -RunDirectory $SecretDirectory
        } catch {
            $failures.Add($_.Exception)
        }
    }
    foreach ($record in $OwnedOutputs) {
        if ($failures.Count -eq 0 -and (Test-Path -LiteralPath $record.path)) {
            try { Remove-ExclusivelyCreatedFile $record }
            catch { $failures.Add($_.Exception) }
        }
    }
    if ($failures.Count -eq 0 -and (Test-Path -LiteralPath $RunDirectory)) {
        try { Remove-OwnedRunDirectory $RunDirectory }
        catch { $failures.Add($_.Exception) }
    }
    return $failures
}

function New-P15CSources(
    [string]$DevOpsSha,
    [string]$DevOpsTree,
    [switch]$InvocationPaths
) {
    $paths = if ($InvocationPaths) {
        @{
            XNode = [IO.Path]::GetFullPath($XNodePath)
            E2E = [IO.Path]::GetFullPath($E2EPath)
            Registry = [IO.Path]::GetFullPath($RegistryPath)
            Staking = [IO.Path]::GetFullPath($StakingPath)
            Contracts = [IO.Path]::GetFullPath($ContractsPath)
        }
    } else {
        @{
            XNode = $Expected.XNode.Path
            E2E = $Expected.E2E.Path
            Registry = $Expected.Registry.Path
            Staking = $Expected.Staking.Path
            Contracts = $Expected.Contracts.Path
        }
    }
    return [ordered]@{
        DevOps = [ordered]@{ Sha = $DevOpsSha; Tree = $DevOpsTree; Path = $Root }
        XNode = [ordered]@{
            Sha = $Expected.XNode.Sha
            Tree = $Expected.XNode.Tree
            Path = $paths.XNode
        }
        E2E = [ordered]@{
            Sha = $Expected.E2E.Sha
            Tree = $Expected.E2E.Tree
            Path = $paths.E2E
        }
        Registry = [ordered]@{
            Sha = $Expected.Registry.Sha
            Tree = $Expected.Registry.Tree
            Path = $paths.Registry
        }
        Staking = [ordered]@{
            Sha = $Expected.Staking.Sha
            Tree = $Expected.Staking.Tree
            Path = $paths.Staking
        }
        Contracts = [ordered]@{
            Sha = $Expected.Contracts.Sha
            Tree = $Expected.Contracts.Tree
            Path = $paths.Contracts
        }
    }
}

function New-P15CImageNames([string]$Project,[string]$DevOpsSha) {
    return [ordered]@{
        XNode = "$Project-xnode:$($Expected.XNode.Sha.Substring(0, 12))"
        Contracts = "$Project-contracts:$($Expected.Contracts.Sha.Substring(0, 12))"
        Registry = "$Project-registry:$($Expected.Registry.Sha.Substring(0, 12))"
        Staking = "$Project-staking:$($Expected.Staking.Sha.Substring(0, 12))"
        Storage = "$Project-storage:$($DevOpsSha.Substring(0, 12))"
        File = "$Project-file:$($DevOpsSha.Substring(0, 12))"
        Push = "$Project-push:$($DevOpsSha.Substring(0, 12))"
        Calls = "$Project-calls:$($DevOpsSha.Substring(0, 12))"
        Test = "$Project-test:$($Expected.E2E.Sha.Substring(0, 12))"
    }
}

function Get-ProtectedFileBytesOnce([string]$Path) {
    Assert-ProtectedAcl $Path
    $stream = [IO.FileStream]::new(
        $Path,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::None
    )
    try {
        if ($stream.Length -gt 1MB) {
            throw 'P15C authority file is unexpectedly large.'
        }
        $bytes = [byte[]]::new([int]$stream.Length)
        $offset = 0
        while ($offset -lt $bytes.Length) {
            $count = $stream.Read($bytes, $offset, $bytes.Length - $offset)
            if ($count -eq 0) { throw 'P15C authority file read was truncated.' }
            $offset += $count
        }
        return ,$bytes
    } finally {
        $stream.Dispose()
    }
}

function Read-ValidatedReceiptOnce([string]$Path,[string]$Expectation) {
    $bytes = Get-ProtectedFileBytesOnce $Path
    $base = Join-Path $env:LOCALAPPDATA 'Deep\P15C'
    if (-not (Test-Path -LiteralPath $base -PathType Container)) {
        throw 'P15C owned authority base is missing.'
    }
    $directory = Join-Path $base ('.receipt-validation-' + (New-Hex 8))
    [void][IO.Directory]::CreateDirectory($directory)
    Protect-P15CAuthorityFile $directory -Directory
    $copy = Join-Path $directory 'receipt.json'
    try {
        [IO.File]::WriteAllBytes($copy, $bytes)
        Protect-P15CAuthorityFile $copy
        $summaryRaw = Invoke-NodeCapture @(
            (Join-Path $PSScriptRoot 'p15c-headless-contracts.mjs'),
            'summarize-receipt', $copy, $Expectation
        )
        return $summaryRaw | ConvertFrom-Json
    } finally {
        [Array]::Clear($bytes, 0, $bytes.Length)
        if (Test-Path -LiteralPath $directory) {
            [IO.Directory]::Delete($directory, $true)
        }
    }
}

function Assert-RetainedHashes($Context) {
    Assert-ProtectedAcl $ReceiptPath
    Assert-ProtectedAcl $Context.ManifestPath
    Assert-ProtectedAcl $Context.ForeignPath
    $bindings = @(
        @((Get-FileSha256 $ReceiptPath), $Context.ReceiptSha256),
        @((Get-FileSha256 $ComposePath), $Context.Receipt.composeSha256),
        @((Get-FileSha256 $Context.ManifestPath), $Context.Receipt.manifestSha256),
        @(
            (Get-FileSha256 $Context.ForeignPath),
            $Context.Receipt.foreignSnapshotSha256
        )
    )
    foreach ($binding in $bindings) {
        if ($binding[0] -cne $binding[1]) {
            throw 'P15C retained authority hash changed.'
        }
    }
}

function Complete-RetainedStateCleanup($Context,[string]$FinalEvidencePath) {
    Assert-RetainedHashes $Context
    & (Join-Path $PSScriptRoot 'p15c-ephemeral-secrets.ps1') `
        -Action Remove `
        -RunDirectory $Context.SecretDirectory
    $stagePath = Join-Path $Context.RunDirectory 'final-evidence.stage.json'
    if (Test-Path -LiteralPath $stagePath) {
        throw 'P15C staged evidence already exists.'
    }
    $stageRecord = New-Evidence $stagePath
    $receiptRecord = [pscustomobject]@{
        created = $true
        path = [IO.Path]::GetFullPath($ReceiptPath)
        expectedSha256 = $Context.ReceiptSha256
    }
    Remove-ExclusivelyCreatedFile $receiptRecord
    $publishedRecord = Publish-OwnedOutput `
        $stageRecord `
        $FinalEvidencePath `
        $Context.Sources `
        $Context.RunDirectory
    try {
        Remove-OwnedRunDirectory $Context.RunDirectory
    } catch {
        $stateError = $_.Exception
        try {
            Remove-ExclusivelyCreatedFile $publishedRecord
        } catch {
            throw [AggregateException]::new(
                'P15C state cleanup and published evidence rollback failed.',
                @($stateError, $_.Exception)
            )
        }
        throw $stateError
    }
    Commit-OwnedOutput $publishedRecord
}

function Invoke-Run {
    Assert-RunInputs
    $project = 'p15c-' + (New-Hex 8)
    $nonce = New-Hex 16
    $runDirectory = Join-Path `
        (Join-Path $env:LOCALAPPDATA 'Deep\P15C') `
        "$project-$nonce"
    $secretDirectory = Join-Path $runDirectory 'secrets'
    if (Test-Path -LiteralPath $runDirectory) {
        throw 'P15C owned run directory collision exists.'
    }
    [void][IO.Directory]::CreateDirectory($runDirectory)
    Protect-P15CAuthorityFile $runDirectory -Directory
    [void](Write-NewUtf8File `
        (Join-Path $runDirectory '.p15c-run-owner') `
        'deep-p15c-run.v1')
    $foreignBefore = $null
    $retained = $false
    $mutationStarted = $false
    $resourcesClean = $false
    $images = $null
    $imagesReceipt = @()
    $ownedOutputs = [Collections.Generic.List[object]]::new()
    $operations = [Collections.Generic.List[string]]::new()
    try {
        $devopsSha = Get-GitValue $Root @('rev-parse', 'HEAD')
        $devopsTree = Get-GitValue $Root @('rev-parse', 'HEAD^{tree}')
        $sources = New-P15CSources $devopsSha $devopsTree -InvocationPaths
        foreach ($name in @('XNode', 'E2E', 'Registry', 'Staking', 'Contracts')) {
            $acceptedPath = [IO.Path]::GetFullPath($Expected[$name].Path)
            if ($sources[$name].Path -ne $acceptedPath) {
                throw 'P15C source path differs from invocation contract.'
            }
        }
        Assert-RunDirectoryOutsideRepositories $runDirectory $sources
        Assert-OutputOutsideRepositories $EvidencePath $sources $runDirectory
        Assert-OutputOutsideRepositories $ReceiptPath $sources $runDirectory
        Assert-DistinctOutputPaths $EvidencePath $ReceiptPath

        $sourceManifest = Join-Path $runDirectory 'sources.json'
        [void](New-SourceManifest $sourceManifest $sources)
        Assert-SourcePreflight $sourceManifest
        $operations.Add('source-preflight')

        Assert-NoCollision $project $nonce
        $operations.Add('collision-check')
        $foreignPath = Join-Path $runDirectory 'foreign-before.json'
        $foreignBefore = Get-ForeignInventory $project
        [void](Write-NewUtf8File $foreignPath $foreignBefore)
        $operations.Add('foreign-snapshot')

        $mutationStarted = $true
        Assert-EngineArchitecture
        Assert-ImageLock $DotnetSdkImage 'sdk' $project $nonce
        Assert-ImageLock $DotnetRuntimeImage 'runtime' $project $nonce
        Assert-ImageLock $NodeImage 'node' $project $nonce
        $operations.Add('image-preflight')

        & (Join-Path $PSScriptRoot 'p15c-ephemeral-secrets.ps1') `
            -Action Generate `
            -RunDirectory $secretDirectory
        $operations.Add('generate-secrets')
        $contexts = New-ExactSourceExports $sources $runDirectory
        $operations.Add('source-export')
        foreach ($port in $Ports.Values) { Assert-PortAvailable $port }

        $images = New-P15CImageNames $project $devopsSha
        $composeContext = New-ComposeContext `
            $project $nonce $secretDirectory $sources $contexts $images $null
        Set-ComposeEnvironment $composeContext
        $composeModel = Join-Path $runDirectory 'compose.json'
        & docker compose `
            -p $project `
            -f $ComposePath `
            config --format json *> $composeModel
        if ($LASTEXITCODE -ne 0) {
            throw 'P15C Compose configuration failed.'
        }
        Protect-P15CAuthorityFile $composeModel
        $composeExpected = @{ sha = $devopsSha; tree = $devopsTree } |
            ConvertTo-Json -Compress
        Invoke-NodeQuiet @(
            (Join-Path $PSScriptRoot 'p15c-headless-contracts.mjs'),
            'validate-compose', $composeModel, $composeExpected
        )
        $operations.Add('compose-config')
        Assert-P15COperationPlan $operations.ToArray() -Prefix
        Invoke-P15CBuild $project (Join-Path $runDirectory 'build.log')
        $operations.Add('build')
        Invoke-P15CUp `
            $project `
            @('contracts-devnet') `
            (Join-Path $runDirectory 'up-contracts.log')
        Wait-RpcChain
        $operations.Add('up-contracts')

        $composeExec = @(
            'compose', '-p', $project, '-f', $ComposePath,
            'exec', '-T', 'contracts-devnet',
            'pnpm', 'exec', 'hardhat', 'run'
        )
        Invoke-DockerQuiet `
            ($composeExec + @('scripts/deploy-local-devnet.js', '--network', 'localhost')) `
            (Join-Path $runDirectory 'deploy.log')
        Invoke-DockerQuiet `
            ($composeExec + @('scripts/local-devnet-smoke.js', '--network', 'localhost')) `
            (Join-Path $runDirectory 'contract-smoke.log')
        $contractContainer = (Invoke-DockerCapture @(
            'compose', '-p', $project, '-f', $ComposePath,
            'ps', '-q', 'contracts-devnet'
        ) -join '').Trim()
        if ($contractContainer -notmatch '^[0-9a-f]{12,64}$') {
            throw 'P15C contract container id is invalid.'
        }
        $rawManifest = Join-Path $runDirectory 'localhost.raw.json'
        Invoke-DockerQuiet @(
            'cp',
            "$contractContainer`:/workspace/deployments/localhost.latest.json",
            $rawManifest
        ) (Join-Path $runDirectory 'copy-manifest.log')
        $localManifest = Join-Path $runDirectory 'localhost.validated.json'
        Invoke-NodeQuiet @(
            (Join-Path $PSScriptRoot 'p15c-local-contract-manifest.mjs'),
            'normalize', $rawManifest, $localManifest,
            "http://127.0.0.1:$($Ports.Contracts)"
        )
        Protect-P15CAuthorityFile $localManifest
        [IO.File]::Delete($rawManifest)
        $contracts = Get-Content -LiteralPath $localManifest -Raw |
            ConvertFrom-Json
        $operations.Add('deploy-contracts')

        $runtimeContext = New-ComposeContext `
            $project $nonce $secretDirectory $sources $contexts $images $contracts
        Set-ComposeEnvironment $runtimeContext
        Invoke-P15CUp `
            $project `
            $RuntimeServices `
            (Join-Path $runDirectory 'up-runtime.log')
        $operations.Add('up-runtime')
        Assert-Runtime $project
        $operations.Add('probe')
        Invoke-DockerQuiet @(
            'compose', '-p', $project, '-f', $ComposePath,
            'run', '--rm', '--no-deps', 'test-client'
        ) (Join-Path $runDirectory 'e2e.log')
        $operations.Add('e2e')
        $imagesReceipt = Get-ImageReceipt $images $sources $nonce
        $operations.Add('labels')

        if ($KeepRunning) {
            $pins = [ordered]@{}
            foreach ($name in $sources.Keys) {
                $pins[$name] = [ordered]@{
                    sha = $sources[$name].Sha
                    tree = $sources[$name].Tree
                }
            }
            $receipt = [ordered]@{
                schema = 'deep-p15c-ownership.v1'
                project = $project
                nonce = $nonce
                composeSha256 = Get-FileSha256 $ComposePath
                manifestSha256 = Get-FileSha256 $localManifest
                foreignSnapshotSha256 = Get-FileSha256 $foreignPath
                sources = $pins
                images = $imagesReceipt
            }
            $stagePath = Join-Path $runDirectory 'ownership-receipt.stage.json'
            $stageRecord = Write-NewUtf8File `
                $stagePath `
                ($receipt | ConvertTo-Json -Depth 10)
            $expectation = New-ReceiptExpectation `
                $sources `
                $ImageRoles `
                $project `
                $nonce `
                $receipt.composeSha256 `
                $receipt.manifestSha256 `
                $receipt.foreignSnapshotSha256
            Invoke-NodeQuiet @(
                (Join-Path $PSScriptRoot 'p15c-headless-contracts.mjs'),
                'validate-receipt', $stagePath, $expectation
            )
            $publishedReceipt = Publish-OwnedOutput `
                $stageRecord $ReceiptPath $sources $runDirectory
            $ownedOutputs.Add($publishedReceipt)
            $operations.Add('receipt-retained')
            Assert-CompletedPlan $operations.ToArray() -Retained
            Commit-OwnedOutput $publishedReceipt
            $retained = $true
            $ownedOutputs.Clear()
            return
        }

        Invoke-OwnedResourceCleanup `
            $project `
            $nonce `
            $imagesReceipt `
            $foreignBefore `
            $runDirectory `
            ([ref]$resourcesClean)
        & (Join-Path $PSScriptRoot 'p15c-ephemeral-secrets.ps1') `
            -Action Remove `
            -RunDirectory $secretDirectory
        $operations.Add('cleanup')
        $stageEvidence = New-Evidence `
            (Join-Path $runDirectory 'final-evidence.stage.json')
        $publishedEvidence = Publish-OwnedOutput `
            $stageEvidence $EvidencePath $sources $runDirectory
        $ownedOutputs.Add($publishedEvidence)
        $operations.Add('evidence')
        Assert-CompletedPlan $operations.ToArray()
        Remove-OwnedRunDirectory $runDirectory
        Commit-OwnedOutput $publishedEvidence
        $ownedOutputs.Clear()
    } catch {
        $operationError = $_.Exception
        if (-not $retained) {
            $cleanupErrors = @(Invoke-FailedRunCleanup `
                $project `
                $nonce `
                $runDirectory `
                $secretDirectory `
                $images `
                $foreignBefore `
                $mutationStarted `
                $resourcesClean `
                $ownedOutputs)
            if ($cleanupErrors.Count) {
                $all = [Collections.Generic.List[Exception]]::new()
                $all.Add($operationError)
                foreach ($error in $cleanupErrors) { $all.Add($error) }
                throw [AggregateException]::new(
                    'P15C operation and cleanup failed; owned state preserved.',
                    $all.ToArray()
                )
            }
        }
        throw $operationError
    }
}

function Get-RetainedContext([switch]$ForDown) {
    if ([string]::IsNullOrWhiteSpace($ReceiptPath)) {
        throw 'P15C exact ownership receipt is required.'
    }
    if (-not (Test-Path -LiteralPath $ReceiptPath -PathType Leaf)) {
        throw 'P15C exact ownership receipt is missing.'
    }
    $devopsSha = Get-GitValue $Root @('rev-parse', 'HEAD')
    $devopsTree = Get-GitValue $Root @('rev-parse', 'HEAD^{tree}')
    $sources = New-P15CSources $devopsSha $devopsTree
    $initialExpectation = New-ReceiptExpectation `
        $sources `
        $ImageRoles `
        $null `
        $null `
        (Get-FileSha256 $ComposePath) `
        $null `
        $null
    $summary = Read-ValidatedReceiptOnce $ReceiptPath $initialExpectation
    $receipt = $summary.receipt
    $runDirectory = Join-Path `
        (Join-Path $env:LOCALAPPDATA 'Deep\P15C') `
        "$($receipt.project)-$($receipt.nonce)"
    $secretDirectory = Join-Path $runDirectory 'secrets'
    $manifestPath = Join-Path $runDirectory 'localhost.validated.json'
    $foreignPath = Join-Path $runDirectory 'foreign-before.json'
    $runMarker = Join-Path $runDirectory '.p15c-run-owner'
    if (-not (Test-Path -LiteralPath $runMarker -PathType Leaf)) {
        throw 'P15C retained run marker is missing.'
    }
    if ([IO.File]::ReadAllText($runMarker) -ne 'deep-p15c-run.v1') {
        throw 'P15C retained run marker is invalid.'
    }
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        throw 'P15C retained manifest is missing.'
    }
    if (-not (Test-Path -LiteralPath $secretDirectory -PathType Container)) {
        throw 'P15C retained secret directory is missing.'
    }
    Assert-ProtectedAcl $runDirectory
    Assert-ProtectedAcl $runMarker
    Assert-ProtectedAcl $manifestPath
    Assert-RunDirectoryOutsideRepositories $runDirectory $sources
    Assert-OutputOutsideRepositories $ReceiptPath $sources $runDirectory
    if ($ForDown) {
        if ([string]::IsNullOrWhiteSpace($EvidencePath)) {
            throw 'P15C Down requires evidence path.'
        }
        Assert-OutputOutsideRepositories $EvidencePath $sources $runDirectory
        Assert-DistinctOutputPaths $EvidencePath $ReceiptPath
        if (Test-Path -LiteralPath $EvidencePath) {
            throw 'P15C evidence path already exists.'
        }
    } elseif (-not [string]::IsNullOrWhiteSpace($EvidencePath)) {
        throw 'P15C Verify does not accept an evidence path.'
    }
    Assert-SecretDirectoryOwnership $secretDirectory
    Invoke-NodeQuiet @(
        (Join-Path $PSScriptRoot 'p15c-local-contract-manifest.mjs'),
        'validate-shape', $manifestPath
    )
    $sourceManifest = Join-Path $runDirectory 'sources.json'
    Assert-ProtectedAcl $sourceManifest
    Assert-SourcePreflight $sourceManifest
    $contexts = Assert-ExactSourceExports $runDirectory $sources
    $foreignBefore = Assert-ForeignSnapshot $foreignPath
    $contracts = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    $images = New-P15CImageNames $receipt.project $devopsSha
    $context = [ordered]@{
        Receipt = $receipt
        ReceiptSha256 = [string]$summary.receiptSha256
        Sources = $sources
        Contexts = $contexts
        RunDirectory = $runDirectory
        SecretDirectory = $secretDirectory
        ManifestPath = $manifestPath
        ForeignPath = $foreignPath
        Contracts = $contracts
        Images = $images
        ForeignBefore = $foreignBefore
    }
    Assert-RetainedHashes $context
    return $context
}

function Invoke-VerifyOrDown([switch]$Remove) {
    $context = Get-RetainedContext -ForDown:$Remove
    Assert-RetainedHashes $context
    $composeContext = New-ComposeContext `
        $context.Receipt.project `
        $context.Receipt.nonce `
        $context.SecretDirectory `
        $context.Sources `
        $context.Contexts `
        $context.Images `
        $context.Contracts
    Set-ComposeEnvironment $composeContext
    $observed = Get-ImageReceipt `
        $context.Images `
        $context.Sources `
        $context.Receipt.nonce
    foreach ($expectedImage in $context.Receipt.images) {
        $actual = @($observed | Where-Object role -eq $expectedImage.role)
        if ($actual.Count -ne 1 -or $actual[0].id -ne $expectedImage.id) {
            throw 'P15C retained image differs from receipt.'
        }
    }
    if (-not $Remove) {
        Invoke-NodeQuiet @(
            (Join-Path $PSScriptRoot 'p15c-local-contract-manifest.mjs'),
            'validate',
            $context.ManifestPath,
            "http://127.0.0.1:$($Ports.Contracts)"
        )
        Assert-Runtime $context.Receipt.project
        return
    }
    Assert-RetainedHashes $context
    $resourcesClean = $false
    try {
        Invoke-OwnedResourceCleanup `
            $context.Receipt.project `
            $context.Receipt.nonce `
            @($context.Receipt.images) `
            $context.ForeignBefore `
            $context.RunDirectory `
            ([ref]$resourcesClean)
    } catch {
        if ($resourcesClean -and (Test-Path -LiteralPath $context.SecretDirectory)) {
            & (Join-Path $PSScriptRoot 'p15c-ephemeral-secrets.ps1') `
                -Action Remove `
                -RunDirectory $context.SecretDirectory
        }
        throw
    }
    Complete-RetainedStateCleanup $context $EvidencePath
}

try {
    switch ($Action) {
        'Run' {
            Invoke-Run
        }
        'Verify' {
            if ($KeepRunning) { throw 'KeepRunning is valid only for Run.' }
            Invoke-VerifyOrDown
        }
        'Down' {
            if ($KeepRunning) { throw 'KeepRunning is valid only for Run.' }
            Invoke-VerifyOrDown -Remove
        }
    }
} finally {
    Clear-P15CEnvironment
}
