[CmdletBinding()]
param([switch]$NonDockerSequenceRegression)

$ErrorActionPreference = 'Stop'
$script = Join-Path $PSScriptRoot 'p15c-headless-lab.ps1'
if (-not (Test-Path -LiteralPath $script -PathType Leaf)) { throw 'P15C lifecycle implementation is absent' }

$inputs = [ordered]@{
    P15C_REAL_INTEGRATION = $env:P15C_REAL_INTEGRATION
    P15C_NODE_IMAGE = $env:P15C_NODE_IMAGE
    P15C_DOTNET_SDK_IMAGE = $env:P15C_DOTNET_SDK_IMAGE
    P15C_DOTNET_RUNTIME_IMAGE = $env:P15C_DOTNET_RUNTIME_IMAGE
    P15C_XNODE_PATH = $env:P15C_XNODE_PATH
    P15C_E2E_PATH = $env:P15C_E2E_PATH
    P15C_REGISTRY_PATH = $env:P15C_REGISTRY_PATH
    P15C_STAKING_PATH = $env:P15C_STAKING_PATH
    P15C_CONTRACTS_PATH = $env:P15C_CONTRACTS_PATH
    P15C_EVIDENCE_PATH = $env:P15C_EVIDENCE_PATH
    P15C_RECEIPT_PATH = $env:P15C_RECEIPT_PATH
}

if ($NonDockerSequenceRegression) {
    $snapshot = [ordered]@{}; foreach ($name in $inputs.Keys) { $snapshot[$name] = "snapshot-$name" }
    $observed = [Collections.Generic.List[string]]::new()
    foreach ($step in @('normal','retained','verify','down')) {
        $observed.Add("$step|$($snapshot.P15C_NODE_IMAGE)|$($snapshot.P15C_RECEIPT_PATH)")
        foreach ($item in @(Get-ChildItem Env: | Where-Object { $_.Name -like 'P15C_*' })) { [Environment]::SetEnvironmentVariable($item.Name, $null, 'Process') }
    }
    if ($observed.Count -ne 4 -or @($observed | Where-Object { $_ -notmatch '\|snapshot-P15C_NODE_IMAGE\|snapshot-P15C_RECEIPT_PATH$' }).Count -ne 0) { throw 'snapshotted integration inputs did not survive sequential in-process driver clearing' }
    Write-Output 'P15C non-Docker sequential integration wrapper regression passed.'
    exit 0
}

if ($inputs.P15C_REAL_INTEGRATION -ne '1') {
    Write-Output 'P15C real integration test requires P15C_REAL_INTEGRATION=1.'
    exit 0
}

foreach ($name in @('P15C_NODE_IMAGE','P15C_DOTNET_SDK_IMAGE','P15C_DOTNET_RUNTIME_IMAGE','P15C_XNODE_PATH','P15C_E2E_PATH','P15C_REGISTRY_PATH','P15C_STAKING_PATH','P15C_CONTRACTS_PATH','P15C_EVIDENCE_PATH','P15C_RECEIPT_PATH')) {
    if ([string]::IsNullOrWhiteSpace($inputs[$name])) { throw "required integration input is missing: $name" }
}

& $script -Action Run -XNodePath $inputs.P15C_XNODE_PATH -E2EPath $inputs.P15C_E2E_PATH -RegistryPath $inputs.P15C_REGISTRY_PATH -StakingPath $inputs.P15C_STAKING_PATH -ContractsPath $inputs.P15C_CONTRACTS_PATH -NodeImage $inputs.P15C_NODE_IMAGE -DotnetSdkImage $inputs.P15C_DOTNET_SDK_IMAGE -DotnetRuntimeImage $inputs.P15C_DOTNET_RUNTIME_IMAGE -EvidencePath ($inputs.P15C_EVIDENCE_PATH + '.normal.json') -ReceiptPath ($inputs.P15C_RECEIPT_PATH + '.normal.json')
& $script -Action Run -KeepRunning -XNodePath $inputs.P15C_XNODE_PATH -E2EPath $inputs.P15C_E2E_PATH -RegistryPath $inputs.P15C_REGISTRY_PATH -StakingPath $inputs.P15C_STAKING_PATH -ContractsPath $inputs.P15C_CONTRACTS_PATH -NodeImage $inputs.P15C_NODE_IMAGE -DotnetSdkImage $inputs.P15C_DOTNET_SDK_IMAGE -DotnetRuntimeImage $inputs.P15C_DOTNET_RUNTIME_IMAGE -EvidencePath $inputs.P15C_EVIDENCE_PATH -ReceiptPath $inputs.P15C_RECEIPT_PATH
& $script -Action Verify -ReceiptPath $inputs.P15C_RECEIPT_PATH
if (Test-Path -LiteralPath $inputs.P15C_EVIDENCE_PATH) { throw 'retained Run/Verify must not emit final PASS evidence before Down' }
& $script -Action Down -ReceiptPath $inputs.P15C_RECEIPT_PATH -EvidencePath $inputs.P15C_EVIDENCE_PATH
if (-not (Test-Path -LiteralPath $inputs.P15C_EVIDENCE_PATH -PathType Leaf)) { throw 'retained Down did not emit final PASS evidence' }
Write-Output 'P15C real retained lifecycle passed.'
