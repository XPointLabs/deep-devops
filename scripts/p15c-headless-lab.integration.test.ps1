$ErrorActionPreference = 'Stop'
$script = Join-Path $PSScriptRoot 'p15c-headless-lab.ps1'
if (-not (Test-Path -LiteralPath $script -PathType Leaf)) { throw 'P15C lifecycle implementation is absent' }

if ($env:P15C_REAL_INTEGRATION -ne '1') {
    Write-Output 'P15C real integration test requires P15C_REAL_INTEGRATION=1.'
    exit 0
}

foreach ($name in @('P15C_NODE_IMAGE','P15C_DOTNET_SDK_IMAGE','P15C_DOTNET_RUNTIME_IMAGE','P15C_XNODE_PATH','P15C_E2E_PATH','P15C_REGISTRY_PATH','P15C_STAKING_PATH','P15C_CONTRACTS_PATH','P15C_EVIDENCE_PATH','P15C_RECEIPT_PATH')) {
    if ([string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($name))) { throw "required integration input is missing: $name" }
}

& $script -Action Run -XNodePath $env:P15C_XNODE_PATH -E2EPath $env:P15C_E2E_PATH -RegistryPath $env:P15C_REGISTRY_PATH -StakingPath $env:P15C_STAKING_PATH -ContractsPath $env:P15C_CONTRACTS_PATH -NodeImage $env:P15C_NODE_IMAGE -DotnetSdkImage $env:P15C_DOTNET_SDK_IMAGE -DotnetRuntimeImage $env:P15C_DOTNET_RUNTIME_IMAGE -EvidencePath ($env:P15C_EVIDENCE_PATH + '.normal.json') -ReceiptPath ($env:P15C_RECEIPT_PATH + '.normal.json')
& $script -Action Run -KeepRunning -XNodePath $env:P15C_XNODE_PATH -E2EPath $env:P15C_E2E_PATH -RegistryPath $env:P15C_REGISTRY_PATH -StakingPath $env:P15C_STAKING_PATH -ContractsPath $env:P15C_CONTRACTS_PATH -NodeImage $env:P15C_NODE_IMAGE -DotnetSdkImage $env:P15C_DOTNET_SDK_IMAGE -DotnetRuntimeImage $env:P15C_DOTNET_RUNTIME_IMAGE -EvidencePath $env:P15C_EVIDENCE_PATH -ReceiptPath $env:P15C_RECEIPT_PATH
& $script -Action Verify -ReceiptPath $env:P15C_RECEIPT_PATH
if (Test-Path -LiteralPath $env:P15C_EVIDENCE_PATH) { throw 'retained Run/Verify must not emit final PASS evidence before Down' }
& $script -Action Down -ReceiptPath $env:P15C_RECEIPT_PATH -EvidencePath $env:P15C_EVIDENCE_PATH
if (-not (Test-Path -LiteralPath $env:P15C_EVIDENCE_PATH -PathType Leaf)) { throw 'retained Down did not emit final PASS evidence' }
Write-Output 'P15C real retained lifecycle passed.'
