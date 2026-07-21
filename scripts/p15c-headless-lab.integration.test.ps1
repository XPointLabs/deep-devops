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

& $script -Action Run -KeepRunning -XNodePath $env:P15C_XNODE_PATH -E2EPath $env:P15C_E2E_PATH -RegistryPath $env:P15C_REGISTRY_PATH -StakingPath $env:P15C_STAKING_PATH -ContractsPath $env:P15C_CONTRACTS_PATH -NodeImage $env:P15C_NODE_IMAGE -DotnetSdkImage $env:P15C_DOTNET_SDK_IMAGE -DotnetRuntimeImage $env:P15C_DOTNET_RUNTIME_IMAGE -EvidencePath $env:P15C_EVIDENCE_PATH -ReceiptPath $env:P15C_RECEIPT_PATH
& $script -Action Verify -ReceiptPath $env:P15C_RECEIPT_PATH
& $script -Action Down -ReceiptPath $env:P15C_RECEIPT_PATH
Write-Output 'P15C real retained lifecycle passed.'
