[CmdletBinding()]
param(
    [string] $RepositoryRoot = ''
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ([string]::IsNullOrWhiteSpace($RepositoryRoot)) {
    $RepositoryRoot = Join-Path $PSScriptRoot '..'
}
$repository = [IO.Path]::GetFullPath($RepositoryRoot)
$protocolSourceRoot = [IO.Path]::GetFullPath((Join-Path $repository `
    '..\deep-protocol\src\Deep.Protocol'))
if (-not (Test-Path -LiteralPath $protocolSourceRoot -PathType Container)) {
    throw 'First-release authority preflight cannot inspect the local Protocol source.'
}

$protocolProductionSource = [Text.StringBuilder]::new()
Get-ChildItem -LiteralPath $protocolSourceRoot -Recurse -File -Filter '*.cs' |
    Where-Object { $_.FullName -notmatch '[\\/](?:bin|obj)[\\/]' } |
    ForEach-Object {
        [void]$protocolProductionSource.AppendLine([IO.File]::ReadAllText($_.FullName))
    }
$source = $protocolProductionSource.ToString()
$protocolProductionSource.Clear() | Out-Null

$hasGenesisAuthor = $source -match '\bclass\s+XPointNetworkBootstrapAuthor\b' -and
    $source -match '\bAuthorGenesisAsync\b'
$hasProofAuthor = $source -match '\bclass\s+AccountDirectoryProofAuthor\b' -and
    $source -match '\bIssueAsync\b'
$hasOperationalGenesisAuthor = $source -match
    '\bclass\s+XPointNetworkOperationalGenesisAuthor\b' -and
    $source -match '\bXPointNetworkOperationalGenesisRequest\b'
$source = $null

$custodyTool = Join-Path $repository 'tools\production-authority-bootstrap\Program.cs'
$hasRootCustody = (Test-Path -LiteralPath $custodyTool -PathType Leaf) -and
    ([IO.File]::ReadAllText($custodyTool) -match
        '\bclass\s+FileSigner[^\{]*:\s*[^\{]*\bIXPointNetworkBootstrapRootSigner\b')

if (-not $hasGenesisAuthor -or -not $hasProofAuthor) {
    throw 'First-release authority blocker: the required Protocol production authoring APIs are unavailable.'
}
if (-not $hasRootCustody -or -not $hasOperationalGenesisAuthor) {
    throw ('First-release signing-authority blocker: the production ' +
        'IXPointNetworkBootstrapRootSigner custody adapter and the complete ' +
        'XPointNetworkOperationalGenesisAuthor must both be present. Required genesis closure: ' +
        'XNA1/DTS1/XVP1/XNV1/XNH1/XND1/PMT2/ADH1/DTT1/ADP1. ' +
        'ADC1 is intentionally absent from the empty generation-zero directory and is admitted ' +
        'only by the verified account-publication pipeline. DEV trust and synthetic artifacts are forbidden.')
}
