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
$hasRootCustody = $source -match
    '\bclass\s+[A-Za-z0-9_]+[^\{]*:\s*[^\{]*\bIXPointNetworkBootstrapRootSigner\b'
$missingGenesisAuthors = [Collections.Generic.List[string]]::new()
foreach ($magic in @('ADH1', 'ADC1', 'XVP1', 'XNV1', 'XNH1', 'XND1', 'PMT2')) {
    if ($source -notmatch "(?is)\b(?:class|interface)\s+[A-Za-z0-9_]*$magic[A-Za-z0-9_]*Author[A-Za-z0-9_]*\b") {
        $missingGenesisAuthors.Add($magic)
    }
}
$source = $null

if (-not $hasGenesisAuthor -or -not $hasProofAuthor) {
    throw 'First-release authority blocker: the required Protocol production authoring APIs are unavailable.'
}
if (-not $hasRootCustody -or $missingGenesisAuthors.Count -gt 0) {
    throw ('First-release signing-authority blocker: no production ' +
        'IXPointNetworkBootstrapRootSigner custody implementation is available for ' +
        'XNA1/DTS1, and no production genesis authoring entry point exists for ' +
        ($missingGenesisAuthors -join '/') + '. Registry production authoring covers ' +
        'only nonce-bound DTT1/ADP1. Exact closure required: ' +
        'XNA1/DTS1/XVP1/XNV1/XNH1/XND1/PMT2/ADH1/DTT1/ADP1/ADC1. ' +
        'DEV trust and synthetic artifacts are forbidden.')
}
