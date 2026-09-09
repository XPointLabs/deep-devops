$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$probeName = 'deep-first-release-bls-probe'
$probePort = 42990
$temporaryDirectory = [IO.Path]::GetFullPath((Join-Path (
    [IO.Path]::GetTempPath()) ('deep-first-release-bls-probe-' + [guid]::NewGuid().ToString('N'))))
$keyPath = Join-Path $temporaryDirectory 'key_bls'
$outputPath = Join-Path $temporaryDirectory 'proof.json'

if (docker ps -a --filter "name=^/$probeName$" --format '{{.Names}}') {
    throw 'The isolated BLS probe container name is already in use.'
}

[IO.Directory]::CreateDirectory($temporaryDirectory) | Out-Null
try {
    $containerId = docker run -d --rm --name $probeName `
        -p "127.0.0.1:${probePort}:8545" `
        --entrypoint anvil `
        ghcr.io/foundry-rs/foundry:latest `
        --silent --host 0.0.0.0 --port 8545 --hardfork prague --chain-id 31337
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($containerId)) {
        throw 'Could not start the isolated BLS bootstrap RPC.'
    }
    $containerId = $null

    $ready = $false
    for ($attempt = 0; $attempt -lt 30; $attempt++) {
        try {
            $response = Invoke-RestMethod -Uri "http://127.0.0.1:$probePort" `
                -Method Post -ContentType 'application/json' `
                -Body '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}' `
                -TimeoutSec 2
            if ($response.result -eq '0x7a69') {
                $ready = $true
                break
            }
        } catch {}
        Start-Sleep -Milliseconds 250
    }
    if (-not $ready) {
        throw 'The isolated BLS bootstrap RPC did not become ready.'
    }

    $scalar = [byte[]]::new(32)
    $generator = [Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $generator.GetBytes($scalar)
    } finally {
        $generator.Dispose()
    }
    $scalar[0] = 0
    if (($scalar | Measure-Object -Sum).Sum -eq 0) {
        $scalar[31] = 1
    }
    try {
        [IO.File]::WriteAllText(
            $keyPath,
            '0x' + ([BitConverter]::ToString($scalar) -replace '-', '').ToLowerInvariant() + [Environment]::NewLine,
            [Text.UTF8Encoding]::new($false))
    } finally {
        [Array]::Clear($scalar, 0, $scalar.Length)
    }

    $helper = Join-Path $repositoryRoot `
        'tools\first-release-bootstrap\bin\Release\net10.0\FirstRelease.Bootstrap.dll'
    $helperOutput = & dotnet $helper `
        --private-key-file $keyPath `
        --output $outputPath `
        --router-id ('11' * 32) `
        --operator-address (('00' * 19) + '01') `
        --domain-address (('00' * 18) + 'f001') `
        --rpc-url "http://127.0.0.1:$probePort" 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw 'The XNode BLS helper rejected the isolated EIP-2537 runtime.'
    }
    $helperOutput = $null

    $proof = Get-Content -Raw -LiteralPath $outputPath | ConvertFrom-Json
    if ($proof.publicKey -notmatch '^[0-9a-f]{256}$' -or
        $proof.signature -notmatch '^[0-9a-f]{512}$') {
        throw 'The XNode BLS helper produced malformed public artifacts.'
    }
    $proof = $null
    Write-Output 'First-release XNode BLS proof integration check passed.'
} finally {
    if (docker ps -a --filter "name=^/$probeName$" --format '{{.Names}}') {
        docker stop --time 2 $probeName | Out-Null
    }
    foreach ($path in @($outputPath, $keyPath)) {
        if (Test-Path -LiteralPath $path) {
            Remove-Item -LiteralPath $path -Force
        }
    }
    if (Test-Path -LiteralPath $temporaryDirectory) {
        Remove-Item -LiteralPath $temporaryDirectory -Force
    }
}
