param(
    [switch] $AsEnv,
    [string] $OutDir = ""
)

$ErrorActionPreference = "Stop"

$node = Get-Command node -ErrorAction SilentlyContinue
if ($null -eq $node) {
    throw "Node.js is required to generate a matching Ed25519 private/public key pair."
}

$scriptPath = Join-Path $PSScriptRoot "new-xnode-identity.mjs"
$nodeArgs = @($scriptPath)
if ($AsEnv) {
    $nodeArgs += "--as-env"
}
if (-not [string]::IsNullOrWhiteSpace($OutDir)) {
    $nodeArgs += @("--out-dir", $OutDir)
}

& $node.Source @nodeArgs
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}
