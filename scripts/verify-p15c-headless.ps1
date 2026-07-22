$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$tests = @(
    @('node','--test','scripts/p15c-headless-contracts.test.mjs'),
    @('node','--test','scripts/p15c-headless-source-preflight.test.mjs'),
    @('node','--test','scripts/p15c-local-contract-manifest.test.mjs'),
    @('node','--test','scripts/p15c-evidence-sanitizer.test.mjs'),
    @('powershell','-NoProfile','-ExecutionPolicy','Bypass','-File','scripts/p15c-ephemeral-secrets.test.ps1'),
    @('powershell','-NoProfile','-ExecutionPolicy','Bypass','-File','scripts/p15c-headless-lab.test.ps1')
)
Push-Location $root
try {
    foreach ($command in $tests) {
        & $command[0] $command[1..($command.Count - 1)]
        if ($LASTEXITCODE -ne 0) { throw 'P15C verification command failed.' }
    }
    if ($env:P15C_REAL_INTEGRATION -ne '1') { throw 'P15C acceptance verification requires P15C_REAL_INTEGRATION=1 and both real lifecycle shapes.' }
    powershell -NoProfile -ExecutionPolicy Bypass -File scripts/p15c-headless-lab.integration.test.ps1
    if ($LASTEXITCODE -ne 0) { throw 'P15C real integration verification failed.' }
    git diff --check
    if ($LASTEXITCODE -ne 0) { throw 'P15C git diff check failed.' }
}
finally { Pop-Location }
Write-Output 'P15C headless harness verification passed.'
