[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('Init','Build','Provision','ProvisionFloor','Up','Status','Stop','Start','Verify','FaultMatrix','HistoryFault')][string]$Action,
    [string]$CustodyRoot = 'C:\Work\DeepSession\secrets\dev\deep-dev'
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$devopsRoot = Split-Path $PSScriptRoot -Parent
$custodyPath = [IO.Path]::GetFullPath($CustodyRoot)
$allowedRoot = [IO.Path]::GetFullPath('C:\Work\DeepSession\secrets\dev') + [IO.Path]::DirectorySeparatorChar
if (-not $custodyPath.StartsWith($allowedRoot, [StringComparison]::OrdinalIgnoreCase)) { throw 'deep-dev custody must remain inside secrets/dev.' }
for ($pathCheck = $custodyPath; $pathCheck; $pathCheck = [IO.Path]::GetDirectoryName($pathCheck)) {
    if ((Test-Path -LiteralPath $pathCheck) -and ((Get-Item -LiteralPath $pathCheck -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'deep-dev custody must not traverse reparse points.'
    }
}
function Run-Native([string]$File, [string[]]$Arguments) {
    & $File @Arguments
    if ($LASTEXITCODE -ne 0) { throw "deep-dev command failed: $File (exit $LASTEXITCODE). No state reset was performed." }
}
$env:DEEP_DEV_ROOT = $custodyPath.Replace('\','/')
$compose = @('compose','--project-name','deep-dev','--file',(Join-Path $devopsRoot 'docker-compose.deep-dev.yml'))
if ($Action -eq 'Init') {
    if (Test-Path -LiteralPath $custodyPath) { throw 'Existing dev custody cannot be overwritten; use Provision/Up for reuse.' }
    $ntsSource = Join-Path $devopsRoot 'tools/nts-observer'
    Run-Native docker @('run','--rm','--mount',"type=bind,source=$ntsSource,target=/src",'-w','/src',
        'golang@sha256:8ac98ca534ac3f51e1f420a1dd2c15e74c75cfa0f23f3ad27eb5d7236c349a0c','sh','-c','GOOS=windows GOARCH=amd64 go build -trimpath -o deep-nts-observer.exe .')
    Run-Native dotnet @('run','--project',(Join-Path $devopsRoot 'tools/deep-dev/Deep.Dev.csproj'),'-c','Debug','--',
        'init',$custodyPath,(Join-Path $ntsSource 'deep-nts-observer.exe'))
    return
}
if (-not (Test-Path -LiteralPath (Join-Path $custodyPath 'public/deep-dev.json') -PathType Leaf)) { throw 'deep-dev is not provisioned; run Init.' }
if ($Action -eq 'Build') {
    Run-Native dotnet @('run','--project',(Join-Path $devopsRoot 'tools/deep-dev/Deep.Dev.csproj'),'-c','Debug','--','configure',$custodyPath)
    Run-Native docker ($compose + @('build','registry','node-1','publisher')); return
}
function Test-CurrentCapabilities {
    $ready = $true
    $registryResult = & docker @($compose + @('exec','-T','registry','curl','--fail','--silent','--max-time','5','--cacert','/run/deep-public/dev-ca.crt','https://localhost/health/did2/ready')) 2>$null
    if ($LASTEXITCODE -ne 0) { return $false }
    try { if (($registryResult | ConvertFrom-Json).ok -ne $true) { return $false } } catch { return $false }
    foreach ($devNode in 1..3) {
        $nodeResult = & docker @($compose + @('exec','-T',"node-$devNode",'curl','--fail','--silent','--max-time','5','http://localhost:8080/health/ready')) 2>$null
        if ($LASTEXITCODE -ne 0) { $ready = $false; continue }
        try { if (($nodeResult | ConvertFrom-Json).privacyRouting -cne 'ready') { $ready = $false } } catch { $ready = $false }
    }
    return $ready
}
function Wait-CurrentCapabilities {
    $deadline = [Diagnostics.Stopwatch]::StartNew()
    while ($deadline.Elapsed.TotalSeconds -lt 180) {
        if (Test-CurrentCapabilities) { return [Math]::Ceiling($deadline.Elapsed.TotalSeconds) }
        Start-Sleep -Seconds 2
    }
    throw 'Current Registry proof and all three ONION capabilities did not recover. No custody reset was attempted.'
}
if ($Action -eq 'Verify') {
    $seconds = Wait-CurrentCapabilities
    [pscustomobject]@{ schema='deep-dev-readiness.v1'; registryProofReady=$true; verifiedOnionNodes=3; recoverySeconds=$seconds; deviceEvidence=$false; messageDeliveryEvidence=$false } | ConvertTo-Json
    return
}
if ($Action -eq 'FaultMatrix') {
    [void](Wait-CurrentCapabilities)
    # Record exact dev container mounts, not private keys/identifiers. They must
    # remain byte-for-byte the same binding throughout stop/start and recreation.
    $mounts = @{}
    foreach ($service in @('floor','registry','publisher','node-1','node-2','node-3')) {
        $containerId = & docker @($compose + @('ps','-q',$service))
        $mounts[$service] = (& docker inspect --format '{{json .Mounts}}' $containerId) | ConvertFrom-Json | ForEach-Object { "$($_.Type)|$($_.Source)|$($_.Destination)|$($_.RW)" } | Sort-Object
        if ($LASTEXITCODE -ne 0) { throw 'Cannot snapshot exact development mounts.' }
    }
    $cases = [Collections.Generic.List[object]]::new()
    foreach ($service in @('node-1','node-2','node-3','registry','floor','publisher')) {
        try {
            Run-Native docker ($compose + @('stop','--timeout','10',$service))
            # Let existing bounded request/refresh windows expire naturally.
            Start-Sleep -Seconds 15
        } finally { Run-Native docker ($compose + @('start',$service)) }
        $seconds = Wait-CurrentCapabilities
        $cases.Add([ordered]@{ fault="stop-start-$service"; recovered=$true; recoverySeconds=$seconds })
    }
    try { Run-Native docker ($compose + @('stop','--timeout','10')); Start-Sleep -Seconds 15 }
    finally { Run-Native docker ($compose + @('start')) }
    $cases.Add([ordered]@{fault='all-containers-stop-start'; recovered=$true; recoverySeconds=(Wait-CurrentCapabilities)})
    foreach ($service in $mounts.Keys) {
        $containerId = & docker @($compose + @('ps','-q',$service))
        $after = (& docker inspect --format '{{json .Mounts}}' $containerId) | ConvertFrom-Json | ForEach-Object { "$($_.Type)|$($_.Source)|$($_.Destination)|$($_.RW)" } | Sort-Object
        if ($LASTEXITCODE -ne 0 -or ($after -join "`n") -cne ($mounts[$service] -join "`n")) { throw 'Dev custody/state mount binding changed.' }
    }
    [ordered]@{schema='deep-dev-fault-matrix.v1';cases=$cases.ToArray();unchangedCustodyMounts=$true;soak72h=$false;deviceEvidence=$false;messageDeliveryEvidence=$false;longTtlOfflineEvidence=$false;historyOver64DockerEvidence=$false} | ConvertTo-Json -Depth 5
    return
}
if ($Action -eq 'HistoryFault') {
    [void](Wait-CurrentCapabilities)
    try {
        Run-Native docker ($compose + @('stop','--timeout','10','node-1','node-2','node-3'))
        # A separate --rm process receives PUBLIC bootstrap only. No root signer,
        # node seed, protected floor or publisher journal is mounted into it.
        Run-Native docker @('run','--rm','--label','deep.project=deep-dev','--network','deep-dev_dev','--ulimit','core=0',
            '--mount',"type=bind,source=$custodyPath/public,target=/run/deep-public,readonly",'deep-dev/publisher:candidate',
            'Deep.Dev.dll','exercise-directory','/run/deep-public')
    } finally { Run-Native docker ($compose + @('start','node-1','node-2','node-3')) }
    [ordered]@{schema='deep-dev-history-fault.v1';offlineNodes=3;admittedFixtures=130;recoveredVerifiedOnionNodes=3;recoverySeconds=(Wait-CurrentCapabilities);custodyReset=$false;deviceEvidence=$false;messageDeliveryEvidence=$false} | ConvertTo-Json
    return
}
if ($Action -in @('Provision','ProvisionFloor')) {
    # Copy only online service custody. Neither offline-root nor operator is mounted.
    foreach ($service in @('floor','registry','node-1','node-2','node-3')) {
        $volume = "deep-dev_$service-secrets"
        $present = & docker volume ls --filter "name=^$volume$" --format '{{.Name}}'
        if ($LASTEXITCODE -ne 0) { throw 'Cannot inspect exact dev custody volumes.' }
        if ($present -cne $volume) { Run-Native docker @('volume','create','--label','deep.environment=dev','--label','deep.project=deep-dev',$volume) }
        $source = Join-Path $custodyPath "$service/secrets"
        $owner = if ($service -eq 'floor') { '70:70' } else { '0:0' }
        $copyOrVerify = 'if test -z "$(ls -A /target)"; then cp /source/* /target/; else for sourceFile in /source/*; do cmp -s "$sourceFile" "/target/${sourceFile##*/}" || exit 2; done; test "$(ls -A /source | wc -l)" = "$(ls -A /target | wc -l)" || exit 2; fi; chmod 0700 /target; chmod 0600 /target/*; chown -R ' + $owner + ' /target'
        Run-Native docker @('run','--rm','--mount',"type=bind,source=$source,target=/source,readonly",'--mount',"type=volume,source=$volume,target=/target",
            'alpine:3.22','sh','-c',$copyOrVerify)
    }
    Run-Native docker ($compose + @('up','-d','floor'))
    $floorReady = $false
    $floorDeadline = [Diagnostics.Stopwatch]::StartNew()
    while ($floorDeadline.Elapsed.TotalSeconds -lt 60) {
        $floorContainer = & docker @($compose + @('ps','-q','floor'))
        if ($LASTEXITCODE -ne 0) { throw 'Cannot inspect dev floor service.' }
        if ($floorContainer) {
            $floorHealth = & docker inspect --format '{{.State.Health.Status}}' $floorContainer
            if ($LASTEXITCODE -ne 0) { throw 'Cannot inspect dev floor health.' }
            if ($floorHealth -eq 'healthy') { $floorReady = $true; break }
        }
        Start-Sleep -Seconds 2
    }
    if (-not $floorReady) { throw 'Dev floor did not become ready; retained custody was not reset.' }
    $schema = Join-Path (Split-Path $devopsRoot -Parent) 'deep-registry-api/docs/sql/did2-latest-head-floor.sql'
    # This is explicit first-time schema provisioning, never an application
    # startup reset/migration. CREATE TABLE deliberately rejects an existing table.
    Get-Content -LiteralPath $schema -Raw | & docker @($compose + @('exec','-T','floor','gosu','postgres','psql','-v','ON_ERROR_STOP=1','-h','/var/run/postgresql','-U','postgres','-d','deep_dev'))
    if ($LASTEXITCODE -ne 0) { throw 'Explicit dev floor schema provisioning failed; no reset performed.' }
    if ($Action -eq 'Provision') {
        Run-Native docker ($compose + @('run','--rm','--no-deps','registry','Deep.Registry.Api.dll','did2-directory','provision-state'))
    }
    # Explicit provisioning commands intentionally reject existing state/floor.
    # For an existing initialized stack, use Up instead of Provision.
    Run-Native docker ($compose + @('run','--rm','--no-deps','registry','Deep.Registry.Api.dll','did2-directory','provision-floor'))
    return
}
switch ($Action) {
    'Up' { Run-Native docker ($compose + @('up','-d','floor','publisher','registry','node-1','node-2','node-3')) }
    'Status' { Run-Native docker ($compose + @('ps','--all')) }
    'Stop' { Run-Native docker ($compose + @('stop')) }
    'Start' { Run-Native docker ($compose + @('start')) }
}
