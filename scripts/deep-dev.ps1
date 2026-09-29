[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('Init','Build','Provision','ProvisionFloor','Up','Status','Stop','Start','Verify','FaultMatrix','HistoryFault','EngineFault','ExpiryFault')][string]$Action,
    [string]$CustodyRoot = 'C:\Work\DeepSession\secrets\dev\deep-dev',
    [ValidateRange(1,20)][int]$Cycles = 2,
    [ValidateRange(20,7200)][int]$OfflineSeconds = 20,
    [ValidateRange(10,300)][int]$StableSeconds = 30
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
function Invoke-DesktopOperation([ValidateSet('start','stop')][string]$Operation, [int]$TimeoutSeconds) {
    # Docker Desktop CLI v0.2 can hang beyond its own --timeout when the backend
    # crashes (for example, an inaccessible stale Windows inference socket).
    # Enforce an independent host-process bound; never reset Docker to repair it.
    $start = [Diagnostics.ProcessStartInfo]::new((Get-Command docker -CommandType Application).Source)
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    # Fixed validated arguments also work in Windows PowerShell 5.1.
    $start.Arguments = "desktop $Operation --timeout $TimeoutSeconds"
    $process = [Diagnostics.Process]::Start($start)
    try {
        if (-not $process.WaitForExit(($TimeoutSeconds + 10) * 1000)) {
            # The CLI starts Desktop as a descendant. Never kill its whole
            # process tree: only the CLI and its directly owned CLI plugin.
            if ($env:OS -ceq 'Windows_NT') {
                Get-CimInstance Win32_Process -Filter "ParentProcessId=$($process.Id)" |
                    Where-Object { $_.Name -ceq 'docker-desktop.exe' } |
                    ForEach-Object { Stop-Process -Id $_.ProcessId -ErrorAction SilentlyContinue }
            }
            if (-not $process.HasExited) { $process.Kill() }
            throw 'Docker Desktop CLI exceeded its host deadline; inspect Desktop backend diagnostics. No state reset was attempted.'
        }
        if ($process.ExitCode -ne 0) { throw 'Docker Desktop operation failed; inspect host diagnostics. Retained volumes/custody were not reset.' }
    } finally { $process.Dispose() }
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
if ($Action -in @('EngineFault','ExpiryFault')) {
    # Engine shutdown is global. Refuse a shared/remote engine or an already
    # stopped dev service instead of silently changing another operator's state.
    $context = & docker context show
    if ($LASTEXITCODE -ne 0 -or $context -cne 'desktop-linux') { throw 'EngineFault requires the local Docker Desktop Linux engine.' }
    $allRunning = @(& docker ps -q)
    if ($LASTEXITCODE -ne 0) { throw 'Cannot inspect engine scope.' }
    $devRunning = @(& docker ps -q --filter 'label=com.docker.compose.project=deep-dev')
    if ($LASTEXITCODE -ne 0 -or $devRunning.Count -ne 6 -or $allRunning.Count -ne 6) { throw 'EngineFault requires exactly the six running deep-dev services and no unrelated running containers.' }
    [void](Wait-CurrentCapabilities)
    $retained = @{}
    foreach ($id in $devRunning) {
        $policy = & docker inspect --format '{{.HostConfig.RestartPolicy.Name}}' $id
        if ($LASTEXITCODE -ne 0 -or $policy -cne 'always') { throw 'Apply Up first: full Desktop shutdown requires restart=always.' }
        $retained[$id] = (& docker inspect --format '{{json .Mounts}}' $id) | ConvertFrom-Json | ForEach-Object { "$($_.Type)|$($_.Source)|$($_.Destination)|$($_.RW)" } | Sort-Object
        if ($LASTEXITCODE -ne 0) { throw 'Cannot snapshot retained dev mounts.' }
    }
    # Digests stay in process memory and never enter the public evidence object.
    $custody = @{}
    foreach ($service in @('registry','node-1','node-2','node-3')) {
        $custody[$service] = & docker @($compose + @('exec','-T',$service,'sh','-c','sha256sum /run/secrets/*'))
        if ($LASTEXITCODE -ne 0 -or -not $custody[$service]) { throw 'Cannot snapshot retained online custody.' }
    }
    if ($Action -eq 'ExpiryFault') {
        # Finish one protected delegated commit while the normal publisher is
        # stopped. Its restart=always restores it only when the engine returns,
        # after this real 180-second view's 200-second offline interval.
        # No root custody, clock manipulation, floor reset or expired extension.
        Run-Native docker ($compose + @('stop','--timeout','10','publisher'))
        $published = $false
        try {
            Run-Native docker ($compose + @('run','--rm','--no-deps','publisher','Deep.Dev.dll','publish-short-view','/run/deep-public','/run/deep-operator','/usr/local/bin/deep-nts-observer'))
            $published = $true
        } finally { if (-not $published) { Run-Native docker ($compose + @('start','publisher')) } }
        $Cycles = 1
        $OfflineSeconds = 200
    }
    $cases = [Collections.Generic.List[object]]::new()
    foreach ($cycle in 1..$Cycles) {
        try {
            Invoke-DesktopOperation 'stop' 60
            $offline = [Diagnostics.Stopwatch]::StartNew()
            while ($offline.Elapsed.TotalSeconds -lt $OfflineSeconds) {
                Start-Sleep -Seconds ([Math]::Min(10,[Math]::Max(1,[Math]::Ceiling($OfflineSeconds - $offline.Elapsed.TotalSeconds))))
            }
        } finally {
            # No compose start/up here: restart-policy recovery itself is under test.
            Invoke-DesktopOperation 'start' 120
        }
        $recovery = [Diagnostics.Stopwatch]::StartNew()
        $engineReady = $false
        while ($recovery.Elapsed.TotalSeconds -lt 120) {
            $engine = & docker info --format '{{.OSType}}' 2>$null
            if ($LASTEXITCODE -eq 0 -and $engine -ceq 'linux') { $engineReady = $true; break }
            Start-Sleep -Seconds 2
        }
        if (-not $engineReady) { throw 'Docker Engine did not return after Desktop start.' }
        [void](Wait-CurrentCapabilities)
        $seconds = [Math]::Ceiling($recovery.Elapsed.TotalSeconds)
        $stable = [Diagnostics.Stopwatch]::StartNew()
        while ($stable.Elapsed.TotalSeconds -lt $StableSeconds) {
            if (-not (Test-CurrentCapabilities)) { throw 'A current proof/ONION capability was lost during the post-restart stability window.' }
            Start-Sleep -Seconds 2
        }
        foreach ($id in $retained.Keys) {
            $after = (& docker inspect --format '{{json .Mounts}}' $id) | ConvertFrom-Json | ForEach-Object { "$($_.Type)|$($_.Source)|$($_.Destination)|$($_.RW)" } | Sort-Object
            if ($LASTEXITCODE -ne 0 -or ($after -join "`n") -cne ($retained[$id] -join "`n")) { throw 'Engine restart changed retained containers or custody/state mounts.' }
        }
        foreach ($service in $custody.Keys) {
            $after = & docker @($compose + @('exec','-T',$service,'sh','-c','sha256sum /run/secrets/*'))
            if ($LASTEXITCODE -ne 0 -or ($after -join "`n") -cne ($custody[$service] -join "`n")) { throw 'Online custody changed across engine restart.' }
        }
        $cases.Add([ordered]@{cycle=$cycle;offlineSeconds=$OfflineSeconds;recovered=$true;recoverySeconds=$seconds;stableSeconds=$StableSeconds})
        # Emit each completed case before starting another, so a later host
        # failure cannot hide earlier results or imply the whole matrix passed.
        [ordered]@{schema='deep-dev-engine-case.v1';cycle=$cycle;offlineSeconds=$OfflineSeconds;recoverySeconds=$seconds;stableSeconds=$StableSeconds;retainedNodeRegistryCustody=$true;retainedMounts=$true} | ConvertTo-Json -Compress
        Write-Host "deep-dev engine cycle $cycle passed; retained custody/state; current capabilities stable."
    }
    [ordered]@{schema='deep-dev-engine-fault.v1';cases=$cases.ToArray();automaticContainerStart=$true;unchangedCustody=$true;unchangedStateMounts=$true;expiredOperationalViewEvidence=($Action -eq 'ExpiryFault');soak72h=$false;deviceEvidence=$false;messageDeliveryEvidence=$false} | ConvertTo-Json -Depth 5
    return
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
    'Stop' {
        # Explicit maintenance stop stays stopped across engine boots. This is
        # distinct from Desktop shutdown of the normally auto-starting network.
        $ids = @(& docker @($compose + @('ps','--all','--quiet')))
        if ($LASTEXITCODE -ne 0 -or $ids.Count -ne 6) { throw 'Cannot resolve exactly six retained dev services.' }
        Run-Native docker (@('update','--restart','unless-stopped') + $ids)
        Run-Native docker ($compose + @('stop'))
    }
    'Start' {
        $ids = @(& docker @($compose + @('ps','--all','--quiet')))
        if ($LASTEXITCODE -ne 0 -or $ids.Count -ne 6) { throw 'Cannot resolve exactly six retained dev services; use Up for initial creation.' }
        Run-Native docker (@('update','--restart','always') + $ids)
        Run-Native docker ($compose + @('start'))
    }
}
