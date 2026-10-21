param(
    [Parameter(Mandatory)][ValidateSet('PrepareOperational','ApplyOperational')][string]$Phase,
    [Parameter(Mandatory)][string]$CustodyRoot,
    [Parameter(Mandatory)][string[]]$ComposeArguments,
    [Parameter(Mandatory)][string]$DevOpsRoot,
    [string]$SourceFile,
    [string]$Candidate
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
function Invoke-Native([string]$File,[string[]]$Arguments) {
    & $File @Arguments
    if($LASTEXITCODE -ne 0) { throw 'Retained time-source maintenance failed; preserve candidate and all volumes. No reset was performed.' }
}
$root=[IO.Path]::GetFullPath($CustodyRoot)
if ($ComposeArguments.Count -lt 5 -or $ComposeArguments[0] -cne 'compose' -or $ComposeArguments[1] -cne '--project-name' -or $ComposeArguments[2] -cne 'deep-dev-current') { throw 'Exact current-dev Compose project required.' }
if($root -cne [IO.Path]::GetFullPath('C:/Work/DeepSession/secrets/dev/deep-dev-current') -or
    -not(Test-Path -LiteralPath (Join-Path $root 'mailbox/nodes-enabled') -PathType Leaf)) { throw 'Retained current-dev mailbox scope required.' }
$project=Join-Path $DevOpsRoot 'tools/deep-dev/Deep.Dev.csproj'
$tool=@('run','--no-build','--project',$project,'-c','Debug','--')
$observer=Join-Path $DevOpsRoot 'tools/nts-observer/deep-nts-observer.exe'
$leasePath=Join-Path $root 'offline-root/time-source-maintenance.lease'
if((Test-Path -LiteralPath $leasePath) -and ((Get-Item -LiteralPath $leasePath).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Linked maintenance custody.' }
$maintenanceLease=[IO.FileStream]::new($leasePath,[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
try {
if($Phase -ceq 'PrepareOperational') {
    if(-not $SourceFile -or $Candidate) { throw 'Preparation requires explicit source input and no candidate override.' }
    $prior=@(& docker inspect --format '{{.HostConfig.RestartPolicy.Name}}' deep-dev-current-publisher-1)
    if($LASTEXITCODE -ne 0 -or $prior.Count -ne 1) { throw 'Cannot establish publisher restart custody.' }
    Invoke-Native docker @('update','--restart','unless-stopped','deep-dev-current-publisher-1')
    Invoke-Native docker ($ComposeArguments+@('stop','--timeout','10','publisher'))
    $prepared=$false
    try {
        Invoke-Native dotnet ($tool+@('prepare-time-sources',$root,$observer,[IO.Path]::GetFullPath($SourceFile)))
        $prepared=$true
    } finally {
        if(-not $prepared) {
            Invoke-Native docker @('update',"--restart=$($prior[0])",'deep-dev-current-publisher-1')
            Invoke-Native docker ($ComposeArguments+@('start','publisher'))
        }
    }
    Write-Host 'Sealed current-mailbox time-source successor prepared; publisher remains stopped. No policy activated.'
    return
}
if(-not $Candidate -or $SourceFile) { throw 'Activation requires one explicit sealed candidate, no new source input.' }
$candidatePath=[IO.Path]::GetFullPath($Candidate)
Invoke-Native dotnet ($tool+@('validate-time-sources',$root,$candidatePath))
foreach($name in @('floor-secrets','registry-mailbox-secrets','node-1-secrets','node-2-secrets','node-3-secrets','deposit-secrets','retrieve-secrets','publisher-state','public-runtime')) {
    $volume=@(& docker volume inspect "deep-dev-current_$name" | ConvertFrom-Json)
    if($LASTEXITCODE -ne 0 -or $volume.Count -ne 1) { throw 'Unknown retained maintenance volume.' }
    if($name -in @('publisher-state','public-runtime')) {
        if($volume[0].Labels.'com.docker.compose.project' -cne 'deep-dev-current' -or $volume[0].Labels.'com.docker.compose.volume' -cne $name) { throw 'Unowned Compose publication volume.' }
    } elseif($volume[0].Labels.'deep.project' -cne 'deep-dev-current' -or $volume[0].Labels.'deep.environment' -cne 'dev') { throw 'Unowned retained secret volume.' }
}
$owners=@('publisher','node-1','node-2','node-3','registry','deposit-signer','retrieve-signer','floor')
Invoke-Native docker ($ComposeArguments+@('stop','--timeout','20')+$owners)
# From this point failures stay stopped/unready; never expose a mixed generation.
foreach($phaseName in @('verify','install')) {
    if($phaseName -ceq 'install') { Invoke-Native dotnet ($tool+@('install-time-sources',$root,$candidatePath)) }
    foreach($service in @('floor','registry','node-1','node-2','node-3')) {
        $volume=if($service -ceq 'registry') {'deep-dev-current_registry-mailbox-secrets'} else {"deep-dev-current_$service-secrets"}
        $files=if($service -like 'node-*') {'server.crt server.key key_x25519 key_x25519_next'} else {'server.crt server.key'}
        $owner=if($service -ceq 'floor') {'70:70'} else {'0:0'}
        # All shell names below come ONLY from the closed literal filename set;
        # avoid nested quotes mangled by Windows PowerShell5.1 native argv.
        $copy='set -eu; for n in '+$files+'; do test -f /source/$n && test ! -L /source/$n; test -f /target/$n && test ! -L /target/$n; cmp -s /source/$n /target/$n || cmp -s /before/$n /target/$n; done; '
        if($service -ceq 'registry') { $copy+='test $(ls -A /target | wc -l) = 9; test ! -e /target/mailbox-deposit.seed; test ! -e /target/mailbox-retrieve.seed; ' }
        if($phaseName -ceq 'install') { $copy+='for n in '+$files+'; do test ! -L /target/$n.installing; if test -e /target/$n.installing; then cmp -s /source/$n /target/$n.installing; else cp /source/$n /target/$n.installing; fi; chmod 0600 /target/$n.installing; chown '+$owner+' /target/$n.installing; sync; mv /target/$n.installing /target/$n; done; sync' }
        Invoke-Native docker @('run','--rm','--network','none','--mount',"type=bind,source=$candidatePath/online/$service,target=/source,readonly",
            '--mount',"type=bind,source=$candidatePath/volume-before/$service,target=/before,readonly",
            '--mount',"type=volume,source=$volume,target=/target",'alpine:3.22','sh','-c',$copy)
    }
}
foreach($role in @('deposit','retrieve')) {
    $copy='set -eu; test -f /target/role.seed; test ! -L /target/role.seed; test $(ls -A /target | wc -l) = 1; (cmp -s /target/role.seed /before/role.seed || cmp -s /target/role.seed /next/role.seed); cp /next/role.seed /target/role.seed.stage; chmod 0600 /target/role.seed.stage; sync; mv /target/role.seed.stage /target/role.seed; sync; cmp -s /target/role.seed /next/role.seed'
    Invoke-Native docker @('run','--rm','--network','none','--mount',"type=bind,source=$candidatePath/volume-before/registry/mailbox-$role.seed,target=/before/role.seed,readonly",
        '--mount',"type=bind,source=$candidatePath/online/registry/mailbox-$role.seed,target=/next/role.seed,readonly",
        '--mount',"type=volume,source=deep-dev-current_$role-secrets,target=/target",'alpine:3.22','sh','-c',$copy)
}
Invoke-Native docker ($ComposeArguments+@('up','-d','--no-deps','--force-recreate','--wait','--wait-timeout','120','floor'))
$sql=[IO.File]::ReadAllText((Join-Path $candidatePath 'operator/revocation-roots.sql'))
$databaseResult=$sql | & docker @($ComposeArguments+@('exec','-T','floor','gosu','postgres','psql','-q','-v','ON_ERROR_STOP=1','-h','/var/run/postgresql','-U','postgres','-d','deep_dev')) 2>&1
if($LASTEXITCODE -ne 0) { throw 'Successor revocation-root transaction rejected; preserve retained SQL and stopped owners.' }
$sql=$null; $databaseResult=$null
# The publisher alone mutates its retained HMAC journal and public NCP2. Its
# one-off process receives only the public tree and sealed operator journal,
# never offline roots or either issuer key.
Invoke-Native docker @('run','--rm','--network','deep-dev-current_dev','--mount',"type=bind,source=$root/public,target=/run/deep-public",
    '--mount',"type=bind,source=$root/operator,target=/run/deep-operator,readonly",
    '--mount',"type=bind,source=$candidatePath/operator,target=/run/deep-renewal,readonly",
    '--mount','type=volume,source=deep-dev-current_public-runtime,target=/run/deep-public-native',
    '--mount','type=volume,source=deep-dev-current_publisher-state,target=/var/lib/deep-publisher',
    'deep-dev-current/publisher:candidate','Deep.Dev.dll','import-operational','/run/deep-public','/run/deep-operator','/run/deep-renewal','/usr/local/bin/deep-nts-observer')
$bindings=Get-Content -LiteralPath (Join-Path $root 'mailbox/node-bindings.json') -Raw|ConvertFrom-Json
if($bindings.MailboxAuthorityCoreHashHex -cnotmatch '^[0-9a-f]{64}$') { throw 'Successor node binding is not canonical.' }
$env:DEEP_DEV_MAILBOX_POLICY=$bindings.MailboxAuthorityCoreHashHex
Invoke-Native docker ($ComposeArguments+@('up','-d','--no-deps','--force-recreate','--wait','--wait-timeout','120','deposit-signer','retrieve-signer','registry'))
foreach($number in 1..3) {
    # Scheduling receipts are NOT authority. Normal startup and Verify still
    # restore/check every actual floor and journal even for a completed node.
    $completed=Join-Path $candidatePath "node-$number.completed"
    if(Test-Path -LiteralPath $completed -PathType Leaf) { continue }
    Invoke-Native docker @('run','--rm','--network','deep-dev-current_dev','--mount',"type=bind,source=$root/public,target=/run/deep-public,readonly",
        '--mount',"type=bind,source=$root/mailbox/node-control,target=/run/node-control",'deep-dev-current/publisher:candidate',
        'Deep.Dev.dll','fetch-node-mailbox-control','/run/deep-public','/run/node-control','/usr/local/bin/deep-nts-observer')
    Invoke-Native docker ($ComposeArguments+@('run','--rm','--no-deps','--volume',"$candidatePath/public/prior.pma2`:/run/time-source-prior.pma2:ro", "node-$number",
        'XNode.dll','current-mailbox-policy-successor','--prior-policy-file','/run/time-source-prior.pma2',
        '--deposit-mgr1-file','/run/node-control/deposit.mgr1','--retrieve-mgr1-file','/run/node-control/retrieve.mgr1'))
    $null=New-Item -ItemType File -Path $completed -ErrorAction Stop
}
Invoke-Native docker ($ComposeArguments+@('up','-d','--force-recreate','node-1','node-2','node-3','publisher'))
if(Test-Path -LiteralPath (Join-Path $root 'mailbox/physical-ingress.json') -PathType Leaf) {
    Invoke-Native docker ($ComposeArguments+@('up','-d','--no-deps','--force-recreate','ingress'))
}
Invoke-Native docker @('update','--restart','always','deep-dev-current-publisher-1')
Write-Host 'Time-source successor activated with retained journals and predecessor floors; run Verify and retained CLI E2E.'
} finally { $maintenanceLease.Dispose() }
