[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('Init','Build','PrepareAuthority','PrepareOperational','ApplyOperational','PrepareMailbox','ProvisionMailbox','ActivateMailbox','PrepareNodeMailbox','ProvisionNodeMailboxKeys','FetchNodeMailboxControl','EnrollNodeMailbox','ActivateNodeMailbox','ProvisionNodeContactKeys','EnrollNodeContact','ActivateNodeContact','PrepareContactCoordination','ProvisionContactCoordination','ActivateContactCoordination','PrepareDevPki','ApplyDevPki','ExerciseOwnedMailbox','AdmitObserver','Provision','ProvisionFloor','Up','Status','Stop','Start','Verify','FaultMatrix','HistoryFault','StackFault','EngineFault','ExpiryFault')][string]$Action,
    [ValidateRange(1,3)][int]$NodeNumber = 1,
    [string]$OperationalCandidate,
    [string]$CustodyRoot = 'C:\Work\DeepSession\secrets\dev\deep-dev',
    [ValidateSet('deep-dev','deep-dev-current')][string]$ProjectName = 'deep-dev',
    [ValidateRange(1,20)][int]$Cycles = 2,
    [ValidateRange(20,7200)][int]$OfflineSeconds = 20,
    [ValidateRange(10,300)][int]$StableSeconds = 30,
    [switch]$ConfirmEngineShutdown
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($Action -eq 'EngineFault' -and -not $ConfirmEngineShutdown) {
    throw 'EngineFault requires explicit whole-Desktop shutdown approval and -ConfirmEngineShutdown. Use StackFault for routine recovery tests.'
}
$devopsRoot = Split-Path $PSScriptRoot -Parent
if (-not $PSBoundParameters.ContainsKey('CustodyRoot')) { $CustodyRoot = Join-Path 'C:\Work\DeepSession\secrets\dev' $ProjectName }
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
$devEnvironmentNames = @('DEEP_DEV_ROOT','DEEP_DEV_PROJECT','DEEP_DEV_IPV4_PREFIX','DEEP_DEV_PORT_PREFIX','DEEP_DEV_REGISTRY_PORT','DEEP_DEV_MAILBOX_NETWORK','DEEP_DEV_MAILBOX_POLICY','DEEP_DEV_CONTACT_NODE1','DEEP_DEV_CONTACT_NODE2','DEEP_DEV_CONTACT_NODE3')
$devPreviousEnvironment = @{}
foreach ($name in $devEnvironmentNames) { $devPreviousEnvironment[$name] = [Environment]::GetEnvironmentVariable($name,'Process') }
try {
$env:DEEP_DEV_ROOT = $custodyPath.Replace('\','/')
$env:DEEP_DEV_PROJECT = $ProjectName
$env:DEEP_DEV_IPV4_PREFIX = if ($ProjectName -ceq 'deep-dev-current') { '172.31.241' } else { '172.31.240' }
$env:DEEP_DEV_PORT_PREFIX = if ($ProjectName -ceq 'deep-dev-current') { '282' } else { '281' }
$env:DEEP_DEV_REGISTRY_PORT = if ($ProjectName -ceq 'deep-dev-current') { '28543' } else { '28443' }
$compose = @('compose','--project-name',$ProjectName,'--file',(Join-Path $devopsRoot 'docker-compose.deep-dev.yml'))
$mailboxMarker = Join-Path $custodyPath 'mailbox/enabled'
$mailboxEnabled = Test-Path -LiteralPath $mailboxMarker -PathType Leaf
if ($mailboxEnabled) {
    if ($ProjectName -cne 'deep-dev-current' -or ((Get-Item -LiteralPath $mailboxMarker).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Invalid current-dev mailbox activation marker.' }
    $compose += @('--file',(Join-Path $devopsRoot 'docker-compose.deep-dev.mailbox.yml'))
}
$nodeMailboxEnabled = Test-Path -LiteralPath (Join-Path $custodyPath 'mailbox/nodes-enabled') -PathType Leaf
if ($nodeMailboxEnabled -or $Action -in @('EnrollNodeMailbox','ActivateNodeMailbox')) {
    if (-not $mailboxEnabled) { throw 'Actual issuer must be enabled before node mailbox composition.' }
    $bindingsFile = Join-Path $custodyPath 'mailbox/node-bindings.json'
    if (-not (Test-Path -LiteralPath $bindingsFile -PathType Leaf) -or ((Get-Item -LiteralPath $bindingsFile).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Verified explicit node mailbox bindings missing/linked.' }
    $bindings = Get-Content -LiteralPath $bindingsFile -Raw | ConvertFrom-Json
    if ($bindings.NetworkIdHex -cnotmatch '^[0-9a-f]{32}$' -or $bindings.MailboxAuthorityCoreHashHex -cnotmatch '^[0-9a-f]{64}$') { throw 'Invalid node mailbox bindings.' }
    $env:DEEP_DEV_MAILBOX_NETWORK = $bindings.NetworkIdHex; $env:DEEP_DEV_MAILBOX_POLICY = $bindings.MailboxAuthorityCoreHashHex
    $compose += @('--file',(Join-Path $devopsRoot 'docker-compose.deep-dev.mailbox-nodes.yml'))
}
$contactMarker = Join-Path $custodyPath 'mailbox/contacts-enabled'
$contactEnabled = Test-Path -LiteralPath $contactMarker -PathType Leaf
if ($contactEnabled -or $Action -in @('EnrollNodeContact','ActivateNodeContact')) {
    if ($ProjectName -cne 'deep-dev-current' -or -not $nodeMailboxEnabled) { throw 'Enrolled current mailbox hosts required before resolver composition.' }
    if ($contactEnabled -and ((Get-Item -LiteralPath $contactMarker).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Linked resolver activation marker.' }
    $compose += @('--file',(Join-Path $devopsRoot 'docker-compose.deep-dev.contacts.yml'))
}
$coordinationMarker = Join-Path $custodyPath 'mailbox/coordination/enabled'
$coordinationEnabled = Test-Path -LiteralPath $coordinationMarker -PathType Leaf
if ($coordinationEnabled -or $Action -eq 'ActivateContactCoordination') {
    if (-not $contactEnabled) { throw 'Enrolled current resolver hosts required before contact coordination.' }
    if ($coordinationEnabled -and ((Get-Item -LiteralPath $coordinationMarker).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Linked coordination marker.' }
    $coordinationBindings = Join-Path $custodyPath 'mailbox/coordination/bindings.json'
    if (-not (Test-Path -LiteralPath $coordinationBindings -PathType Leaf) -or ((Get-Item -LiteralPath $coordinationBindings).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Prepared coordination transport bindings missing/linked.' }
    $transport = Get-Content -LiteralPath $coordinationBindings -Raw | ConvertFrom-Json
    if ($transport.NetworkIdHex -cne $env:DEEP_DEV_MAILBOX_NETWORK -or $transport.Nodes.Count -ne 3 -or @($transport.Nodes | Sort-Object -Unique).Count -ne 3) { throw 'Foreign coordination transport bindings.' }
    foreach ($number in 1..3) {
        $key = $transport.Nodes[$number-1]
        if ($key -cnotmatch '^[0-9a-f]{64}$' -or $key -ceq ('0'*64)) { throw 'Invalid coordination transport identity.' }
        [Environment]::SetEnvironmentVariable("DEEP_DEV_CONTACT_NODE$number",$key,'Process')
    }
    $compose += @('--file',(Join-Path $devopsRoot 'docker-compose.deep-dev.coordination.yml'))
}
$pkiMarker = Join-Path $custodyPath 'mailbox/pki-enabled'
$pkiEnabled = Test-Path -LiteralPath $pkiMarker -PathType Leaf
if ($pkiEnabled -or $Action -eq 'ApplyDevPki') {
    if ($ProjectName -cne 'deep-dev-current' -or -not $coordinationEnabled) { throw 'Current retained issuer/coordination required for dev PKI.' }
    if ($pkiEnabled -and ((Get-Item -LiteralPath $pkiMarker).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Linked dev PKI marker.' }
    $compose += @('--file',(Join-Path $devopsRoot 'docker-compose.deep-dev.pki.yml'))
}
$devServiceCount = if ($mailboxEnabled) { 8 } else { 6 }
$devServices = @('floor','registry','publisher','node-1','node-2','node-3')
if ($mailboxEnabled) { $devServices += @('deposit-signer','retrieve-signer') }
if ($mailboxEnabled -and $Action -in @('PrepareOperational','ApplyOperational','Provision','ProvisionFloor')) {
    throw 'Mailbox-enabled custody requires coordinated role-volume/journal rollover; these pre-mailbox ceremonies cannot mutate it.'
}
if ($Action -eq 'Init') {
    if (Test-Path -LiteralPath $custodyPath) { throw 'Existing dev custody cannot be overwritten; use Provision/Up for reuse.' }
    $ntsSource = Join-Path $devopsRoot 'tools/nts-observer'
    Run-Native docker @('run','--rm','--mount',"type=bind,source=$ntsSource,target=/src",'-w','/src',
        'golang@sha256:8ac98ca534ac3f51e1f420a1dd2c15e74c75cfa0f23f3ad27eb5d7236c349a0c','sh','-c','GOOS=windows GOARCH=amd64 go build -trimpath -o deep-nts-observer.exe .')
    Run-Native dotnet @('run','--project',(Join-Path $devopsRoot 'tools/deep-dev/Deep.Dev.csproj'),'-c','Debug','--',
        'init',$custodyPath,(Join-Path $ntsSource 'deep-nts-observer.exe'),$ProjectName)
    return
}
if (-not (Test-Path -LiteralPath (Join-Path $custodyPath 'public/deep-dev.json') -PathType Leaf)) { throw 'deep-dev is not provisioned; run Init.' }
if ($Action -notin @('Status','Stop')) {
    $devManifest = Get-Content -LiteralPath (Join-Path $custodyPath 'public/deep-dev.json') -Raw | ConvertFrom-Json
    if ($devManifest.projectName -cne $ProjectName -or $devManifest.containerIpv4Prefix -cne $env:DEEP_DEV_IPV4_PREFIX) {
        throw 'The current custody manifest does not match this isolated Compose project. No legacy configuration inference is supported.'
    }
}
if ($Action -in @('PrepareAuthority','PrepareOperational')) {
    $observer = Join-Path $devopsRoot 'tools/nts-observer/deep-nts-observer.exe'
    if (-not (Test-Path -LiteralPath $observer -PathType Leaf)) { throw 'Build the existing pinned NTS observer first; no clock fallback is supported.' }
    if ($Action -eq 'PrepareOperational') {
        $publisherId = & docker @($compose + @('ps','--quiet','publisher'))
        if ($LASTEXITCODE -ne 0 -or -not $publisherId) { throw 'Operational preparation requires the running owned publisher; operator-stopped services stay stopped.' }
        $publisherState = (& docker inspect $publisherId | ConvertFrom-Json)[0].State
        if ($LASTEXITCODE -ne 0 -or -not $publisherState.Running) { throw 'Operator-stopped publisher cannot be resumed by preparation.' }
        $publisherPolicy = (& docker inspect $publisherId | ConvertFrom-Json)[0].HostConfig.RestartPolicy.Name
        if ($LASTEXITCODE -ne 0 -or $publisherPolicy -notin @('always','unless-stopped')) { throw 'Unexpected owned publisher restart policy.' }
        Run-Native docker @('update','--restart','unless-stopped',$publisherId)
        Run-Native docker ($compose + @('stop','--timeout','10','publisher'))
        $operationalPrepared = $false
        try {
            Run-Native dotnet @('run','--project',(Join-Path $devopsRoot 'tools/deep-dev/Deep.Dev.csproj'),'-c','Debug','--',
                'prepare-operational',$custodyPath,$observer)
            $operationalPrepared = $true
            Write-Host 'Operational successor prepared. Publisher remains stopped for exact-predecessor activation; Start explicitly cancels this preparation.'
        } finally { if (-not $operationalPrepared) {
            Run-Native docker @('update','--restart',$publisherPolicy,$publisherId)
            Run-Native docker ($compose + @('start','publisher'))
        } }
    } else {
        Run-Native dotnet @('run','--project',(Join-Path $devopsRoot 'tools/deep-dev/Deep.Dev.csproj'),'-c','Debug','--',
            'prepare-authority',$custodyPath,$observer)
    }
    return
}
function Invoke-DevObserverAdmission {
    $admissionFile = Join-Path $custodyPath 'observer/admission.dga2'
    if (-not (Test-Path -LiteralPath $admissionFile -PathType Leaf)) { throw 'Retained exact observer admission is missing; do not regenerate the observer.' }
    Run-Native docker @('run','--rm','--label',"deep.project=$ProjectName",'--network',"$($ProjectName)_dev",'--ulimit','core=0',
        '--mount',"type=bind,source=$custodyPath/public,target=/run/deep-public,readonly",
        '--mount',"type=bind,source=$admissionFile,target=/run/deep-observer/admission.dga2,readonly",
        "$ProjectName/publisher:candidate",'Deep.Dev.dll','admit-observer','/run/deep-public','/run/deep-observer/admission.dga2')
}
if ($Action -eq 'PrepareMailbox') {
    if ($ProjectName -cne 'deep-dev-current' -or $mailboxEnabled) { throw 'Preparation requires the retained current contour before activation.' }
    Run-Native dotnet @('run','--project',(Join-Path $devopsRoot 'tools/deep-dev/Deep.Dev.csproj'),'-c','Debug','--','prepare-mailbox',$custodyPath,(Join-Path $devopsRoot 'tools/nts-observer/deep-nts-observer.exe'))
    return
}
if ($Action -eq 'ProvisionMailbox') {
    if ($ProjectName -cne 'deep-dev-current' -or $mailboxEnabled -or (Test-Path -LiteralPath (Join-Path $custodyPath 'mailbox/provisioned'))) { throw 'Explicit first mailbox provisioning only; never reset a retained issuer.' }
    Run-Native dotnet @('run','--project',(Join-Path $devopsRoot 'tools/deep-dev/Deep.Dev.csproj'),'-c','Debug','--','prepare-mailbox',$custodyPath,(Join-Path $devopsRoot 'tools/nts-observer/deep-nts-observer.exe'))
    $roots = Join-Path $custodyPath 'mailbox/roots.sql'
    if (-not (Test-Path -LiteralPath $roots -PathType Leaf)) { throw 'PrepareMailbox must verify retained signed role custody first.' }
    foreach ($role in @('deposit','retrieve')) {
        foreach ($kind in @('secrets','socket')) { Run-Native docker @('volume','create','--label','deep.environment=dev','--label',"deep.project=$ProjectName","$($ProjectName)_$role-$kind") }
        $seed = Join-Path $custodyPath "registry/secrets/mailbox-$role.seed"
        $copy = 'set -eu; test -f /source/role.seed && test ! -L /source/role.seed; if test -f /target/role.seed; then cmp -s /source/role.seed /target/role.seed; else test -z "$(ls -A /target)"; cp /source/role.seed /target/role.seed; fi; test "$(ls -A /target | wc -l)" = 1; chmod 0700 /target; chmod 0600 /target/role.seed; chown 0:0 /target /target/role.seed'
        Run-Native docker @('run','--rm','--network','none','--mount',"type=bind,source=$seed,target=/source/role.seed,readonly",'--mount',"type=volume,source=$($ProjectName)_$role-secrets,target=/target",'alpine:3.22','sh','-c',$copy)
        Run-Native docker @('run','--rm','--network','none','--mount',"type=volume,source=$($ProjectName)_$role-socket,target=/target",'alpine:3.22','sh','-c','set -eu; test -z "$(ls -A /target)"; chmod 0700 /target; chown 0:0 /target')
    }
    Run-Native docker @('volume','create','--label','deep.environment=dev','--label',"deep.project=$ProjectName","$($ProjectName)_registry-mailbox-secrets")
    # Keep the original volume intact for recovery. Registry's new mount excludes both role seeds.
    $filtered = 'set -eu; for f in /source/*; do test -f "$f" && test ! -L "$f"; n=${f##*/}; case "$n" in mailbox-deposit.seed|mailbox-retrieve.seed) continue;; directory-integrity.key|proof-ledger-integrity.key|request-ledger-integrity.key|time-integrity.key|server.crt|server.key|witness-1.seed|witness-2.seed|witness-3.seed) ;; *) exit 2;; esac; if test -f "/target/$n"; then cmp -s "$f" "/target/$n"; else cp "$f" "/target/$n"; fi; done; test "$(ls -A /target | wc -l)" = 9; test ! -e /target/mailbox-deposit.seed; test ! -e /target/mailbox-retrieve.seed; chmod 0700 /target; chmod 0600 /target/*; chown -R 0:0 /target'
    Run-Native docker @('run','--rm','--network','none','--mount',"type=bind,source=$custodyPath/registry/secrets,target=/source,readonly",'--mount',"type=volume,source=$($ProjectName)_registry-mailbox-secrets,target=/target",'alpine:3.22','sh','-c',$filtered)
    # One explicit atomic DDL/root transaction. Existing tables reject; no IF NOT EXISTS,
    # upsert, deletion or floor provisioning can silently repair lost issuer state.
    $sql = 'BEGIN;' + [IO.File]::ReadAllText((Join-Path (Split-Path $devopsRoot -Parent) 'deep-registry-api/docs/sql/did2-mailbox-grant-journal.sql')) +
        [IO.File]::ReadAllText((Join-Path (Split-Path $devopsRoot -Parent) 'deep-registry-api/docs/sql/mailbox-revocation-journal.sql')) + [IO.File]::ReadAllText($roots) + 'COMMIT;'
    $result = $sql | & docker @($compose + @('exec','-T','floor','gosu','postgres','psql','-q','-v','ON_ERROR_STOP=1','-h','/var/run/postgresql','-U','postgres','-d','deep_dev')) 2>&1
    if ($LASTEXITCODE -ne 0) { throw 'Explicit mailbox journal transaction failed; inspect private state, never reinitialize retained floors.' }
    $null = New-Item -ItemType File -Path (Join-Path $custodyPath 'mailbox/provisioned') -ErrorAction Stop
    Write-Host 'Existing role keys copied to isolated custody; permanent grant/MGR roots explicitly committed. Not activated.'
    return
}
if ($Action -eq 'ActivateMailbox') {
    if ($ProjectName -cne 'deep-dev-current' -or $mailboxEnabled -or -not (Test-Path -LiteralPath (Join-Path $custodyPath 'mailbox/provisioned') -PathType Leaf)) { throw 'Explicit prepared/provisioned current mailbox custody required.' }
    $null = New-Item -ItemType File -Path $mailboxMarker -ErrorAction Stop
    $compose += @('--file',(Join-Path $devopsRoot 'docker-compose.deep-dev.mailbox.yml'))
    Run-Native docker ($compose + @('up','-d','--wait','--wait-timeout','90','deposit-signer','retrieve-signer','registry'))
    Write-Host 'Mailbox composition enabled with retained journals; run Verify before any issuer/device acceptance claim.'
    return
}
if ($Action -eq 'AdmitObserver') { Invoke-DevObserverAdmission; return }
if ($Action -in @('PrepareNodeMailbox','ProvisionNodeMailboxKeys','FetchNodeMailboxControl','EnrollNodeMailbox','ActivateNodeMailbox')) {
    if ($ProjectName -cne 'deep-dev-current' -or -not $mailboxEnabled) { throw 'Current retained issuer required; no old-scope inference.' }
    $nodeName = "node-$NodeNumber"
    $enrollmentMarker = Join-Path $custodyPath "mailbox/$nodeName-enrolled"
    switch ($Action) {
        'PrepareNodeMailbox' {
            if ($nodeMailboxEnabled) { throw 'Existing node scopes cannot be re-prepared as new.' }
            Run-Native dotnet @('run','--project',(Join-Path $devopsRoot 'tools/deep-dev/Deep.Dev.csproj'),'-c','Debug','--','prepare-node-mailbox',$custodyPath,(Join-Path $devopsRoot 'tools/nts-observer/deep-nts-observer.exe'))
        }
        'ProvisionNodeMailboxKeys' {
            if ($nodeMailboxEnabled -or (Test-Path -LiteralPath $enrollmentMarker)) { throw 'First key provision only; never regenerate enrolled custody.' }
            foreach ($kind in @('keys','custody')) { Run-Native docker @('volume','create','--label','deep.environment=dev','--label',"deep.project=$ProjectName","$($ProjectName)_$nodeName-mailbox-$kind") }
            Run-Native docker @('run','--rm','--network','none','--cap-drop','ALL','--security-opt','no-new-privileges:true','--ulimit','core=0',
                '--mount',"type=volume,source=$($ProjectName)_$nodeName-mailbox-keys,target=/run/mailbox-keys",'--entrypoint','dotnet',
                "$ProjectName/publisher:candidate",'Deep.Dev.dll','provision-node-mailbox-keys','/run/mailbox-keys')
        }
        'FetchNodeMailboxControl' {
            $control = Join-Path $custodyPath 'mailbox/node-control'
            if (-not (Test-Path -LiteralPath $control)) { $null=New-Item -ItemType Directory -Path $control }
            if ((Get-Item -LiteralPath $control).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Control capture directory must not be linked.' }
            Run-Native docker @('run','--rm','--network',"$($ProjectName)_dev",'--ulimit','core=0',
                '--mount',"type=bind,source=$custodyPath/public,target=/run/deep-public,readonly",'--mount',"type=bind,source=$control,target=/run/node-control",
                "$ProjectName/publisher:candidate",'Deep.Dev.dll','fetch-node-mailbox-control','/run/deep-public','/run/node-control','/usr/local/bin/deep-nts-observer')
        }
        'EnrollNodeMailbox' {
            if ($nodeMailboxEnabled -or (Test-Path -LiteralPath $enrollmentMarker)) { throw 'Explicit genuinely new node enrollment only; preserve partial failures.' }
            # Stop the existing owner before touching its same retained data/proof roots.
            Run-Native docker ($compose + @('stop','--timeout','10',$nodeName))
            Run-Native docker ($compose + @('run','--rm','--no-deps',$nodeName,'XNode.dll','current-mailbox-enroll',
                '--deposit-mgr1-file','/run/node-control/deposit.mgr1','--retrieve-mgr1-file','/run/node-control/retrieve.mgr1'))
            $null=New-Item -ItemType File -Path $enrollmentMarker -ErrorAction Stop
            Write-Host 'Explicit new node mailbox floor enrollment completed; activate normal consumers separately.'
        }
        'ActivateNodeMailbox' {
            if ($nodeMailboxEnabled) { throw 'Already enabled; use normal Up/Start with retained state.' }
            foreach ($number in 1..3) { if (-not (Test-Path -LiteralPath (Join-Path $custodyPath "mailbox/node-$number-enrolled") -PathType Leaf)) { throw 'All three explicit enrollments required.' } }
            $null=New-Item -ItemType File -Path (Join-Path $custodyPath 'mailbox/nodes-enabled') -ErrorAction Stop
            Run-Native docker ($compose + @('up','-d','node-1','node-2','node-3'))
            Write-Host 'Current node mailbox consumers activated; verified admission/restart still required.'
        }
    }
    return
}
if ($Action -in @('ProvisionNodeContactKeys','EnrollNodeContact','ActivateNodeContact')) {
    if ($ProjectName -cne 'deep-dev-current' -or -not $nodeMailboxEnabled) { throw 'Enrolled current mailbox hosts required; no new scope inference.' }
    $nodeName = "node-$NodeNumber"
    $enrollmentMarker = Join-Path $custodyPath "mailbox/$nodeName-contact-enrolled"
    switch ($Action) {
        'ProvisionNodeContactKeys' {
            if ($contactEnabled -or (Test-Path -LiteralPath $enrollmentMarker)) { throw 'First resolver key provision only; preserve enrolled custody.' }
            foreach ($kind in @('keys','custody')) { Run-Native docker @('volume','create','--label','deep.environment=dev','--label',"deep.project=$ProjectName","$($ProjectName)_$nodeName-contact-$kind") }
            Run-Native docker @('run','--rm','--network','none','--cap-drop','ALL','--security-opt','no-new-privileges:true','--ulimit','core=0',
                '--mount',"type=volume,source=$($ProjectName)_$nodeName-contact-keys,target=/run/contact-keys",'--entrypoint','dotnet',
                "$ProjectName/publisher:candidate",'Deep.Dev.dll','provision-node-contact-keys','/run/contact-keys')
        }
        'EnrollNodeContact' {
            if ($contactEnabled -or (Test-Path -LiteralPath $enrollmentMarker)) { throw 'Explicit genuinely new resolver enrollment only; preserve uncertain state.' }
            Run-Native docker ($compose + @('stop','--timeout','10',$nodeName))
            Run-Native docker ($compose + @('run','--rm','--no-deps',$nodeName,'XNode.dll','contact-resolver-enroll'))
            $null=New-Item -ItemType File -Path $enrollmentMarker -ErrorAction Stop
            Write-Host 'Explicit resolver enrollment completed; current runtime verification remains required.'
        }
        'ActivateNodeContact' {
            if ($contactEnabled) { throw 'Already enabled; use normal Up/Start with retained state.' }
            foreach ($number in 1..3) { if (-not (Test-Path -LiteralPath (Join-Path $custodyPath "mailbox/node-$number-contact-enrolled") -PathType Leaf)) { throw 'All three explicit resolver enrollments required.' } }
            $null=New-Item -ItemType File -Path $contactMarker -ErrorAction Stop
            Run-Native docker ($compose + @('up','-d','node-1','node-2','node-3'))
            Write-Host 'Current contact and private grant consumers activated; no client delivery claim.'
        }
    }
    return
}
if ($Action -in @('PrepareContactCoordination','ProvisionContactCoordination','ActivateContactCoordination')) {
    if ($ProjectName -cne 'deep-dev-current' -or -not $contactEnabled -or $coordinationEnabled) { throw 'First current coordination enrollment only; preserve existing journals.' }
    $coordinationProvisioned = Join-Path $custodyPath 'mailbox/coordination/provisioned'
    if ($Action -in @('PrepareContactCoordination','ProvisionContactCoordination')) {
        if (Test-Path -LiteralPath $coordinationProvisioned) { throw 'Existing coordination roots cannot be provisioned as new.' }
        Run-Native dotnet @('run','--project',(Join-Path $devopsRoot 'tools/deep-dev/Deep.Dev.csproj'),'-c','Debug','--','prepare-contact-coordination',$custodyPath,(Join-Path $devopsRoot 'tools/nts-observer/deep-nts-observer.exe'))
    }
    if ($Action -eq 'ProvisionContactCoordination') {
        $roots = Join-Path $custodyPath 'mailbox/coordination/roots.sql'
        $schema = Join-Path (Split-Path $devopsRoot -Parent) 'deep-registry-api/docs/sql'
        $sql = 'BEGIN;' + [IO.File]::ReadAllText((Join-Path $schema 'did2-route-threshold-journal.sql')) +
            [IO.File]::ReadAllText((Join-Path $schema 'did2-publication-journal.sql')) + [IO.File]::ReadAllText($roots) + 'COMMIT;'
        $result = $sql | & docker @($compose + @('exec','-T','floor','gosu','postgres','psql','-q','-v','ON_ERROR_STOP=1','-h','/var/run/postgresql','-U','postgres','-d','deep_dev')) 2>&1
        if ($LASTEXITCODE -ne 0) { throw 'Explicit coordination journal transaction failed; preserve uncertain state, no root reset.' }
        $null=New-Item -ItemType File -Path $coordinationProvisioned -ErrorAction Stop
        Write-Host 'Permanent current route/publication journal roots explicitly committed; runtime performs no DDL.'
    }
    if ($Action -eq 'ActivateContactCoordination') {
        if (-not (Test-Path -LiteralPath $coordinationProvisioned -PathType Leaf)) { throw 'Explicit coordination journal provisioning required.' }
        $null=New-Item -ItemType File -Path $coordinationMarker -ErrorAction Stop
        Run-Native docker ($compose + @('up','-d','registry','node-1','node-2','node-3'))
        Write-Host 'Current contact threshold coordination activated; owned-client grant acceptance remains required.'
    }
    return
}
if ($Action -in @('PrepareDevPki','ApplyDevPki')) {
    if ($ProjectName -cne 'deep-dev-current' -or -not $coordinationEnabled) { throw 'Supported current-dev-only TLS ceremony.' }
    $project = Join-Path $devopsRoot 'tools/deep-dev/Deep.Dev.csproj'
    if ($Action -eq 'PrepareDevPki') {
        Run-Native dotnet @('run','--project',$project,'-c','Debug','--','prepare-dev-pki',$custodyPath,(Join-Path $devopsRoot 'tools/nts-observer/deep-nts-observer.exe'))
        return
    }
    $candidate = Join-Path $custodyPath 'offline-root/dev-pki'
    $leasePath = Join-Path $custodyPath 'offline-root/dev-pki-activation.lease'
    if ((Test-Path -LiteralPath $leasePath) -and ((Get-Item -LiteralPath $leasePath).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Linked dev PKI lease.' }
    $lease = [IO.FileStream]::new($leasePath,[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
    try {
        Run-Native dotnet @('run','--project',$project,'-c','Debug','--','validate-dev-pki',$custodyPath)
        Run-Native docker ($compose + @('stop','--timeout','10'))
        # A partial installation stays stopped and resumes from sealed before/after images.
        foreach ($service in @('registry','floor','node-1','node-2','node-3')) {
            $volume = if ($service -ceq 'registry') { "$($ProjectName)_registry-mailbox-secrets" } else { "$($ProjectName)_$service-secrets" }
            $after = Join-Path $candidate "$service/secrets/server.crt"
            $before = Join-Path $candidate "volume-before/$service/secrets/server.crt"
            $copy = 'set -eu; test -f /target/server.crt && test ! -L /target/server.crt; test -f /target/server.key && test ! -L /target/server.key; cmp -s /source/server.crt /target/server.crt || cmp -s /before/server.crt /target/server.crt; if test -e /target/server.crt.pki-stage; then test ! -L /target/server.crt.pki-stage; cmp -s /source/server.crt /target/server.crt.pki-stage; else cp /source/server.crt /target/server.crt.pki-stage; fi; owner=$(stat -c "%u:%g" /target/server.key); chown "$owner" /target/server.crt.pki-stage; chmod 0600 /target/server.crt.pki-stage; mv /target/server.crt.pki-stage /target/server.crt'
            Run-Native docker @('run','--rm','--network','none','--mount',"type=bind,source=$after,target=/source/server.crt,readonly",
                '--mount',"type=bind,source=$before,target=/before/server.crt,readonly",'--mount',"type=volume,source=$volume,target=/target",'alpine:3.22','sh','-c',$copy)
        }
        Run-Native dotnet @('run','--project',$project,'-c','Debug','--','install-dev-pki',$custodyPath)
        if (-not $pkiEnabled) { $null=New-Item -ItemType File -Path $pkiMarker -ErrorAction Stop }
        Run-Native docker ($compose + @('up','-d'))
        Write-Host 'Same-key dev PKI and signed revocation distribution activated; Verify and owned-client TLS/admission still required.'
    } finally { $lease.Dispose() }
    return
}
if ($Action -eq 'ExerciseOwnedMailbox') {
    if ($ProjectName -cne 'deep-dev-current' -or -not $coordinationEnabled) { throw 'Actual current issuer, resolver and coordination required for the owned client.' }
    Run-Native docker @('run','--rm','--network',"$($ProjectName)_dev",'--ulimit','core=0',
        '--mount',"type=bind,source=$custodyPath/public,target=/run/deep-public,readonly",
        "$ProjectName/publisher:candidate",'Deep.Dev.dll','exercise-owned-mailbox','/run/deep-public')
    return
}
if ($Action -eq 'Build') {
    Run-Native dotnet @('run','--project',(Join-Path $devopsRoot 'tools/deep-dev/Deep.Dev.csproj'),'-c','Debug','--','configure',$custodyPath)
    Run-Native docker ($compose + @('build','registry','node-1','publisher')); return
}
function Test-CurrentCapabilities {
    $ready = $true
    if ($pkiEnabled) {
        & docker @($compose + @('exec','-T','publisher','curl','--fail','--silent','--max-time','5','--output','/dev/null','http://localhost:8080/deep-dev-ca.crl')) 2>$null
        if ($LASTEXITCODE -ne 0) { Write-Host 'Current capability unavailable: signed dev CRL distribution.'; return $false }
    }
    if ($mailboxEnabled) {
        foreach ($role in @('deposit','retrieve')) {
            & docker @($compose + @('exec','-T',"$role-signer",'test','-S',"/run/role-socket/$role.sock")) 2>$null
            if ($LASTEXITCODE -ne 0) { Write-Host "Current capability unavailable: $role-signer process/socket."; return $false }
        }
    }
    $registryResult = & docker @($compose + @('exec','-T','registry','curl','--fail','--silent','--max-time','5','--cacert','/run/deep-public/dev-ca.crt','https://localhost/health/did2/ready')) 2>$null
    if ($LASTEXITCODE -ne 0) { Write-Host "Current capability unavailable: Registry readiness HTTP (exit $LASTEXITCODE)."; return $false }
    try { if (($registryResult | ConvertFrom-Json).ok -ne $true) { return $false } } catch { return $false }
    foreach ($devNode in 1..3) {
        $nodeResult = & docker @($compose + @('exec','-T',"node-$devNode",'curl','--fail','--silent','--max-time','5','http://localhost:8080/health/ready')) 2>$null
        if ($LASTEXITCODE -ne 0) { Write-Host "Current capability unavailable: node-$devNode health HTTP (exit $LASTEXITCODE)."; $ready = $false; continue }
        try {
            $health = $nodeResult | ConvertFrom-Json
            if ($health.privacyRouting -cne 'ready') { Write-Host "Current capability unavailable: node-$devNode verified ONION."; $ready = $false }
            if ($nodeMailboxEnabled -and ($health.currentMailboxHost.recovered -ne $true -or $health.currentMailboxHost.state -cne 'recovered')) {
                Write-Host "Current capability unavailable: node-$devNode native mailbox recovery."; $ready = $false
            }
            if ($contactEnabled -and $health.requiredTerminals.ready -ne $true) {
                Write-Host "Current capability unavailable: node-$devNode required contact terminal."; $ready = $false
            }
        } catch { $ready = $false }
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
if ($Action -eq 'ApplyOperational') {
    if (-not $OperationalCandidate) { throw 'ApplyOperational requires the exact completed private candidate path.' }
    $candidatePath = [IO.Path]::GetFullPath($OperationalCandidate)
    $activationLeasePath = Join-Path $custodyPath 'offline-root/activation.lease'
    if ((Test-Path -LiteralPath $activationLeasePath) -and ((Get-Item -LiteralPath $activationLeasePath -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Activation lease must not traverse links.' }
    $activationLease = [IO.File]::Open($activationLeasePath,[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
    try {
        $ids = @(& docker @($compose + @('ps','--all','--quiet')))
        if ($LASTEXITCODE -ne 0 -or $ids.Count -ne 6) { throw 'Activation requires exactly six retained owned services.' }
        $publisherId = & docker @($compose + @('ps','--all','--quiet','publisher'))
        if ($LASTEXITCODE -ne 0 -or -not $publisherId) { throw 'Retained publisher missing.' }
        $publisherInspection = (& docker inspect $publisherId | ConvertFrom-Json)[0]
        if ($LASTEXITCODE -ne 0 -or $publisherInspection.State.Running -or $publisherInspection.HostConfig.RestartPolicy.Name -cne 'unless-stopped') { throw 'PrepareOperational must leave the publisher stopped before activation.' }
        $tool = Join-Path $devopsRoot 'tools/deep-dev/Deep.Dev.csproj'
        Run-Native dotnet @('run','--no-build','--project',$tool,'-c','Debug','--','validate-operational-install',$custodyPath,$candidatePath)
        # Reject foreign/missing volumes before stopping or writing any owner.
        foreach ($service in @('floor','registry','node-1','node-2','node-3')) {
            $volume = "$($ProjectName)_$service-secrets"
            $inspection = (& docker volume inspect $volume | ConvertFrom-Json)[0]
            if ($LASTEXITCODE -ne 0 -or $inspection.Labels.'deep.project' -cne $ProjectName -or $inspection.Labels.'deep.environment' -cne 'dev') { throw 'Unowned retained custody volume.' }
        }
        Run-Native docker (@('update','--restart','unless-stopped') + $ids)
        Run-Native docker ($compose + @('stop','--timeout','10'))
        $copyImage = 'alpine:3.22'
        foreach ($phase in @('verify','install')) {
            if ($phase -ceq 'install') { Run-Native dotnet @('run','--no-build','--project',$tool,'-c','Debug','--','install-operational',$custodyPath,$candidatePath) }
            foreach ($service in @('floor','registry','node-1','node-2','node-3')) {
                $source = Join-Path $candidatePath "online/$service"
                $before = Join-Path $candidatePath "volume-before/$service"
                $owner = if ($service -ceq 'floor') { '70:70' } else { '0:0' }
                # Exact bounded source set, no wildcard copy of retained identity/state keys.
                $copy = 'set -eu; for f in /source/*; do test -f "$f" && test ! -L "$f"; n=${f##*/}; case "$n" in server.crt|server.key|key_x25519|key_x25519_next|mailbox-deposit.seed|mailbox-retrieve.seed) ;; *) exit 2;; esac; test ! -L "/target/$n"; if cmp -s "$f" "/target/$n"; then :; elif test -f "/before/$n"; then cmp -s "/before/$n" "/target/$n"; else test -f "/before/$n.absent" && test ! -e "/target/$n"; fi; done; '
                if ($phase -ceq 'install') { $copy += 'for f in /source/*; do n=${f##*/}; test ! -L "/target/$n.installing"; cp "$f" "/target/$n.installing"; chmod 0600 "/target/$n.installing"; chown ' + $owner + ' "/target/$n.installing"; mv "/target/$n.installing" "/target/$n"; cmp -s "$f" "/target/$n"; done; sync' }
                Run-Native docker @('run','--rm','--label',"deep.project=$ProjectName",'--network','none','--ulimit','core=0',
                    '--mount',"type=bind,source=$source,target=/source,readonly",'--mount',"type=bind,source=$before,target=/before,readonly",
                    '--mount',"type=volume,source=$($ProjectName)_$service-secrets,target=/target",$copyImage,'sh','-c',$copy)
            }
        }
        # The publisher's existing journal/lease remains the only distribution owner.
        # Never mount the whole candidate or offline-root into this online process.
        $preparedOperator = Join-Path $candidatePath 'operator'
        Run-Native docker @('run','--rm','--label',"deep.project=$ProjectName",'--network',"$($ProjectName)_dev",'--ulimit','core=0',
            '--mount',"type=bind,source=$custodyPath/public,target=/run/deep-public",'--mount',"type=bind,source=$custodyPath/operator,target=/run/deep-operator,readonly",
            '--mount',"type=bind,source=$preparedOperator,target=/run/deep-renewal,readonly",'--mount',"type=volume,source=$($ProjectName)_publisher-state,target=/var/lib/deep-publisher",
            "$ProjectName/publisher:candidate",'Deep.Dev.dll','import-operational','/run/deep-public','/run/deep-operator','/run/deep-renewal','/usr/local/bin/deep-nts-observer')
        Run-Native docker (@('update','--restart','always') + $ids)
        Run-Native docker ($compose + @('start'))
        $recovery = Wait-CurrentCapabilities
        [ordered]@{schema='deep-dev-operational-activation.v1';retainedState=$true;verifiedRegistryAndThreeOnion=$true;recoverySeconds=$recovery;deviceEvidence=$false;mailboxIssuanceEvidence=$false} | ConvertTo-Json
    } finally { $activationLease.Dispose() }
    return
}
if ($Action -in @('StackFault','EngineFault','ExpiryFault')) {
    $wholeEngine = $Action -eq 'EngineFault'
    # Routine faults are project-scoped, including the expired-view case.
    # Only separately approved EngineFault may affect the whole Desktop.
    if ($wholeEngine) {
        $context = & docker context show
        if ($LASTEXITCODE -ne 0 -or $context -cne 'desktop-linux') { throw 'EngineFault requires the local Docker Desktop Linux engine.' }
        $allRunning = @(& docker ps -q)
        if ($LASTEXITCODE -ne 0 -or $allRunning.Count -ne $devServiceCount) { throw 'EngineFault requires no unrelated running containers.' }
    }
    $devRunning = @(& docker ps -q --filter "label=com.docker.compose.project=$ProjectName")
    if ($LASTEXITCODE -ne 0 -or $devRunning.Count -ne $devServiceCount) { throw 'Recovery fault requires the exact owned running service set.' }
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
        $custodyCommand = if ($contactEnabled -and $service -match '^node-[123]$') { 'sha256sum /run/secrets/* /var/lib/mailbox-keys/key-*.xml /var/lib/contact-keys/key-*.xml' }
            elseif ($nodeMailboxEnabled -and $service -match '^node-[123]$') { 'sha256sum /run/secrets/* /var/lib/mailbox-keys/key-*.xml' } else { 'sha256sum /run/secrets/*' }
        $custody[$service] = & docker @($compose + @('exec','-T',$service,'sh','-c',$custodyCommand))
        if ($LASTEXITCODE -ne 0 -or -not $custody[$service]) { throw 'Cannot snapshot retained online custody.' }
    }
    if ($mailboxEnabled) {
        foreach ($role in @('deposit','retrieve')) {
            $custody["$role-signer"] = & docker @($compose + @('exec','-T',"$role-signer",'sh','-c','sha256sum /run/role-secrets/role.seed'))
            if ($LASTEXITCODE -ne 0 -or -not $custody["$role-signer"]) { throw 'Cannot snapshot retained role custody.' }
        }
    }
    if ($Action -eq 'ExpiryFault') {
        # Finish one protected delegated commit while the normal publisher is
        # stopped. The entire dev stack starts only after this real 180-second
        # view's 200-second offline interval; Docker Desktop stays running.
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
            if ($wholeEngine) { Invoke-DesktopOperation 'stop' 60 }
            else { Run-Native docker ($compose + @('stop','--timeout','10')) }
            $offline = [Diagnostics.Stopwatch]::StartNew()
            while ($offline.Elapsed.TotalSeconds -lt $OfflineSeconds) {
                Start-Sleep -Seconds ([Math]::Min(10,[Math]::Max(1,[Math]::Ceiling($OfflineSeconds - $offline.Elapsed.TotalSeconds))))
            }
        } finally {
            if ($wholeEngine) {
                # No compose repair: restart-policy recovery itself is under test.
                Invoke-DesktopOperation 'start' 120
            } else { Run-Native docker ($compose + @('start')) }
        }
        $recovery = [Diagnostics.Stopwatch]::StartNew()
        if ($wholeEngine) {
            $engineReady = $false
            while ($recovery.Elapsed.TotalSeconds -lt 120) {
                $engine = & docker info --format '{{.OSType}}' 2>$null
                if ($LASTEXITCODE -eq 0 -and $engine -ceq 'linux') { $engineReady = $true; break }
                Start-Sleep -Seconds 2
            }
            if (-not $engineReady) { throw 'Docker Engine did not return after Desktop start.' }
        }
        [void](Wait-CurrentCapabilities)
        $seconds = [Math]::Ceiling($recovery.Elapsed.TotalSeconds)
        $stable = [Diagnostics.Stopwatch]::StartNew()
        while ($stable.Elapsed.TotalSeconds -lt $StableSeconds) {
            if (-not (Test-CurrentCapabilities)) { throw 'A current proof/ONION capability was lost during the post-restart stability window.' }
            Start-Sleep -Seconds 2
        }
        foreach ($id in $retained.Keys) {
            $after = (& docker inspect --format '{{json .Mounts}}' $id) | ConvertFrom-Json | ForEach-Object { "$($_.Type)|$($_.Source)|$($_.Destination)|$($_.RW)" } | Sort-Object
            if ($LASTEXITCODE -ne 0 -or ($after -join "`n") -cne ($retained[$id] -join "`n")) { throw 'Recovery changed retained containers or custody/state mounts.' }
        }
        foreach ($service in $custody.Keys) {
            $digestCommand = if ($service -in @('deposit-signer','retrieve-signer')) { 'sha256sum /run/role-secrets/role.seed' }
                elseif ($contactEnabled -and $service -match '^node-[123]$') { 'sha256sum /run/secrets/* /var/lib/mailbox-keys/key-*.xml /var/lib/contact-keys/key-*.xml' }
                elseif ($nodeMailboxEnabled -and $service -match '^node-[123]$') { 'sha256sum /run/secrets/* /var/lib/mailbox-keys/key-*.xml' }
                else { 'sha256sum /run/secrets/*' }
            $after = & docker @($compose + @('exec','-T',$service,'sh','-c',$digestCommand))
            if ($LASTEXITCODE -ne 0 -or ($after -join "`n") -cne ($custody[$service] -join "`n")) { throw 'Online custody changed across recovery.' }
        }
        $cases.Add([ordered]@{cycle=$cycle;offlineSeconds=$OfflineSeconds;recovered=$true;recoverySeconds=$seconds;stableSeconds=$StableSeconds})
        # Emit each completed case before starting another, so a later host
        # failure cannot hide earlier results or imply the whole matrix passed.
        $caseSchema = if ($wholeEngine) { 'deep-dev-engine-case.v1' } else { 'deep-dev-stack-case.v1' }
        [ordered]@{schema=$caseSchema;cycle=$cycle;offlineSeconds=$OfflineSeconds;recoverySeconds=$seconds;stableSeconds=$StableSeconds;retainedNodeRegistryCustody=$true;retainedMounts=$true} | ConvertTo-Json -Compress
        Write-Host "deep-dev recovery cycle $cycle passed; retained custody/state; current capabilities stable."
    }
    $faultSchema = if ($wholeEngine) { 'deep-dev-engine-fault.v1' } else { 'deep-dev-stack-fault.v1' }
    [ordered]@{schema=$faultSchema;cases=$cases.ToArray();automaticContainerStart=$wholeEngine;wholeEngineShutdown=$wholeEngine;unchangedCustody=$true;unchangedStateMounts=$true;expiredOperationalViewEvidence=($Action -eq 'ExpiryFault');soak72h=$false;deviceEvidence=$false;messageDeliveryEvidence=$false} | ConvertTo-Json -Depth 5
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
    foreach ($service in $devServices) {
        $containerId = & docker @($compose + @('ps','-q',$service))
        $mounts[$service] = (& docker inspect --format '{{json .Mounts}}' $containerId) | ConvertFrom-Json | ForEach-Object { "$($_.Type)|$($_.Source)|$($_.Destination)|$($_.RW)" } | Sort-Object
        if ($LASTEXITCODE -ne 0) { throw 'Cannot snapshot exact development mounts.' }
    }
    $cases = [Collections.Generic.List[object]]::new()
    foreach ($service in $devServices) {
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
        Run-Native docker @('run','--rm','--label',"deep.project=$ProjectName",'--network',"$($ProjectName)_dev",'--ulimit','core=0',
            '--mount',"type=bind,source=$custodyPath/public,target=/run/deep-public,readonly","$ProjectName/publisher:candidate",
            'Deep.Dev.dll','exercise-directory','/run/deep-public')
    } finally { Run-Native docker ($compose + @('start','node-1','node-2','node-3')) }
    [ordered]@{schema='deep-dev-history-fault.v1';offlineNodes=3;admittedFixtures=130;recoveredVerifiedOnionNodes=3;recoverySeconds=(Wait-CurrentCapabilities);custodyReset=$false;deviceEvidence=$false;messageDeliveryEvidence=$false} | ConvertTo-Json
    return
}
if ($Action -in @('Provision','ProvisionFloor')) {
    # Copy only online service custody. Neither offline-root nor operator is mounted.
    foreach ($service in @('floor','registry','node-1','node-2','node-3')) {
        $volume = "$($ProjectName)_$service-secrets"
        $present = & docker volume ls --filter "name=^$volume$" --format '{{.Name}}'
        if ($LASTEXITCODE -ne 0) { throw 'Cannot inspect exact dev custody volumes.' }
        if ($present -cne $volume) { Run-Native docker @('volume','create','--label','deep.environment=dev','--label',"deep.project=$ProjectName",$volume) }
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
    'Up' {
        Run-Native docker ($compose + @('up','-d'))
        Invoke-DevObserverAdmission
    }
    'Status' { Run-Native docker ($compose + @('ps','--all')) }
    'Stop' {
        # Explicit maintenance stop stays stopped across engine boots. This is
        # distinct from Desktop shutdown of the normally auto-starting network.
        $ids = @(& docker @($compose + @('ps','--all','--quiet')))
        if ($LASTEXITCODE -ne 0 -or $ids.Count -ne $devServiceCount) { throw 'Cannot resolve exact retained dev services.' }
        Run-Native docker (@('update','--restart','unless-stopped') + $ids)
        Run-Native docker ($compose + @('stop'))
    }
    'Start' {
        $ids = @(& docker @($compose + @('ps','--all','--quiet')))
        if ($LASTEXITCODE -ne 0 -or $ids.Count -ne $devServiceCount) { throw 'Cannot resolve exact retained dev services; use Up for initial creation.' }
        Run-Native docker (@('update','--restart','always') + $ids)
        Run-Native docker ($compose + @('start'))
    }
}
} finally {
    foreach ($name in $devEnvironmentNames) { [Environment]::SetEnvironmentVariable($name,$devPreviousEnvironment[$name],'Process') }
}
