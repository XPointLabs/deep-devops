[CmdletBinding()]
param(
    [string]$XNodeRepository,
    [string]$EvidencePath,
    [Parameter(Mandatory)]
    [string]$BindHost
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$Root = [IO.Path]::GetFullPath((Split-Path $PSScriptRoot -Parent))
if ([string]::IsNullOrWhiteSpace($XNodeRepository)) { $XNodeRepository = Join-Path $Root '..\xnode' }
if ([string]::IsNullOrWhiteSpace($EvidencePath)) {
    $EvidencePath = Join-Path $Root 'artifacts\survival-dev\p10e-mailbox-integration.json'
}
$XNodeRepository = [IO.Path]::GetFullPath($XNodeRepository)
$EvidencePath = [IO.Path]::GetFullPath($EvidencePath)
$ArtifactsRoot = [IO.Path]::GetFullPath((Join-Path $Root 'artifacts'))
$ArtifactsPrefix = $ArtifactsRoot.TrimEnd(
    [IO.Path]::DirectorySeparatorChar,
    [IO.Path]::AltDirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
if (-not $EvidencePath.StartsWith($ArtifactsPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Mailbox integration evidence path must stay inside the DevOps artifacts directory.'
}
# Invalidate prior success before the first source, runtime, or Docker gate. A
# failed rehearsal must never leave stale passed:true evidence discoverable.
Remove-Item -LiteralPath $EvidencePath -Force -ErrorAction SilentlyContinue
$ComposePath = Join-Path $Root 'docker-compose.survival.dev.yml'
$UatTlsComposePath = Join-Path $Root 'docker-compose.survival-uat-tls.dev.yml'
$Launcher = Join-Path $PSScriptRoot 'survival-dev.ps1'
$Project = 'deep-survival-dev'
$expectedCommit = '9fc47598622820430c233bcb8499824540979536'
$expectedManifest = '98e9685bf8c45f2b2507efe5f2ed597dda052b9af0c90571bb0f8a003791a290'
$base = @('compose', '-p', $Project, '-f', $ComposePath, '-f', $UatTlsComposePath)
$nodes = 1..6 | ForEach-Object { "xnode-$_" }
$TlsSecretDirectory = [Environment]::GetEnvironmentVariable('SURVIVAL_UAT_TLS_SECRET_DIR')
if ([string]::IsNullOrWhiteSpace($TlsSecretDirectory)) {
    throw 'SURVIVAL_UAT_TLS_SECRET_DIR is required for the clean-break HTTPS privacy-route rehearsal.'
}
$TlsSecretDirectory = [IO.Path]::GetFullPath($TlsSecretDirectory)
$env:SURVIVAL_UAT_TLS_SECRET_DIR = $TlsSecretDirectory
$TlsCaPath = Join-Path $TlsSecretDirectory 'ca.crt'
if (-not (Test-Path -LiteralPath $TlsCaPath -PathType Leaf)) {
    throw 'The clean-break HTTPS privacy-route rehearsal requires ca.crt in SURVIVAL_UAT_TLS_SECRET_DIR.'
}
$PrivacyRoutesPath = Join-Path $Root 'artifacts\survival-dev\privacy-routes.android.v1.json'

function Invoke-Checked([string]$File, [string[]]$Arguments) {
    & $File @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$File failed with exit code $LASTEXITCODE." }
}

function Invoke-Docker([string[]]$Arguments) {
    Invoke-Checked docker ($base + $Arguments)
}

function Invoke-TlsTopologyVerify() {
    $priorExtraCa = [Environment]::GetEnvironmentVariable('NODE_EXTRA_CA_CERTS')
    try {
        $env:NODE_EXTRA_CA_CERTS = $TlsCaPath
        Invoke-Checked node @(
            (Join-Path $PSScriptRoot 'survival-dev-verify.mjs'),
            '--host', $BindHost,
            '--scheme', 'https')
    }
    finally {
        if ($null -eq $priorExtraCa) {
            Remove-Item Env:NODE_EXTRA_CA_CERTS -ErrorAction SilentlyContinue
        } else {
            $env:NODE_EXTRA_CA_CERTS = $priorExtraCa
        }
    }
}

function Invoke-Driver([string]$Phase, [string]$RunId = '') {
    if (-not (Test-Path -LiteralPath $PrivacyRoutesPath -PathType Leaf)) {
        throw 'The launcher did not publish the required clean-break privacy routes.'
    }
    $arguments = @(
        '--profile', 'mailbox-rehearsal', 'run', '--rm', '--no-deps',
        '--volume', "${PrivacyRoutesPath}:/run/survival/privacy-routes.v1.json:ro",
        '--volume', "${TlsCaPath}:/run/survival/ca.crt:ro",
        '--env', 'SSL_CERT_FILE=/run/survival/ca.crt',
        'mailbox-driver', $Phase,
        '--state-dir', '/state/driver',
        '--client-url', "https://${BindHost}:41801",
        '--privacy-routes', '/run/survival/privacy-routes.v1.json',
        '--coordinator-url', "https://${BindHost}:41801"
    )
    if (-not [Net.IPAddress]::IsLoopback([Net.IPAddress]::Parse($BindHost))) {
        $arguments += '--require-non-loopback-coordinator'
    }
    if (-not [string]::IsNullOrWhiteSpace($RunId)) { $arguments += @('--run-id', $RunId) }
    $output = @(& docker @base @arguments)
    if ($LASTEXITCODE -ne 0) { throw "Live mailbox driver phase '$Phase' failed." }
    $jsonLines = @($output | Where-Object { $_ -match '^\{"schemaVersion":1,' })
    if ($jsonLines.Count -ne 1) { throw "Live mailbox driver phase '$Phase' emitted no unique sanitized result." }
    $result = $jsonLines[0] | ConvertFrom-Json
    if ($result.passed -ne $true -or $result.phase -notmatch '^(reset|retention-gc|store|replay|selected-peer-loss|selected-peer-retry|tombstone|client-lifecycle|client-fallback-continuity|client-selected-peer-loss|client-selected-peer-retry)$') {
        throw "Live mailbox driver phase '$Phase' did not pass."
    }
    return $result
}

function Get-XNodeInternalDocument([int]$Index,[string]$Path) {
    if ($Path -notmatch '^/[a-z/]+$') { throw 'Internal XNode probe path is invalid.' }
    $container = "$Project-xnode-$Index-1"
    $health = (& docker inspect $container --format '{{.State.Health.Status}}').Trim()
    if ($LASTEXITCODE -ne 0 -or $health -cne 'healthy') {
        throw "xnode-$Index is not healthy."
    }
    $probe = "exec 3<>/dev/tcp/127.0.0.1/8080; printf 'GET $Path HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n' >&3; cat <&3"
    $response = @(& docker exec $container bash -ec $probe)
    $separator = [Array]::IndexOf($response, '')
    if ($LASTEXITCODE -ne 0 -or $response.Count -gt 64 -or
        $separator -lt 2 -or $response[0] -notmatch '^HTTP/1\.1 200 ' -or
        -not (@($response[1..($separator - 1)]) -contains 'Transfer-Encoding: chunked')) {
        throw "xnode-$Index did not return one bounded internal JSON document for $Path."
    }
    $chunk = @($response[($separator + 1)..($response.Count - 1)] | Where-Object { $_ -ne '' })
    $declaredBytes = 0
    if ($chunk.Count -ne 3 -or $chunk[0] -notmatch '^[0-9a-f]+$' -or
        -not [int]::TryParse($chunk[0], [Globalization.NumberStyles]::HexNumber,
            [Globalization.CultureInfo]::InvariantCulture, [ref]$declaredBytes) -or
        $declaredBytes -le 0 -or $declaredBytes -gt 65536 -or $chunk[2] -cne '0' -or
        [Text.Encoding]::UTF8.GetByteCount($chunk[1]) -ne $declaredBytes) {
        throw "xnode-$Index returned malformed or oversized chunked JSON for $Path."
    }
    return $chunk[1] | ConvertFrom-Json
}

function Assert-Runtime() {
    $runtime = @()
    foreach ($index in 1..6) {
        $ready = Get-XNodeInternalDocument $index '/health/ready'
        $status = Get-XNodeInternalDocument $index '/status'
        if ($ready.ready -ne $true -or $ready.mailboxPeer -ne 'ready' -or $status.mailbox.peerRuntime -ne 'ready') {
            throw "xnode-$index did not report peer-runtime readiness."
        }
        if ($index -eq 1) {
            if ($ready.mailboxClient.reason -ne 'ready' -or
                $status.mailboxClient.enabled -ne $true -or
                $status.mailboxClient.clientRoutesMapped -ne $true -or
                $status.mailboxClient.clientIngress -ne 'native-mau2-meo1-mbr2-mba2' -or
                $status.mailboxAuthorityForwarding -ne 'authority') {
                throw 'xnode-1 does not truthfully report the sole canonical client authority.'
            }
            $clientIngress = 'native-mau2-meo1-mbr2-mba2'
        } elseif ($index -eq 2) {
            if ($status.mailboxClient.enabled -ne $false -or
                $status.mailboxClient.clientIngress -ne 'dormant-unmapped' -or
                $status.mailboxAuthorityForwarding -ne 'forwarding-exit') {
                throw 'xnode-2 does not truthfully report forwarding-only mailbox authority state.'
            }
            $clientIngress = 'forwarding-only'
        } else {
            if ($status.mailboxClient.enabled -ne $false -or
                $status.mailboxClient.clientIngress -ne 'dormant-unmapped' -or
                $status.mailboxAuthorityForwarding -ne 'disabled') {
                throw "xnode-$index does not truthfully report dormant-unmapped client ingress."
            }
            $clientIngress = 'dormant-unmapped'
        }
        $runtime += [pscustomobject]@{
            node = "xnode-$index"
            ready = $true
            peerRuntime = 'ready'
            clientIngress = $clientIngress
        }
    }
    return $runtime
}

function Assert-NoCoordinatorStateOnForwardingExit() {
    $container = (& docker @base ps -q xnode-2).Trim()
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($container)) {
        throw 'The forwarding-only xnode-2 container is unavailable.'
    }
    & docker exec $container sh -ec 'for path in /state/mailbox-client-native-mau2-v1 /state/mailbox-capability-replay-v3 /state/mailbox-client-canonical-outcomes-v1; do test ! -e "$path" || exit 1; done'
    if ($LASTEXITCODE -ne 0) {
        throw 'Forwarding-only xnode-2 created or retained forbidden coordinator state.'
    }
}

function Get-ImageBinding() {
    $imageId = (& docker image inspect deep-survival/xnode:dev --format '{{.Id}}').Trim()
    # Windows PowerShell removes the quotes required by Go's index expression
    # before invoking a native executable. Preserve them for docker.exe.
    $revision = (& docker image inspect deep-survival/xnode:dev --format '{{index .Config.Labels \"org.opencontainers.image.revision\"}}').Trim()
    $manifest = (& docker image inspect deep-survival/xnode:dev --format '{{index .Config.Labels \"com.xpoint.source-context.manifest-sha256\"}}').Trim()
    if ($LASTEXITCODE -ne 0 -or $revision -ne $expectedCommit -or $manifest -ne $expectedManifest -or $imageId -notmatch '^sha256:[0-9a-f]{64}$') {
        throw 'The live XNode image is not bound to the exact accepted source revision and context manifest.'
    }
    foreach ($node in $nodes) {
        $container = (& docker @base ps -q $node).Trim()
        $containerImage = (& docker inspect $container --format '{{.Image}}').Trim()
        if ($LASTEXITCODE -ne 0 -or $containerImage -ne $imageId) {
            throw "$node is not running the exact shared accepted XNode image."
        }
    }
    return [pscustomobject]@{ imageId = $imageId; revision = $revision; sourceContextManifestSha256 = $manifest; allSixExact = $true }
}

function Get-StateVolumeBindings() {
    $bindings = @()
    foreach ($node in $nodes) {
        $container = "$Project-$node-1"
        $containerDocument = @((& docker inspect $container) | ConvertFrom-Json)
        if ($LASTEXITCODE -ne 0 -or $containerDocument.Count -ne 1) {
            throw "Unable to inspect $container state volume."
        }

        $stateMount = @($containerDocument[0].Mounts | Where-Object {
            $_.Type -eq 'volume' -and $_.Destination -eq '/state'
        })
        $expectedName = "${Project}_${node}-state"
        if ($stateMount.Count -ne 1 -or $stateMount[0].Name -cne $expectedName) {
            throw "$container does not use the exact expected named state volume."
        }

        $volumeDocument = @((& docker volume inspect $stateMount[0].Name) | ConvertFrom-Json)
        if ($LASTEXITCODE -ne 0 -or $volumeDocument.Count -ne 1) {
            throw "Unable to inspect $($stateMount[0].Name)."
        }

        $bindings += [pscustomobject]@{
            node = $node
            name = $stateMount[0].Name
            createdAt = $volumeDocument[0].CreatedAt
            driver = $volumeDocument[0].Driver
        }
    }
    return $bindings
}

$commit = (& git -C $XNodeRepository rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $commit -ne $expectedCommit) {
    throw 'P10E live rehearsal requires the accepted XNode revision.'
}
if ((& git -C $XNodeRepository status --porcelain=v1 --untracked-files=all)) {
    throw 'P10E live rehearsal requires a clean XNode source checkout.'
}
$bindAddress = [Net.IPAddress]::Parse($BindHost)
if ($bindAddress.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or
    $bindAddress.ToString() -cne $BindHost -or
    $bindAddress.Equals([Net.IPAddress]::Any)) {
    throw 'BindHost must be an exact IPv4 address.'
}

$env:SURVIVAL_BIND_HOST = $BindHost
$env:SURVIVAL_XNODE_PATH = $XNodeRepository
$phases = @()
$runId = [Guid]::NewGuid().ToString('N')
$volumeBindingsBefore = Get-StateVolumeBindings
try {
    # Retain source regressions, then build both consumers from the same exact
    # filtered context. The runtime proof below is independent and live.
    Invoke-Checked dotnet @('test', (Join-Path $XNodeRepository 'tests\XNode.Tests\XNode.Tests.csproj'), '--no-restore', '--filter', 'FullyQualifiedName~ReplicatedMailboxTests', '--logger', 'console;verbosity=minimal')
    Invoke-Checked dotnet @('test', (Join-Path $XNodeRepository 'tests\XNode.Tests\XNode.Tests.csproj'), '--no-restore', '--filter', 'FullyQualifiedName~DurableMailboxCapabilityReplayJournalTests', '--logger', 'console;verbosity=minimal')
    Invoke-Checked dotnet @('test', (Join-Path $XNodeRepository 'tests\XNode.Tests\XNode.Tests.csproj'), '--no-restore', '--filter', 'FullyQualifiedName~MailboxNativeMau2BusinessInvariantTests', '--logger', 'console;verbosity=minimal')
    Invoke-Checked powershell @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (Join-Path $PSScriptRoot 'survival-dev-mailbox-driver.test.ps1'))
    Invoke-Checked dotnet @('test', (Join-Path $XNodeRepository 'tests\XNode.IntegrationTests\XNode.IntegrationTests.csproj'), '--no-restore', '--filter', 'FullyQualifiedName~ReplicatedMailboxIntegrationTests', '--logger', 'console;verbosity=minimal')
    Invoke-Checked dotnet @('test', (Join-Path $XNodeRepository 'tests\XNode.IntegrationTests\XNode.IntegrationTests.csproj'), '--no-restore', '--filter', 'FullyQualifiedName~MailboxClientActivatedEndToEndTests', '--logger', 'console;verbosity=minimal')
    # Build without starting the cleartext base topology, then publish fresh
    # authority for the exact LAN host. Only the merged TLS topology below is
    # allowed to create runtime containers for this rehearsal.
    & $Launcher -Action Build
    if ($LASTEXITCODE -ne 0) { throw 'Survival build failed before the privacy-route rehearsal.' }
    & $Launcher -Action Prepare -LanHost $BindHost
    if ($LASTEXITCODE -ne 0) { throw 'Survival authority preparation failed before the privacy-route rehearsal.' }
    & $Launcher -Action Build -Service @('mailbox-driver')
    if ($LASTEXITCODE -ne 0) { throw 'Mailbox driver build failed before the privacy-route rehearsal.' }

    # Recreate, never reset, the peers behind the CA-trusted UAT ingress so
    # public MAU2 traverses exact HTTPS privacy routes. The merged Compose model
    # removes every direct cleartext XNode host port while preserving volumes.
    Invoke-Docker (@('up', '-d', '--no-build', '--force-recreate', '--wait', '--wait-timeout', '180') +
        $nodes + @('survival-uat-tls-ingress', 'survival-uat-crl', 'turn'))
    # This is a one-shot ownership initializer. `compose up` remains attached
    # after the container exits successfully, so use a bounded disposable run.
    Invoke-Docker @('--profile', 'mailbox-rehearsal', 'run', '--rm', '--no-deps', 'mailbox-driver-state-init')
    $phases += Invoke-Driver 'reset'
    $phases += Invoke-Driver 'retention-gc'
    $phases += Invoke-Driver 'client-fallback-continuity' $runId
    $phases += Invoke-Driver 'client-lifecycle' $runId
    $phases += Invoke-Driver 'store' $runId

    # Exact recipient MRR2 and sender MQR3 must survive recipient recreation.
    Invoke-Docker @('up', '-d', '--no-deps', '--force-recreate', '--wait', '--wait-timeout', '180', 'xnode-2')
    $phases += Invoke-Driver 'replay'

    # Public client Store must never claim quorum while its selected xnode-2
    # peer is unavailable. Retry the exact persisted MAU2 after recovery.
    Invoke-Docker @('stop', '-t', '10', 'xnode-2')
    $phases += Invoke-Driver 'client-loss' $runId
    Invoke-Docker @('start', 'xnode-2')
    Invoke-Docker @('up', '-d', '--no-deps', '--wait', '--wait-timeout', '180', 'xnode-2')
    $phases += Invoke-Driver 'client-retry-loss'

    # Loss is the selected recipient, so local durability is explicitly partial
    # and cannot be reported as quorum. Retry the same PRQ2 after recovery.
    Invoke-Docker @('stop', '-t', '10', 'xnode-3')
    $phases += Invoke-Driver 'loss' $runId
    Invoke-Docker @('start', 'xnode-3')
    Invoke-Docker @('up', '-d', '--no-deps', '--wait', '--wait-timeout', '180', 'xnode-3')
    $phases += Invoke-Driver 'retry-loss'
    $phases += Invoke-Driver 'tombstone'

    [void](Assert-Runtime)
    Assert-NoCoordinatorStateOnForwardingExit
    [void](Get-ImageBinding)
    Invoke-TlsTopologyVerify
}
finally {
    # Restore the selected peer and converge all XNodes to healthy without
    # deleting or recreating any named state volume.
    Invoke-Docker (@('up', '-d', '--no-deps', '--wait', '--wait-timeout', '180') + $nodes)
}

# Evidence is published only after checked restoration and a second live
# validation. A failed finally block therefore cannot leave a new green file.
$runtime = Assert-Runtime
Assert-NoCoordinatorStateOnForwardingExit
$binding = Get-ImageBinding
$volumeBindingsAfter = Get-StateVolumeBindings
if (($volumeBindingsBefore | ConvertTo-Json -Compress) -cne
    ($volumeBindingsAfter | ConvertTo-Json -Compress)) {
    throw 'One or more XNode state volumes changed during the live rehearsal.'
}
Invoke-TlsTopologyVerify

$evidence = [pscustomobject]@{
    schemaVersion = 3
    generatedAt = [DateTimeOffset]::UtcNow
    scope = 'development-only-live-docker-public-client-and-peer-rehearsal'
    passed = $true
    imageBinding = $binding
    stateVolumes = $volumeBindingsAfter
    protocol = 'P10J/MCP2/MAU2/MEO1/MBR2/MBA2/MRP1/MAR1/MIP1/RIP1/PRQ2/MRR2/MQR3'
    phases = $phases
    runtime = $runtime
    assertions = [pscustomobject]@{
        realPeerNetwork = $true
        publicStoreRetrieveAck = $true
        publicStoreExactReplay = $true
        publicClientPrivacyRouted = $true
        fallbackStorePrimaryRetrieveExactlyOnce = $true
        fallbackCoordinatorIsXnode1 = $true
        directCleartextClientIngress = $false
        publicSelectedPeerLossNeverQuorum = $true
        publicSelectedPeerRestartExactRetryQuorum = $true
        boundedReplayRetirementGcSourceRegression = $true
        boundedReplayRetirementGcDriver = $true
        storeTwoOfTwo = $true
        exactReplayAfterRecipientRecreate = $true
        selectedPeerLossNeverQuorum = $true
        selectedPeerRestartRetryQuorum = $true
        tombstoneTwoOfTwoAndReplay = $true
        namedVolumesPreserved = $true
        publicClientMailbox = 'xnode-1-bounded-development-fixture-only'
    }
    limitations = 'The public client ingress and issuer are deterministic DEV-LOCAL-ONLY fixtures; this is not production authority, production durability, or a production-readiness claim.'
}
[void][IO.Directory]::CreateDirectory((Split-Path $EvidencePath -Parent))
[IO.File]::WriteAllText($EvidencePath, (($evidence | ConvertTo-Json -Depth 8) + "`n"), [Text.UTF8Encoding]::new($false))
Write-Output "Live P10E mailbox rehearsal evidence: $EvidencePath"
