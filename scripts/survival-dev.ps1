[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('Prepare','Up','Down','Status','Logs','Build','Restart','ChaosBegin','ChaosEnd','ChaosStatus')]
    [string]$Action,
    [string[]]$Service = @(),
    [string]$LanHost,
    [switch]$Chain,
    [switch]$Reset,
    [ValidateRange(5, 300)]
    [int]$ChaosTtlSeconds = 60
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$Root = [IO.Path]::GetFullPath((Split-Path $PSScriptRoot -Parent))
$ComposePath = Join-Path $Root 'docker-compose.survival.dev.yml'
$ChaosComposePath = Join-Path $Root 'docker-compose.survival-resend-chaos.dev.yml'
$Project = 'deep-survival-dev'
$baseArguments = @('compose', '-p', $Project, '-f', $ComposePath)
$chaosArguments = @('compose', '-p', $Project, '-f', $ComposePath, '-f', $ChaosComposePath, '--profile', 'resend-chaos')
$ContextRoot = Join-Path $Root 'artifacts\survival-dev\build-contexts'
$SurvivalXNodeCommit = '4d05fe7dd2dadd3f094c172a382ad675d2ff545a'
$SurvivalXNodeContextManifestSha256 = '2b2a223c96bb3a9cb075262e14b64e083d28f3a2b4a1068b68c737250311e52a'
$SurvivalMailboxBuildHelperSha256 = '04c0f2cf9118b648ce4868390451afd33cd6ad9ce550703b24b3f429ce694b2c'
$SurvivalMailboxDriverSha256 = @{
    'MailboxGrantProvisioner.cs' = 'f88f7ebb0c06f11fde52386341202090e8bd4205ad23bb40c31e7d79d2ac8184'
    'MailboxRuntimePublisher.cs' = 'd6aad71f65987f620ccf0d5a06394240aa199d3bb92ef38b81a9594f8e9ff94b'
    'Program.cs' = '6f8017cf7eb6902a99ffe98d5931e1731c3a704746c598287d1a6147e135f1c2'
    'SurvivalMailboxDriver.csproj' = '4db436d69ea88ac3ff16f08c161b61cc0c048bad84cb7e529b2208fa569eafbe'
}
$ChainLifecycleServices = @(
    'contracts-devnet',
    'contracts-deploy',
    'contracts-smoke',
    'staking-backend'
)
. (Join-Path $PSScriptRoot 'survival-dev-private-secrets.ps1')
$mailboxBuildHelper = Join-Path $PSScriptRoot 'survival-dev-mailbox-build-inputs.ps1'
$mailboxBuildHelperBytes = [IO.File]::ReadAllBytes($mailboxBuildHelper)
try {
    $mailboxBuildHelperHasher = [Security.Cryptography.SHA256]::Create()
    try {
        $actualMailboxBuildHelperSha256 = ([BitConverter]::ToString(
            $mailboxBuildHelperHasher.ComputeHash($mailboxBuildHelperBytes)).Replace('-', '')).ToLowerInvariant()
    } finally {
        $mailboxBuildHelperHasher.Dispose()
    }
    if ($mailboxBuildHelperBytes.Length -gt 1024 * 1024 -or
        $actualMailboxBuildHelperSha256 -cne $SurvivalMailboxBuildHelperSha256) {
        throw 'The immutable mailbox build helper does not match its exact reviewed pin.'
    }
    . ([ScriptBlock]::Create([Text.Encoding]::UTF8.GetString($mailboxBuildHelperBytes)))
} finally {
    [Array]::Clear($mailboxBuildHelperBytes, 0, $mailboxBuildHelperBytes.Length)
}

function Invoke-SurvivalDocker([string[]]$Arguments) {
    & docker @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Survival dev Docker command failed with exit code $LASTEXITCODE."
    }
}

function Resolve-SurvivalSource([string]$EnvironmentName,[string]$DefaultRelativePath) {
    $configured = [Environment]::GetEnvironmentVariable($EnvironmentName)
    $candidate = if ([string]::IsNullOrWhiteSpace($configured)) {
        Join-Path $Root $DefaultRelativePath
    } else {
        $configured
    }
    return [IO.Path]::GetFullPath($candidate)
}

function Invoke-SurvivalDockerBounded([string[]]$Arguments,[int]$TimeoutSeconds) {
    $runId = [Guid]::NewGuid().ToString('N')
    $stdoutPath = Join-Path ([IO.Path]::GetTempPath()) "deep-survival-docker-$runId.stdout.log"
    $stderrPath = Join-Path ([IO.Path]::GetTempPath()) "deep-survival-docker-$runId.stderr.log"
    $process = $null
    try {
        $process = Start-Process -FilePath 'docker' -ArgumentList $Arguments -PassThru `
            -WindowStyle Hidden -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath
        [void]$process.Handle
        $startedAt = [DateTimeOffset]::UtcNow
        $nextProgressAt = $startedAt.AddSeconds(15)
        while (-not $process.WaitForExit(1000)) {
            $now = [DateTimeOffset]::UtcNow
            $elapsedSeconds = [int]($now - $startedAt).TotalSeconds
            if ($elapsedSeconds -ge $TimeoutSeconds) {
                try {
                    if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
                        & taskkill.exe /PID $process.Id /T /F *> $null
                    } else {
                        $process.Kill()
                    }
                } catch { Write-Warning "Failed to terminate timed-out Survival Docker process tree: $_" }
                $process.WaitForExit()
                throw "Survival Docker command exceeded bounded timeout of ${TimeoutSeconds}s."
            }
            if ($now -ge $nextProgressAt) {
                Write-Output "Survival Docker command still running (${elapsedSeconds}s elapsed)."
                $nextProgressAt = $now.AddSeconds(15)
            }
        }
        $process.WaitForExit()
        $process.Refresh()
        $exitCode = $process.ExitCode
        foreach ($path in @($stdoutPath, $stderrPath)) {
            if (Test-Path -LiteralPath $path) { Get-Content -LiteralPath $path }
        }
        if ($null -eq $exitCode -or -not ($exitCode -is [int])) {
            throw 'Survival Docker process completed without an observable integer exit code.'
        }
        if ($exitCode -ne 0) { throw "Survival Docker command failed with exit code $exitCode." }
    } finally {
        foreach ($path in @($stdoutPath, $stderrPath)) {
            Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
        }
        if ($null -ne $process) { $process.Dispose() }
    }
}

function Export-SurvivalContext([string]$Kind,[string]$Source,[string]$Name,[string]$EnvironmentName,[string]$ExpectedCommit = '') {
    $destination = Join-Path $ContextRoot $Name
    $arguments = @((Join-Path $PSScriptRoot 'survival-dev-context-export.mjs'), $Kind, $Source, $destination, $ContextRoot)
    if (-not [string]::IsNullOrWhiteSpace($ExpectedCommit)) { $arguments += $ExpectedCommit }
    $output = @(& node @arguments)
    if ($LASTEXITCODE -ne 0) { throw "Survival $Name build context export failed." }
    $output | Write-Output
    if (-not [string]::IsNullOrWhiteSpace($ExpectedCommit)) {
        $pins = @($output | Where-Object { $_ -match '^SourceContextManifestSha256=([0-9a-f]{64})$' })
        $manifestHash = if ($pins.Count -eq 1 -and $pins[0] -match '^SourceContextManifestSha256=([0-9a-f]{64})$') { $Matches[1] } else { '' }
        if ($manifestHash -ne $SurvivalXNodeContextManifestSha256) {
            throw 'Pinned XNode filtered source-context manifest hash mismatch.'
        }
        $env:SURVIVAL_XNODE_CONTEXT_MANIFEST_SHA256 = $manifestHash
    }
    Set-Item -Path "Env:$EnvironmentName" -Value $destination
}

function Prepare-SurvivalMembershipFixturePackages() {
    # Only public, pinned NuGet inputs cross into the one-shot generator build context.
    # DEV-LOCAL-ONLY deterministic seeds remain compiled in that one-shot tool and are never copied here.
    $source = Resolve-SurvivalSource 'SURVIVAL_CLIENT_SHARED_PATH' '..\deep-client-shared'
    $destination = Join-Path $ContextRoot 'membership-packages'
    $inputs = @(
        @{ Name = 'Deep.Protocol.0.3.0-p04.b887fa0.nupkg'; Hash = '8EF4E70AD0B6C1CC0087F25C0313D6AB6A5387D16246679E4C10A3C00898A442'; Path = 'vendor\p14a2\packages\Deep.Protocol.0.3.0-p04.b887fa0.nupkg' },
        @{ Name = 'Deep.Protocol.Abstractions.0.3.0-p04.b887fa0.nupkg'; Hash = 'FC1212A6765F5778188FCB3866EF923023C2253C3EAD299A542271F4CC4F844F'; Path = 'vendor\p14a2\packages\Deep.Protocol.Abstractions.0.3.0-p04.b887fa0.nupkg' },
        @{ Name = 'Deep.Protocol.Protobuf.0.3.0-p04.b887fa0.nupkg'; Hash = '755A027C58BE670151456CC0BCA4764731F7C493932D9EEDD00C02E704BAF818'; Path = 'vendor\p14a2\packages\Deep.Protocol.Protobuf.0.3.0-p04.b887fa0.nupkg' },
        @{ Name = 'Deep.Protocol.MembershipRoutes.0.1.0-p15.local.nupkg'; Hash = 'FE7B5E638C1AB5E7505F45BB7D5804048D2A4AD273C88DD75D7D46AE80DB641A'; Path = 'vendor\p15\packages\Deep.Protocol.MembershipRoutes.0.1.0-p15.local.nupkg' },
        @{ Name = 'Google.Protobuf.3.32.1.nupkg'; Hash = '02A4A40AD4B81AAE6652A4B163EB5622D1B3B3519CCA348B3CB79AC71D9B2CAB'; Path = 'vendor\p14a2\packages\Google.Protobuf.3.32.1.nupkg' },
        @{ Name = 'Sodium.Core.1.4.1.nupkg'; Hash = 'DE0B567D19BD1C0B9974EE5D98FC4DA87045924B94FFA1B4378BB14E623A65B7'; Path = 'vendor\p14a2\packages\Sodium.Core.1.4.1.nupkg' },
        @{ Name = 'libsodium.1.0.22.nupkg'; Hash = 'F66EAC31EA413C1D5D068B46ADE11D3295C86EC9D6CD29FF158BA58EF51DB51A'; Path = 'vendor\p14a2\packages\libsodium.1.0.22.nupkg' }
    )
    $stage = Join-Path $ContextRoot ('.membership-packages-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $stage -Force | Out-Null
    try {
        foreach ($input in $inputs) {
            $path = Join-Path $source $input.Path
            if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Pinned membership package is missing: $($input.Name)" }
            if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ne $input.Hash) { throw "Pinned membership package hash mismatch: $($input.Name)" }
            Copy-Item -LiteralPath $path -Destination (Join-Path $stage $input.Name) -Force
        }
        Remove-Item -LiteralPath $destination -Recurse -Force -ErrorAction SilentlyContinue
        Move-Item -LiteralPath $stage -Destination $destination
    } catch { Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue; throw }
    Set-Item -Path 'Env:SURVIVAL_MEMBERSHIP_PACKAGES_BUILD_CONTEXT' -Value $destination
}

function Prepare-SurvivalBuildContexts([switch]$IncludeChain) {
    Export-SurvivalContext 'dotnet' (Resolve-SurvivalSource 'SURVIVAL_XNODE_PATH' '..\xnode') 'xnode' 'SURVIVAL_XNODE_BUILD_CONTEXT' $SurvivalXNodeCommit
    Export-SurvivalContext 'dotnet' (Resolve-SurvivalSource 'SURVIVAL_REGISTRY_PATH' '..\deep-registry-api') 'registry' 'SURVIVAL_REGISTRY_BUILD_CONTEXT'
    Prepare-SurvivalMembershipFixturePackages
    if ($IncludeChain) {
        Export-SurvivalContext 'dotnet' (Resolve-SurvivalSource 'SURVIVAL_STAKING_PATH' '..\xpoint-staking-backend') 'staking' 'SURVIVAL_STAKING_BUILD_CONTEXT'
        Export-SurvivalContext 'contracts' (Resolve-SurvivalSource 'SURVIVAL_CONTRACTS_PATH' '..\xpoint-staking-contracts') 'contracts' 'SURVIVAL_CONTRACTS_BUILD_CONTEXT'
    }
}

function Invoke-SurvivalMailboxDriverImmutable([string]$PinnedXNodeSource,[string[]]$Arguments) {
    $work = Join-Path ([IO.Path]::GetTempPath()) (
        'deep-survival-mailbox-driver-' + [Guid]::NewGuid().ToString('N'))
    $sourceRoot = Join-Path $work 'source'
    $artifactsRoot = Join-Path $work 'artifacts'
    $publishRoot = Join-Path $work 'publish'
    $sourceLocks = $null
    try {
        [void][IO.Directory]::CreateDirectory($work)
        Set-MailboxDirectoryExclusiveWritable $work
        $isolated = New-SurvivalMailboxIsolatedSource `
            -XNodeSource $PinnedXNodeSource `
            -DriverSource (Join-Path $Root 'tools\survival-mailbox-driver') `
            -Destination $sourceRoot `
            -ExpectedCommit $SurvivalXNodeCommit `
            -ExpectedManifestSha256 $SurvivalXNodeContextManifestSha256 `
            -ExpectedDriverSha256 $SurvivalMailboxDriverSha256
        Set-MailboxTreeReadOnly $sourceRoot
        $sourceLocks = Open-MailboxTreeReadLocks $sourceRoot
        Assert-SurvivalMailboxIsolatedSource $isolated
        & dotnet publish $isolated.DriverProject `
            --configuration Release `
            --output $publishRoot `
            --artifacts-path $artifactsRoot `
            --no-self-contained `
            '-p:UseAppHost=false' `
            "-p:XNodeSource=$($isolated.XNode)" `
            '-p:ImportDirectoryBuildProps=false' `
            '-p:ImportDirectoryBuildTargets=false' `
            "-p:DirectoryPackagesPropsPath=$(Join-Path $isolated.XNode 'Directory.Packages.props')"
        if ($LASTEXITCODE -ne 0) { throw 'The immutable survival mailbox driver build failed.' }
        Assert-SurvivalMailboxIsolatedSource $isolated
        $driverDll = Join-Path $publishRoot 'SurvivalMailboxDriver.dll'
        if (-not (Test-Path -LiteralPath $driverDll -PathType Leaf)) {
            throw 'The immutable survival mailbox driver entry assembly is missing.'
        }
        & dotnet $driverDll @Arguments
        if ($LASTEXITCODE -ne 0) { throw 'The immutable survival mailbox driver command failed.' }
    } finally {
        if ($null -ne $sourceLocks) {
            foreach ($sourceLock in $sourceLocks) { $sourceLock.Dispose() }
        }
        if (Test-Path -LiteralPath $sourceRoot) { Set-MailboxTreeWritable $sourceRoot }
        Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Prepare-SurvivalMailboxPeerAuthority([string]$PinnedXNodeSource = '') {
    # Generate the real MIP1 Merkle commitment, canonical RIP1 proofs and exact
    # 15-pair placement allowlist through the pinned XNode/Deep.Protocol code.
    $outputDirectory = Join-Path $Root 'artifacts\survival-dev'
    [void][IO.Directory]::CreateDirectory($outputDirectory)
    $xnodeSource = if ([string]::IsNullOrWhiteSpace($PinnedXNodeSource)) {
        Get-PinnedSurvivalXNodeContext
    } else { [IO.Path]::GetFullPath($PinnedXNodeSource) }
    $authorityPath = Join-Path $outputDirectory 'mailbox-peer-authority.env'
    $clientAuthorityPath = Join-Path $outputDirectory 'mailbox-client-xnode-1.env'
    $publicPath = Join-Path $outputDirectory 'mailbox-peer-authority.public.json'
    $clientPublicPath = Join-Path $outputDirectory 'mailbox-client-authority.public.json'
    $coordinatorHost = [Environment]::GetEnvironmentVariable('SURVIVAL_BIND_HOST')
    if ([string]::IsNullOrWhiteSpace($coordinatorHost)) { $coordinatorHost = '127.0.0.1' }
    $authorityStatePath = Get-SurvivalMailboxAuthorityState
    Invoke-SurvivalMailboxDriverImmutable $xnodeSource @(
        'authority',
        '--secrets-dir', (Join-Path $Root '.secrets\survival-dev'),
        '--authority-state', $authorityStatePath,
        '--output-env', $authorityPath,
        '--output-client-env', $clientAuthorityPath,
        '--coordinator-url', "http://$coordinatorHost`:41801",
        '--output-public', $publicPath,
        '--output-client-public', $clientPublicPath)
    Set-Item -Path 'Env:SURVIVAL_MAILBOX_AUTHORITY_ENV' -Value $authorityPath
    Set-Item -Path 'Env:SURVIVAL_MAILBOX_CLIENT_AUTHORITY_ENV' -Value $clientAuthorityPath
    Set-Item -Path 'Env:SURVIVAL_MAILBOX_PUBLIC_AUTHORITY' -Value $publicPath
    Set-Item -Path 'Env:SURVIVAL_MAILBOX_CLIENT_PUBLIC_AUTHORITY' -Value $clientPublicPath
}

function Get-SurvivalMailboxAuthorityState() {
    $directory = Join-Path $Root '.secrets\survival-dev'
    [void][IO.Directory]::CreateDirectory($directory)
    $path = Join-Path $directory 'mailbox-authority-state.v1.json'
    $now = [uint64][DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $anchor = [uint64]([Math]::Floor($now / 60) * 60)
    $state = $null
    $changed = $false
    if (Test-Path -LiteralPath $path -PathType Leaf) {
        $bytes = [IO.File]::ReadAllBytes($path)
        if ($bytes.Length -eq 0 -or $bytes.Length -gt 4096) {
            throw 'DEV mailbox authority state has an invalid size.'
        }
        $state = [Text.Encoding]::UTF8.GetString($bytes) | ConvertFrom-Json
        $names = @($state.PSObject.Properties.Name | Sort-Object)
        $expected = @(
            'currentEpoch', 'currentExpiresAtUnixSeconds', 'currentNotBeforeUnixSeconds',
            'nextEpoch', 'nextExpiresAtUnixSeconds', 'nextNotBeforeUnixSeconds', 'schemaVersion')
        if (($names -join '|') -ne (($expected | Sort-Object) -join '|') -or $state.schemaVersion -ne 1) {
            throw 'DEV mailbox authority state schema is invalid.'
        }
    } else {
        $state = [pscustomobject][ordered]@{
            schemaVersion = 1
            currentEpoch = [uint64]1
            currentNotBeforeUnixSeconds = $anchor - 300
            currentExpiresAtUnixSeconds = $anchor + 28800
            nextEpoch = [uint64]2
            nextNotBeforeUnixSeconds = $anchor - 60
            nextExpiresAtUnixSeconds = $anchor + 43200
        }
        $changed = $true
    }

    $currentEpoch = [uint64]$state.currentEpoch
    $currentNotBefore = [uint64]$state.currentNotBeforeUnixSeconds
    $currentExpires = [uint64]$state.currentExpiresAtUnixSeconds
    $nextEpoch = [uint64]$state.nextEpoch
    $nextNotBefore = [uint64]$state.nextNotBeforeUnixSeconds
    $nextExpires = [uint64]$state.nextExpiresAtUnixSeconds
    if ($currentEpoch -eq 0 -or $nextEpoch -ne $currentEpoch + 1 `
        -or $currentNotBefore -ge $nextNotBefore -or $nextNotBefore -gt $currentExpires `
        -or $currentExpires -ge $nextExpires -or ($nextExpires - $nextNotBefore) -ne 43260) {
        throw 'DEV mailbox authority state window is invalid.'
    }

    if ($now + 1800 -gt $currentExpires) {
        if ($now + 1800 -gt $nextExpires) {
            throw 'DEV mailbox authority overlap was allowed to expire; forward rotation cannot be reconstructed safely.'
        }
        $newNextNotBefore = $anchor - 60
        $newNextExpires = $anchor + 43200
        if ($newNextNotBefore -le $nextNotBefore -or $newNextNotBefore -gt $nextExpires `
            -or $newNextExpires -le $nextExpires) {
            throw 'DEV mailbox authority cannot form the next bounded overlap window.'
        }
        $state = [pscustomobject][ordered]@{
            schemaVersion = 1
            currentEpoch = $nextEpoch
            currentNotBeforeUnixSeconds = $nextNotBefore
            currentExpiresAtUnixSeconds = $nextExpires
            nextEpoch = $nextEpoch + 1
            nextNotBeforeUnixSeconds = $newNextNotBefore
            nextExpiresAtUnixSeconds = $newNextExpires
        }
        $changed = $true
    }

    if ($changed) {
        $temp = $path + '.' + [Guid]::NewGuid().ToString('N') + '.tmp'
        try {
            $json = ($state | ConvertTo-Json -Depth 3) + "`n"
            [IO.File]::WriteAllText($temp, $json, [Text.UTF8Encoding]::new($false))
            Protect-SurvivalDevPrivateFile $temp
            Move-Item -LiteralPath $temp -Destination $path -Force
            Protect-SurvivalDevPrivateFile $path
        } finally {
            Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue
        }
    }
    return $path
}

function Prepare-SurvivalXNodeIdentitySecrets() {
    $directory = Join-Path $Root '.secrets\survival-dev'
    [void][IO.Directory]::CreateDirectory($directory)
    foreach ($index in 1..6) {
        $path = Join-Path $directory "xnode-$index-ed25519.seed"
        $seed = ('{0:x64}' -f $index)
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            if (([IO.File]::ReadAllText($path).Trim()) -ne $seed) { throw 'Existing DEV-LOCAL-ONLY XNode identity secret does not match the pinned fixture identity.' }
        } else {
            [IO.File]::WriteAllText($path, $seed + "`n", [Text.UTF8Encoding]::new($false))
        }
        Protect-SurvivalDevPrivateFile $path
    }
    $issuerPath = Join-Path $directory 'mailbox-client-issuer.seed'
    $issuerSeed = ('{0:x64}' -f 1001)
    if (Test-Path -LiteralPath $issuerPath -PathType Leaf) {
        if (([IO.File]::ReadAllText($issuerPath).Trim()) -ne $issuerSeed) {
            throw 'Existing DEV-LOCAL-ONLY mailbox issuer secret does not match the pinned fixture identity.'
        }
    } else {
        [IO.File]::WriteAllText($issuerPath, $issuerSeed + "`n", [Text.UTF8Encoding]::new($false))
    }
    Protect-SurvivalDevPrivateFile $issuerPath
}

function Reset-SurvivalMembershipFixture() {
    # Force the local-only one-shot to republish a bounded fresh artifact on every supported Up.
    Invoke-SurvivalDocker ($baseArguments + @(
        'rm', '-sf',
        'membership-fixture',
        'membership-artifact-init',
        'membership-artifact-owner-init'))
}

function Remove-SurvivalClientEnvironment() {
    # Never leave a prior catalog pin looking current while a new one-shot is
    # being generated or if its Sodium read-after-publication check fails.
    $outputDirectory = Join-Path $Root 'artifacts\survival-dev'
    foreach ($name in @('client.android.env', 'client.windows.env')) {
        Remove-Item -LiteralPath (Join-Path $outputDirectory $name) -Force -ErrorAction SilentlyContinue
    }
}

function Assert-SurvivalMembershipFixtureVerified() {
    # One-shot success is an exited container. Current Compose excludes exited
    # services from `ps -q` unless --all is explicit.
    $containerId = (& docker @baseArguments 'ps' '-q' '--all' 'membership-fixture')
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($containerId)) {
        throw 'DEV-LOCAL-ONLY membership fixture container is missing.'
    }
    $state = (& docker 'inspect' '--format' '{{.State.Status}}|{{.State.ExitCode}}' $containerId)
    if ($LASTEXITCODE -ne 0 -or ([string]$state).Trim() -ne 'exited|0') {
        throw 'DEV-LOCAL-ONLY membership fixture did not complete its Sodium read-after-publication verification.'
    }
}

function Get-SurvivalVerifiedMembershipPin() {
    $logs = (& docker @baseArguments 'logs' '--no-color' '--no-log-prefix' 'membership-fixture')
    if ($LASTEXITCODE -ne 0) {
        throw 'Unable to read the verified DEV-LOCAL-ONLY membership fixture result.'
    }
    $matches = [regex]::Matches(
        ($logs -join "`n"),
        '(?m)^PublishedArtifactSha256=([0-9a-f]{64})\r?$'
    )
    if ($matches.Count -ne 1) {
        throw 'DEV-LOCAL-ONLY membership fixture did not publish exactly one verified artifact pin.'
    }
    return $matches[0].Groups[1].Value
}

function Get-SurvivalPublishedMembershipPin(
    [string]$MembershipUrl,
    [string]$ExpectedSha256
) {
    $pin = (& node `
        (Join-Path $PSScriptRoot 'survival-dev-membership-trust.mjs') `
        '--url' $MembershipUrl `
        '--expected-sha256' $ExpectedSha256)
    if ($LASTEXITCODE -ne 0 -or ([string]$pin).Trim() -notmatch '^[0-9a-f]{64}$') {
        throw 'Published DEV-LOCAL-ONLY membership trust artifact validation failed.'
    }
    return ([string]$pin).Trim()
}

function Reset-SurvivalChainLifecycle() {
    # Hardhat node state is intentionally in-memory, while the deployment
    # manifest volume persists. Recreate these services for every supported
    # Up -Chain so a stale manifest can never release the staking backend.
    Invoke-SurvivalDocker ($baseArguments + @(
        '--profile', 'chain', 'rm', '-sf',
        'contracts-deploy', 'contracts-smoke', 'staking-backend'))
}

function Assert-SurvivalHostEndpoints([string]$HostName,[switch]$IncludeChain) {
    $targets = @(
        "http://$HostName`:41801/api/network/contact",
        "http://$HostName`:41802/api/network/contact",
        "http://$HostName`:41803/api/network/contact",
        "http://$HostName`:41804/api/network/contact",
        "http://$HostName`:41805/api/network/contact",
        "http://$HostName`:41806/api/network/contact",
        "http://$HostName`:41810/health/live",
        "http://$HostName`:41810/api/network/membership-route-catalog",
        "http://$HostName`:41801/api/network/membership-route-catalog",
        "http://$HostName`:41820/health/ready",
        "http://$HostName`:41821/health/ready",
        "http://$HostName`:41822/health/ready",
        "http://$HostName`:41823/health/ready",
        'http://127.0.0.1:41999/health/ready'
    )
    if ($IncludeChain) {
        $targets += "http://$HostName`:41811/health/ready"
    }
    foreach ($target in $targets) {
        $ready = $false
        foreach ($attempt in 1..40) {
            try {
                $response = Invoke-WebRequest -UseBasicParsing -Uri $target -TimeoutSec 3
                if ($response.StatusCode -ge 200 -and $response.StatusCode -lt 300) {
                    $ready = $true
                    break
                }
            } catch {}
            Start-Sleep -Milliseconds 500
        }
        if (-not $ready) { throw "Survival dev endpoint is unreachable: $target" }
    }
    if ($IncludeChain) {
        $rpcResponse = Invoke-RestMethod `
            -Uri "http://$HostName`:41545" `
            -Method Post `
            -ContentType 'application/json' `
            -Body '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}' `
            -TimeoutSec 3
        if ($rpcResponse.result -ne '0x7a69') {
            throw "Survival dev chain id mismatch: $($rpcResponse.result)"
        }

        $info = Invoke-RestMethod -Uri "http://$HostName`:41811/info" -TimeoutSec 3
        if ($info.contracts.chainId -ne 31337 -or $info.contracts.networkName -ne 'localhost') {
            throw 'Survival staking backend is not bound to the current localhost chain.'
        }
        foreach ($name in @(
            'tokenAddress',
            'serviceNodeRewardsAddress',
            'serviceNodeContributionFactoryAddress',
            'rewardRatePoolAddress'
        )) {
            $value = [string]$info.contracts.$name
            if ($value -notmatch '^0x[0-9a-fA-F]{40}$') {
                throw "Survival staking backend has an invalid $name."
            }
        }
    }
}

function Write-ClientEnvironment(
    [string]$HostName,
    [string]$MembershipArtifactSha256,
    [switch]$IncludeChain
) {
    $address = $null
    if (-not [Net.IPAddress]::TryParse($HostName, [ref]$address) -or
        $address.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or
        $address.Equals([Net.IPAddress]::Any)) {
        throw 'LanHost must be an IPv4 address.'
    }
    if ($MembershipArtifactSha256 -notmatch '^[0-9a-f]{64}$') {
        throw 'An exact lowercase DEV-LOCAL-ONLY membership artifact SHA-256 pin is required.'
    }
    $outputDirectory = Join-Path $Root 'artifacts\survival-dev'
    [void][IO.Directory]::CreateDirectory($outputDirectory)
    $routerIds = @(
        '4cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29',
        '7422b9887598068e32c4448a949adb290d0f4e35b9e01b0ee5f1a1e600fe2674',
        'f381626e41e7027ea431bfe3009e94bdd25a746beec468948d6c3c7c5dc9a54b',
        'fd50b8e3b144ea244fbf7737f550bc8dd0c2650bbc1aada833ca17ff8dbf329b',
        'fde4fba030ad002f7c2f7d4c331f49d13fb0ec747eceebec634f1ff4cbca9def',
        'b4c92afb3ba57f3ab959ffe6d319c98484a2155a0f4c65b2c37011ffd197b075'
    )
    foreach ($target in @(
        [pscustomobject]@{ Name = 'client.android.env'; Host = $HostName },
        [pscustomobject]@{ Name = 'client.windows.env'; Host = $HostName }
    )) {
        $hostValue = $target.Host
        $values = @(
            'SURVIVAL_ENV=Development',
            'DEEP_TRANSPORT_PROTOCOL=authenticated-mau2',
            'DEEP_TRANSPORT_OWNERSHIP=user-managed',
            "XNODE_URLS=$($routerIds[0])|http://$hostValue`:41801;$($routerIds[1])|http://$hostValue`:41802;$($routerIds[2])|http://$hostValue`:41803;$($routerIds[3])|http://$hostValue`:41804;$($routerIds[4])|http://$hostValue`:41805;$($routerIds[5])|http://$hostValue`:41806",
            "DEEP_REGISTRY_URL=http://$hostValue`:41810",
            "DEEP_MEMBERSHIP_ROUTE_CATALOG_URL=http://$hostValue`:41810/api/network/membership-route-catalog",
            "DEEP_DEV_LOCAL_MEMBERSHIP_TRUST_URL=http://$hostValue`:41810/api/network/membership-route-catalog",
            "DEEP_DEV_LOCAL_MEMBERSHIP_TRUST_SHA256=$MembershipArtifactSha256",
            "DEEP_FILE_URL=http://$hostValue`:41821",
            "DEEP_PUSH_URL=http://$hostValue`:41822",
            "DEEP_CALL_SIGNALING_BASE_URL=http://$hostValue`:41823",
            'DEEP_TLS_PINS='
        )
        if ($IncludeChain) {
            $values += "DEEP_STAKING_BACKEND_URL=http://$hostValue`:41811"
            $values += "DEEP_DEVNET_RPC_URL=http://$hostValue`:41545"
        }
        $content = $values -join "`n"
        [IO.File]::WriteAllText(
            (Join-Path $outputDirectory $target.Name),
            $content + "`n",
            [Text.UTF8Encoding]::new($false)
        )
    }
    Write-Output "Client environments: $outputDirectory"
}

function Get-SurvivalChaosHost() {
    $environmentPath = Join-Path $Root 'artifacts\survival-dev\client.windows.env'
    if (-not (Test-Path -LiteralPath $environmentPath -PathType Leaf)) {
        throw 'ChaosBegin requires a successfully prepared survival client environment.'
    }
    $line = @(Get-Content -LiteralPath $environmentPath | Where-Object { $_ -clike 'XNODE_URLS=*' })
    if ($line.Count -ne 1 -or $line[0] -cnotmatch '^XNODE_URLS=[0-9a-f]{64}\|http://(?<host>[0-9.]+):41801(?:;|$)') {
        throw 'Survival client environment does not contain the exact first XNode endpoint.'
    }
    $publishedHost = $Matches.host
    $address = $null
    if (-not [Net.IPAddress]::TryParse($publishedHost, [ref]$address) -or
        $address.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or
        $address.Equals([Net.IPAddress]::Any)) {
        throw 'Survival chaos host must be one exact non-wildcard IPv4 address.'
    }
    if (-not [string]::IsNullOrWhiteSpace($LanHost) -and $LanHost -cne $publishedHost) {
        throw 'ChaosBegin LanHost must exactly match the current verified client environment.'
    }
    return $publishedHost
}

function Get-PinnedSurvivalXNodeContext() {
    $context = Join-Path $ContextRoot 'xnode'
    $manifest = Join-Path $context '.survival-source-manifest.json'
    if (-not (Test-Path -LiteralPath $manifest -PathType Leaf) -or
        (Get-FileHash -LiteralPath $manifest -Algorithm SHA256).Hash.ToLowerInvariant() -cne
            $SurvivalXNodeContextManifestSha256) {
        throw 'ChaosBegin requires the exact previously verified pinned XNode build context.'
    }
    return $context
}

function New-SurvivalChaosToken() {
    $directory = Join-Path $Root '.secrets\survival-dev'
    [void][IO.Directory]::CreateDirectory($directory)
    $path = Join-Path $directory 'resend-chaos.token'
    $temporary = "$path.$([Guid]::NewGuid().ToString('N')).tmp"
    try {
        $random = [byte[]]::new(32)
        $generator = [Security.Cryptography.RandomNumberGenerator]::Create()
        try { $generator.GetBytes($random) } finally { $generator.Dispose() }
        $token = ([BitConverter]::ToString($random) -replace '-', '').ToLowerInvariant()
        [Array]::Clear($random, 0, $random.Length)
        [IO.File]::WriteAllText($temporary, "$token`n", [Text.UTF8Encoding]::new($false))
        Protect-SurvivalDevPrivateFile $temporary
        Move-Item -LiteralPath $temporary -Destination $path -Force
        Assert-SurvivalDevPrivateFile $path
    } finally {
        Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
    }
    $env:SURVIVAL_RESEND_CHAOS_TOKEN_FILE = $path
    return $path
}

function Invoke-SurvivalChaosControl([ValidateSet('arm','disarm','status')][string]$Command) {
    $arguments = $chaosArguments + @(
        'exec', '-T', 'resend-chaos', 'node',
        '/opt/deep-chaos/control-client.mjs', $Command)
    if ($Command -eq 'arm') { $arguments += @('--ttl', [string]$ChaosTtlSeconds) }
    $json = (& docker @arguments | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) { throw 'Survival resend chaos control failed.' }
    $status = $json | ConvertFrom-Json
    if ($status.schema -cne 'deep-survival-resend-chaos-status.v1' -or
        $status.mode -cne 'development-only' -or
        $status.identifiersIncluded -ne $false -or
        $status.payloadInspected -ne $false) {
        throw 'Survival resend chaos returned invalid or unsafe status.'
    }
    return $status
}

function Test-SurvivalChaosRunning() {
    $id = (& docker @($chaosArguments + @('ps', '--status', 'running', '--quiet', 'resend-chaos')) | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) { throw 'Unable to inspect survival resend chaos state.' }
    return -not [string]::IsNullOrWhiteSpace($id)
}

function Wait-SurvivalXNodeOne([string]$HostName) {
    foreach ($attempt in 1..40) {
        try {
            $response = Invoke-WebRequest -UseBasicParsing -Uri "http://$HostName`:41801/health/ready" -TimeoutSec 2
            if ($response.StatusCode -eq 200) { return }
        } catch {}
        Start-Sleep -Milliseconds 500
    }
    throw 'xnode-1 did not recover its ordinary host publisher.'
}

function Stop-SurvivalChaos([string]$HostName, [switch]$BestEffort) {
    $failure = $null
    try {
        if (Test-SurvivalChaosRunning) { [void](Invoke-SurvivalChaosControl 'disarm') }
        Invoke-SurvivalDocker ($chaosArguments + @('stop', 'resend-chaos', 'xnode-1'))
        Invoke-SurvivalDocker ($chaosArguments + @('rm', '-f', 'resend-chaos', 'xnode-1'))
        Invoke-SurvivalDockerBounded -TimeoutSeconds 120 -Arguments ($baseArguments + @('up', '-d', '--no-deps', '--wait', 'xnode-1'))
        Wait-SurvivalXNodeOne $HostName
    } catch {
        $failure = $_
    }
    $tokenPath = Join-Path $Root '.secrets\survival-dev\resend-chaos.token'
    if ($null -eq $failure -and (Test-Path -LiteralPath $tokenPath)) {
        Remove-Item -LiteralPath $tokenPath -Force
    }
    if ($null -ne $failure -and -not $BestEffort) { throw $failure }
    if ($null -ne $failure -and $BestEffort) { Write-Warning 'Chaos cleanup failed; protected token retained.' }
}

switch ($Action) {
    'Prepare' {
        if ($Chain -or $Service.Count -gt 0 -or $Reset) {
            throw 'Prepare does not accept -Chain, -Service, or -Reset.'
        }
        $advertisedHost = if ([string]::IsNullOrWhiteSpace($LanHost)) { '127.0.0.1' } else { $LanHost }
        $env:SURVIVAL_BIND_HOST = $advertisedHost
        Prepare-SurvivalBuildContexts
        Prepare-SurvivalXNodeIdentitySecrets
        Prepare-SurvivalMailboxPeerAuthority
    }
    'Up' {
        if ($Chain -and $Service.Count -gt 0) {
            throw 'Up -Chain always recreates the complete chain lifecycle; do not combine it with -Service.'
        }
        if (-not $Chain -and @($Service | Where-Object { $ChainLifecycleServices -contains $_ }).Count -gt 0) {
            throw 'Chain lifecycle services can only be started with -Action Up -Chain.'
        }
        $advertisedHost = if ([string]::IsNullOrWhiteSpace($LanHost)) { '127.0.0.1' } else { $LanHost }
        Remove-SurvivalClientEnvironment
        $env:SURVIVAL_BIND_HOST = $advertisedHost
        Prepare-SurvivalBuildContexts -IncludeChain:$Chain
        Prepare-SurvivalXNodeIdentitySecrets
        $buildArguments = @($baseArguments)
        if ($Chain) { $buildArguments += @('--profile', 'chain') }
        Invoke-SurvivalDockerBounded `
            -TimeoutSeconds 900 `
            -Arguments ($buildArguments + @('build') + $Service)
        # Authority windows are intentionally generated only after every image
        # build succeeds, immediately before one-shots and XNodes are created.
        Prepare-SurvivalMailboxPeerAuthority
        Reset-SurvivalMembershipFixture
        if ($Chain) { Reset-SurvivalChainLifecycle }
        $upArguments = @($baseArguments)
        if ($Chain) { $upArguments += @('--profile', 'chain') }
        Invoke-SurvivalDockerBounded `
            -TimeoutSeconds 300 `
            -Arguments ($upArguments + @('up', '-d', '--no-build', '--wait') + $Service)
        Assert-SurvivalHostEndpoints $advertisedHost -IncludeChain:$Chain
        & node (Join-Path $PSScriptRoot 'survival-dev-seed.mjs') '--host' $advertisedHost
        if ($LASTEXITCODE -ne 0) { throw 'Survival relay contact seed failed.' }
        Invoke-SurvivalDocker ($baseArguments + @('restart', 'xnode-1', 'xnode-2', 'xnode-3', 'xnode-4', 'xnode-5', 'xnode-6'))
        Assert-SurvivalHostEndpoints $advertisedHost -IncludeChain:$Chain
        & node (Join-Path $PSScriptRoot 'survival-dev-verify.mjs') '--host' $advertisedHost
        if ($LASTEXITCODE -ne 0) { throw 'Survival relay contact verification failed.' }
        Assert-SurvivalMembershipFixtureVerified
        $verifiedMembershipPin = Get-SurvivalVerifiedMembershipPin
        $membershipUrl = "http://$advertisedHost`:41810/api/network/membership-route-catalog"
        $membershipPin = Get-SurvivalPublishedMembershipPin $membershipUrl $verifiedMembershipPin
        Write-ClientEnvironment $advertisedHost $membershipPin -IncludeChain:$Chain
    }
    'Down' {
        $arguments = @($baseArguments)
        if ($Chain) { $arguments += @('--profile', 'chain') }
        $arguments += 'down'
        if ($Reset) { $arguments += '--volumes' }
        Invoke-SurvivalDocker $arguments
    }
    'Status' { Invoke-SurvivalDocker ($baseArguments + @('ps')) }
    'Logs' { Invoke-SurvivalDocker ($baseArguments + @('logs', '-f', '--tail=200') + $Service) }
    'Build' {
        $includeChainContexts = $Chain -or $Service -contains 'contracts-devnet' -or $Service -contains 'staking-backend'
        Prepare-SurvivalBuildContexts -IncludeChain:$includeChainContexts
        Prepare-SurvivalXNodeIdentitySecrets
        $arguments = @($baseArguments)
        if ($Service -contains 'mailbox-driver') { $arguments += @('--profile', 'mailbox-rehearsal') }
        Invoke-SurvivalDockerBounded -TimeoutSeconds 900 -Arguments ($arguments + @('build') + $Service)
    }
    'Restart' {
        if ($Service.Count -eq 0) { throw 'Restart requires at least one -Service.' }
        if (@($Service | Where-Object { $ChainLifecycleServices -contains $_ }).Count -gt 0) {
            throw 'Chain lifecycle services cannot be restarted independently. Use -Action Up -Chain so devnet, deployment, smoke, and staking backend are recreated in order.'
        }
        Invoke-SurvivalDocker ($baseArguments + @('restart') + $Service)
    }
    'ChaosBegin' {
        if ($Chain -or $Service.Count -gt 0 -or $Reset) {
            throw 'ChaosBegin does not accept -Chain, -Service, or -Reset.'
        }
        if (Test-SurvivalChaosRunning) { throw 'Resend chaos is already running; use ChaosEnd first.' }
        $advertisedHost = Get-SurvivalChaosHost
        $env:SURVIVAL_BIND_HOST = $advertisedHost
        $tokenPath = New-SurvivalChaosToken
        try {
            Prepare-SurvivalMailboxPeerAuthority (Get-PinnedSurvivalXNodeContext)
            $nodes = 1..6 | ForEach-Object { "xnode-$_" }
            Invoke-SurvivalDocker ($baseArguments + @('stop') + $nodes)
            Invoke-SurvivalDocker ($chaosArguments + @('rm', '-f', 'resend-chaos') + $nodes)
            Invoke-SurvivalDockerBounded -TimeoutSeconds 180 -Arguments (
                $chaosArguments + @('up', '-d', '--no-build', '--no-deps', '--wait') + $nodes + @('resend-chaos'))
            & node (Join-Path $PSScriptRoot 'survival-dev-seed.mjs') '--host' $advertisedHost
            if ($LASTEXITCODE -ne 0) { throw 'Survival resend chaos relay contact seed failed.' }
            Invoke-SurvivalDocker ($chaosArguments + @('restart') + $nodes)
            Invoke-SurvivalDockerBounded -TimeoutSeconds 120 -Arguments (
                $chaosArguments + @('up', '-d', '--no-deps', '--wait') + $nodes + @('resend-chaos'))
            & node (Join-Path $PSScriptRoot 'survival-dev-verify.mjs') '--host' $advertisedHost
            if ($LASTEXITCODE -ne 0) { throw 'Survival resend chaos topology verification failed.' }
            $status = Invoke-SurvivalChaosControl 'status'
            if ($status.armed -or $status.consumed) {
                throw 'Resend chaos did not start from a clean disarmed state.'
            }
            Invoke-SurvivalChaosControl 'arm' | ConvertTo-Json -Compress
        } catch {
            Stop-SurvivalChaos $advertisedHost -BestEffort
            throw
        }
    }
    'ChaosEnd' {
        if ($Chain -or $Service.Count -gt 0 -or $Reset) {
            throw 'ChaosEnd does not accept -Chain, -Service, or -Reset.'
        }
        $advertisedHost = Get-SurvivalChaosHost
        $env:SURVIVAL_BIND_HOST = $advertisedHost
        Stop-SurvivalChaos $advertisedHost
        [pscustomobject]@{
            schema = 'deep-survival-resend-chaos-end.v1'
            status = 'ok'
            running = $false
            armed = $false
            protectedTokenDeleted = $true
        } | ConvertTo-Json -Compress
    }
    'ChaosStatus' {
        if ($Chain -or $Service.Count -gt 0 -or $Reset -or -not [string]::IsNullOrWhiteSpace($LanHost)) {
            throw 'ChaosStatus does not accept -Chain, -Service, -Reset, or -LanHost.'
        }
        if (Test-SurvivalChaosRunning) {
            Invoke-SurvivalChaosControl 'status' | ConvertTo-Json -Compress
        } else {
            [pscustomobject]@{
                schema = 'deep-survival-resend-chaos-status.v1'
                mode = 'development-only'
                running = $false
                armed = $false
                consumed = $false
                upstreamSuccessObserved = 0
                downstreamDropped = 0
                requestCount = 0
                expiresInSeconds = 0
                identifiersIncluded = $false
                payloadInspected = $false
            } | ConvertTo-Json -Compress
        }
    }
}
