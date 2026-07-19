[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{40}$')]
    [string]$ExpectedSourceSha,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{40}$')]
    [string]$ExpectedSourceTree,

    [Parameter(Mandatory = $true)]
    [string]$EvidencePath,

    [ValidatePattern('^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$')]
    [string]$EvidenceClock = '2026-07-20T00:00:00.000Z',

    [string]$ProjectName,

    [switch]$InjectFailureAfterUp,
    [switch]$InjectFailureAfterBuild,
    [switch]$InjectValidationFailureAfterBuild
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$SourceBaseSha = '1c01e24e24647a46b4f37622f3934dc2cc1284ef'
$SourceBaseTree = 'f608ecf9a53d1ce2c99d9c71bdebe4e95b2ebea2'
$BaseImageDigest = 'sha256:242549cd46785b480c832479a730f4f2a20865d61ea2e404fdb2a5c3d3b73ecf'
$BaseImageReference = "node@$BaseImageDigest"
$BaseImageId = $BaseImageDigest
$ComposeFile = Join-Path (Split-Path $PSScriptRoot -Parent) 'docker-compose.p15-compat.yml'
$RepositoryRoot = [IO.Path]::GetFullPath((Split-Path $PSScriptRoot -Parent))
. (Join-Path $PSScriptRoot 'p15-cleanup-state.ps1')
$resourcesMayExist = $false
$runImageReference = $null
$runImageId = $null
$runImageOwned = $false
$buildMayHaveCreatedImage = $false
$contextSha256 = $null
$cleanupFailure = $null

function Invoke-ProcessCapture {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string[]]$ArgumentList,
        [switch]$AllowFailure
    )

    $savedErrorPreference = $ErrorActionPreference
    try {
        # Windows PowerShell promotes native stderr to ErrorRecord. Keep it
        # capturable so AllowFailure can make the fail-closed decision itself.
        $ErrorActionPreference = 'Continue'
        $output = & $FilePath @ArgumentList 2>&1
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $savedErrorPreference
    }
    if (-not $AllowFailure -and $exitCode -ne 0) {
        throw "$FilePath failed with exit code $exitCode."
    }
    return [pscustomobject]@{
        ExitCode = $exitCode
        Text = ($output | Out-String)
    }
}

function Get-GitValue {
    param([string[]]$Arguments)
    $allArguments = @('-C', $RepositoryRoot) + $Arguments
    return (Invoke-ProcessCapture -FilePath 'git' -ArgumentList $allArguments).Text.Trim()
}

function Assert-SourceLock {
    $actualSha = Get-GitValue @('rev-parse', 'HEAD')
    $actualTree = Get-GitValue @('rev-parse', 'HEAD^{tree}')
    $dirty = Get-GitValue @('status', '--porcelain=v1', '--untracked-files=all')
    if ($actualSha -ne $ExpectedSourceSha) {
        throw 'P15A source SHA mismatch.'
    }
    if ($actualTree -ne $ExpectedSourceTree) {
        throw 'P15A source tree mismatch.'
    }
    if ($dirty) {
        throw 'P15A source worktree is dirty.'
    }
    $baseTree = Get-GitValue @('rev-parse', "$SourceBaseSha`^{tree}")
    if ($baseTree -ne $SourceBaseTree) {
        throw 'P15A immutable base tree mismatch.'
    }
    Invoke-ProcessCapture -FilePath 'git' -ArgumentList @(
        '-C', $RepositoryRoot, 'merge-base', '--is-ancestor', $SourceBaseSha, 'HEAD'
    ) | Out-Null
}

function Assert-DockerEnvironment {
    $engine = (Invoke-ProcessCapture -FilePath 'docker' -ArgumentList @(
        'info', '--format', '{{json .Architecture}}'
    )).Text | ConvertFrom-Json
    if ($engine -notin @('arm64', 'aarch64')) {
        throw 'P15A requires a native ARM64 Docker Engine; emulation is prohibited.'
    }

    $inspectResult = Invoke-ProcessCapture -FilePath 'docker' -ArgumentList @(
        'image', 'inspect', $BaseImageReference, '--format', '{{json .}}'
    ) -AllowFailure
    if ($inspectResult.ExitCode -ne 0 -or -not $inspectResult.Text.Trim()) {
        throw 'P15A exact local base image is missing; network pull is prohibited.'
    }
    $image = $inspectResult.Text | ConvertFrom-Json
    if ($image.Id -ne $BaseImageId -or
        $image.Architecture -ne 'arm64' -or
        $image.Os -ne 'linux' -or
        $image.RepoDigests -notcontains $BaseImageReference) {
        throw 'P15A base image identity, digest, OS, or architecture mismatch.'
    }
}

function New-P15ProjectName {
    $bytes = [byte[]]::new(8)
    $generator = [Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $generator.GetBytes($bytes)
    }
    finally {
        $generator.Dispose()
    }
    $hex = [BitConverter]::ToString($bytes).Replace('-', '').ToLowerInvariant()
    return "p15a-$hex"
}

function Assert-ProjectName {
    if ($ProjectName -notmatch '^p15a-[0-9a-f]{16}$') {
        throw 'P15A project name must be a bounded unique p15a namespace.'
    }
}

function Get-LabeledInventory {
    $filter = "label=com.docker.compose.project=$ProjectName"
    $containers = (Invoke-ProcessCapture -FilePath 'docker' -ArgumentList @(
        'ps', '-aq', '--filter', $filter
    )).Text.Split([Environment]::NewLine, [StringSplitOptions]::RemoveEmptyEntries)
    $networks = (Invoke-ProcessCapture -FilePath 'docker' -ArgumentList @(
        'network', 'ls', '-q', '--filter', $filter
    )).Text.Split([Environment]::NewLine, [StringSplitOptions]::RemoveEmptyEntries)
    $volumes = (Invoke-ProcessCapture -FilePath 'docker' -ArgumentList @(
        'volume', 'ls', '-q', '--filter', $filter
    )).Text.Split([Environment]::NewLine, [StringSplitOptions]::RemoveEmptyEntries)
    $images = (Invoke-ProcessCapture -FilePath 'docker' -ArgumentList @(
        'image', 'ls', '-q', '--filter', $filter
    )).Text.Split([Environment]::NewLine, [StringSplitOptions]::RemoveEmptyEntries)
    return [pscustomobject]@{
        Containers = @($containers)
        Networks = @($networks)
        Volumes = @($volumes)
        Images = @($images)
    }
}

function Assert-NoForeignNameCollision {
    $networkName = "${ProjectName}_lab"
    $network = Invoke-ProcessCapture -FilePath 'docker' -ArgumentList @(
        'network', 'inspect', $networkName, '--format', '{{json .}}'
    ) -AllowFailure
    if ($network.ExitCode -eq 0) {
        $networkOwner = ($network.Text | ConvertFrom-Json).Labels.'com.docker.compose.project'
        if ($networkOwner -ne $ProjectName) {
            throw 'P15A refuses a foreign network name collision.'
        }
    }

    foreach ($suffix in @('storage-state', 'file-state', 'push-state', 'calls-state')) {
        $volumeName = "${ProjectName}_$suffix"
        $volume = Invoke-ProcessCapture -FilePath 'docker' -ArgumentList @(
            'volume', 'inspect', $volumeName, '--format', '{{json .}}'
        ) -AllowFailure
        if ($volume.ExitCode -eq 0) {
            $volumeOwner = ($volume.Text | ConvertFrom-Json).Labels.'com.docker.compose.project'
            if ($volumeOwner -ne $ProjectName) {
                throw 'P15A refuses a foreign volume name collision.'
            }
        }
    }
}

function Assert-EmptyProjectNamespace {
    $inventory = Get-LabeledInventory
    if ($inventory.Containers.Count -ne 0 -or
        $inventory.Networks.Count -ne 0 -or
        $inventory.Volumes.Count -ne 0 -or $inventory.Images.Count -ne 0) {
        throw 'P15A project namespace is not empty.'
    }
    Assert-NoForeignNameCollision
}

function Assert-EmptyImageReference {
    $existing = Invoke-ProcessCapture -FilePath 'docker' -ArgumentList @(
        'image', 'inspect', $runImageReference, '--format', '{{json .}}'
    ) -AllowFailure
    if ($existing.ExitCode -eq 0) {
        throw 'P15A run image reference is preexisting or foreign.'
    }
}

function Get-ComposeArguments {
    param([string[]]$Tail)
    return @(
        'compose',
        '-f', $ComposeFile,
        '--project-name', $ProjectName,
        '--profile', 'p15-compat-core',
        '--profile', 'p15-compat-probe',
        '--profile', 'p15-compat-faults'
    ) + $Tail
}

function Invoke-Compose {
    param(
        [string[]]$Arguments,
        [switch]$AllowFailure
    )
    return Invoke-ProcessCapture -FilePath 'docker' -ArgumentList (Get-ComposeArguments $Arguments) -AllowFailure:$AllowFailure
}

function Assert-ComposeContract {
    $temporary = [IO.Path]::GetTempFileName()
    try {
        $config = Invoke-Compose @('config', '--format', 'json')
        [IO.File]::WriteAllText($temporary, $config.Text, [Text.UTF8Encoding]::new($false))
        Invoke-ProcessCapture -FilePath 'node' -ArgumentList @(
            (Join-Path $PSScriptRoot 'p15-compat-contracts.mjs'),
            'validate-compose',
            $temporary
        ) | Out-Null
    }
    finally {
        Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
    }
}

function Get-OwnedRunImageId {
    param([switch]$AllowMissing)

    $result = Invoke-ProcessCapture -FilePath 'docker' -ArgumentList @(
        'image', 'inspect', $runImageReference, '--format', '{{json .}}'
    ) -AllowFailure:$AllowMissing
    if ($result.ExitCode -ne 0) {
        return $null
    }
    $image = $result.Text | ConvertFrom-Json
    $labels = $image.Config.Labels
    if ($image.Id -notmatch '^sha256:[0-9a-f]{64}$' -or
        $labels.'com.docker.compose.project' -ne $ProjectName -or
        $labels.'org.opencontainers.image.revision' -ne $ExpectedSourceSha -or
        $labels.'com.xpoint.p15.source-tree' -ne $ExpectedSourceTree -or
        $labels.'com.xpoint.p15.context-sha256' -ne $env:P15_CONTEXT_SHA256) {
        throw 'P15A cannot establish ownership of the run image.'
    }
    return $image.Id
}

function Assert-BuiltImage {
    param([Parameter(Mandatory = $true)][string]$ImageId)

    $image = ((Invoke-ProcessCapture -FilePath 'docker' -ArgumentList @(
        'image', 'inspect', $ImageId, '--format', '{{json .}}'
    )).Text | ConvertFrom-Json)
    $labels = $image.Config.Labels
    if ($image.Id -ne $ImageId -or
        $image.Architecture -ne 'arm64' -or
        $image.Os -ne 'linux' -or
        $labels.'org.opencontainers.image.revision' -ne $ExpectedSourceSha -or
        $labels.'org.opencontainers.image.source' -ne 'deep-devops' -or
        $labels.'com.xpoint.evidence-class' -ne 'compatibility-lab' -or
        $labels.'com.xpoint.product-runtime' -ne 'false' -or
        $labels.'com.xpoint.p15.source-tree' -ne $ExpectedSourceTree -or
        $labels.'com.xpoint.p15.context-sha256' -ne $env:P15_CONTEXT_SHA256 -or
        $labels.'com.docker.compose.project' -ne $ProjectName -or
        $labels.'com.xpoint.p15.base-image-digest' -ne $BaseImageReference) {
        throw 'P15A built image identity, architecture, or labels are invalid.'
    }
}

function Get-ServiceContainer {
    param([string]$Service)
    $id = (Invoke-Compose @('ps', '-q', $Service)).Text.Trim()
    if ($id -notmatch '^[0-9a-f]{64}$') {
        throw "P15A service $Service has no exact container identity."
    }
    $inspect = ((Invoke-ProcessCapture -FilePath 'docker' -ArgumentList @(
        'container', 'inspect', $id, '--format', '{{json .}}'
    )).Text | ConvertFrom-Json)
    if ($inspect.Config.Labels.'com.docker.compose.project' -ne $ProjectName -or
        $inspect.Config.Labels.'com.xpoint.evidence-class' -ne 'compatibility-lab' -or
        $inspect.Config.Labels.'com.xpoint.product-runtime' -ne 'false') {
        throw "P15A service $Service has wrong ownership or evidence labels."
    }
    if ($inspect.Image -ne $runImageId) {
        throw "P15A service $Service did not start from the exact built image ID."
    }
    return $inspect
}

function Wait-ServiceHealth {
    param(
        [string]$Service,
        [int]$TimeoutSeconds = 30
    )
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        $inspect = Get-ServiceContainer $Service
        if ($inspect.State.Health.Status -eq 'healthy') {
            return $inspect
        }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "P15A service $Service health timeout."
}

function Invoke-Probe {
    param(
        [string]$Action,
        [string]$Target,
        [switch]$AllowFailure
    )
    $arguments = @('run', '--rm', '--no-deps', '--pull', 'never', 'probe',
        'node', 'scripts/p15-compat-contracts.mjs', 'probe', $Action)
    if ($Target) {
        $arguments += $Target
    }
    return Invoke-Compose -Arguments $arguments -AllowFailure:$AllowFailure
}

function Assert-OwnedProjectResources {
    $inventory = Get-LabeledInventory
    foreach ($id in $inventory.Containers) {
        $resource = ((Invoke-ProcessCapture -FilePath 'docker' -ArgumentList @(
            'container', 'inspect', $id, '--format', '{{json .}}'
        )).Text | ConvertFrom-Json)
        $owner = $resource.Config.Labels.'com.docker.compose.project'
        if ($owner -ne $ProjectName) {
            throw 'P15A cleanup refuses a foreign container.'
        }
    }
    foreach ($id in $inventory.Networks) {
        $resource = ((Invoke-ProcessCapture -FilePath 'docker' -ArgumentList @(
            'network', 'inspect', $id, '--format', '{{json .}}'
        )).Text | ConvertFrom-Json)
        $owner = $resource.Labels.'com.docker.compose.project'
        if ($owner -ne $ProjectName) {
            throw 'P15A cleanup refuses a foreign network.'
        }
    }
    foreach ($id in $inventory.Volumes) {
        $resource = ((Invoke-ProcessCapture -FilePath 'docker' -ArgumentList @(
            'volume', 'inspect', $id, '--format', '{{json .}}'
        )).Text | ConvertFrom-Json)
        $owner = $resource.Labels.'com.docker.compose.project'
        if ($owner -ne $ProjectName) {
            throw 'P15A cleanup refuses a foreign volume.'
        }
    }
}

function Invoke-ScopedCleanup {
    if (-not $resourcesMayExist) {
        return
    }
    Assert-OwnedProjectResources
    Invoke-Compose @('down', '--volumes', '--remove-orphans') | Out-Null
}

function Remove-OwnedRunImage {
    if (-not $runImageOwned -or -not $runImageId) {
        if (-not $buildMayHaveCreatedImage) {
            return
        }
        $capturedImageId = Get-OwnedRunImageId -AllowMissing
        if (-not $capturedImageId) {
            return
        }
        $runImageId = $capturedImageId
        $runImageOwned = $true
    }
    $imageResult = Invoke-ProcessCapture -FilePath 'docker' -ArgumentList @(
        'image', 'inspect', $runImageId, '--format', '{{json .}}'
    ) -AllowFailure
    if ($imageResult.ExitCode -ne 0) {
        $runImageOwned = $false
        return
    }
    $image = $imageResult.Text | ConvertFrom-Json
    if ($image.Config.Labels.'com.docker.compose.project' -ne $ProjectName) {
        throw 'P15A refuses to remove a foreign image.'
    }
    $tagResult = Invoke-ProcessCapture -FilePath 'docker' -ArgumentList @(
        'image', 'inspect', $runImageReference, '--format', '{{json .Id}}'
    ) -AllowFailure
    if ($tagResult.ExitCode -eq 0) {
        $tagImageId = $tagResult.Text | ConvertFrom-Json
        if ($tagImageId -eq $runImageId) {
            Invoke-ProcessCapture -FilePath 'docker' -ArgumentList @(
                'image', 'rm', $runImageReference
            ) | Out-Null
        }
    }
    $remaining = Invoke-ProcessCapture -FilePath 'docker' -ArgumentList @(
        'image', 'inspect', $runImageId, '--format', '{{json .}}'
    ) -AllowFailure
    if ($remaining.ExitCode -eq 0) {
        Invoke-ProcessCapture -FilePath 'docker' -ArgumentList @(
            'image', 'rm', $runImageId
        ) | Out-Null
    }
    $runImageOwned = $false
}

function Assert-ZeroResidualResources {
    $inventory = Get-LabeledInventory
    if ($inventory.Containers.Count -ne 0 -or
        $inventory.Networks.Count -ne 0 -or
        $inventory.Volumes.Count -ne 0 -or $inventory.Images.Count -ne 0) {
        throw 'P15A cleanup left residual project resources.'
    }
}

function Assert-PrivacySafeLogs {
    $logs = (Invoke-Compose @('logs', '--no-color', '--timestamps=false')).Text
    $scan = $logs | & node (Join-Path $PSScriptRoot 'p15-evidence-sanitizer.mjs') scan-text 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw 'P15A runtime log privacy scan failed.'
    }
}

function Write-SanitizedEvidence {
    $evidenceFullPath = [IO.Path]::GetFullPath($EvidencePath)
    if ($evidenceFullPath.StartsWith(
        "$RepositoryRoot$([IO.Path]::DirectorySeparatorChar)",
        [StringComparison]::OrdinalIgnoreCase)) {
        throw 'P15A evidence must remain outside the source repository until the carrier phase.'
    }
    $parent = Split-Path $evidenceFullPath -Parent
    if (-not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    if (Test-Path -LiteralPath $evidenceFullPath) {
        throw 'P15A evidence output must not already exist.'
    }

    $evidenceInput = [ordered]@{
        clock = $EvidenceClock
        sourceSha = $ExpectedSourceSha
        sourceTree = $ExpectedSourceTree
        baseImageDigest = $BaseImageDigest
        baseImageId = $BaseImageId
        contextSha256 = $contextSha256
        architecture = 'arm64'
        scenarios = [ordered]@{
            'source-lock' = 'pass'
            'image-lock' = 'pass'
            'empty-start' = 'pass'
            'health-identity' = 'pass'
            operations = 'pass'
            'restart-persistence' = 'pass'
            'network-fault-recovery' = 'pass'
            'privacy-scan' = 'pass'
            cleanup = 'pass'
        }
        counts = [ordered]@{
            services = 4
            probes = 4
            restarts = 4
            networkFaults = 1
            residualResources = 0
            residualImages = 0
        }
        durationBoundsMs = [ordered]@{
            health = 30000
            operation = 5000
            networkFailure = 5000
        }
    }

    $temporary = [IO.Path]::GetTempFileName()
    try {
        $inputJson = $evidenceInput | ConvertTo-Json -Depth 8
        [IO.File]::WriteAllText($temporary, $inputJson, [Text.UTF8Encoding]::new($false))
        Invoke-ProcessCapture -FilePath 'node' -ArgumentList @(
            (Join-Path $PSScriptRoot 'p15-compat-contracts.mjs'),
            'write-evidence',
            $temporary,
            $evidenceFullPath
        ) | Out-Null
    }
    finally {
        Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
    }
}

if (-not $ProjectName) {
    $ProjectName = New-P15ProjectName
}

# This order is a contract: source identity must fail before any Docker access.
Assert-SourceLock
Assert-DockerEnvironment
Assert-ProjectName

$evidenceDate = [DateTime]::Parse(
    $EvidenceClock,
    [Globalization.CultureInfo]::InvariantCulture,
    [Globalization.DateTimeStyles]::AdjustToUniversal
)
if ($evidenceDate.ToString('yyyy-MM-ddTHH:mm:ss.fffZ') -ne $EvidenceClock) {
    throw 'P15A evidence clock is not canonical UTC.'
}

$savedEnvironment = @{}
foreach ($name in @(
    'P15_PROJECT_NAME',
    'P15_SOURCE_SHA',
    'P15_SOURCE_TREE',
    'P15_BASE_IMAGE',
    'P15_IMAGE_NAME',
    'P15_CONTEXT_SHA256'
)) {
    $savedEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}

try {
    $env:P15_PROJECT_NAME = $ProjectName
    $env:P15_SOURCE_SHA = $ExpectedSourceSha
    $env:P15_SOURCE_TREE = $ExpectedSourceTree
    $env:P15_BASE_IMAGE = $BaseImageReference
    $runImageReference = "local/p15-compat:$ProjectName"
    $env:P15_IMAGE_NAME = $runImageReference
    $contextContract = Join-Path $RepositoryRoot 'release\contracts\p15-compat-lab-v1.json'
    $contextSha256 = (Invoke-ProcessCapture -FilePath 'node' -ArgumentList @(
        (Join-Path $PSScriptRoot 'p15-compat-contracts.mjs'),
        'context-hash',
        $RepositoryRoot,
        $contextContract
    )).Text.Trim()
    $env:P15_CONTEXT_SHA256 = $contextSha256

    Assert-EmptyProjectNamespace
    Assert-EmptyImageReference
    Assert-ComposeContract

    # Docker Compose build expresses the no-network-pull invariant as pull=false;
    # container creation additionally uses the explicit --pull never policy.
    $buildMayHaveCreatedImage = $true
    Invoke-Compose @('build', '--pull=false', 'storage') | Out-Null
    $runImageId = Get-OwnedRunImageId
    $runImageOwned = $true
    if ($InjectValidationFailureAfterBuild) {
        throw 'P15A injected validation failure after build ownership.'
    }
    Assert-BuiltImage -ImageId $runImageId

    if ($InjectFailureAfterBuild) {
        throw 'P15A injected failure after build.'
    }

    # Use the immutable built image ID for create/up; the mutable build tag is
    # never a runtime authority.
    $env:P15_IMAGE_NAME = $runImageId

    $resourcesMayExist = $true
    Invoke-Compose @(
        'up', '-d', '--pull', 'never', '--no-build',
        'storage', 'file', 'push', 'calls'
    ) | Out-Null

    if ($InjectFailureAfterUp) {
        throw 'P15A injected failure after up.'
    }

    foreach ($service in @('storage', 'file', 'push', 'calls')) {
        Wait-ServiceHealth $service | Out-Null
    }
    Invoke-Probe 'initial' | Out-Null

    foreach ($service in @('storage', 'file', 'push', 'calls')) {
        Invoke-Compose @('restart', $service) | Out-Null
        Wait-ServiceHealth $service | Out-Null
    }
    Invoke-Probe 'persistence' | Out-Null

    $fileContainer = Get-ServiceContainer 'file'
    $networkName = "${ProjectName}_lab"
    Invoke-ProcessCapture -FilePath 'docker' -ArgumentList @(
        'network', 'disconnect', $networkName, $fileContainer.Id
    ) | Out-Null

    $faultStarted = [Diagnostics.Stopwatch]::StartNew()
    $faultProbe = Invoke-Probe 'health-target' 'file' -AllowFailure
    $faultStarted.Stop()
    if ($faultProbe.ExitCode -eq 0 -or $faultStarted.ElapsedMilliseconds -gt 5000) {
        throw 'P15A network disconnect did not produce the expected bounded failure.'
    }

    Invoke-ProcessCapture -FilePath 'docker' -ArgumentList @(
        'network', 'connect', '--alias', 'file', $networkName, $fileContainer.Id
    ) | Out-Null
    Invoke-Probe 'health-target' 'file' | Out-Null

    Assert-PrivacySafeLogs
}
finally {
    try {
        Invoke-P15CleanupStages `
            -ShutdownProject { Invoke-ScopedCleanup } `
            -RemoveRunImage { Remove-OwnedRunImage } `
            -AssertResidualInventory { Assert-ZeroResidualResources }
    }
    catch {
        $cleanupFailure = $_
    }
    foreach ($name in $savedEnvironment.Keys) {
        [Environment]::SetEnvironmentVariable($name, $savedEnvironment[$name], 'Process')
    }
    if ($cleanupFailure) {
        throw $cleanupFailure
    }
}

if ($InjectFailureAfterUp) {
    throw 'P15A injected failure unexpectedly continued.'
}
if ($InjectFailureAfterBuild) {
    throw 'P15A injected build failure unexpectedly continued.'
}
if ($InjectValidationFailureAfterBuild) {
    throw 'P15A injected validation failure unexpectedly continued.'
}

Write-SanitizedEvidence
Write-Output 'P15A compatibility lifecycle lab: PASS'
