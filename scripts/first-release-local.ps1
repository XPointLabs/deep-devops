[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Config', 'ProvisionTime', 'AuthorPackage', 'Up', 'Verify', 'Down')]
    [string] $Action,

    [Parameter(Mandatory = $true)]
    [string] $EnvFile,

    [switch] $Tls,

    [UInt64] $ObservedUnixTime = 0,

    [UInt64] $TrustedTimeValidUntilUnix = 0,

    [ValidateRange(0, 30)]
    [UInt32] $TrustedTimeUncertaintySeconds = 0,

    [string] $ExpectedTrustedTimeStateSha256 = '',

    [string] $RequestFile = '',

    [string] $OutputFile = ''
)

$ErrorActionPreference = 'Stop'
$scriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $scriptDirectory '..'))
$environmentPath = [IO.Path]::GetFullPath($EnvFile)
if (-not (Test-Path -LiteralPath $environmentPath -PathType Leaf)) {
    throw 'The private environment file does not exist.'
}
$environmentFile = Get-Item -LiteralPath $environmentPath -Force
if (($environmentFile.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw 'The private environment file must not be a symlink or reparse point.'
}
if ($environmentFile.Length -gt 65536) {
    throw 'The private environment file is unexpectedly large.'
}
$environmentText = [IO.File]::ReadAllText($environmentPath)
if ($environmentText.IndexOf('__REQUIRED_', [StringComparison]::Ordinal) -ge 0) {
    throw 'The private environment file still contains required-value markers.'
}
$environmentText = $null

function Read-PrivateEnvironment {
    $values = [Collections.Generic.Dictionary[string,string]]::new(
        [StringComparer]::Ordinal)
    foreach ($line in [IO.File]::ReadLines($environmentPath)) {
        if ([string]::IsNullOrWhiteSpace($line) -or $line.TrimStart().StartsWith('#')) {
            continue
        }
        $separator = $line.IndexOf('=')
        if ($separator -lt 1) {
            throw 'The private environment file contains a malformed entry.'
        }
        $name = $line.Substring(0, $separator)
        if ($name -notmatch '^[A-Z][A-Z0-9_]*$' -or $values.ContainsKey($name)) {
            throw 'The private environment file contains an invalid or duplicate name.'
        }
        $values.Add($name, $line.Substring($separator + 1).TrimEnd("`r"))
    }
    return $values
}

$privateEnvironment = Read-PrivateEnvironment
$compose = @(
    'compose',
    '-p', 'deep-first-release-local',
    '--env-file', $environmentPath,
    '-f', (Join-Path $repositoryRoot 'docker-compose.first-release.local.yml')
)
if ($Tls) {
    $compose += @(
        '-f', (Join-Path $repositoryRoot 'docker-compose.first-release.tls.yml'),
        '--profile', 'tls'
    )
}

function Invoke-Docker {
    param([Parameter(Mandatory = $true)][string[]] $Arguments)
    & docker @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Docker command failed with exit code $LASTEXITCODE."
    }
}

function Assert-FirstReleaseRuntimeCapability {
    $runtimeSource = [IO.Path]::GetFullPath((Join-Path $repositoryRoot `
        '..\xnode\src\XNode\PrivacyRoutingRuntime.cs'))
    if (-not (Test-Path -LiteralPath $runtimeSource -PathType Leaf)) {
        throw 'First-release runtime capability preflight cannot inspect the local XNode source.'
    }
    $runtimeContract = [IO.File]::ReadAllText($runtimeSource)
    if ($runtimeContract -match 'ProductionCapabilityAvailable\s*=>\s*false\s*;') {
        throw ('First-release runtime blocker: XNode hard-codes ' +
            'PrivacyRoutingRuntime.ProductionCapabilityAvailable=false; ' +
            'the verified production ONION runtime closure is not activated.')
    }
}

function Assert-FirstReleaseContactAuthorityPrerequisites {
    $registrySourceRoot = [IO.Path]::GetFullPath((Join-Path $repositoryRoot `
        '..\deep-registry-api\src\Deep.Registry.Api'))
    $issuerSource = Join-Path $registrySourceRoot `
        'DirectoryPublication\ProductionContactResolveDirectoryPackageIssuer.cs'
    if (-not (Test-Path -LiteralPath $issuerSource -PathType Leaf)) {
        throw 'First-release authority preflight cannot inspect the local Registry issuer source.'
    }

    $allProductionSource = [Text.StringBuilder]::new()
    Get-ChildItem -LiteralPath $registrySourceRoot -Recurse -File -Filter '*.cs' |
        Where-Object { $_.FullName -notmatch '[\\/](?:bin|obj)[\\/]' } |
        ForEach-Object { [void]$allProductionSource.AppendLine([IO.File]::ReadAllText($_.FullName)) }
    $missing = [Collections.Generic.List[string]]::new()
    foreach ($boundary in @(
        'IContactResolveTrustedTimeContextSource',
        'IContactResolveOneUseRequestLedger',
        'IContactResolveDtt1WitnessCustody')) {
        $registrationPattern = "(?:Add|TryAdd)Singleton\s*<\s*$boundary\b"
        if ($allProductionSource.ToString() -notmatch $registrationPattern) {
            $missing.Add($boundary)
        }
    }
    $allProductionSource.Clear() | Out-Null

    if ($missing.Count -gt 0) {
        throw ('First-release authority blocker: Registry cannot issue the nonce-bound ' +
            'production CDR1 package required by XNode. Missing production service composition: ' +
            ($missing -join ', ') + '. Consequently no verified current ' +
            'XNA1/DTS1/XVP1/XNV1/XNH1/XND1/PMT2/ADH1/DTT1/ADP1/ADC1 package can be ' +
            'served. DEV trust and synthetic artifacts are forbidden.')
    }

    $operatorSource = Join-Path $registrySourceRoot `
        'DirectoryPublication\ContactResolveOperatorCommand.cs'
    if (-not (Test-Path -LiteralPath $operatorSource -PathType Leaf)) {
        throw 'First-release authority preflight cannot inspect the Registry operator command.'
    }
    $operatorContract = [IO.File]::ReadAllText($operatorSource)
    foreach ($requiredAction in @('contact-resolve-authority', 'provision-time', 'author-package')) {
        if ($operatorContract.IndexOf($requiredAction, [StringComparison]::Ordinal) -lt 0) {
            throw "First-release authority preflight is missing Registry operator action $requiredAction."
        }
    }
}

function Assert-ExactProductionAuthorityClosure {
    & (Join-Path $scriptDirectory 'first-release-local-authority-preflight.ps1') `
        -RepositoryRoot $repositoryRoot
}

function Get-RequiredPrivateValue([string] $Name) {
    $value = ''
    if (-not $privateEnvironment.TryGetValue($Name, [ref]$value) -or
        [string]::IsNullOrWhiteSpace($value)) {
        throw "The private environment file is missing $Name."
    }
    return $value
}

function Resolve-OperatorExchangePath([string] $Path, [bool] $MustExist) {
    $root = [IO.Path]::GetFullPath((Get-RequiredPrivateValue `
        'FIRST_RELEASE_CONTACT_RESOLVE_OPERATOR_ROOT'))
    if (-not (Test-Path -LiteralPath $root -PathType Container)) {
        throw 'The protected ContactResolve operator exchange directory is unavailable.'
    }
    $candidate = [IO.Path]::GetFullPath($Path)
    if (-not [StringComparer]::OrdinalIgnoreCase.Equals(
            [IO.Path]::GetDirectoryName($candidate),
            $root.TrimEnd([char[]]@('\', '/'))) -or
        ($MustExist -and -not (Test-Path -LiteralPath $candidate -PathType Leaf)) -or
        (-not $MustExist -and (Test-Path -LiteralPath $candidate))) {
        throw 'The ContactResolve operator file must be a new/existing regular file directly in the protected operator exchange directory.'
    }
    $item = if ($MustExist) {
        Get-Item -LiteralPath $candidate -Force
    } else {
        Get-Item -LiteralPath $root -Force
    }
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'ContactResolve operator exchange paths must not be reparse points.'
    }
    return '/contact-resolve/operator/' + [IO.Path]::GetFileName($candidate)
}

function Invoke-RegistryOperator([string[]] $Arguments) {
    Invoke-Docker ($compose + @('build', 'registry'))
    Invoke-Docker ($compose + @('run', '--rm', '--no-deps', 'state-init'))
    $dockerArguments = $compose + @(
        'run', '--rm', '--no-deps', 'registry', 'contact-resolve-authority') + $Arguments
    $operatorOutput = & docker @dockerArguments 2>&1
    $exitCode = $LASTEXITCODE
    $operatorOutput = $null
    if ($exitCode -ne 0) {
        throw "Registry ContactResolve operator command failed closed with exit code $exitCode."
    }
}

& node (Join-Path $scriptDirectory 'first-release-local-contracts.mjs')
if ($LASTEXITCODE -ne 0) {
    throw 'The static first-release Compose contract failed.'
}
Invoke-Docker ($compose + @('config', '--quiet'))

switch ($Action) {
    'Config' {
        Write-Output 'First-release local Compose configuration is valid.'
    }
    'ProvisionTime' {
        Assert-FirstReleaseContactAuthorityPrerequisites
        Assert-ExactProductionAuthorityClosure
        if ($ObservedUnixTime -eq 0 -or $TrustedTimeValidUntilUnix -eq 0 -or
            $TrustedTimeUncertaintySeconds -eq 0) {
            throw 'ProvisionTime requires explicit operator-observed time, expiry, and uncertainty inputs.'
        }
        $arguments = @(
            'provision-time',
            '--observed-unix-time', "$ObservedUnixTime",
            '--valid-until-unix', "$TrustedTimeValidUntilUnix",
            '--uncertainty-seconds', "$TrustedTimeUncertaintySeconds")
        if (-not [string]::IsNullOrWhiteSpace($ExpectedTrustedTimeStateSha256)) {
            if ($ExpectedTrustedTimeStateSha256 -notmatch '^[0-9A-Fa-f]{64}$') {
                throw 'The expected trusted-time state SHA-256 must be exactly 64 hexadecimal characters.'
            }
            $arguments += @('--expected-state-sha256', $ExpectedTrustedTimeStateSha256)
        }
        Invoke-RegistryOperator $arguments
        Write-Output 'Registry ContactResolve trusted-time state was provisioned without exposing custody material.'
    }
    'AuthorPackage' {
        Assert-FirstReleaseContactAuthorityPrerequisites
        Assert-ExactProductionAuthorityClosure
        if ([string]::IsNullOrWhiteSpace($RequestFile) -or
            [string]::IsNullOrWhiteSpace($OutputFile)) {
            throw 'AuthorPackage requires request and output files in the protected operator exchange directory.'
        }
        $request = Resolve-OperatorExchangePath $RequestFile $true
        $output = Resolve-OperatorExchangePath $OutputFile $false
        Invoke-RegistryOperator @('author-package', '--request', $request, '--output', $output)
        Write-Output 'Registry authored the production ContactResolve package without exposing custody material.'
    }
    'Up' {
        Assert-FirstReleaseRuntimeCapability
        Assert-FirstReleaseContactAuthorityPrerequisites
        Assert-ExactProductionAuthorityClosure
        Invoke-Docker ($compose + @('build', 'registry', 'xnode-1'))
        Invoke-Docker ($compose + @('up', '-d', '--no-build', '--wait', '--wait-timeout', '300'))
        Invoke-Docker ($compose + @('run', '--rm', '--no-deps', 'topology-ready'))
        Write-Output 'First-release local topology reached exact three-node readiness.'
    }
    'Verify' {
        Assert-FirstReleaseRuntimeCapability
        Assert-FirstReleaseContactAuthorityPrerequisites
        Assert-ExactProductionAuthorityClosure
        Invoke-Docker ($compose + @('run', '--rm', '--no-deps', 'topology-ready'))
        Invoke-Docker ($compose + @('ps'))
        Write-Output 'First-release local topology verification passed.'
    }
    'Down' {
        Invoke-Docker ($compose + @('down', '--remove-orphans'))
        Write-Output 'First-release local containers stopped; named state volumes were preserved.'
    }
}
