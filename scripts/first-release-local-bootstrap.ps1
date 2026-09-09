[CmdletBinding()]
param(
    [switch] $Start,

    [ValidatePattern('^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])$')]
    [string] $MaskDomain = 'www.microsoft.com',

    [ValidatePattern('^(?:127\.0\.0\.1|10\.(?:\d{1,3}\.){2}\d{1,3}|192\.168\.(?:\d{1,3}\.)\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.(?:\d{1,3}\.)\d{1,3})$')]
    [string] $BindHost = '127.0.0.1',

    [ValidatePattern('^(?:127\.0\.0\.1|10\.(?:\d{1,3}\.){2}\d{1,3}|192\.168\.(?:\d{1,3}\.)\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.(?:\d{1,3}\.)\d{1,3})$')]
    [string] $PublicHost = '127.0.0.1',

    [UInt64] $TrustedObservedUnixTime = 0,

    [UInt64] $TrustedTimeValidUntilUnix = 0,

    [ValidateRange(0, 30)]
    [UInt32] $TrustedTimeUncertaintySeconds = 0
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$secretParent = [IO.Path]::GetFullPath('C:\Work\DeepSession\secrets')
$secretRoot = [IO.Path]::GetFullPath((Join-Path $secretParent 'first-release-local'))
$stagingRoot = [IO.Path]::GetFullPath((Join-Path $secretParent (
    'first-release-local.bootstrap-' + [guid]::NewGuid().ToString('N'))))
$xnodeImage = 'deep-first-release/xnode:local'
$anvilImage = 'ghcr.io/foundry-rs/foundry@sha256:8347b728d5d393dac1c018691b36f506d23b9dcd78341d40ea0fcb11c3a19cdd'
$anvilContainer = 'deep-first-release-bls-bootstrap-rpc'
$anvilPort = 42990
$protocolVersion = '0.6.0-local.2ee5f72df11c'
$blsDomainAddress = '000000000000000000000000000000000000f001'
$committed = $false

if ($Start -and ($TrustedObservedUnixTime -eq 0 -or
        $TrustedTimeValidUntilUnix -eq 0 -or
        $TrustedTimeUncertaintySeconds -eq 0)) {
    throw ('Starting the production-authority lane requires explicit operator-observed ' +
        'trusted-time, expiry, and uncertainty inputs; bootstrap never substitutes the OS clock.')
}

function Assert-ExactPrivateParent {
    if (-not (Test-Path -LiteralPath $secretParent -PathType Container)) {
        throw 'The configured Deep secrets parent does not exist.'
    }
    $parent = Get-Item -Force -LiteralPath $secretParent
    if (($parent.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'The Deep secrets parent must not be a reparse point.'
    }
    if (Test-Path -LiteralPath $secretRoot) {
        throw 'The first-release local secret directory already exists; bootstrap never overwrites or rotates identities.'
    }
}

function Set-ProtectedDirectoryAcl([string] $Path) {
    if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
        $current = [Security.Principal.WindowsIdentity]::GetCurrent().User
        $security = [Security.AccessControl.DirectorySecurity]::new()
        $security.SetAccessRuleProtection($true, $false)
        foreach ($sid in @(
            $current,
            [Security.Principal.SecurityIdentifier]::new('S-1-5-18'),
            [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))) {
            $security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
                $sid,
                [Security.AccessControl.FileSystemRights]::FullControl,
                [Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit',
                [Security.AccessControl.PropagationFlags]::None,
                [Security.AccessControl.AccessControlType]::Allow))
        }
        Set-Acl -LiteralPath $Path -AclObject $security
    } else {
        [IO.File]::SetUnixFileMode(
            $Path,
            [IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite -bor
                [IO.UnixFileMode]::UserExecute)
    }
}

function Set-ProtectedFileAcl([string] $Path) {
    if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
        $current = [Security.Principal.WindowsIdentity]::GetCurrent().User
        $security = [Security.AccessControl.FileSecurity]::new()
        $security.SetAccessRuleProtection($true, $false)
        foreach ($sid in @(
            $current,
            [Security.Principal.SecurityIdentifier]::new('S-1-5-18'),
            [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))) {
            $security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
                $sid,
                [Security.AccessControl.FileSystemRights]::FullControl,
                [Security.AccessControl.AccessControlType]::Allow))
        }
        Set-Acl -LiteralPath $Path -AclObject $security
    } else {
        [IO.File]::SetUnixFileMode(
            $Path,
            [IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite)
    }
}

function Invoke-QuietNative(
    [string] $Executable,
    [string[]] $Arguments,
    [string] $FailureMessage) {
    $output = & $Executable @Arguments 2>&1
    $exitCode = $LASTEXITCODE
    $output = $null
    if ($exitCode -ne 0) {
        throw "$FailureMessage (exit $exitCode)."
    }
}

function Assert-PublicIdentity([object] $Identity, [object] $Proof) {
    if ($Identity.routerId -notmatch '^[0-9a-f]{64}$' -or
        $Identity.vlessClientId -notmatch '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' -or
        $Identity.realityPublicKey -notmatch '^[A-Za-z0-9_-]{43}$' -or
        $Identity.realityPrivateKey -notmatch '^[A-Za-z0-9_-]{43}$' -or
        $Identity.realityShortId -notmatch '^[0-9a-f]{16}$' -or
        $Identity.realityPublicKey -ceq $Identity.realityPrivateKey -or
        $Proof.publicKey -notmatch '^[0-9a-f]{256}$' -or
        $Proof.signature -notmatch '^[0-9a-f]{512}$') {
        throw 'Generated first-release identity material is malformed.'
    }
}

function Remove-ProtectedStaging {
    if (-not (Test-Path -LiteralPath $stagingRoot)) {
        return
    }
    $resolved = [IO.Path]::GetFullPath($stagingRoot)
    if (-not $resolved.StartsWith($secretParent + [IO.Path]::DirectorySeparatorChar,
            [StringComparison]::OrdinalIgnoreCase) -or
        -not ([IO.Path]::GetFileName($resolved)).StartsWith(
            'first-release-local.bootstrap-', [StringComparison]::Ordinal)) {
        throw 'Refusing to clean an unexpected bootstrap staging path.'
    }
    foreach ($directory in Get-ChildItem -LiteralPath $resolved -Directory -Force) {
        foreach ($file in Get-ChildItem -LiteralPath $directory.FullName -File -Force) {
            Remove-Item -LiteralPath $file.FullName -Force
        }
        Remove-Item -LiteralPath $directory.FullName -Force
    }
    foreach ($file in Get-ChildItem -LiteralPath $resolved -File -Force) {
        Remove-Item -LiteralPath $file.FullName -Force
    }
    Remove-Item -LiteralPath $resolved -Force
}

Assert-ExactPrivateParent
if ($Start) {
    & (Join-Path $repositoryRoot 'scripts\first-release-local-authority-preflight.ps1') `
        -RepositoryRoot $repositoryRoot
}
if (docker ps -a --filter "name=^/$anvilContainer$" --format '{{.Names}}') {
    throw 'The isolated first-release BLS bootstrap container name is already in use.'
}
Invoke-QuietNative 'docker' @('image', 'inspect', $xnodeImage) `
    'The previously validated local XNode image is unavailable'
Invoke-QuietNative 'docker' @('image', 'inspect', $anvilImage) `
    'The pinned local Foundry image is unavailable'

$helperProject = Join-Path $repositoryRoot `
    'tools\first-release-bootstrap\FirstRelease.Bootstrap.csproj'
$nugetConfig = Join-Path $repositoryRoot 'tools\first-release-bootstrap\NuGet.Config'
Invoke-QuietNative 'dotnet' @(
    'restore', $helperProject, '--locked-mode', '--configfile', $nugetConfig,
    '-p:DeepProtocolLocalCutover=true',
    "-p:DeepProtocolLocalPackageVersion=$protocolVersion") `
    'The locked XNode BLS bootstrap restore failed'
Invoke-QuietNative 'dotnet' @(
    'build', $helperProject, '--configuration', 'Release', '--no-restore',
    '-warnaserror', '-p:DeepProtocolLocalCutover=true',
    "-p:DeepProtocolLocalPackageVersion=$protocolVersion") `
    'The XNode BLS bootstrap helper build failed'

[IO.Directory]::CreateDirectory($stagingRoot) | Out-Null
Set-ProtectedDirectoryAcl $stagingRoot
try {
    for ($index = 1; $index -le 3; $index++) {
        $nodeDirectory = Join-Path $stagingRoot "xnode-$index"
        Invoke-QuietNative 'node' @(
            (Join-Path $repositoryRoot 'scripts\first-release-local-keygen.mjs'),
            '--out-dir', $nodeDirectory,
            '--node-index', "$index",
            '--xnode-image', $xnodeImage) `
            "XNode $index identity generation failed"
        Set-ProtectedDirectoryAcl $nodeDirectory
        Get-ChildItem -LiteralPath $nodeDirectory -File | ForEach-Object {
            Set-ProtectedFileAcl $_.FullName
        }
    }

    $containerId = docker run -d --rm --name $anvilContainer `
        -p "127.0.0.1:${anvilPort}:8545" `
        --entrypoint anvil $anvilImage `
        --silent --host 0.0.0.0 --port 8545 --hardfork prague --chain-id 31337 2>&1
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($containerId)) {
        throw 'The isolated EIP-2537 bootstrap RPC could not start.'
    }
    $containerId = $null
    try {
        $rpcReady = $false
        for ($attempt = 0; $attempt -lt 40; $attempt++) {
            try {
                $response = Invoke-RestMethod -Uri "http://127.0.0.1:$anvilPort" `
                    -Method Post -ContentType 'application/json' `
                    -Body '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}' `
                    -TimeoutSec 2
                if ($response.result -eq '0x7a69') {
                    $rpcReady = $true
                    break
                }
            } catch {}
            Start-Sleep -Milliseconds 250
        }
        if (-not $rpcReady) {
            throw 'The isolated EIP-2537 bootstrap RPC did not become ready.'
        }

        $helper = Join-Path $repositoryRoot `
            'tools\first-release-bootstrap\bin\Release\net10.0\FirstRelease.Bootstrap.dll'
        for ($index = 1; $index -le 3; $index++) {
            $nodeDirectory = Join-Path $stagingRoot "xnode-$index"
            $identity = Get-Content -Raw -LiteralPath (
                Join-Path $nodeDirectory "xnode-$index-identity.private.json") | ConvertFrom-Json
            $proofPath = Join-Path $nodeDirectory "xnode-$index-bls.public.json"
            Invoke-QuietNative 'dotnet' @(
                $helper,
                '--private-key-file', (Join-Path $nodeDirectory "xnode-$index-bls.private"),
                '--output', $proofPath,
                '--router-id', $identity.routerId,
                '--operator-address', (('00' * 19) + $index.ToString('x2')),
                '--domain-address', $blsDomainAddress,
                '--rpc-url', "http://127.0.0.1:$anvilPort") `
                "XNode $index BLS public proof generation failed"
            Set-ProtectedFileAcl $proofPath
        }
    } finally {
        if (docker ps -a --filter "name=^/$anvilContainer$" --format '{{.Names}}') {
            docker stop --time 2 $anvilContainer | Out-Null
        }
    }

    $environmentLines = [Collections.Generic.List[string]]::new()
    $environmentLines.Add('# Generated first-release local identities. Do not commit or print this file.')
    $environmentLines.Add("FIRST_RELEASE_BIND_HOST=$BindHost")
    $environmentLines.Add("FIRST_RELEASE_PUBLIC_HOST=$PublicHost")
    $environmentLines.Add("FIRST_RELEASE_MASK_DOMAIN=$MaskDomain")
    $routerIds = [Collections.Generic.List[string]]::new()
    $blsKeys = [Collections.Generic.List[string]]::new()
    $realityKeys = [Collections.Generic.List[string]]::new()
    $vlessIds = [Collections.Generic.List[string]]::new()
    for ($index = 1; $index -le 3; $index++) {
        $nodeDirectory = Join-Path $stagingRoot "xnode-$index"
        $identityPath = Join-Path $nodeDirectory "xnode-$index-identity.private.json"
        $proofPath = Join-Path $nodeDirectory "xnode-$index-bls.public.json"
        $identity = Get-Content -Raw -LiteralPath $identityPath | ConvertFrom-Json
        $proof = Get-Content -Raw -LiteralPath $proofPath | ConvertFrom-Json
        Assert-PublicIdentity $identity $proof
        $routerIds.Add($identity.routerId)
        $blsKeys.Add($proof.publicKey)
        $realityKeys.Add($identity.realityPublicKey)
        $vlessIds.Add($identity.vlessClientId)

        $finalNodePath = (Join-Path $secretRoot "xnode-$index").Replace('\', '/')
        $vlessClientIdPath = Join-Path $nodeDirectory "xnode-$index-vless-client-id"
        $realityPrivateKeyPath = Join-Path $nodeDirectory "xnode-$index-reality.private"
        [IO.File]::WriteAllText(
            $vlessClientIdPath,
            "$($identity.vlessClientId)`n",
            [Text.UTF8Encoding]::new($false))
        [IO.File]::WriteAllText(
            $realityPrivateKeyPath,
            "$($identity.realityPrivateKey)`n",
            [Text.UTF8Encoding]::new($false))
        Set-ProtectedFileAcl $vlessClientIdPath
        Set-ProtectedFileAcl $realityPrivateKeyPath
        $environmentLines.Add("FIRST_RELEASE_XNODE_${index}_ROUTER_ID=$($identity.routerId)")
        $environmentLines.Add("FIRST_RELEASE_XNODE_${index}_ED25519_FILE=$finalNodePath/xnode-$index-ed25519.seed")
        $environmentLines.Add("FIRST_RELEASE_XNODE_${index}_X25519_FILE=$finalNodePath/xnode-$index-x25519.private")
        $environmentLines.Add("FIRST_RELEASE_XNODE_${index}_BLS_PUBLIC_KEY=$($proof.publicKey)")
        $environmentLines.Add("FIRST_RELEASE_XNODE_${index}_BLS_SIGNATURE=$($proof.signature)")
        $environmentLines.Add("FIRST_RELEASE_XNODE_${index}_VLESS_CLIENT_ID_FILE=$finalNodePath/xnode-$index-vless-client-id")
        $environmentLines.Add("FIRST_RELEASE_XNODE_${index}_REALITY_PUBLIC_KEY=$($identity.realityPublicKey)")
        $environmentLines.Add("FIRST_RELEASE_XNODE_${index}_REALITY_PRIVATE_KEY_FILE=$finalNodePath/xnode-$index-reality.private")
        $environmentLines.Add("FIRST_RELEASE_XNODE_${index}_REALITY_SHORT_ID=$($identity.realityShortId)")
        $identity = $null
        $proof = $null
        Remove-Item -LiteralPath $identityPath -Force
        Remove-Item -LiteralPath $proofPath -Force
    }
    foreach ($values in @($routerIds, $blsKeys, $realityKeys, $vlessIds)) {
        if (($values | Sort-Object -Unique).Count -ne 3) {
            throw 'Generated first-release identities are not unique.'
        }
    }

    $environmentPath = Join-Path $stagingRoot 'first-release.env'
    [IO.File]::WriteAllLines(
        $environmentPath,
        $environmentLines,
        [Text.UTF8Encoding]::new($false))
    $environmentLines.Clear()
    Set-ProtectedFileAcl $environmentPath

    [IO.Directory]::Move($stagingRoot, $secretRoot)
    $committed = $true
    $finalEnvironmentPath = Join-Path $secretRoot 'first-release.env'
    Write-Output 'Three fresh first-release local identities were generated and protected.'

    & (Join-Path $repositoryRoot 'scripts\first-release-local-runtime-provision.ps1') `
        -SecretRoot $secretRoot -EnvFile $finalEnvironmentPath

    $launcher = Join-Path $repositoryRoot 'scripts\first-release-local.ps1'
    & $launcher -Action Config -EnvFile $finalEnvironmentPath
    if ($LASTEXITCODE -ne 0) {
        throw 'First-release Config validation failed.'
    }
    if ($Start) {
        & $launcher -Action ProvisionTime -EnvFile $finalEnvironmentPath `
            -ObservedUnixTime $TrustedObservedUnixTime `
            -TrustedTimeValidUntilUnix $TrustedTimeValidUntilUnix `
            -TrustedTimeUncertaintySeconds $TrustedTimeUncertaintySeconds
        if ($LASTEXITCODE -ne 0) {
            throw 'First-release trusted-time provisioning failed.'
        }
        & $launcher -Action Up -EnvFile $finalEnvironmentPath
        if ($LASTEXITCODE -ne 0) {
            throw 'First-release startup failed.'
        }
        & $launcher -Action Verify -EnvFile $finalEnvironmentPath
        if ($LASTEXITCODE -ne 0) {
            throw 'First-release runtime verification failed.'
        }
    }
} finally {
    if (docker ps -a --filter "name=^/$anvilContainer$" --format '{{.Names}}') {
        docker stop --time 2 $anvilContainer | Out-Null
    }
    if (-not $committed) {
        Remove-ProtectedStaging
    }
}
