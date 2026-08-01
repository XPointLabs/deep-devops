[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('Generate', 'Cleanup')]
    [string]$Action,
    [Parameter(Mandatory)]
    [string]$RunRoot,
    [string]$WindowsRuntimeRoot = 'C:\Work\DeepSession\secrets\mailbox-bootstrap\runtime\windows',
    [string]$AndroidRuntimeRoot = 'C:\Work\DeepSession\secrets\mailbox-bootstrap\runtime\android'
)

# DEV-only negative fixture materializer. Runtime bytes never leave the protected
# secrets tree and the emitted manifest contains only case names and hashes.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$bootstrapRoot = [IO.Path]::GetFullPath('C:\Work\DeepSession\secrets\mailbox-bootstrap')
$runsRoot = Join-Path $bootstrapRoot 'e2e-runs'
$caseNames = @('tampered-signature', 'missing-authority', 'android-runtime-on-windows')

function Assert-NoReparseTraversal([string]$Path) {
    $full = [IO.Path]::GetFullPath($Path)
    $current = if (Test-Path -LiteralPath $full) { $full } else { Split-Path -Parent $full }
    while (-not [string]::IsNullOrWhiteSpace($current)) {
        if (Test-Path -LiteralPath $current) {
            if (((Get-Item -Force -LiteralPath $current).Attributes -band
                [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw 'Negative runtime paths must not traverse reparse points.'
            }
        }
        $parent = [IO.Path]::GetDirectoryName($current)
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent -ceq $current) { break }
        $current = $parent
    }
    if (Test-Path -LiteralPath $full -PathType Container) {
        foreach ($item in Get-ChildItem -Force -Recurse -LiteralPath $full) {
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw 'Negative runtime trees must not contain reparse points.'
            }
        }
    }
}

function Get-RelativeChildPath([string]$Root, [string]$Child) {
    $canonicalRoot = [IO.Path]::GetFullPath($Root).TrimEnd('\', '/')
    $canonicalChild = [IO.Path]::GetFullPath($Child)
    $prefix = $canonicalRoot + [IO.Path]::DirectorySeparatorChar
    if (-not $canonicalChild.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Negative runtime enumeration escaped its protected root.'
    }
    return $canonicalChild.Substring($prefix.Length).Replace('\', '/')
}

function Set-ExactProtectedAcl([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { throw 'ACL target is missing.' }
    if (((Get-Item -Force -LiteralPath $Path).Attributes -band
        [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'ACL target cannot be a reparse point.' }
    $current = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $security = if ((Get-Item -Force -LiteralPath $Path).PSIsContainer) {
        [Security.AccessControl.DirectorySecurity]::new()
    } else { [Security.AccessControl.FileSecurity]::new() }
    $security.SetOwner($current)
    $security.SetAccessRuleProtection($true, $false)
    foreach ($sid in @(
        $current,
        [Security.Principal.SecurityIdentifier]'S-1-5-18',
        [Security.Principal.SecurityIdentifier]'S-1-5-32-544')) {
        $security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            $sid,
            [Security.AccessControl.FileSystemRights]::FullControl,
            [Security.AccessControl.InheritanceFlags]::None,
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow))
    }
    if ((Get-Item -Force -LiteralPath $Path).PSIsContainer) {
        ([IO.DirectoryInfo](Get-Item -Force -LiteralPath $Path)).SetAccessControl(
            [Security.AccessControl.DirectorySecurity]$security)
    } else {
        ([IO.FileInfo](Get-Item -Force -LiteralPath $Path)).SetAccessControl(
            [Security.AccessControl.FileSecurity]$security)
    }
}

function Assert-ExactProtectedAcl([string]$Path, [switch]$PublishedSource) {
    $acl = Get-Acl -LiteralPath $Path
    $isDirectory = (Get-Item -Force -LiteralPath $Path).PSIsContainer
    $expectedInheritance = if ($PublishedSource -and $isDirectory) {
        [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
            [Security.AccessControl.InheritanceFlags]::ObjectInherit
    } else { [Security.AccessControl.InheritanceFlags]::None }
    $owner = [Security.Principal.WindowsIdentity]::GetCurrent()
    $expected = @($owner.User.Value, 'S-1-5-18', 'S-1-5-32-544') | Sort-Object
    $actual = @($acl.Access | ForEach-Object {
        if ($_.IsInherited -or
            $_.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
            $_.FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl -or
            $_.InheritanceFlags -ne $expectedInheritance -or
            $_.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None) {
            throw 'Negative runtime ACL contains a non-canonical rule.'
        }
        $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
    } | Sort-Object)
    if (-not $acl.AreAccessRulesProtected -or $acl.Owner -cne $owner.Name -or
        ($actual -join ',') -cne ($expected -join ',')) {
        throw 'Negative runtime ACL is not the exact protected owner/DACL.'
    }
}

function Set-ProtectedTree([string]$Root) {
    Set-ExactProtectedAcl $Root
    foreach ($item in Get-ChildItem -Force -Recurse -LiteralPath $Root) {
        Set-ExactProtectedAcl $item.FullName
    }
    Assert-NoReparseTraversal $Root
    Assert-ExactProtectedAcl $Root
    foreach ($item in Get-ChildItem -Force -Recurse -LiteralPath $Root) {
        Assert-ExactProtectedAcl $item.FullName
    }
}

function Get-TreeSha256([string]$Root) {
    $lines = foreach ($file in Get-ChildItem -LiteralPath $Root -File -Recurse -Force |
        Sort-Object FullName) {
        $relative = Get-RelativeChildPath $Root $file.FullName
        $hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        "$relative`n$hash`n$($file.Length)"
    }
    $bytes = [Text.Encoding]::UTF8.GetBytes(($lines -join "`n"))
    $hasher = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($hasher.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
    } finally {
        $hasher.Dispose()
        [Array]::Clear($bytes, 0, $bytes.Length)
    }
}

function Assert-CanonicalSource([string]$Path, [string]$Platform) {
    $full = [IO.Path]::GetFullPath($Path)
    $expected = Join-Path $bootstrapRoot "runtime\$Platform"
    if ($full -cne [IO.Path]::GetFullPath($expected) -or
        -not (Test-Path -LiteralPath $full -PathType Container)) {
        throw "The $Platform source must be the canonical protected issued runtime."
    }
    Assert-NoReparseTraversal $full
    Assert-ExactProtectedAcl $full -PublishedSource
    foreach ($item in Get-ChildItem -Force -Recurse -LiteralPath $full) {
        Assert-ExactProtectedAcl $item.FullName -PublishedSource
    }
    foreach ($required in @('activation.v1.json', 'authority.public.json',
        'revocations.v1.json', 'mr-x-mailbox-policy.payload.json',
        'mr-x-mailbox-policy.signature', 'mr-x-mailbox-policy.public-key',
        'pair\current-generation.json')) {
        if (-not (Test-Path -LiteralPath (Join-Path $full $required) -PathType Leaf)) {
            throw "Canonical issued runtime is incomplete: $required"
        }
    }
    return $full
}

function Copy-ProtectedRuntime([string]$Source, [string]$AppDataRoot) {
    [IO.Directory]::CreateDirectory($AppDataRoot) | Out-Null
    $destination = Join-Path $AppDataRoot 'mailbox-runtime-v1'
    [IO.Directory]::CreateDirectory($destination) | Out-Null
    foreach ($directory in Get-ChildItem -LiteralPath $Source -Directory -Recurse -Force |
        Sort-Object FullName) {
        [IO.Directory]::CreateDirectory((Join-Path $destination (
            Get-RelativeChildPath $Source $directory.FullName))) | Out-Null
    }
    foreach ($file in Get-ChildItem -LiteralPath $Source -File -Recurse -Force |
        Sort-Object FullName) {
        [IO.File]::Copy($file.FullName,
            (Join-Path $destination (Get-RelativeChildPath $Source $file.FullName)), $false)
    }
    Set-ProtectedTree $AppDataRoot
    return $destination
}

if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'Physical negative runtime fixtures require Windows protected DACLs.'
}
$run = [IO.Path]::GetFullPath($RunRoot).TrimEnd('\', '/')
$runsPrefix = [IO.Path]::GetFullPath($runsRoot).TrimEnd('\', '/') + '\'
if (-not $run.StartsWith($runsPrefix, [StringComparison]::OrdinalIgnoreCase) -or
    (Split-Path -Leaf $run) -cnotmatch '^[a-f0-9]{32}$' -or
    -not (Test-Path -LiteralPath $run -PathType Container)) {
    throw 'RunRoot must be an existing canonical e2e-runs/<32-hex> directory.'
}
Assert-NoReparseTraversal $run
Assert-ExactProtectedAcl $run
$fixtureRoot = Join-Path $run 'negative-runtime'
if ($Action -eq 'Cleanup') {
    if (Test-Path -LiteralPath $fixtureRoot) {
        Assert-NoReparseTraversal $fixtureRoot
        Remove-Item -LiteralPath $fixtureRoot -Recurse -Force
    }
    Write-Output 'DEV negative mailbox runtime fixtures removed.'
    exit 0
}
if (Test-Path -LiteralPath $fixtureRoot) {
    throw 'Negative runtime fixture root already exists; explicit cleanup is required.'
}

$windowsSource = Assert-CanonicalSource $WindowsRuntimeRoot 'windows'
$androidSource = Assert-CanonicalSource $AndroidRuntimeRoot 'android'
$windowsHashBefore = Get-TreeSha256 $windowsSource
$androidHashBefore = Get-TreeSha256 $androidSource
[IO.Directory]::CreateDirectory($fixtureRoot) | Out-Null
Set-ProtectedTree $fixtureRoot
try {
    $tampered = Copy-ProtectedRuntime $windowsSource (Join-Path $fixtureRoot 'tampered-signature')
    $signaturePath = Join-Path $tampered 'mr-x-mailbox-policy.signature'
    $signature = [IO.File]::ReadAllBytes($signaturePath)
    try {
        if ($signature.Length -ne 64) { throw 'Canonical approval signature has an invalid length.' }
        $signature[0] = $signature[0] -bxor 1
        [IO.File]::WriteAllBytes($signaturePath, $signature)
    } finally { [Array]::Clear($signature, 0, $signature.Length) }
    Set-ProtectedTree (Join-Path $fixtureRoot 'tampered-signature')

    $missing = Copy-ProtectedRuntime $windowsSource (Join-Path $fixtureRoot 'missing-authority')
    Remove-Item -LiteralPath (Join-Path $missing 'authority.public.json') -Force
    Set-ProtectedTree (Join-Path $fixtureRoot 'missing-authority')

    Copy-ProtectedRuntime $androidSource (Join-Path $fixtureRoot 'android-runtime-on-windows') | Out-Null

    if ((Get-TreeSha256 $windowsSource) -cne $windowsHashBefore -or
        (Get-TreeSha256 $androidSource) -cne $androidHashBefore) {
        throw 'Canonical issued runtime changed while negative fixtures were generated.'
    }

    $cases = foreach ($case in $caseNames) {
        $appData = Join-Path $fixtureRoot $case
        [ordered]@{
            case = $case
            status = 'prepared'
            fixtureTreeSha256 = Get-TreeSha256 $appData
        }
    }
    $manifest = [ordered]@{
        schema = 'deep.dev-negative-mailbox-runtime.v1'
        runId = Split-Path -Leaf $run
        status = 'prepared'
        canonicalWindowsRuntimeSha256 = $windowsHashBefore
        canonicalAndroidRuntimeSha256 = $androidHashBefore
        cases = @($cases)
    }
    $manifestPath = Join-Path $run 'negative-runtime-fixtures.json'
    [IO.File]::WriteAllText($manifestPath,
        ($manifest | ConvertTo-Json -Depth 5), [Text.UTF8Encoding]::new($false))
    Set-ExactProtectedAcl $manifestPath
    Set-ProtectedTree $fixtureRoot
} catch {
    if (Test-Path -LiteralPath $fixtureRoot) {
        Remove-Item -LiteralPath $fixtureRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
    throw
}

Write-Output 'DEV negative mailbox runtime fixtures prepared.'
