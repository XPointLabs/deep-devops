[CmdletBinding()]
param(
    [string] $SecretRoot = 'C:\Work\DeepSession\secrets\first-release-local',
    [string] $EnvFile = ''
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$secretRootPath = [IO.Path]::GetFullPath($SecretRoot)
$environmentPath = if ([string]::IsNullOrWhiteSpace($EnvFile)) {
    [IO.Path]::GetFullPath((Join-Path $secretRootPath 'first-release.env'))
} else {
    [IO.Path]::GetFullPath($EnvFile)
}

function Assert-RegularPath([string] $Path, [bool] $Directory) {
    $pathType = if ($Directory) { 'Container' } else { 'Leaf' }
    if (-not (Test-Path -LiteralPath $Path -PathType $pathType)) {
        throw "Required protected path is missing."
    }
    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Protected first-release paths must not be symlinks or reparse points.'
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
                [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit',
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

function Clear-Bytes([byte[]] $Bytes) {
    if ($null -ne $Bytes -and $Bytes.Length -gt 0) {
        [Array]::Clear($Bytes, 0, $Bytes.Length)
    }
}

function Test-StateKey([string] $Path) {
    Assert-RegularPath $Path $false
    $bytes = [IO.File]::ReadAllBytes($Path)
    try {
        if ($bytes.Length -ne 32 -or (@($bytes | Where-Object { $_ -ne 0 })).Count -eq 0) {
            throw 'An ONION state-protection key is not an exact nonzero 32-byte value.'
        }
        $sha256 = [Security.Cryptography.SHA256]::Create()
        try {
            return [Convert]::ToBase64String($sha256.ComputeHash($bytes))
        } finally {
            $sha256.Dispose()
        }
    } finally {
        Clear-Bytes $bytes
    }
}

function New-ProtectedRandomFile([string] $Path, [int] $Length) {
    $temporary = "$Path.provision-$([guid]::NewGuid().ToString('N'))"
    $bytes = [byte[]]::new($Length)
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($bytes)
        if (($bytes | Where-Object { $_ -ne 0 }).Count -eq 0) {
            throw 'The random provider returned an invalid protected value.'
        }
        $stream = [IO.File]::Open($temporary, [IO.FileMode]::CreateNew,
            [IO.FileAccess]::Write, [IO.FileShare]::None)
        try {
            $stream.Write($bytes, 0, $bytes.Length)
            $stream.Flush($true)
        } finally {
            $stream.Dispose()
        }
        Set-ProtectedFileAcl $temporary
        [IO.File]::Move($temporary, $Path)
    } finally {
        $rng.Dispose()
        Clear-Bytes $bytes
        if (Test-Path -LiteralPath $temporary) {
            Remove-Item -LiteralPath $temporary -Force
        }
    }
}

function New-RandomHex([int] $Length) {
    $bytes = [byte[]]::new($Length)
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($bytes)
        if (($bytes | Where-Object { $_ -ne 0 }).Count -eq 0) {
            throw 'The random provider returned an invalid public identifier.'
        }
        return ([BitConverter]::ToString($bytes)).Replace('-', '').ToLowerInvariant()
    } finally {
        $rng.Dispose()
        Clear-Bytes $bytes
    }
}

function Assert-VlessClientId([string] $Value) {
    $parsed = [guid]::Empty
    if (-not [guid]::TryParseExact($Value, 'D', [ref]$parsed) -or
        $parsed -eq [guid]::Empty) {
        throw 'A protected VLESS client ID is invalid.'
    }
}

function Assert-RealityPrivateKey([string] $Value) {
    if ($Value -notmatch '^[A-Za-z0-9_-]{43}$') {
        throw 'A protected REALITY private key is invalid.'
    }
    $bytes = $null
    try {
        $base64 = $Value.Replace('-', '+').Replace('_', '/') + '='
        $bytes = [Convert]::FromBase64String($base64)
        if ($bytes.Length -ne 32 -or (@($bytes | Where-Object { $_ -ne 0 })).Count -eq 0) {
            throw 'A protected REALITY private key is invalid.'
        }
    } catch [FormatException] {
        throw 'A protected REALITY private key is invalid.'
    } finally {
        Clear-Bytes $bytes
    }
}

function Write-ProtectedTextFile([string] $Path, [string] $Value) {
    $temporary = "$Path.provision-$([guid]::NewGuid().ToString('N'))"
    try {
        [IO.File]::WriteAllText(
            $temporary,
            "$Value`n",
            [Text.UTF8Encoding]::new($false))
        Set-ProtectedFileAcl $temporary
        [IO.File]::Move($temporary, $Path)
    } finally {
        if (Test-Path -LiteralPath $temporary) {
            Remove-Item -LiteralPath $temporary -Force
        }
    }
}

function Read-SingleEnvironmentValue([string] $Text, [string] $Name) {
    $matches = [regex]::Matches($Text, "(?m)^$([regex]::Escape($Name))=([^\r\n]*)\r?$")
    if ($matches.Count -gt 1) {
        throw 'A private environment binding is duplicated.'
    }
    if ($matches.Count -eq 0) {
        return $null
    }
    return $matches[0].Groups[1].Value
}

Assert-RegularPath $secretRootPath $true
Assert-RegularPath $environmentPath $false
if ((Get-Item -LiteralPath $environmentPath -Force).Length -gt 65536) {
    throw 'The private first-release environment file is unexpectedly large.'
}

$keyPaths = 1..3 | ForEach-Object {
    $nodeDirectory = [IO.Path]::GetFullPath((Join-Path $secretRootPath "xnode-$_"))
    Assert-RegularPath $nodeDirectory $true
    [IO.Path]::GetFullPath((Join-Path $nodeDirectory "xnode-$_-onion-state-protection.key"))
}
$existingCount = @($keyPaths | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf }).Count
if ($existingCount -ne 0 -and $existingCount -ne 3) {
    throw 'ONION state-protection provisioning is partial; refusing to rotate or fill a subset.'
}

if ($existingCount -eq 0) {
    foreach ($path in $keyPaths) {
        New-ProtectedRandomFile $path 32
    }
}

$fingerprints = @($keyPaths | ForEach-Object { Test-StateKey $_ })
if (($fingerprints | Sort-Object -Unique).Count -ne 3) {
    throw 'Every XNode must have a distinct ONION state-protection key.'
}

$authorityRoot = [IO.Path]::GetFullPath((Join-Path $secretRootPath 'registry-contact-resolve'))
$authorityPrivateRoot = [IO.Path]::GetFullPath((Join-Path $authorityRoot 'private'))
$authorityArtifactRoot = [IO.Path]::GetFullPath((Join-Path $authorityRoot 'artifacts'))
$authorityOperatorRoot = [IO.Path]::GetFullPath((Join-Path $authorityRoot 'operator'))
$authorityManifestPath = [IO.Path]::GetFullPath((Join-Path $authorityRoot 'custody-plan.v1.json'))
$authorityKeyPaths = @(
    [IO.Path]::GetFullPath((Join-Path $authorityPrivateRoot 'trusted-time-integrity.key')),
    [IO.Path]::GetFullPath((Join-Path $authorityPrivateRoot 'request-ledger-integrity.key')),
    [IO.Path]::GetFullPath((Join-Path $authorityPrivateRoot 'artifact-state-integrity.key')),
    [IO.Path]::GetFullPath((Join-Path $authorityPrivateRoot 'witness-1-ed25519.seed')),
    [IO.Path]::GetFullPath((Join-Path $authorityPrivateRoot 'witness-2-ed25519.seed')),
    [IO.Path]::GetFullPath((Join-Path $authorityPrivateRoot 'witness-3-ed25519.seed'))
)
$authorityExisting = @($authorityKeyPaths | Where-Object {
    Test-Path -LiteralPath $_ -PathType Leaf
}).Count
$authorityManifestExists = Test-Path -LiteralPath $authorityManifestPath -PathType Leaf
if (($authorityExisting -ne 0 -or $authorityManifestExists) -and
    ($authorityExisting -ne $authorityKeyPaths.Count -or -not $authorityManifestExists)) {
    throw 'ContactResolve custody provisioning is partial; refusing to rotate or fill a subset.'
}

if (-not (Test-Path -LiteralPath $authorityRoot)) {
    [IO.Directory]::CreateDirectory($authorityRoot) | Out-Null
    Set-ProtectedDirectoryAcl $authorityRoot
}
foreach ($directory in @(
        $authorityPrivateRoot,
        $authorityArtifactRoot,
        $authorityOperatorRoot)) {
    if (-not (Test-Path -LiteralPath $directory)) {
        [IO.Directory]::CreateDirectory($directory) | Out-Null
        Set-ProtectedDirectoryAcl $directory
    }
    Assert-RegularPath $directory $true
}

if ($authorityExisting -eq 0) {
    foreach ($path in $authorityKeyPaths) {
        New-ProtectedRandomFile $path 32
    }
    $custodyPlan = [ordered]@{
        format = 'deep-contact-resolve-custody-plan-v1'
        status = 'bound-preproduction-single-operator'
        authorityOwner = 'Mr. X'
        activation = 'blocked-pending-distinct-failure-domains-and-authority-closure'
        networkIdHex = New-RandomHex 16
        witnesses = @(1..3 | ForEach-Object {
            [ordered]@{
                ordinal = $_
                witnessIdHex = New-RandomHex 32
                keyGeneration = 0
            }
        })
    }
    $temporaryManifest = "$authorityManifestPath.provision-$([guid]::NewGuid().ToString('N'))"
    try {
        [IO.File]::WriteAllText(
            $temporaryManifest,
            ($custodyPlan | ConvertTo-Json -Depth 4 -Compress),
            [Text.UTF8Encoding]::new($false))
        Set-ProtectedFileAcl $temporaryManifest
        [IO.File]::Move($temporaryManifest, $authorityManifestPath)
    } finally {
        if (Test-Path -LiteralPath $temporaryManifest) {
            Remove-Item -LiteralPath $temporaryManifest -Force
        }
    }
}

$authorityFingerprints = @($authorityKeyPaths | ForEach-Object { Test-StateKey $_ })
if (($authorityFingerprints | Sort-Object -Unique).Count -ne $authorityKeyPaths.Count) {
    throw 'ContactResolve protection and witness-custody files must all be distinct.'
}
Assert-RegularPath $authorityManifestPath $false
$custodyPlan = [IO.File]::ReadAllText($authorityManifestPath) | ConvertFrom-Json
if ($custodyPlan.format -ne 'deep-contact-resolve-custody-plan-v1' -or
    $custodyPlan.status -ne 'bound-preproduction-single-operator' -or
    $custodyPlan.authorityOwner -cne 'Mr. X' -or
    $custodyPlan.activation -ne 'blocked-pending-distinct-failure-domains-and-authority-closure' -or
    $custodyPlan.networkIdHex -notmatch '^[0-9a-f]{32}$' -or
    @($custodyPlan.witnesses).Count -ne 3) {
    throw 'The ContactResolve custody plan is invalid.'
}
$witnessIds = @($custodyPlan.witnesses | ForEach-Object {
    if ($_.witnessIdHex -notmatch '^[0-9a-f]{64}$' -or $_.keyGeneration -ne 0) {
        throw 'The ContactResolve witness custody plan is invalid.'
    }
    $_.witnessIdHex
})
if (($witnessIds | Sort-Object -Unique).Count -ne 3) {
    throw 'ContactResolve witness IDs must be distinct.'
}

$text = [IO.File]::ReadAllText($environmentPath)
$newLines = [Collections.Generic.List[string]]::new()
$environmentChanged = $false
$migratedSecretPaths = [Collections.Generic.List[string]]::new()
$transportPlans = [Collections.Generic.List[object]]::new()

for ($index = 1; $index -le 3; $index++) {
    $nodeDirectory = [IO.Path]::GetFullPath((Join-Path $secretRootPath "xnode-$index"))
    $vlessPath = [IO.Path]::GetFullPath((Join-Path $nodeDirectory "xnode-$index-vless-client-id"))
    $realityPath = [IO.Path]::GetFullPath((Join-Path $nodeDirectory "xnode-$index-reality.private"))
    $vlessLegacyName = "FIRST_RELEASE_XNODE_${index}_VLESS_CLIENT_ID"
    $realityLegacyName = "FIRST_RELEASE_XNODE_${index}_REALITY_PRIVATE_KEY"
    $vlessFileName = "${vlessLegacyName}_FILE"
    $realityFileName = "${realityLegacyName}_FILE"
    $vlessLegacy = Read-SingleEnvironmentValue $text $vlessLegacyName
    $realityLegacy = Read-SingleEnvironmentValue $text $realityLegacyName
    $vlessFile = Read-SingleEnvironmentValue $text $vlessFileName
    $realityFile = Read-SingleEnvironmentValue $text $realityFileName
    $vlessExists = Test-Path -LiteralPath $vlessPath -PathType Leaf
    $realityExists = Test-Path -LiteralPath $realityPath -PathType Leaf

    $legacyState = $null -ne $vlessLegacy -and $null -ne $realityLegacy -and
        $null -eq $vlessFile -and $null -eq $realityFile -and
        -not $vlessExists -and -not $realityExists
    $fileState = $null -eq $vlessLegacy -and $null -eq $realityLegacy -and
        $null -ne $vlessFile -and $null -ne $realityFile -and
        $vlessExists -and $realityExists

    if (-not $legacyState -and -not $fileState) {
        throw 'XNode transport-secret provisioning is partial; refusing to expose or overwrite credentials.'
    }
    $transportPlans.Add([pscustomobject]@{
        State = if ($legacyState) { 'legacy' } else { 'file' }
        VlessPath = $vlessPath
        RealityPath = $realityPath
        VlessLegacyName = $vlessLegacyName
        RealityLegacyName = $realityLegacyName
        VlessFileName = $vlessFileName
        RealityFileName = $realityFileName
        VlessValue = $vlessLegacy
        RealityValue = $realityLegacy
        VlessFile = $vlessFile
        RealityFile = $realityFile
    })
}

if ((@($transportPlans.State | Sort-Object -Unique)).Count -ne 1) {
    throw 'XNode transport-secret provisioning mixes legacy and file-backed state.'
}

$transportVlessValues = [Collections.Generic.List[string]]::new()
$transportRealityValues = [Collections.Generic.List[string]]::new()
if ($transportPlans[0].State -ceq 'legacy') {
    foreach ($plan in $transportPlans) {
        Assert-VlessClientId $plan.VlessValue
        Assert-RealityPrivateKey $plan.RealityValue
        $transportVlessValues.Add($plan.VlessValue)
        $transportRealityValues.Add($plan.RealityValue)
    }
    if ((@($transportVlessValues | Sort-Object -Unique)).Count -ne 3 -or
        (@($transportRealityValues | Sort-Object -Unique)).Count -ne 3) {
        throw 'Every XNode must have distinct VLESS and REALITY credentials.'
    }
    try {
        foreach ($plan in $transportPlans) {
            Write-ProtectedTextFile $plan.VlessPath $plan.VlessValue
            $migratedSecretPaths.Add($plan.VlessPath)
            Write-ProtectedTextFile $plan.RealityPath $plan.RealityValue
            $migratedSecretPaths.Add($plan.RealityPath)
            $text = [regex]::Replace(
                $text,
                "(?m)^$([regex]::Escape($plan.VlessLegacyName))=[^\r\n]*(?:\r?\n|$)",
                '')
            $text = [regex]::Replace(
                $text,
                "(?m)^$([regex]::Escape($plan.RealityLegacyName))=[^\r\n]*(?:\r?\n|$)",
                '')
            $newLines.Add("$($plan.VlessFileName)=$($plan.VlessPath.Replace('\', '/'))")
            $newLines.Add("$($plan.RealityFileName)=$($plan.RealityPath.Replace('\', '/'))")
        }
        $environmentChanged = $true
    } catch {
        foreach ($createdPath in $migratedSecretPaths) {
            if (Test-Path -LiteralPath $createdPath -PathType Leaf) {
                Remove-Item -LiteralPath $createdPath -Force
            }
        }
        throw
    }
} else {
    foreach ($plan in $transportPlans) {
        $expectedVless = $plan.VlessPath.Replace('\', '/')
        $expectedReality = $plan.RealityPath.Replace('\', '/')
        if (-not [StringComparer]::OrdinalIgnoreCase.Equals($plan.VlessFile, $expectedVless) -or
            -not [StringComparer]::OrdinalIgnoreCase.Equals($plan.RealityFile, $expectedReality)) {
            throw 'An existing transport-secret environment binding is not the exact protected file.'
        }
        Assert-RegularPath $plan.VlessPath $false
        Assert-RegularPath $plan.RealityPath $false
        $vlessValue = [IO.File]::ReadAllText($plan.VlessPath).TrimEnd("`r", "`n")
        $realityValue = [IO.File]::ReadAllText($plan.RealityPath).TrimEnd("`r", "`n")
        Assert-VlessClientId $vlessValue
        Assert-RealityPrivateKey $realityValue
        $transportVlessValues.Add($vlessValue)
        $transportRealityValues.Add($realityValue)
    }
    if ((@($transportVlessValues | Sort-Object -Unique)).Count -ne 3 -or
        (@($transportRealityValues | Sort-Object -Unique)).Count -ne 3) {
        throw 'Every XNode must have distinct VLESS and REALITY credentials.'
    }
}
$transportVlessValues.Clear()
$transportRealityValues.Clear()

for ($index = 1; $index -le 3; $index++) {
    $name = "FIRST_RELEASE_XNODE_${index}_ONION_STATE_PROTECTION_FILE"
    $expected = $keyPaths[$index - 1].Replace('\', '/')
    $match = [regex]::Match($text, "(?m)^$([regex]::Escape($name))=(.*)$")
    if ($match.Success) {
        $configuredPath = $match.Groups[1].Value.TrimEnd("`r")
        if (-not [StringComparer]::OrdinalIgnoreCase.Equals($configuredPath, $expected)) {
            throw 'The existing ONION state-protection environment binding is not the exact protected file.'
        }
    } else {
        $newLines.Add("$name=$expected")
    }
}
$authorityBindings = [ordered]@{
    FIRST_RELEASE_CONTACT_RESOLVE_NETWORK_ID = [string]$custodyPlan.networkIdHex
    FIRST_RELEASE_CONTACT_RESOLVE_TRUSTED_TIME_KEY_FILE = $authorityKeyPaths[0].Replace('\', '/')
    FIRST_RELEASE_CONTACT_RESOLVE_REQUEST_LEDGER_KEY_FILE = $authorityKeyPaths[1].Replace('\', '/')
    FIRST_RELEASE_CONTACT_RESOLVE_ARTIFACT_ROOT = $authorityArtifactRoot.Replace('\', '/')
    FIRST_RELEASE_CONTACT_RESOLVE_OPERATOR_ROOT = $authorityOperatorRoot.Replace('\', '/')
    FIRST_RELEASE_CONTACT_RESOLVE_ARTIFACT_STATE_KEY_FILE = $authorityKeyPaths[2].Replace('\', '/')
}
for ($index = 1; $index -le 3; $index++) {
    $authorityBindings["FIRST_RELEASE_CONTACT_RESOLVE_WITNESS_${index}_ID"] = $witnessIds[$index - 1]
    $authorityBindings["FIRST_RELEASE_CONTACT_RESOLVE_WITNESS_${index}_SEED_FILE"] = $authorityKeyPaths[$index + 2].Replace('\', '/')
}
foreach ($entry in $authorityBindings.GetEnumerator()) {
    $match = [regex]::Match($text, "(?m)^$([regex]::Escape($entry.Key))=(.*)$")
    if ($match.Success) {
        if (-not [StringComparer]::OrdinalIgnoreCase.Equals(
                $match.Groups[1].Value.TrimEnd("`r"), [string]$entry.Value)) {
            throw 'An existing ContactResolve environment binding differs from protected custody.'
        }
    } else {
        $newLines.Add("$($entry.Key)=$($entry.Value)")
    }
}

if ($newLines.Count -gt 0 -or $environmentChanged) {
    $updated = $text.TrimEnd("`r", "`n") + "`r`n" +
        '# Generated production custody paths; public IDs remain untrusted until bound by verified XNA1.' + "`r`n" +
        ($newLines -join "`r`n") + "`r`n"
    $operationId = [guid]::NewGuid().ToString('N')
    $temporaryEnvironment = "$environmentPath.provision-$operationId"
    $backupEnvironment = "$environmentPath.backup-$operationId"
    $environmentCommitted = $false
    try {
        [IO.File]::WriteAllText(
            $temporaryEnvironment,
            $updated,
            [Text.UTF8Encoding]::new($false))
        Set-ProtectedFileAcl $temporaryEnvironment
        [IO.File]::Replace($temporaryEnvironment, $environmentPath, $backupEnvironment, $true)
        $environmentCommitted = $true
        Remove-Item -LiteralPath $backupEnvironment -Force
    } finally {
        if (Test-Path -LiteralPath $temporaryEnvironment) {
            Remove-Item -LiteralPath $temporaryEnvironment -Force
        }
        if (Test-Path -LiteralPath $backupEnvironment) {
            Remove-Item -LiteralPath $backupEnvironment -Force
        }
        if (-not $environmentCommitted) {
            foreach ($createdPath in $migratedSecretPaths) {
                if (Test-Path -LiteralPath $createdPath -PathType Leaf) {
                    Remove-Item -LiteralPath $createdPath -Force
                }
            }
        }
    }
}

$text = $null
$newLines.Clear()
Write-Output 'Three distinct ONION state-protection keys and private environment bindings are ready.'
Write-Output 'XNode VLESS and REALITY credentials are protected by file-backed secret bindings.'
Write-Output 'ContactResolve protected state keys, fresh witness custody, and dormant runtime bindings are ready.'
