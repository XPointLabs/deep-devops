Set-StrictMode -Version Latest

function Assert-NoMailboxBuildReparseTraversal([string]$Path) {
    $full = [IO.Path]::GetFullPath($Path)
    if ((Test-Path -LiteralPath $full) -and
        ((Get-Item -Force -LiteralPath $full).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "Mailbox build input uses a reparse point: $full"
    }
    $parent = if (Test-Path -LiteralPath $full -PathType Container) {
        [IO.DirectoryInfo]::new($full)
    } else {
        [IO.DirectoryInfo]::new([IO.Path]::GetDirectoryName($full))
    }
    while ($null -ne $parent) {
        if ($parent.Exists -and
            ($parent.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw "Mailbox build input traverses a reparse point: $($parent.FullName)"
        }
        $parent = $parent.Parent
    }
}

function Get-MailboxRelativePath([string]$Root, [string]$Path) {
    $prefix = [IO.Path]::GetFullPath($Root).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    $full = [IO.Path]::GetFullPath($Path)
    $comparison = if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
        [StringComparison]::OrdinalIgnoreCase
    } else {
        [StringComparison]::Ordinal
    }
    if (-not $full.StartsWith($prefix, $comparison)) {
        throw "Mailbox build inventory path escapes its root: $full"
    }
    return $full.Substring($prefix.Length).Replace('\', '/')
}

function Get-MailboxTreeFiles([string]$Root) {
    return @(
        Get-ChildItem -Force -LiteralPath $Root -Recurse |
            ForEach-Object {
                if ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) {
                    throw "Mailbox build tree contains a reparse point: $($_.FullName)"
                }
                if (-not $_.PSIsContainer) {
                    Get-MailboxRelativePath $Root $_.FullName
                }
            } |
            Sort-Object -CaseSensitive
    )
}

function Test-MailboxManifestPath([string]$Value) {
    if ([string]::IsNullOrWhiteSpace($Value) -or
        $Value.Contains('\') -or
        [IO.Path]::IsPathRooted($Value)) {
        return $false
    }
    $parts = $Value.Split('/')
    return -not ($parts | Where-Object {
        [string]::IsNullOrWhiteSpace($_) -or $_ -eq '.' -or $_ -eq '..'
    })
}

function Assert-MailboxExactFileInventory(
    [string]$Root,
    [string[]]$ExpectedPaths,
    [hashtable]$ExpectedMetadata) {
    $actual = @(Get-MailboxTreeFiles $Root)
    $expected = @($ExpectedPaths | Sort-Object -CaseSensitive)
    if ($actual.Count -ne $expected.Count) {
        throw "Mailbox build inventory differs from its exact allowlist ($($actual.Count) != $($expected.Count))."
    }
    for ($index = 0; $index -lt $expected.Count; $index++) {
        if ($actual[$index] -cne $expected[$index]) {
            throw "Mailbox build inventory contains an unlisted or missing file: $($actual[$index])"
        }
        $metadata = $ExpectedMetadata[$expected[$index]]
        $candidate = Join-Path $Root $expected[$index]
        Assert-NoMailboxBuildReparseTraversal $candidate
        if ((Get-Item -Force -LiteralPath $candidate).Length -ne [long]$metadata.Bytes -or
            (Get-FileHash -LiteralPath $candidate -Algorithm SHA256).Hash.ToLowerInvariant() -cne
                [string]$metadata.Sha256) {
            throw "Mailbox build allowlisted file changed: $($expected[$index])"
        }
    }
}

function New-SurvivalMailboxIsolatedSource {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$XNodeSource,
        [Parameter(Mandatory)][string]$DriverSource,
        [Parameter(Mandatory)][string]$Destination,
        [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{40}$')][string]$ExpectedCommit,
        [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{64}$')][string]$ExpectedManifestSha256,
        [Parameter(Mandatory)][hashtable]$ExpectedDriverSha256
    )

    $xnode = [IO.Path]::GetFullPath($XNodeSource)
    $driver = [IO.Path]::GetFullPath($DriverSource)
    $destination = [IO.Path]::GetFullPath($Destination)
    $manifestPath = Join-Path $xnode '.survival-source-manifest.json'
    Assert-NoMailboxBuildReparseTraversal $xnode
    Assert-NoMailboxBuildReparseTraversal $driver
    Assert-NoMailboxBuildReparseTraversal $manifestPath
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf) -or
        (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne
            $ExpectedManifestSha256) {
        throw 'The exported XNode source manifest is missing or does not match its exact pin.'
    }

    $manifest = Get-Content -Raw -LiteralPath $manifestPath | ConvertFrom-Json
    if ($manifest.schemaVersion -ne 1 -or
        [string]$manifest.kind -cne 'dotnet' -or
        [string]$manifest.sourceCommit -cne $ExpectedCommit -or
        @($manifest.files).Count -eq 0) {
        throw 'The exported XNode source manifest schema or revision is invalid.'
    }

    $sourceMetadata = @{}
    $prior = ''
    foreach ($file in @($manifest.files)) {
        $relative = [string]$file.path
        if (-not (Test-MailboxManifestPath $relative) -or
            $relative -cne $relative.ToLowerInvariant() -and
                $sourceMetadata.ContainsKey($relative.ToLowerInvariant()) -or
            $sourceMetadata.ContainsKey($relative)) {
            throw "The exported XNode manifest path is unsafe or duplicated: $relative"
        }
        if ($prior -and [StringComparer]::Ordinal.Compare($prior, $relative) -ge 0) {
            throw 'The exported XNode manifest is not in exact ordinal path order.'
        }
        if ([long]$file.bytes -lt 0 -or
            [string]$file.sha256 -notmatch '^[0-9a-f]{64}$') {
            throw "The exported XNode manifest metadata is invalid: $relative"
        }
        $sourceMetadata[$relative] = [pscustomobject]@{
            Bytes = [long]$file.bytes
            Sha256 = [string]$file.sha256
        }
        $prior = $relative
    }
    $sourceMetadata['.survival-source-manifest.json'] = [pscustomobject]@{
        Bytes = (Get-Item -Force -LiteralPath $manifestPath).Length
        Sha256 = $ExpectedManifestSha256
    }
    $sourcePaths = @($sourceMetadata.Keys | Sort-Object -CaseSensitive)
    Assert-MailboxExactFileInventory $xnode $sourcePaths $sourceMetadata

    $driverNames = @(
        'MailboxGrantProvisioner.cs',
        'MailboxRuntimePublisher.cs',
        'PrivateCrossProcessState.cs',
        'Program.cs',
        'ProductionMailboxUatPublisher.cs',
        'SurvivalMailboxDriver.csproj'
    )
    $driverBuildInputs = @(
        Get-ChildItem -Force -LiteralPath $driver -File |
            Where-Object {
                $_.Name -match '(?i)\.(?:cs|csproj|props|targets)$' -or
                $_.Name -match '(?i)^Directory\.Build\.' -or
                $_.Name -ieq 'global.json'
            } |
            Select-Object -ExpandProperty Name |
            Sort-Object -CaseSensitive
    )
    $expectedDriver = @($driverNames | Sort-Object -CaseSensitive)
    if ($driverBuildInputs.Count -ne $expectedDriver.Count -or
        (Compare-Object $expectedDriver $driverBuildInputs -CaseSensitive)) {
        throw 'The mailbox driver directory contains an unlisted C#/MSBuild input.'
    }
    if ($ExpectedDriverSha256.Count -ne $driverNames.Count) {
        throw 'The mailbox driver exact hash allowlist is incomplete.'
    }
    foreach ($name in $driverNames) {
        $actualDriverHash = (Get-FileHash -LiteralPath (
            Join-Path $driver $name) -Algorithm SHA256).Hash.ToLowerInvariant()
        if (-not $ExpectedDriverSha256.ContainsKey($name) -or
            [string]$ExpectedDriverSha256[$name] -notmatch '^[0-9a-f]{64}$' -or
            $actualDriverHash -cne [string]$ExpectedDriverSha256[$name]) {
            throw "The mailbox driver tracked input does not match its exact reviewed hash: $name"
        }
    }

    if (Test-Path -LiteralPath $destination) {
        throw 'The isolated mailbox source destination must not already exist.'
    }
    [void][IO.Directory]::CreateDirectory($destination)
    Set-MailboxDirectoryExclusiveWritable $destination
    $stagedXNode = Join-Path $destination 'xnode'
    $stagedDriver = Join-Path $destination 'driver'
    [void][IO.Directory]::CreateDirectory($stagedXNode)
    [void][IO.Directory]::CreateDirectory($stagedDriver)

    $isolatedMetadata = @{}
    try {
        foreach ($relative in $sourcePaths) {
            $sourcePath = Join-Path $xnode $relative
            $targetPath = Join-Path $stagedXNode $relative
            [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($targetPath))
            Assert-NoMailboxBuildReparseTraversal $sourcePath
            $input = [IO.FileStream]::new(
                $sourcePath,
                [IO.FileMode]::Open,
                [IO.FileAccess]::Read,
                [IO.FileShare]::Read)
            try {
                $output = [IO.FileStream]::new(
                    $targetPath,
                    [IO.FileMode]::CreateNew,
                    [IO.FileAccess]::Write,
                    [IO.FileShare]::None)
                try {
                    $input.CopyTo($output)
                    $output.Flush($true)
                } finally {
                    $output.Dispose()
                }
            } finally {
                $input.Dispose()
            }
            $isolatedMetadata["xnode/$relative"] = $sourceMetadata[$relative]
        }

        foreach ($name in $driverNames) {
            $sourcePath = Join-Path $driver $name
            Assert-NoMailboxBuildReparseTraversal $sourcePath
            $targetPath = Join-Path $stagedDriver $name
            $input = [IO.FileStream]::new(
                $sourcePath,
                [IO.FileMode]::Open,
                [IO.FileAccess]::Read,
                [IO.FileShare]::Read)
            try {
                $output = [IO.FileStream]::new(
                    $targetPath,
                    [IO.FileMode]::CreateNew,
                    [IO.FileAccess]::Write,
                    [IO.FileShare]::None)
                try {
                    $input.CopyTo($output)
                    $output.Flush($true)
                } finally {
                    $output.Dispose()
                }
            } finally {
                $input.Dispose()
            }
            $isolatedMetadata["driver/$name"] = [pscustomobject]@{
                Bytes = (Get-Item -Force -LiteralPath $targetPath).Length
                Sha256 = (Get-FileHash -LiteralPath $targetPath -Algorithm SHA256).Hash.ToLowerInvariant()
            }
            if ($isolatedMetadata["driver/$name"].Sha256 -cne
                [string]$ExpectedDriverSha256[$name]) {
                throw "The mailbox driver input changed while it was materialized: $name"
            }
        }

        # Pin SDK selection at the isolated common ancestor. Directory.Build.*
        # discovery is disabled during publish, so no ambient parent file can run.
        $globalSource = Join-Path $stagedXNode 'global.json'
        $globalTarget = Join-Path $destination 'global.json'
        [IO.File]::Copy($globalSource, $globalTarget, $false)
        $isolatedMetadata['global.json'] = [pscustomobject]@{
            Bytes = (Get-Item -Force -LiteralPath $globalTarget).Length
            Sha256 = (Get-FileHash -LiteralPath $globalTarget -Algorithm SHA256).Hash.ToLowerInvariant()
        }
        $isolatedPaths = @($isolatedMetadata.Keys | Sort-Object -CaseSensitive)
        Assert-MailboxExactFileInventory $destination $isolatedPaths $isolatedMetadata
        return [pscustomobject]@{
            Root = $destination
            XNode = $stagedXNode
            DriverProject = Join-Path $stagedDriver 'SurvivalMailboxDriver.csproj'
            Paths = $isolatedPaths
            Metadata = $isolatedMetadata
        }
    } catch {
        Remove-Item -Force -Recurse -LiteralPath $destination -ErrorAction SilentlyContinue
        throw
    }
}

function Assert-SurvivalMailboxIsolatedSource($Source) {
    Assert-MailboxExactFileInventory $Source.Root $Source.Paths $Source.Metadata
}

function Set-MailboxDirectoryExclusiveWritable([string]$Path) {
    if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
        $current = [Security.Principal.WindowsIdentity]::GetCurrent().User
        $system = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
        $administrators = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
        $item = [IO.DirectoryInfo](Get-Item -Force -LiteralPath $Path)
        $owner = $item.GetAccessControl(
            [Security.AccessControl.AccessControlSections]::Owner).GetOwner(
                [Security.Principal.SecurityIdentifier])
        if (-not $owner.Equals($current)) {
            throw 'Mailbox writable directory owner must be the exact current Windows identity.'
        }
        $security = [Security.AccessControl.DirectorySecurity]::new()
        $security.SetAccessRuleProtection($true, $false)
        foreach ($identity in @($current, $system, $administrators)) {
            $security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
                $identity,
                [Security.AccessControl.FileSystemRights]::FullControl,
                [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
                    [Security.AccessControl.InheritanceFlags]::ObjectInherit,
                [Security.AccessControl.PropagationFlags]::None,
                [Security.AccessControl.AccessControlType]::Allow))
        }
        $item.SetAccessControl($security)
    } else {
        [IO.File]::SetUnixFileMode(
            $Path,
            [IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite -bor
                [IO.UnixFileMode]::UserExecute)
    }
}

function Set-MailboxFileExclusiveWritable([string]$Path) {
    Assert-NoMailboxBuildReparseTraversal $Path
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Mailbox private-state cleanup requires a regular file: $Path"
    }
    if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
        $current = [Security.Principal.WindowsIdentity]::GetCurrent().User
        $system = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
        $administrators = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
        $item = [IO.FileInfo](Get-Item -Force -LiteralPath $Path)
        $owner = $item.GetAccessControl(
            [Security.AccessControl.AccessControlSections]::Owner).GetOwner(
                [Security.Principal.SecurityIdentifier])
        if (-not $owner.Equals($current)) {
            throw 'Mailbox private-state file owner must be the exact current Windows identity.'
        }
        $security = [Security.AccessControl.FileSecurity]::new()
        $security.SetAccessRuleProtection($true, $false)
        foreach ($identity in @($current, $system, $administrators)) {
            $security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
                $identity,
                [Security.AccessControl.FileSystemRights]::FullControl,
                [Security.AccessControl.AccessControlType]::Allow))
        }
        $item.SetAccessControl($security)
        [IO.File]::SetAttributes(
            $Path,
            [IO.File]::GetAttributes($Path) -band (-bnot [IO.FileAttributes]::ReadOnly))
    } else {
        [IO.File]::SetUnixFileMode(
            $Path,
            [IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite)
    }
}

function Remove-MailboxPrivateStateDirectory(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$ExpectedParent) {
    $full = [IO.Path]::GetFullPath($Path)
    $parent = [IO.Path]::GetFullPath($ExpectedParent).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar)
    $comparison = if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
        [StringComparison]::OrdinalIgnoreCase
    } else {
        [StringComparison]::Ordinal
    }
    if (-not [string]::Equals(
            [IO.Path]::GetDirectoryName($full), $parent, $comparison)) {
        throw 'Mailbox private-state cleanup target must be a direct child of its exact parent.'
    }
    if (-not (Test-Path -LiteralPath $full)) { return }
    Assert-NoMailboxBuildReparseTraversal $full
    if (-not (Test-Path -LiteralPath $full -PathType Container)) {
        throw 'Mailbox private-state cleanup target must be a directory.'
    }
    $directory = Get-Item -Force -LiteralPath $full
    if ($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw 'Mailbox private-state cleanup target cannot be a reparse point.'
    }
    Set-MailboxDirectoryExclusiveWritable $full
    foreach ($child in @(Get-ChildItem -Force -LiteralPath $full)) {
        if ($child.PSIsContainer -or
            ($child.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'Mailbox private-state cleanup rejects nested directories and reparse points.'
        }
        Set-MailboxFileExclusiveWritable $child.FullName
    }
    Remove-Item -LiteralPath $full -Recurse -Force -ErrorAction Stop
    if (Test-Path -LiteralPath $full) {
        throw 'Mailbox private-state directory still exists after terminating deletion.'
    }
}

function Set-MailboxTreeReadOnly([string]$Root) {
    if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
        $current = [Security.Principal.WindowsIdentity]::GetCurrent().User
        $system = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
        $administrators = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
        # Files first and directories deepest-first preserve our ability to
        # replace every inherited DACL before each parent becomes read-only.
        $files = @(Get-ChildItem -Force -LiteralPath $Root -File -Recurse)
        $directories = @(
            Get-ChildItem -Force -LiteralPath $Root -Directory -Recurse |
                Sort-Object { $_.FullName.Length } -Descending
        ) + @(Get-Item -Force -LiteralPath $Root)
        $items = $files + $directories
        foreach ($item in $items) {
            $security = if ($item.PSIsContainer) {
                [Security.AccessControl.DirectorySecurity]::new()
            } else {
                [Security.AccessControl.FileSecurity]::new()
            }
            $security.SetAccessRuleProtection($true, $false)
            $currentRights = if ($item.PSIsContainer) {
                [Security.AccessControl.FileSystemRights]::ReadAndExecute -bor
                    [Security.AccessControl.FileSystemRights]::ListDirectory
            } else {
                [Security.AccessControl.FileSystemRights]::ReadAndExecute
            }
            $security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
                $current, $currentRights,
                [Security.AccessControl.AccessControlType]::Allow))
            foreach ($identity in @($system, $administrators)) {
                $security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
                    $identity, [Security.AccessControl.FileSystemRights]::FullControl,
                    [Security.AccessControl.AccessControlType]::Allow))
            }
            if ($item.PSIsContainer) {
                ([IO.DirectoryInfo]$item).SetAccessControl($security)
            } else {
                ([IO.FileInfo]$item).SetAccessControl($security)
            }
        }
    } else {
        foreach ($file in Get-ChildItem -Force -LiteralPath $Root -File -Recurse) {
            [IO.File]::SetUnixFileMode(
                $file.FullName,
                [IO.UnixFileMode]::UserRead -bor
                    [IO.UnixFileMode]::GroupRead -bor
                    [IO.UnixFileMode]::OtherRead)
        }
        $directories = @(Get-ChildItem -Force -LiteralPath $Root -Directory -Recurse) +
            @(Get-Item -Force -LiteralPath $Root)
        foreach ($directory in $directories) {
            [IO.File]::SetUnixFileMode(
                $directory.FullName,
                [IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserExecute -bor
                    [IO.UnixFileMode]::GroupRead -bor [IO.UnixFileMode]::GroupExecute -bor
                    [IO.UnixFileMode]::OtherRead -bor [IO.UnixFileMode]::OtherExecute)
        }
    }
}

function Set-MailboxTreeWritable([string]$Root) {
    if (-not (Test-Path -LiteralPath $Root)) {
        return
    }
    if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
        $current = [Security.Principal.WindowsIdentity]::GetCurrent().User
        $items = @(Get-Item -Force -LiteralPath $Root) +
            @(Get-ChildItem -Force -LiteralPath $Root -Recurse)
        foreach ($item in $items) {
            $security = if ($item.PSIsContainer) {
                [Security.AccessControl.DirectorySecurity]::new()
            } else {
                [Security.AccessControl.FileSecurity]::new()
            }
            $security.SetAccessRuleProtection($true, $false)
            $security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
                $current,
                [Security.AccessControl.FileSystemRights]::FullControl,
                [Security.AccessControl.AccessControlType]::Allow))
            if ($item.PSIsContainer) {
                ([IO.DirectoryInfo]$item).SetAccessControl($security)
            } else {
                ([IO.FileInfo]$item).SetAccessControl($security)
            }
        }
    } else {
        foreach ($file in Get-ChildItem -Force -LiteralPath $Root -File -Recurse) {
            [IO.File]::SetUnixFileMode(
                $file.FullName,
                [IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite)
        }
        $directories = @(Get-ChildItem -Force -LiteralPath $Root -Directory -Recurse) +
            @(Get-Item -Force -LiteralPath $Root)
        foreach ($directory in $directories) {
            [IO.File]::SetUnixFileMode(
                $directory.FullName,
                [IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite -bor
                    [IO.UnixFileMode]::UserExecute)
        }
    }
}

function Open-MailboxTreeReadLocks([string]$Root) {
    $locks = [Collections.Generic.List[IDisposable]]::new()
    try {
        foreach ($file in Get-ChildItem -Force -LiteralPath $Root -File -Recurse) {
            $locks.Add([IO.FileStream]::new(
                $file.FullName,
                [IO.FileMode]::Open,
                [IO.FileAccess]::Read,
                [IO.FileShare]::Read))
        }
        return $locks
    } catch {
        foreach ($lock in $locks) { $lock.Dispose() }
        throw
    }
}
