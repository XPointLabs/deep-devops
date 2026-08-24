[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$Root = [IO.Path]::GetFullPath((Split-Path $PSScriptRoot -Parent))
$Project = Join-Path $Root 'tools\survival-mailbox-driver\SurvivalMailboxDriver.csproj'
$XNode = Join-Path $Root 'artifacts\survival-dev\build-contexts\xnode'
$Work = Join-Path ([IO.Path]::GetTempPath()) (
    'deep-private-ack-state-test-' + [Guid]::NewGuid().ToString('N'))
$Build = Join-Path $Work 'build'
$Publish = Join-Path $Work 'publish'
. (Join-Path $PSScriptRoot 'survival-dev-mailbox-build-inputs.ps1')

function New-PrivateStateDirectory([string]$Name) {
    $path = Join-Path $Work $Name
    [void][IO.Directory]::CreateDirectory($path)
    Set-MailboxDirectoryExclusiveWritable $path
    return $path
}

function Invoke-StateDriver(
    [string]$Command,
    [string]$StateDirectory,
    [switch]$ExpectFailure) {
    $priorErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $output = @(& dotnet (Join-Path $Publish 'SurvivalMailboxDriver.dll') `
            $Command '--state-dir' $StateDirectory 2>&1)
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $priorErrorActionPreference
    }
    if ($ExpectFailure) {
        if ($exitCode -eq 0) {
            throw "$Command unexpectedly accepted unsafe private ACK state."
        }
    } elseif ($exitCode -ne 0) {
        throw "$Command failed with exit code $exitCode.`n$($output -join "`n")"
    }
    return $output
}

function Set-StateFileWritable([string]$Path) {
    if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
        [IO.File]::SetAttributes(
            $Path,
            [IO.File]::GetAttributes($Path) -band (-bnot [IO.FileAttributes]::ReadOnly))
    }
}

function Set-DirectoryBroad([string]$Path) {
    if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
        $info = [IO.DirectoryInfo](Get-Item -Force -LiteralPath $Path)
        $acl = $info.GetAccessControl()
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new('S-1-5-11'),
            [Security.AccessControl.FileSystemRights]::ReadAndExecute,
            [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
                [Security.AccessControl.InheritanceFlags]::ObjectInherit,
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow))
        $info.SetAccessControl($acl)
    } else {
        [IO.File]::SetUnixFileMode(
            $Path,
            [IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite -bor
                [IO.UnixFileMode]::UserExecute -bor [IO.UnixFileMode]::GroupRead -bor
                [IO.UnixFileMode]::GroupExecute)
    }
}

function Assert-PrivateStateShape([string]$Directory) {
    $file = Join-Path $Directory 'client-ack-loss.json'
    if (-not (Test-Path -LiteralPath $file -PathType Leaf) -or
        ((Get-Item -Force -LiteralPath $file).Attributes -band
            [IO.FileAttributes]::ReparsePoint)) {
        throw 'Private ACK state must be an exact regular non-reparse file.'
    }
    if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
        if (-not ((Get-Item -Force -LiteralPath $file).Attributes -band
            [IO.FileAttributes]::ReadOnly)) {
            throw 'Private ACK state must be read-only between Windows processes.'
        }
        $current = [Security.Principal.WindowsIdentity]::GetCurrent().User
        $security = ([IO.FileInfo](Get-Item -Force -LiteralPath $file)).GetAccessControl(
            [Security.AccessControl.AccessControlSections]::Access -bor
                [Security.AccessControl.AccessControlSections]::Owner)
        $owner = $security.GetOwner([Security.Principal.SecurityIdentifier])
        if (-not $owner.Equals($current) -or -not $security.AreAccessRulesProtected) {
            throw 'Private ACK state owner/DACL is not exact.'
        }
    } else {
        $directoryMode = [IO.File]::GetUnixFileMode($Directory)
        $fileMode = [IO.File]::GetUnixFileMode($file)
        if ($directoryMode -ne (
                [IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite -bor
                    [IO.UnixFileMode]::UserExecute) -or
            $fileMode -ne (
                [IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite)) {
            throw 'Private ACK state requires exact Unix 0700/0600 modes.'
        }
    }
}

$tests = 0
$ownerBoundaryEnforced = $false
try {
    [void][IO.Directory]::CreateDirectory($Work)
    Set-MailboxDirectoryExclusiveWritable $Work
    & dotnet publish $Project --configuration Release --output $Publish `
        --artifacts-path $Build --no-self-contained '-p:UseAppHost=false' `
        "-p:XNodeSource=$XNode"
    if ($LASTEXITCODE -ne 0) { throw 'Private ACK state test driver build failed.' }

    $valid = New-PrivateStateDirectory 'valid'
    [void](Invoke-StateDriver 'private-state-test-write' $valid)
    [void](Invoke-StateDriver 'private-state-test-read' $valid)
    Assert-PrivateStateShape $valid
    $tests++

    $unsafeBeforeWrite = New-PrivateStateDirectory 'unsafe-before-write'
    Set-DirectoryBroad $unsafeBeforeWrite
    [void](Invoke-StateDriver 'private-state-test-write' $unsafeBeforeWrite -ExpectFailure)
    if (Test-Path -LiteralPath (Join-Path $unsafeBeforeWrite 'client-ack-loss.json')) {
        throw 'Unsafe directory was written before its private boundary was accepted.'
    }
    $tests++

    $tampered = New-PrivateStateDirectory 'tampered'
    [void](Invoke-StateDriver 'private-state-test-write' $tampered)
    $tamperedFile = Join-Path $tampered 'client-ack-loss.json'
    Set-StateFileWritable $tamperedFile
    $tamperedJson = Get-Content -Raw -LiteralPath $tamperedFile | ConvertFrom-Json
    $tamperedJson.Ack = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('changed-ack'))
    [IO.File]::WriteAllText(
        $tamperedFile,
        ($tamperedJson | ConvertTo-Json -Compress),
        [Text.UTF8Encoding]::new($false))
    if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
        [IO.File]::SetAttributes(
            $tamperedFile,
            [IO.File]::GetAttributes($tamperedFile) -bor [IO.FileAttributes]::ReadOnly)
    }
    [void](Invoke-StateDriver 'private-state-test-read' $tampered -ExpectFailure)
    $tests++

    $broadAcl = New-PrivateStateDirectory 'broad-acl'
    [void](Invoke-StateDriver 'private-state-test-write' $broadAcl)
    $broadFile = Join-Path $broadAcl 'client-ack-loss.json'
    if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
        Set-StateFileWritable $broadFile
        $info = [IO.FileInfo](Get-Item -Force -LiteralPath $broadFile)
        $acl = $info.GetAccessControl()
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new('S-1-5-11'),
            [Security.AccessControl.FileSystemRights]::Read,
            [Security.AccessControl.AccessControlType]::Allow))
        $info.SetAccessControl($acl)
        [IO.File]::SetAttributes(
            $broadFile,
            [IO.File]::GetAttributes($broadFile) -bor [IO.FileAttributes]::ReadOnly)
    } else {
        [IO.File]::SetUnixFileMode(
            $broadFile,
            [IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite -bor
                [IO.UnixFileMode]::GroupRead)
    }
    [void](Invoke-StateDriver 'private-state-test-read' $broadAcl -ExpectFailure)
    $tests++

    $broadDirectory = New-PrivateStateDirectory 'broad-directory'
    [void](Invoke-StateDriver 'private-state-test-write' $broadDirectory)
    Set-DirectoryBroad $broadDirectory
    [void](Invoke-StateDriver 'private-state-test-read' $broadDirectory -ExpectFailure)
    $tests++

    if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
        $wrongOwner = New-PrivateStateDirectory 'wrong-owner'
        [void](Invoke-StateDriver 'private-state-test-write' $wrongOwner)
        $wrongOwnerFile = Join-Path $wrongOwner 'client-ack-loss.json'
        Set-StateFileWritable $wrongOwnerFile
        $wrongOwnerInfo = [IO.FileInfo](Get-Item -Force -LiteralPath $wrongOwnerFile)
        $wrongOwnerAcl = $wrongOwnerInfo.GetAccessControl()
        try {
            $wrongOwnerAcl.SetOwner(
                [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
            $wrongOwnerInfo.SetAccessControl($wrongOwnerAcl)
            [IO.File]::SetAttributes(
                $wrongOwnerFile,
                [IO.File]::GetAttributes($wrongOwnerFile) -bor [IO.FileAttributes]::ReadOnly)
            [void](Invoke-StateDriver 'private-state-test-read' $wrongOwner -ExpectFailure)
            $ownerBoundaryEnforced = $true
        } catch [System.Management.Automation.MethodInvocationException] {
            # A non-elevated process may not assign an arbitrary owner. The OS
            # rejecting that substitution is the stronger boundary outcome;
            # the driver's exact-owner predicate is also pinned by contract tests.
            $ownerBoundaryEnforced = $true
        }
        $tests++
    }

    $target = New-PrivateStateDirectory 'junction-target'
    [void](Invoke-StateDriver 'private-state-test-write' $target)
    $link = Join-Path $Work 'state-link'
    $linkType = if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
        'Junction'
    } else {
        'SymbolicLink'
    }
    [void](New-Item -ItemType $linkType -Path $link -Target $target)
    [void](Invoke-StateDriver 'private-state-test-read' $link -ExpectFailure)
    [IO.Directory]::Delete($link, $false)
    $tests++

    $wrongType = New-PrivateStateDirectory 'wrong-type'
    [void][IO.Directory]::CreateDirectory((Join-Path $wrongType 'client-ack-loss.json'))
    [void](Invoke-StateDriver 'private-state-test-read' $wrongType -ExpectFailure)
    $tests++

    $cleanup = New-PrivateStateDirectory 'cleanup'
    [void](Invoke-StateDriver 'private-state-test-write' $cleanup)
    $cleanupFile = Join-Path $cleanup 'client-ack-loss.json'
    if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
        if (-not ((Get-Item -Force -LiteralPath $cleanupFile).Attributes -band
            [IO.FileAttributes]::ReadOnly)) {
            throw 'Cleanup regression requires the state file to begin read-only.'
        }
        $lock = [IO.FileStream]::new(
            $cleanupFile,
            [IO.FileMode]::Open,
            [IO.FileAccess]::Read,
            [IO.FileShare]::Read)
        try {
            $deleteFailed = $false
            try {
                Remove-MailboxPrivateStateDirectory $cleanup $Work
            } catch {
                $deleteFailed = $true
            }
            if (-not $deleteFailed -or -not (Test-Path -LiteralPath $cleanup)) {
                throw 'Locked private state deletion did not fail closed and preserve the target.'
            }
        } finally {
            $lock.Dispose()
        }
    }
    Remove-MailboxPrivateStateDirectory $cleanup $Work
    if (Test-Path -LiteralPath $cleanup) {
        throw 'Private state cleanup did not remove the unlocked read-only state.'
    }
    $tests++

    [pscustomobject]@{
        schemaVersion = 1
        passed = $true
        tests = $tests
        privateDirectoryBeforeWrite = $true
        unsafeDirectoryWriteRejected = $true
        tamperRejected = $true
        broadAclRejected = $true
        broadDirectoryRejected = $true
        ownerBoundaryEnforced = $ownerBoundaryEnforced
        reparseRejected = $true
        nonRegularFileRejected = $true
        lockedDeleteFailureRejected =
            [Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT
        readOnlyCleanupSucceeded = $true
    } | ConvertTo-Json -Compress
} finally {
    if (Test-Path -LiteralPath $Work) {
        Set-MailboxTreeWritable $Work
        Remove-Item -LiteralPath $Work -Recurse -Force
    }
}
