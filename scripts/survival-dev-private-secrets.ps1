Set-StrictMode -Version Latest

function Assert-SurvivalDevPrivateFileWindowsSecurity(
    [Security.AccessControl.FileSecurity]$Security,
    [Security.Principal.SecurityIdentifier]$Current) {
    $owner = $Security.GetOwner([Security.Principal.SecurityIdentifier])
    if (-not $owner.Equals($Current) -or
        -not $Security.AreAccessRulesProtected -or
        -not $Security.AreAccessRulesCanonical) {
        throw 'Survival DEV private file owner/DACL is not exact and protected.'
    }
    $allowed = @($Current.Value, 'S-1-5-18', 'S-1-5-32-544') | Sort-Object
    $rules = @($Security.GetAccessRules(
        $true,
        $true,
        [Security.Principal.SecurityIdentifier]))
    if ($rules.Count -ne 3) {
        throw 'Survival DEV private file DACL must contain exactly three ACEs.'
    }
    $actual = @($rules | ForEach-Object {
        if ($_.IsInherited -or
            $_.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
            $_.InheritanceFlags -ne [Security.AccessControl.InheritanceFlags]::None -or
            $_.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None -or
            ($_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -ne
                [Security.AccessControl.FileSystemRights]::FullControl) {
            throw 'Survival DEV private file DACL contains an inherited, deny, or non-full-control ACE.'
        }
        ([Security.Principal.SecurityIdentifier]$_.IdentityReference).Value
    } | Sort-Object)
    if (($actual -join ',') -cne ($allowed -join ',')) {
        throw 'Survival DEV private file DACL contains a non-allowlisted identity.'
    }
}

function Assert-SurvivalDevPrivateFile([string]$Path) {
    $item = Get-Item -Force -LiteralPath $Path
    if ($item.PSIsContainer -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Survival DEV private input must be a regular file.'
    }
    if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
        $current = [Security.Principal.WindowsIdentity]::GetCurrent().User
        Assert-SurvivalDevPrivateFileWindowsSecurity `
            (Get-Acl -LiteralPath $Path) `
            $current
    } elseif ([IO.File]::GetUnixFileMode($Path) -ne
        ([IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite)) {
        throw 'Survival DEV private file must have Unix mode 0600.'
    }
}

function Protect-SurvivalDevPrivateFile([string]$Path) {
    $item = [IO.FileInfo](Get-Item -Force -LiteralPath $Path)
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Survival DEV private input cannot be a reparse point.'
    }
    if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
        $current = [Security.Principal.WindowsIdentity]::GetCurrent().User
        $owner = (Get-Acl -LiteralPath $Path).GetOwner(
                [Security.Principal.SecurityIdentifier])
        if (-not $owner.Equals($current)) {
            throw 'Survival DEV private file owner must already be the exact current Windows identity.'
        }
        $security = [Security.AccessControl.FileSecurity]::new()
        $security.SetAccessRuleProtection($true, $false)
        foreach ($identity in @(
            $current,
            [Security.Principal.SecurityIdentifier]::new('S-1-5-18'),
            [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))) {
            $security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
                $identity,
                [Security.AccessControl.FileSystemRights]::FullControl,
                [Security.AccessControl.AccessControlType]::Allow))
        }
        Set-Acl -LiteralPath $Path -AclObject $security
    } else {
        [IO.File]::SetUnixFileMode(
            $Path,
            [IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite)
    }
    Assert-SurvivalDevPrivateFile $Path
}
