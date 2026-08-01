$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'survival-dev-private-secrets.ps1')

function Assert-Failure([scriptblock]$Action) {
    try { & $Action } catch { return }
    throw 'Expected Survival DEV private-secret ACL validation failure.'
}

if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    Write-Output 'survival-dev private-secret ACL tests skipped: Windows-only negatives.'
    exit 0
}

$current = [Security.Principal.WindowsIdentity]::GetCurrent().User
$system = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
$administrators = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
function New-TestSecurity(
    [Security.Principal.SecurityIdentifier]$Owner,
    [bool]$Protected) {
    $security = [Security.AccessControl.FileSecurity]::new()
    $security.SetOwner($Owner)
    $security.SetAccessRuleProtection($Protected, $false)
    foreach ($identity in @($current, $system, $administrators)) {
        $security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            $identity,
            [Security.AccessControl.FileSystemRights]::FullControl,
            [Security.AccessControl.AccessControlType]::Allow))
    }
    return $security
}

Assert-SurvivalDevPrivateFileWindowsSecurity (New-TestSecurity $current $true) $current
Assert-Failure { Assert-SurvivalDevPrivateFileWindowsSecurity (New-TestSecurity $current $false) $current }

$deny = New-TestSecurity $current $true
$deny.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
    [Security.Principal.SecurityIdentifier]::new('S-1-1-0'),
    [Security.AccessControl.FileSystemRights]::ReadData,
    [Security.AccessControl.AccessControlType]::Deny))
Assert-Failure { Assert-SurvivalDevPrivateFileWindowsSecurity $deny $current }

Assert-Failure {
    Assert-SurvivalDevPrivateFileWindowsSecurity `
        (New-TestSecurity $administrators $true) `
        $current
}

$temporary = Join-Path ([IO.Path]::GetTempPath()) (
    'deep-survival-private-secret-' + [Guid]::NewGuid().ToString('N'))
try {
    [IO.File]::WriteAllText($temporary, ('a' * 64) + "`n")
    Assert-Failure { Assert-SurvivalDevPrivateFile $temporary }
    Protect-SurvivalDevPrivateFile $temporary
    Assert-SurvivalDevPrivateFile $temporary
} finally {
    [IO.File]::Delete($temporary)
}

Write-Output 'survival-dev private-secret ACL tests: PASS'
