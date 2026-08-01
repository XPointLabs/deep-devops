$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    Write-Output 'survival-dev negative mailbox runtime integration skipped: Windows-only ACL contract.'
    exit 0
}

$generator = Join-Path $PSScriptRoot 'survival-dev-mailbox-negative-runtime.ps1'
$runsRoot = 'C:\Work\DeepSession\secrets\mailbox-bootstrap\e2e-runs'
$runRoot = Join-Path $runsRoot ([Guid]::NewGuid().ToString('N'))

function Set-RunRootAcl([string]$Path) {
    $current = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $security = [Security.AccessControl.DirectorySecurity]::new()
    $security.SetOwner($current)
    $security.SetAccessRuleProtection($true, $false)
    foreach ($sid in @($current,
        [Security.Principal.SecurityIdentifier]'S-1-5-18',
        [Security.Principal.SecurityIdentifier]'S-1-5-32-544')) {
        $security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            $sid, [Security.AccessControl.FileSystemRights]::FullControl,
            [Security.AccessControl.InheritanceFlags]::None,
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow))
    }
    Set-Acl -LiteralPath $Path -AclObject $security
}

[IO.Directory]::CreateDirectory($runRoot) | Out-Null
Set-RunRootAcl $runRoot
try {
    & powershell -NoProfile -ExecutionPolicy Bypass -File $generator `
        -Action Generate -RunRoot $runRoot
    if ($LASTEXITCODE -ne 0) { throw 'Negative runtime fixture generation failed.' }
    $manifestPath = Join-Path $runRoot 'negative-runtime-fixtures.json'
    $manifest = Get-Content -Raw -LiteralPath $manifestPath | ConvertFrom-Json
    if ([string]$manifest.schema -cne 'deep.dev-negative-mailbox-runtime.v1' -or
        [string]$manifest.status -cne 'prepared' -or
        @($manifest.cases).Count -ne 3 -or
        @($manifest.cases | Where-Object {
            [string]$_.case -notin @('tampered-signature', 'missing-authority',
                'android-runtime-on-windows') -or
            [string]$_.status -cne 'prepared' -or
            [string]$_.fixtureTreeSha256 -cnotmatch '^[a-f0-9]{64}$'
        }).Count -ne 0) {
        throw 'Negative runtime fixture manifest is not the exact sanitized schema.'
    }
    $manifestText = Get-Content -Raw -LiteralPath $manifestPath
    foreach ($forbidden in @('sessionId', 'holder', 'credential', 'capability',
        'privateKey', 'seed', 'payload', 'message')) {
        if ($manifestText.IndexOf($forbidden, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
            throw 'Negative runtime fixture manifest contains forbidden material.'
        }
    }
    & powershell -NoProfile -ExecutionPolicy Bypass -File $generator `
        -Action Cleanup -RunRoot $runRoot
    if ($LASTEXITCODE -ne 0 -or
        (Test-Path -LiteralPath (Join-Path $runRoot 'negative-runtime'))) {
        throw 'Negative runtime fixture cleanup failed.'
    }
    Write-Output 'survival-dev negative mailbox runtime integration: PASS (3 cases)'
} finally {
    if (Test-Path -LiteralPath $runRoot) {
        Remove-Item -LiteralPath $runRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}
