[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $OutputDirectory,

    [Parameter(Mandatory = $true)]
    [string] $RegistrySourceIpv4
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not [IO.Path]::IsPathFullyQualified($OutputDirectory)) {
    throw 'The private pg_hba output directory must be absolute.'
}
if ($RegistrySourceIpv4 -cnotmatch '^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$') {
    throw 'The Registry source must be one canonical IPv4 address.'
}
$address = $null
if (-not [Net.IPAddress]::TryParse($RegistrySourceIpv4, [ref]$address) -or
    $address.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or
    $address.ToString() -cne $RegistrySourceIpv4 -or
    [Net.IPAddress]::IsLoopback($address) -or
    $address.Equals([Net.IPAddress]::Any) -or
    $address.GetAddressBytes()[0] -ge 224) {
    throw 'The Registry source is not a canonical unicast IPv4 address.'
}

$target = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $target) {
    throw 'The private pg_hba output directory already exists.'
}
$parent = [IO.Path]::GetDirectoryName($target)
if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
    throw 'Create and protect the private parent directory first.'
}
$permitted = @(
    [Security.Principal.WindowsIdentity]::GetCurrent().User.Value,
    'S-1-5-18', 'S-1-5-32-544')
foreach ($rule in (Get-Acl -LiteralPath $parent).Access) {
    if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
        $rule.IdentityReference.Translate(
            [Security.Principal.SecurityIdentifier]).Value -notin $permitted) {
        throw 'The pg_hba parent grants access beyond owner, SYSTEM and Administrators.'
    }
}

New-Item -ItemType Directory -Path $target -ErrorAction Stop | Out-Null
$acl = Get-Acl -LiteralPath $target
$acl.SetAccessRuleProtection($true, $false)
$inherit = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
    [Security.AccessControl.InheritanceFlags]::ObjectInherit
foreach ($sid in $permitted) {
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        [Security.Principal.SecurityIdentifier]::new($sid),
        [Security.AccessControl.FileSystemRights]::FullControl,
        $inherit, [Security.AccessControl.PropagationFlags]::None,
        [Security.AccessControl.AccessControlType]::Allow))
}
Set-Acl -LiteralPath $target -AclObject $acl

$content = @(
    '# Private DID2 latest-head floor: local admin, one TLS-only Registry source.',
    'local all postgres peer',
    'local all all reject',
    'hostnossl all all all reject',
    "hostssl deep_did2_floor did2_floor_runtime $RegistrySourceIpv4/32 scram-sha-256",
    "hostssl deep_did2_floor did2_floor_provision $RegistrySourceIpv4/32 scram-sha-256",
    'host all all all reject',
    '') -join "`n"
$path = Join-Path $target 'pg_hba.conf'
$bytes = [Text.UTF8Encoding]::new($false).GetBytes($content)
try {
    $stream = [IO.FileStream]::new($path, [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $stream.Write($bytes); $stream.Flush($true) }
    finally { $stream.Dispose() }
} finally { [Array]::Clear($bytes, 0, $bytes.Length) }
Write-Output 'Private DID2 floor pg_hba.conf created for one exact Registry source.'
