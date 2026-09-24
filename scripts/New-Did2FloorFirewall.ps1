[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $OutputDirectory,

    [Parameter(Mandatory = $true)]
    [string] $FloorHostIpv4,

    [Parameter(Mandatory = $true)]
    [string] $RegistrySourceIpv4,

    [ValidateRange(1, 65535)]
    [int] $Port = 5432
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-UnicastIpv4([string] $Value) {
    $address = $null
    if ($Value -cnotmatch '^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$' -or
        -not [Net.IPAddress]::TryParse($Value, [ref]$address) -or
        $address.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or
        $address.ToString() -cne $Value -or
        [Net.IPAddress]::IsLoopback($address) -or
        $address.Equals([Net.IPAddress]::Any) -or
        $address.GetAddressBytes()[0] -ge 224) {
        throw 'The firewall requires canonical unicast IPv4 addresses.'
    }
}

if (-not [IO.Path]::IsPathFullyQualified($OutputDirectory)) {
    throw 'The private firewall output directory must be absolute.'
}
Assert-UnicastIpv4 $FloorHostIpv4
Assert-UnicastIpv4 $RegistrySourceIpv4
if ($FloorHostIpv4 -ceq $RegistrySourceIpv4) {
    throw 'The floor host and Registry source must be distinct.'
}

$target = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $target) {
    throw 'The private firewall output directory already exists.'
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
        throw 'The firewall parent grants access beyond owner, SYSTEM and Administrators.'
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

$rules = @(
    'table inet did2_floor_guard {',
    '    chain prerouting {',
    '        type filter hook prerouting priority -300; policy accept;',
    "        ip daddr $FloorHostIpv4 tcp dport $Port ip saddr != $RegistrySourceIpv4 drop",
    '    }',
    '}',
    '') -join "`n"
$service = @(
    '[Unit]',
    'Description=Private DID2 floor pre-Docker ingress guard',
    'Before=docker.service',
    '',
    '[Service]',
    'Type=oneshot',
    'RemainAfterExit=yes',
    'ExecStart=/usr/sbin/nft -f /etc/deep-did2-floor/guard.nft',
    '',
    '[Install]',
    'WantedBy=docker.service',
    '') -join "`n"
$dockerDependency = @(
    '[Unit]',
    'Requires=did2-floor-guard.service',
    'After=did2-floor-guard.service',
    '') -join "`n"
$encoding = [Text.UTF8Encoding]::new($false)
[IO.File]::WriteAllText((Join-Path $target 'guard.nft'), $rules, $encoding)
[IO.File]::WriteAllText((Join-Path $target 'did2-floor-guard.service'),
    $service, $encoding)
[IO.File]::WriteAllText((Join-Path $target 'docker-guard-requires.conf'),
    $dockerDependency, $encoding)
Write-Output 'Private DID2 floor firewall and fail-closed Docker dependency authored.'
