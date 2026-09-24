[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $OutputDirectory,

    [Parameter(Mandatory = $true)]
    [string] $FloorHostIpv4,

    [Parameter(Mandatory = $true)]
    [string] $RuntimePasswordFile,

    [Parameter(Mandatory = $true)]
    [string] $ProvisionPasswordFile,

    [ValidateRange(1, 65535)]
    [int] $Port = 5432
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not [IO.Path]::IsPathFullyQualified($OutputDirectory) -or
    -not [IO.Path]::IsPathFullyQualified($RuntimePasswordFile) -or
    -not [IO.Path]::IsPathFullyQualified($ProvisionPasswordFile)) {
    throw 'The private floor output and credential paths must be absolute.'
}
$address = $null
if ($FloorHostIpv4 -cnotmatch '^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$' -or
    -not [Net.IPAddress]::TryParse($FloorHostIpv4, [ref]$address) -or
    $address.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or
    $address.ToString() -cne $FloorHostIpv4 -or
    [Net.IPAddress]::IsLoopback($address) -or
    $address.Equals([Net.IPAddress]::Any) -or
    $address.GetAddressBytes()[0] -ge 224) {
    throw 'The floor host must be one canonical unicast IPv4 address.'
}

$target = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $target) {
    throw 'The private passfile directory already exists.'
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
        throw 'The passfile parent grants access beyond owner, SYSTEM and Administrators.'
    }
}
$runtime = (Get-Content -LiteralPath $RuntimePasswordFile -Raw).Trim()
$provision = (Get-Content -LiteralPath $ProvisionPasswordFile -Raw).Trim()
if ($runtime -cnotmatch '^[0-9a-f]{64}$' -or
    $provision -cnotmatch '^[0-9a-f]{64}$' -or
    $runtime -ceq $provision) {
    throw 'The floor role credentials must be distinct 256-bit hex values.'
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
$encoding = [Text.UTF8Encoding]::new($false)
try {
    [IO.File]::WriteAllText((Join-Path $target 'runtime.pgpass'),
        "${FloorHostIpv4}:${Port}:deep_did2_floor:did2_floor_runtime:${runtime}`n",
        $encoding)
    [IO.File]::WriteAllText((Join-Path $target 'provision.pgpass'),
        "${FloorHostIpv4}:${Port}:deep_did2_floor:did2_floor_provision:${provision}`n",
        $encoding)
} finally {
    $runtime = $null
    $provision = $null
}
Write-Output 'Separate private DID2 floor role passfiles authored.'
