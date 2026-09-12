[CmdletBinding()]
param(
    [string] $SecretRoot = 'C:\Work\DeepSession\secrets\prod'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root = [IO.Path]::GetFullPath($SecretRoot)
$nodes = @(
    [pscustomobject]@{ Name = 'seed1'; Role = 'Ingress'; HostName = 'seed1.xpoint.network'; Ip = '45.13.226.112' },
    [pscustomobject]@{ Name = 'seed2'; Role = 'Core'; HostName = 'seed2.xpoint.network'; Ip = '107.161.160.34' },
    [pscustomobject]@{ Name = 'seed3'; Role = 'Exit'; HostName = 'seed3.xpoint.network'; Ip = '185.206.171.178' }
)

function Read-Environment([string] $Path) {
    $result = [Collections.Generic.Dictionary[string,string]]::new([StringComparer]::Ordinal)
    foreach ($line in [IO.File]::ReadAllLines($Path)) {
        if ([string]::IsNullOrWhiteSpace($line) -or $line.TrimStart().StartsWith('#')) { continue }
        $separator = $line.IndexOf('=')
        if ($separator -lt 1) { throw 'A candidate environment entry is malformed.' }
        $name = $line.Substring(0, $separator)
        if (-not $result.TryAdd($name, $line.Substring($separator + 1).TrimEnd("`r"))) {
            throw 'A candidate environment contains a duplicate key.'
        }
    }
    return $result
}

function Require-Hex32([string] $Value, [string] $Name) {
    if ($Value -cnotmatch '^[0-9a-f]{64}$' -or $Value -match '^0{64}$') {
        throw "$Name is not canonical nonzero 32-byte hex."
    }
}

function Get-Pin([string] $Directory, [string] $Name) {
    $path = Join-Path $Directory "secrets\ingress\$Name.spki-sha256"
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw 'A candidate SPKI pin is missing.' }
    $value = [IO.File]::ReadAllText($path).TrimEnd("`r", "`n")
    Require-Hex32 $value 'SPKI pin'
    return $value
}

function Set-EnvironmentValues([string] $Path, [Collections.IDictionary] $Values) {
    $lines = [Collections.Generic.List[string]]::new()
    $remaining = [Collections.Generic.Dictionary[string,string]]::new([StringComparer]::Ordinal)
    foreach ($entry in $Values.GetEnumerator()) { $remaining.Add([string]$entry.Key, [string]$entry.Value) }
    foreach ($line in [IO.File]::ReadAllLines($Path)) {
        $separator = $line.IndexOf('=')
        if ($separator -gt 0) {
            $name = $line.Substring(0, $separator)
            $value = ''
            if ($remaining.TryGetValue($name, [ref]$value)) {
                $lines.Add("$name=$value")
                [void]$remaining.Remove($name)
                continue
            }
        }
        $lines.Add($line)
    }
    foreach ($entry in $remaining.GetEnumerator() | Sort-Object Key) {
        $lines.Add("$($entry.Key)=$($entry.Value)")
    }
    $temporary = "$Path.bind-$([guid]::NewGuid().ToString('N'))"
    $backup = "$Path.backup-$([guid]::NewGuid().ToString('N'))"
    try {
        [IO.File]::WriteAllLines($temporary, $lines, [Text.UTF8Encoding]::new($false))
        [IO.File]::Replace($temporary, $Path, $backup, $true)
        Remove-Item -LiteralPath $backup -Force
    } finally {
        if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Force }
        if (Test-Path -LiteralPath $backup) { Remove-Item -LiteralPath $backup -Force }
    }
}

$states = [ordered]@{}
foreach ($node in $nodes) {
    $directory = Join-Path $root "$($node.Name)\deployment-candidate"
    $environmentPath = Join-Path $directory '.env.node.prod'
    if (-not (Test-Path -LiteralPath $environmentPath -PathType Leaf)) {
        throw "Candidate environment is missing for $($node.Name)."
    }
    $environment = Read-Environment $environmentPath
    $routerId = $environment['DEEP_NODE_ED25519_PUBLIC_KEY']
    Require-Hex32 $routerId "$($node.Name) router ID"
    $currentPin = Get-Pin $directory 'current'
    $nextPin = Get-Pin $directory 'next'
    if ($currentPin -ceq $nextPin) { throw 'Current and next SPKI pins must differ.' }
    $states[$node.Name] = [pscustomobject]@{
        Definition = $node
        Directory = $directory
        EnvironmentPath = $environmentPath
        RouterId = $routerId
        CurrentPin = $currentPin
        NextPin = $nextPin
    }
}
if ((@($states.Values.RouterId | Sort-Object -Unique)).Count -ne 3) {
    throw 'Production seed router IDs must be distinct.'
}

foreach ($state in $states.Values) {
    $peers = @($states.Values | Where-Object {
        $_.Definition.Name -cne $state.Definition.Name
    } | Sort-Object { $_.Definition.Name })
    if ($peers.Count -ne 2) { throw 'Each seed must have exactly two peers.' }
    $values = [ordered]@{
        DEEP_NODE_ONION_RECEIVE_POSITION = $state.Definition.Role
        DEEP_NODE_PUBLIC_HOST = $state.Definition.HostName
        DEEP_NODE_PUBLIC_IP = $state.Definition.Ip
        DEEP_NODE_PUBLIC_PORT = '443'
        DEEP_INGRESS_CERTIFICATE_PROFILE = 'pinned-self-issued'
        DEEP_INGRESS_HOST = $state.Definition.HostName
        DEEP_INGRESS_HTTPS_BIND = '443'
        DEEP_QUORUM_COORDINATOR_CIDR = '111.235.151.150/32'
        DEEP_XPOINT_NETWORK_ID_HEX = 'edc5dc1516a847a65fc8ba0e690d000d'
        DEEP_XPOINT_GENESIS_PIN_HEX = '304911104767ae1036a44c71116a5fcdee3449fc71ea1467c09295f89be3a2b7'
        DEEP_XPOINT_DIRECTORY_LEAF_KEY_HEX = '3fd0371522bcfe473b36645f76a3817c722887fcbaa39ef75f4644a124d7b359'
    }
    for ($index = 0; $index -lt 2; $index++) {
        $ordinal = $index + 1
        $peer = $peers[$index]
        $values["DEEP_PRIVACY_PEER_${ordinal}_ROUTER_ID"] = $peer.RouterId
        $values["DEEP_PRIVACY_PEER_${ordinal}_BASE_URL"] = "https://$($peer.Definition.HostName)/"
        $values["DEEP_PRIVACY_PEER_${ordinal}_CURRENT_SPKI_SHA256"] = $peer.CurrentPin
        $values["DEEP_PRIVACY_PEER_${ordinal}_NEXT_SPKI_SHA256"] = $peer.NextPin
    }
    Set-EnvironmentValues $state.EnvironmentPath $values
}

$manifest = [ordered]@{
    schema = 'deep-production-seed-topology.v1'
    environment = 'prod'
    authorityOwner = 'Mr. X'
    nodes = @($states.Values | ForEach-Object {
        [ordered]@{
            name = $_.Definition.Name
            role = $_.Definition.Role
            host = $_.Definition.HostName
            publicIp = $_.Definition.Ip
            routerId = $_.RouterId
            currentSpkiSha256 = $_.CurrentPin
            nextSpkiSha256 = $_.NextPin
        }
    })
}
$manifestPath = Join-Path $root 'seed-topology.public.v1.json'
[IO.File]::WriteAllText($manifestPath, ($manifest | ConvertTo-Json -Depth 5) + "`n",
    [Text.UTF8Encoding]::new($false))
Write-Output 'Three production seed candidates are bound to distinct roles and exact dual-pinned peers.'
