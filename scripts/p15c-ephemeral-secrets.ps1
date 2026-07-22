[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('Generate','Remove')][string]$Action,
    [Parameter(Mandatory)][string]$RunDirectory
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Resolve-ExactPath([string]$Path, [switch]$AllowMissing) {
    $full = [System.IO.Path]::GetFullPath($Path)
    if (-not $AllowMissing -and -not (Test-Path -LiteralPath $full)) { throw 'P15C secret directory is missing.' }
    return $full.TrimEnd([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)
}

function Protect-Path([string]$Path, [switch]$Directory) {
    $currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    if (-not $Directory) { $acl = New-Object System.Security.AccessControl.FileSecurity }
    $acl.SetAccessRuleProtection($true, $false)
    $inheritance = if ($Directory) { [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit' } else { [System.Security.AccessControl.InheritanceFlags]::None }
    $propagation = [System.Security.AccessControl.PropagationFlags]::None
    foreach ($sidValue in @($currentSid, 'S-1-5-18')) {
        $sid = New-Object System.Security.Principal.SecurityIdentifier($sidValue)
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($sid, [System.Security.AccessControl.FileSystemRights]::FullControl, $inheritance, $propagation, [System.Security.AccessControl.AccessControlType]::Allow)
        [void]$acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}

$resolved = Resolve-ExactPath $RunDirectory -AllowMissing
$marker = Join-Path $resolved '.p15c-secret-owner'

if ($Action -eq 'Generate') {
    if (Test-Path -LiteralPath $resolved) { throw 'P15C secret directory already exists.' }
    [void](New-Item -ItemType Directory -Path $resolved)
    try {
        Protect-Path $resolved -Directory
        [System.IO.File]::WriteAllText($marker, 'deep-p15c-ephemeral-secrets.v1', [System.Text.UTF8Encoding]::new($false))
        Protect-Path $marker
        foreach ($index in 1..3) {
            $bytes = [byte[]]::new(32)
            $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
            try {
                $rng.GetBytes($bytes)
                $seedPath = Join-Path $resolved "node-$index.seed"
                $seedHex = ([System.BitConverter]::ToString($bytes) -replace '-', '').ToLowerInvariant()
                [System.IO.File]::WriteAllText($seedPath, $seedHex, [System.Text.UTF8Encoding]::new($false))
                Protect-Path $seedPath
                $deriveScript = "const fs=require('fs'),c=require('crypto');const s=Buffer.from(fs.readFileSync(process.argv[1],'utf8').trim(),'hex');const k=c.createPrivateKey({key:Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'),s]),format:'der',type:'pkcs8'});process.stdout.write(c.createPublicKey(k).export({format:'der',type:'spki'}).subarray(-32).toString('hex'))"
                $routerId = (& node -e $deriveScript $seedPath).Trim()
                if ($LASTEXITCODE -ne 0 -or $routerId -notmatch '^[0-9a-f]{64}$') { throw 'Failed to derive an ephemeral node public identity.' }
                $configPath = Join-Path $resolved "node-$index.config.json"
                $config = [ordered]@{ Node = [ordered]@{ RouterId = $routerId } } | ConvertTo-Json -Depth 4 -Compress
                [System.IO.File]::WriteAllText($configPath, $config, [System.Text.UTF8Encoding]::new($false))
                Protect-Path $configPath
            }
            finally {
                $seedHex = $null
                $rng.Dispose()
                [Array]::Clear($bytes, 0, $bytes.Length)
            }
        }
    }
    catch {
        if (Test-Path -LiteralPath $resolved -PathType Container) { [System.IO.Directory]::Delete($resolved, $true) }
        throw
    }
    return
}

if (-not (Test-Path -LiteralPath $marker -PathType Leaf)) { throw 'P15C ownership marker is missing; refusing recursive removal.' }
$markerValue = [System.IO.File]::ReadAllText($marker)
if ($markerValue -ne 'deep-p15c-ephemeral-secrets.v1') { throw 'P15C ownership marker is invalid; refusing recursive removal.' }
$children = @(Get-ChildItem -LiteralPath $resolved -Force)
if ($children.Count -ne 7 -or @($children | Where-Object { $_.Name -notmatch '^(?:\.p15c-secret-owner|node-[123]\.(?:seed|config\.json))$' }).Count -ne 0) { throw 'P15C secret directory contains unowned files; refusing removal.' }
Remove-Item -LiteralPath $resolved -Recurse -Force
