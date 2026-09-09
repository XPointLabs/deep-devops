[CmdletBinding()]
param(
    [ValidateSet('pinned-self-issued', 'deep-managed', 'operator-managed')]
    [string]$Profile = 'deep-managed',
    [Parameter(Mandatory = $true)]
    [string]$HostName,
    [Parameter(Mandatory = $true)]
    [string]$CurrentCertificate,
    [Parameter(Mandatory = $true)]
    [string]$CurrentPrivateKey,
    [Parameter(Mandatory = $true)]
    [string]$CurrentPin,
    [Parameter(Mandatory = $true)]
    [string]$NextCertificate,
    [Parameter(Mandatory = $true)]
    [string]$NextPrivateKey,
    [Parameter(Mandatory = $true)]
    [string]$NextPin,
    [ValidateRange(5, 120)]
    [uint32]$ClientTimeoutSeconds = 30,
    [ValidateRange(5, 120)]
    [uint32]$ServerTimeoutSeconds = 30,
    [Parameter(Mandatory = $true)]
    [string]$QuorumCoordinatorCidr,
    [string]$ExpectedPriorNextSpki,
    [switch]$AllowLabCertificate
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Resolve-ProtectedFile([string]$Path, [string]$Label) {
    $item = Get-Item -LiteralPath $Path -Force
    if (-not $item.PSIsContainer -and ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) {
        return $item.FullName
    }
    throw "$Label must be a regular, non-reparse file."
}

function Assert-PrivateKeyProtection([string]$Path) {
    if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
        $acl = Get-Acl -LiteralPath $Path
        if (-not $acl.AreAccessRulesProtected) {
            throw 'Ingress private-key ACL inheritance must be disabled.'
        }
        $currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        $allowedSids = @($currentSid, 'S-1-5-18', 'S-1-5-32-544')
        $ownerSid = $acl.Owner
        try {
            $ownerSid = ([Security.Principal.NTAccount]$acl.Owner).Translate(
                [Security.Principal.SecurityIdentifier]).Value
        }
        catch {
            if ($ownerSid -notmatch '^S-1-') { throw 'Ingress private-key owner SID is unavailable.' }
        }
        if ($ownerSid -notin $allowedSids) {
            throw 'Ingress private-key owner is not an approved exact SID.'
        }
        foreach ($rule in $acl.Access) {
            try {
                $sid = $rule.IdentityReference.Translate(
                    [Security.Principal.SecurityIdentifier]).Value
            }
            catch {
                throw 'Ingress private-key ACL contains an unresolvable identity.'
            }
            if ($sid -notin $allowedSids) {
                throw 'Ingress private-key ACL contains an unapproved exact SID.'
            }
        }
        if (@($acl.Access | Where-Object {
            $_.AccessControlType -eq 'Allow' -and
            $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -eq $currentSid
        }).Count -eq 0) {
            throw 'Ingress private-key ACL grants access outside the approved identities.'
        }
        return
    }

    $mode = (& stat -c '%a' -- $Path).Trim()
    if ($LASTEXITCODE -ne 0 -or $mode -notmatch '^[0-7]{3,4}$' -or [int]$mode.Substring($mode.Length - 2) -ne 0) {
        throw 'Ingress private key must not be accessible by group or other.'
    }
}

if ($HostName -cnotmatch '^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$') {
    throw 'Ingress host must be one exact DNS name.'
}

$currentCertificate = Resolve-ProtectedFile $CurrentCertificate 'current certificate'
$currentPrivateKey = Resolve-ProtectedFile $CurrentPrivateKey 'current private key'
$currentPin = Resolve-ProtectedFile $CurrentPin 'current pin'
$nextCertificate = Resolve-ProtectedFile $NextCertificate 'next certificate'
$nextPrivateKey = Resolve-ProtectedFile $NextPrivateKey 'next private key'
$nextPin = Resolve-ProtectedFile $NextPin 'next pin'
Assert-PrivateKeyProtection $currentPrivateKey
Assert-PrivateKeyProtection $nextPrivateKey

$node = Get-Command node -ErrorAction Stop
$helper = Join-Path $PSScriptRoot 'production-ingress-spki.mjs'
$arguments = @(
    $helper,
    '--profile', $Profile,
    '--host', $HostName,
    '--current-cert', $currentCertificate,
    '--current-key', $currentPrivateKey,
    '--current-pin', $currentPin,
    '--next-cert', $nextCertificate,
    '--next-key', $nextPrivateKey,
    '--next-pin', $nextPin,
    '--client-timeout-seconds', $ClientTimeoutSeconds,
    '--server-timeout-seconds', $ServerTimeoutSeconds,
    '--quorum-cidr', $QuorumCoordinatorCidr
)
if ($ExpectedPriorNextSpki) { $arguments += @('--expected-prior-next-spki', $ExpectedPriorNextSpki) }
if ($AllowLabCertificate) { $arguments += '--allow-lab-certificate' }
& $node.Source @arguments
if ($LASTEXITCODE -ne 0) { throw 'Production ingress certificate preflight failed.' }
