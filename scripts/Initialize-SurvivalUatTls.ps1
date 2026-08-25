[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)')]
    [string]$LanHost,
    [Parameter(Mandatory)]
    [string]$SecretRoot,
    [switch]$RotateLeaf
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$OpenSslImage = 'alpine/openssl@sha256:ef8657028239a006f3de0bd04529e22c073bf0ab6655ece9f25c8dde9adec146'
$root = [IO.Path]::GetFullPath($SecretRoot)
[IO.Directory]::CreateDirectory($root) | Out-Null
if ((Get-Item -LiteralPath $root).Attributes.HasFlag([IO.FileAttributes]::ReparsePoint)) {
    throw 'TLS secret root must not be a reparse point.'
}

if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $security = [Security.AccessControl.DirectorySecurity]::new()
    $security.SetAccessRuleProtection($true, $false)
    foreach ($sid in @(
        $identity.User,
        [Security.Principal.SecurityIdentifier]::new('S-1-5-18'),
        [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))) {
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            $sid,
            [Security.AccessControl.FileSystemRights]::FullControl,
            [Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit',
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow)
        $security.AddAccessRule($rule)
    }
    [IO.DirectoryInfo]::new($root).SetAccessControl($security)
}

function Invoke-OpenSsl([string[]]$Arguments) {
    & docker run --rm --network none --mount "type=bind,source=$root,target=/certs" $OpenSslImage @Arguments
    if ($LASTEXITCODE -ne 0) { throw "Pinned OpenSSL failed with exit code $LASTEXITCODE." }
}

$caKey = Join-Path $root 'ca.key'
$caCert = Join-Path $root 'ca.crt'
if ((Test-Path -LiteralPath $caKey) -xor (Test-Path -LiteralPath $caCert)) {
    throw 'Incomplete UAT CA state; restore both CA files or rotate the authority explicitly.'
}
if (-not (Test-Path -LiteralPath $caKey)) {
    Invoke-OpenSsl @('req','-x509','-newkey','rsa:3072','-sha256','-nodes','-days','1825',
        '-subj','/CN=Deep Physical UAT Root CA',
        '-addext','basicConstraints=critical,CA:TRUE,pathlen:0',
        '-addext','keyUsage=critical,keyCertSign,cRLSign',
        '-keyout','/certs/ca.key','-out','/certs/ca.crt')
}

$publicRoot = Join-Path $root 'public'
[IO.Directory]::CreateDirectory($publicRoot) | Out-Null
$caConfig = @"
[ ca ]
default_ca = deep_uat_ca
[ deep_uat_ca ]
dir = /certs
database = /certs/index.txt
new_certs_dir = /certs/newcerts
certificate = /certs/ca.crt
private_key = /certs/ca.key
serial = /certs/serial
crlnumber = /certs/crlnumber
default_md = sha256
default_crl_days = 7
policy = policy_any
[ policy_any ]
commonName = supplied
"@
[IO.Directory]::CreateDirectory((Join-Path $root 'newcerts')) | Out-Null
[IO.File]::WriteAllText((Join-Path $root 'openssl-ca.cnf'), $caConfig, [Text.UTF8Encoding]::new($false))
foreach ($state in @(@('index.txt',''), @('serial','1000'), @('crlnumber','1000'))) {
    $path = Join-Path $root $state[0]
    if (-not (Test-Path -LiteralPath $path)) {
        [IO.File]::WriteAllText($path, $state[1] + $(if ($state[1]) { [Environment]::NewLine } else { '' }),
            [Text.UTF8Encoding]::new($false))
    }
}

$leafFiles = @('server.key','server.csr','server.crt','server.pem','server.ext') |
    ForEach-Object { Join-Path $root $_ }
if ($RotateLeaf) {
    foreach ($path in $leafFiles) { Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue }
}
if (-not (Test-Path -LiteralPath (Join-Path $root 'server.pem'))) {
    $extensions = @"
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=IP:$LanHost
crlDistributionPoints=URI:http://${LanHost}:41824/deep-physical-uat-ca.crl
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
"@
    [IO.File]::WriteAllText((Join-Path $root 'server.ext'), $extensions, [Text.UTF8Encoding]::new($false))
    Invoke-OpenSsl @('req','-new','-newkey','rsa:3072','-sha256','-nodes',
        '-subj',"/CN=$LanHost",'-keyout','/certs/server.key','-out','/certs/server.csr')
    Invoke-OpenSsl @('x509','-req','-sha256','-days','60','-in','/certs/server.csr',
        '-CA','/certs/ca.crt','-CAkey','/certs/ca.key','-CAcreateserial',
        '-extfile','/certs/server.ext','-out','/certs/server.crt')
    $certificate = [IO.File]::ReadAllBytes((Join-Path $root 'server.crt'))
    $privateKey = [IO.File]::ReadAllBytes((Join-Path $root 'server.key'))
    try {
        [IO.File]::WriteAllBytes((Join-Path $root 'server.pem'), $certificate + $privateKey)
    } finally {
        [Array]::Clear($privateKey, 0, $privateKey.Length)
    }
}

$turnSecretPath = Join-Path $root 'turn-shared-secret'
if (-not (Test-Path -LiteralPath $turnSecretPath -PathType Leaf)) {
    $turnSecret = [byte[]]::new(48)
    $generator = [Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $generator.GetBytes($turnSecret)
        [IO.File]::WriteAllText(
            $turnSecretPath,
            [Convert]::ToBase64String($turnSecret) + [Environment]::NewLine,
            [Text.UTF8Encoding]::new($false))
    } finally {
        [Array]::Clear($turnSecret, 0, $turnSecret.Length)
        $generator.Dispose()
    }
}

Invoke-OpenSsl @('ca','-gencrl','-config','/certs/openssl-ca.cnf',
    '-out','/certs/public/deep-physical-uat-ca.crl')
Invoke-OpenSsl @('verify','-CAfile','/certs/ca.crt','-verify_ip',$LanHost,'/certs/server.crt')
Invoke-OpenSsl @('verify','-CAfile','/certs/ca.crt','-CRLfile',
    '/certs/public/deep-physical-uat-ca.crl','-crl_check','/certs/server.crt')
Invoke-OpenSsl @('x509','-in','/certs/ca.crt','-noout','-checkend','2592000')
Invoke-OpenSsl @('x509','-in','/certs/server.crt','-noout','-checkend','604800')

$ca = [Security.Cryptography.X509Certificates.X509Certificate2]::new($caCert)
try {
    $hasher = [Security.Cryptography.SHA256]::Create()
    try {
        $caHash = ([BitConverter]::ToString($hasher.ComputeHash($ca.RawData))).Replace('-', '').ToLowerInvariant()
    } finally { $hasher.Dispose() }
    [pscustomobject]@{
        schema = 'deep-survival-uat-tls.v1'
        lanHost = $LanHost
        caCertificate = $caCert
        caCertificateSha256 = $caHash
        leafCertificate = (Join-Path $root 'server.crt')
        crl = (Join-Path $publicRoot 'deep-physical-uat-ca.crl')
        leafRotatedIndependently = $true
        windowsTrustRequiresInteractiveApproval = $true
    }
} finally { $ca.Dispose() }
