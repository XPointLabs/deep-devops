[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{64}$')][string]$AndroidHolderPublicKey,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{64}$')][string]$WindowsHolderPublicKey,
    [string]$AuthorityPublic = '',
    [string]$IssuerSeedPath = '',
    [string]$OutputDirectory = '',
    [string]$MailboxSecretDirectory = '',
    [string]$CoordinatorUrl = 'http://192.168.1.44:41801'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$root = [IO.Path]::GetFullPath((Split-Path $PSScriptRoot -Parent))
if ([string]::IsNullOrWhiteSpace($AuthorityPublic)) { $AuthorityPublic = Join-Path $root 'artifacts\survival-dev\mailbox-peer-authority.public.json' }
if ([string]::IsNullOrWhiteSpace($IssuerSeedPath)) { $IssuerSeedPath = Join-Path $root '.secrets\survival-dev\mailbox-client-issuer.seed' }
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) { $OutputDirectory = Join-Path $root 'artifacts\survival-dev\maui-mailbox-grants' }
if ([string]::IsNullOrWhiteSpace($MailboxSecretDirectory)) { $MailboxSecretDirectory = Join-Path $root '.secrets\survival-dev\maui-mailbox-grants' }

# This wrapper intentionally does not call Docker or export the issuer seed.
$xnodeSource = [Environment]::GetEnvironmentVariable('SURVIVAL_XNODE_PATH')
if ([string]::IsNullOrWhiteSpace($xnodeSource)) { $xnodeSource = Join-Path $root '..\xnode' }
$arguments = @(
    'run', '--project', (Join-Path $root 'tools\survival-mailbox-driver\SurvivalMailboxDriver.csproj'),
    "-p:XNodeSource=$([IO.Path]::GetFullPath($xnodeSource))", '--', 'provision',
    '--development-only', '--allow-http', '--physical-dev',
    '--android-holder-public-key', $AndroidHolderPublicKey,
    '--windows-holder-public-key', $WindowsHolderPublicKey,
    '--authority-public', ([IO.Path]::GetFullPath($AuthorityPublic)),
    '--issuer-seed-path', ([IO.Path]::GetFullPath($IssuerSeedPath)),
    '--output-directory', ([IO.Path]::GetFullPath($OutputDirectory)),
    '--mailbox-secret-directory', ([IO.Path]::GetFullPath($MailboxSecretDirectory)),
    '--coordinator-url', $CoordinatorUrl)
& dotnet @arguments
if ($LASTEXITCODE -ne 0) { throw 'DEV-LOCAL-ONLY MAUI mailbox grant provisioning failed.' }
