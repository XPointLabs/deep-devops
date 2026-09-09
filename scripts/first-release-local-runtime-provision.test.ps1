$ErrorActionPreference = 'Stop'
$provision = Join-Path $PSScriptRoot 'first-release-local-runtime-provision.ps1'
$source = Get-Content -Raw -LiteralPath $provision
[void][scriptblock]::Create($source)

foreach ($required in @(
    'RandomNumberGenerator]::Create()',
    '[Array]::Clear',
    'Sort-Object -Unique',
    'provisioning is partial',
    '[IO.File]::Replace($temporaryEnvironment, $environmentPath, $backupEnvironment, $true)')) {
    if ($source.IndexOf($required, [StringComparison]::Ordinal) -lt 0) {
        throw "Runtime provisioning contract is missing: $required"
    }
}
if ($source -match '(?i)survival|volume\s+rm|docker\s+(?:compose\s+)?down') {
    throw 'Runtime provisioning must not reference survival or Docker teardown.'
}

$fixture = Join-Path ([IO.Path]::GetTempPath()) (
    'deep-first-release-runtime-test-' + [guid]::NewGuid().ToString('N'))
try {
    [IO.Directory]::CreateDirectory($fixture) | Out-Null
    1..3 | ForEach-Object {
        [IO.Directory]::CreateDirectory((Join-Path $fixture "xnode-$_")) | Out-Null
    }
    $envFile = Join-Path $fixture 'first-release.env'
    $legacyLines = [Collections.Generic.List[string]]::new()
    $legacyLines.Add('FIRST_RELEASE_MASK_DOMAIN=example.test')
    for ($index = 1; $index -le 3; $index++) {
        $legacyLines.Add("FIRST_RELEASE_XNODE_${index}_VLESS_CLIENT_ID=00000000-0000-4000-8000-$($index.ToString().PadLeft(12, '0'))")
        $legacyLines.Add("FIRST_RELEASE_XNODE_${index}_REALITY_PRIVATE_KEY=$([char](65 + $index))$('A' * 42)")
    }
    [IO.File]::WriteAllLines($envFile, $legacyLines, [Text.UTF8Encoding]::new($false))
    $legacyLines.Clear()

    & $provision -SecretRoot $fixture -EnvFile $envFile | Out-Null
    & $provision -SecretRoot $fixture -EnvFile $envFile | Out-Null

    $hashes = 1..3 | ForEach-Object {
        $path = Join-Path $fixture "xnode-$_\xnode-$_-onion-state-protection.key"
        $bytes = [IO.File]::ReadAllBytes($path)
        try {
            if ($bytes.Length -ne 32) { throw 'Generated ONION key has the wrong length.' }
            $sha256 = [Security.Cryptography.SHA256]::Create()
            try { [Convert]::ToBase64String($sha256.ComputeHash($bytes)) }
            finally { $sha256.Dispose() }
        } finally {
            [Array]::Clear($bytes, 0, $bytes.Length)
        }
    }
    if (($hashes | Sort-Object -Unique).Count -ne 3) {
        throw 'Generated ONION keys are not distinct.'
    }
    $environment = [IO.File]::ReadAllText($envFile)
    for ($index = 1; $index -le 3; $index++) {
        if (([regex]::Matches(
                $environment,
                "(?m)^FIRST_RELEASE_XNODE_${index}_ONION_STATE_PROTECTION_FILE=")).Count -ne 1) {
            throw 'Provisioning must add each environment binding exactly once.'
        }
        foreach ($name in @(
                "FIRST_RELEASE_XNODE_${index}_VLESS_CLIENT_ID_FILE",
                "FIRST_RELEASE_XNODE_${index}_REALITY_PRIVATE_KEY_FILE")) {
            if (([regex]::Matches($environment, "(?m)^$name=")).Count -ne 1) {
                throw 'Provisioning must add each transport-secret file binding exactly once.'
            }
        }
        if ($environment -match "(?m)^FIRST_RELEASE_XNODE_${index}_(?:VLESS_CLIENT_ID|REALITY_PRIVATE_KEY)=") {
            throw 'Provisioning must remove legacy inline transport secrets.'
        }
        foreach ($name in @("xnode-$index-vless-client-id", "xnode-$index-reality.private")) {
            if (-not (Test-Path -LiteralPath (Join-Path $fixture "xnode-$index\$name") -PathType Leaf)) {
                throw 'Provisioning must create each protected transport-secret file.'
            }
        }
    }
    foreach ($relative in @(
        'registry-contact-resolve\private\trusted-time-integrity.key',
        'registry-contact-resolve\private\request-ledger-integrity.key',
        'registry-contact-resolve\private\artifact-state-integrity.key',
        'registry-contact-resolve\private\witness-1-ed25519.seed',
        'registry-contact-resolve\private\witness-2-ed25519.seed',
        'registry-contact-resolve\private\witness-3-ed25519.seed')) {
        $bytes = [IO.File]::ReadAllBytes((Join-Path $fixture $relative))
        try {
            if ($bytes.Length -ne 32) { throw 'Generated ContactResolve custody has the wrong length.' }
        } finally {
            [Array]::Clear($bytes, 0, $bytes.Length)
        }
    }
    foreach ($name in @(
        'FIRST_RELEASE_CONTACT_RESOLVE_NETWORK_ID',
        'FIRST_RELEASE_CONTACT_RESOLVE_ARTIFACT_ROOT',
        'FIRST_RELEASE_CONTACT_RESOLVE_OPERATOR_ROOT',
        'FIRST_RELEASE_CONTACT_RESOLVE_TRUSTED_TIME_KEY_FILE',
        'FIRST_RELEASE_CONTACT_RESOLVE_REQUEST_LEDGER_KEY_FILE',
        'FIRST_RELEASE_CONTACT_RESOLVE_ARTIFACT_STATE_KEY_FILE',
        'FIRST_RELEASE_CONTACT_RESOLVE_WITNESS_1_ID',
        'FIRST_RELEASE_CONTACT_RESOLVE_WITNESS_2_ID',
        'FIRST_RELEASE_CONTACT_RESOLVE_WITNESS_3_ID',
        'FIRST_RELEASE_CONTACT_RESOLVE_WITNESS_1_SEED_FILE',
        'FIRST_RELEASE_CONTACT_RESOLVE_WITNESS_2_SEED_FILE',
        'FIRST_RELEASE_CONTACT_RESOLVE_WITNESS_3_SEED_FILE')) {
        if (([regex]::Matches($environment, "(?m)^$name=")).Count -ne 1) {
            throw "Provisioning must add exactly one $name binding."
        }
    }
    if (-not (Test-Path -LiteralPath (
            Join-Path $fixture 'registry-contact-resolve\operator') -PathType Container)) {
        throw 'The protected ContactResolve operator exchange directory was not created.'
    }

    $mixedEnvironment = [IO.File]::ReadAllText($envFile)
    $mixedEnvironment = [regex]::Replace(
        $mixedEnvironment,
        '(?m)^FIRST_RELEASE_XNODE_1_VLESS_CLIENT_ID_FILE=[^\r\n]*\r?$',
        'FIRST_RELEASE_XNODE_1_VLESS_CLIENT_ID=00000000-0000-4000-8000-000000000001')
    $mixedEnvironment = [regex]::Replace(
        $mixedEnvironment,
        '(?m)^FIRST_RELEASE_XNODE_1_REALITY_PRIVATE_KEY_FILE=[^\r\n]*\r?$',
        "FIRST_RELEASE_XNODE_1_REALITY_PRIVATE_KEY=B$('A' * 42)")
    [IO.File]::WriteAllText($envFile, $mixedEnvironment, [Text.UTF8Encoding]::new($false))
    $mixedEnvironment = $null
    Remove-Item -LiteralPath (Join-Path $fixture 'xnode-1\xnode-1-vless-client-id') -Force
    Remove-Item -LiteralPath (Join-Path $fixture 'xnode-1\xnode-1-reality.private') -Force
    $mixedFailedClosed = $false
    try {
        & $provision -SecretRoot $fixture -EnvFile $envFile | Out-Null
    } catch {
        $mixedFailedClosed = $_.Exception.Message -match 'mixes legacy and file-backed state'
    }
    if (-not $mixedFailedClosed -or
        (Test-Path -LiteralPath (Join-Path $fixture 'xnode-1\xnode-1-vless-client-id')) -or
        (Test-Path -LiteralPath (Join-Path $fixture 'xnode-1\xnode-1-reality.private'))) {
        throw 'Mixed transport-secret state was not rejected before mutation.'
    }

    Remove-Item -LiteralPath (Join-Path $fixture 'xnode-2\xnode-2-onion-state-protection.key') -Force
    $failedClosed = $false
    try {
        & $provision -SecretRoot $fixture -EnvFile $envFile | Out-Null
    } catch {
        $failedClosed = $_.Exception.Message -match 'partial'
    }
    if (-not $failedClosed) {
        throw 'Partial ONION state-protection material was not rejected.'
    }
} finally {
    if (Test-Path -LiteralPath $fixture) {
        $resolvedFixture = [IO.Path]::GetFullPath($fixture)
        $temporaryRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
        if (-not $resolvedFixture.StartsWith($temporaryRoot, [StringComparison]::OrdinalIgnoreCase) -or
            -not ([IO.Path]::GetFileName($resolvedFixture)).StartsWith(
                'deep-first-release-runtime-test-', [StringComparison]::Ordinal)) {
            throw 'Refusing to remove an unexpected runtime-provisioning test path.'
        }
        Remove-Item -LiteralPath $fixture -Recurse -Force
    }
}

Write-Output 'First-release ONION and Registry authority custody provisioning checks passed.'
