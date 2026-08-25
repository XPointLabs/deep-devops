[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$root = Split-Path -Parent $PSScriptRoot
$runId = [Guid]::NewGuid().ToString('N')
$secretRoot = Join-Path $root ".secrets/production-ingress-lab/$runId"
$evidenceRoot = Join-Path $root "artifacts/test-results/production-ingress/$runId"
$project = "deep-ingress-$($runId.Substring(0, 12))"
$port = 28443
$compose = Join-Path $root 'docker-compose.node.prod.yml'
$override = Join-Path $root 'docker-compose.production-ingress.lab.yml'
$envFile = Join-Path $secretRoot 'lab.env'
$summary = $null

function Invoke-Docker([string[]]$Arguments) {
    $preference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { & docker @Arguments 2>$null | Out-Null; $exitCode = $LASTEXITCODE }
    finally { $ErrorActionPreference = $preference }
    if ($exitCode -ne 0) { throw 'Docker operation failed without exposing command arguments.' }
}

function Invoke-ExpectedFailure([scriptblock]$Action, [string]$FailureMessage) {
    $preference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { & $Action 2>$null | Out-Null; $exitCode = $LASTEXITCODE }
    finally { $ErrorActionPreference = $preference }
    if ($exitCode -eq 0) { throw $FailureMessage }
}

function Protect-Directory([string]$Path) {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { & chmod 700 -- $Path; return }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    & icacls $Path /inheritance:r /grant:r "${identity}:(OI)(CI)F" 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not protect the lab secret directory.' }
}

function Protect-Key([string]$Path) {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { & chmod 600 -- $Path; return }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    & icacls $Path /inheritance:r /grant:r "${identity}:F" 'SYSTEM:F' 'Administrators:F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not protect a lab private key.' }
}

New-Item -ItemType Directory -Force -Path $secretRoot, $evidenceRoot | Out-Null
Protect-Directory $secretRoot

try {
    $mount = $secretRoot.Replace('\', '/')
    Invoke-Docker -Arguments @('run', '--rm', '-v', "${mount}:/work", 'alpine/openssl:3.5.2', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '32', '-subj', '/CN=Deep ingress lab CA', '-keyout', '/work/ca.key', '-out', '/work/ca.crt')
    foreach ($name in @('current', 'next')) {
        Invoke-Docker -Arguments @('run', '--rm', '-v', "${mount}:/work", 'alpine/openssl:3.5.2', 'req', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=node.deep.test', '-addext', 'subjectAltName=DNS:node.deep.test', '-keyout', "/work/$name.key", '-out', "/work/$name.csr")
        Invoke-Docker -Arguments @('run', '--rm', '-v', "${mount}:/work", 'alpine/openssl:3.5.2', 'x509', '-req', '-in', "/work/$name.csr", '-CA', '/work/ca.crt', '-CAkey', '/work/ca.key', '-CAcreateserial', '-days', '30', '-copy_extensions', 'copyall', '-out', "/work/$name.crt")
        $pin = (& docker run --rm --entrypoint sh -v "${mount}:/work:ro" alpine/openssl:3.5.2 -c "openssl x509 -in /work/$name.crt -pubkey -noout | openssl pkey -pubin -outform DER | openssl dgst -sha256 | sed 's/^.*= //' ").Trim()
        if ($LASTEXITCODE -ne 0 -or $pin -notmatch '^[0-9a-f]{64}$') { throw 'Could not calculate a lab SPKI pin.' }
        [IO.File]::WriteAllText((Join-Path $secretRoot "$name.spki-sha256"), "$pin`n", [Text.UTF8Encoding]::new($false))
        Protect-Key (Join-Path $secretRoot "$name.key")
    }
    Invoke-Docker -Arguments @('run', '--rm', '-v', "${mount}:/work", 'alpine/openssl:3.5.2', 'req', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=node.deep.test', '-keyout', '/work/cn-only.key', '-out', '/work/cn-only.csr')
    Invoke-Docker -Arguments @('run', '--rm', '-v', "${mount}:/work", 'alpine/openssl:3.5.2', 'x509', '-req', '-in', '/work/cn-only.csr', '-CA', '/work/ca.crt', '-CAkey', '/work/ca.key', '-CAcreateserial', '-days', '30', '-out', '/work/cn-only.crt')
    Protect-Key (Join-Path $secretRoot 'cn-only.key')
    Invoke-Docker -Arguments @('run', '--rm', '-v', "${mount}:/work", 'alpine/openssl:3.5.2', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2', '-subj', '/CN=www.microsoft.com', '-addext', 'subjectAltName=DNS:www.microsoft.com', '-keyout', '/work/reality.key', '-out', '/work/reality.crt')
    Protect-Key (Join-Path $secretRoot 'reality.key')
    [IO.File]::WriteAllText((Join-Path $secretRoot 'node-ed25519'), 'lab-only', [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText((Join-Path $secretRoot 'node-x25519'), ('11' * 32), [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText((Join-Path $secretRoot 'node-bls'), 'lab-only', [Text.UTF8Encoding]::new($false))
    Protect-Key (Join-Path $secretRoot 'node-ed25519')
    Protect-Key (Join-Path $secretRoot 'node-x25519')
    Protect-Key (Join-Path $secretRoot 'node-bls')

    $helper = Join-Path $PSScriptRoot 'production-ingress-spki.mjs'
    $baseHelper = @($helper, '--profile', 'operator-managed', '--host', 'node.deep.test',
        '--current-cert', (Join-Path $secretRoot 'current.crt'), '--current-key', (Join-Path $secretRoot 'current.key'), '--current-pin', (Join-Path $secretRoot 'current.spki-sha256'),
        '--next-cert', (Join-Path $secretRoot 'next.crt'), '--next-key', (Join-Path $secretRoot 'next.key'), '--next-pin', (Join-Path $secretRoot 'next.spki-sha256'),
        '--client-timeout-seconds', '30', '--server-timeout-seconds', '30', '--quorum-cidr', '111.235.151.150/32', '--allow-lab-certificate')
    $currentPinPath = Join-Path $secretRoot 'current.spki-sha256'
    $currentPinValue = [IO.File]::ReadAllText($currentPinPath)
    [IO.File]::WriteAllText($currentPinPath, "$('0' * 64)`n", [Text.UTF8Encoding]::new($false))
    Invoke-ExpectedFailure { & node @baseHelper } 'Mismatched SPKI pin did not fail closed.'
    [IO.File]::WriteAllText($currentPinPath, $currentPinValue, [Text.UTF8Encoding]::new($false))
    $broadCidr = @($baseHelper); $broadCidr[$broadCidr.IndexOf('111.235.151.150/32')] = '0.0.0.0/0'
    Invoke-ExpectedFailure { & node @broadCidr } 'Broad quorum CIDR did not fail closed.'
    $zeroTimeout = @($baseHelper); $zeroTimeout[$zeroTimeout.IndexOf('30')] = '0'
    Invoke-ExpectedFailure { & node @zeroTimeout } 'Zero client timeout did not fail closed.'
    $cnOnly = @($baseHelper); $cnOnly[$cnOnly.IndexOf((Join-Path $secretRoot 'current.crt'))] = (Join-Path $secretRoot 'cn-only.crt'); $cnOnly[$cnOnly.IndexOf((Join-Path $secretRoot 'current.key'))] = (Join-Path $secretRoot 'cn-only.key')
    Invoke-ExpectedFailure { & node @cnOnly } 'A CN-only certificate without an exact SAN did not fail closed.'

    $preflight = & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'production-ingress-preflight.ps1') `
        -Profile operator-managed -HostName node.deep.test `
        -CurrentCertificate (Join-Path $secretRoot 'current.crt') -CurrentPrivateKey (Join-Path $secretRoot 'current.key') -CurrentPin $currentPinPath `
        -NextCertificate (Join-Path $secretRoot 'next.crt') -NextPrivateKey (Join-Path $secretRoot 'next.key') -NextPin (Join-Path $secretRoot 'next.spki-sha256') `
        -ClientTimeoutSeconds 30 -ServerTimeoutSeconds 30 -QuorumCoordinatorCidr '111.235.151.150/32' -AllowLabCertificate
    if ($LASTEXITCODE -ne 0) { throw 'Lab certificate preflight failed.' }

    $secretPath = $secretRoot.Replace('\','/')
    $envLines = @(
        'XNODE_IMAGE=node:24-alpine', 'DEEP_STORAGE_SERVICE_IMAGE=node:24-alpine', 'DEEP_NETWORK=lab',
        'DEEP_INGRESS_CERTIFICATE_PROFILE=operator-managed', 'DEEP_INGRESS_HOST=node.deep.test', "DEEP_INGRESS_HTTPS_BIND=127.0.0.1:$port",
        "DEEP_INGRESS_CURRENT_CERT_FILE=$secretPath/current.crt", "DEEP_INGRESS_CURRENT_KEY_FILE=$secretPath/current.key", "DEEP_INGRESS_CURRENT_SPKI_FILE=$secretPath/current.spki-sha256",
        "DEEP_INGRESS_NEXT_CERT_FILE=$secretPath/next.crt", "DEEP_INGRESS_NEXT_KEY_FILE=$secretPath/next.key", "DEEP_INGRESS_NEXT_SPKI_FILE=$secretPath/next.spki-sha256",
        "DEEP_INGRESS_LAB_SECRET_DIR=$secretPath", 'DEEP_NODE_PUBLIC_HOST=node.deep.test', 'DEEP_NODE_PUBLIC_IP=127.0.0.1',
        'DEEP_REGISTRY_URL=https://registry.deep.test', 'DEEP_STORAGE_RPC_URL=http://storage-service:8080',
        'DEEP_NODE_ED25519_PUBLIC_KEY=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', "DEEP_NODE_ED25519_PRIVATE_KEY_FILE=$secretPath/node-ed25519",
        "DEEP_NODE_X25519_PRIVATE_KEY_FILE=$secretPath/node-x25519",
        'DEEP_PRIVACY_PEER_1_ROUTER_ID=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', 'DEEP_PRIVACY_PEER_1_BASE_URL=https://peer-1.deep.test/', 'DEEP_PRIVACY_PEER_1_CURRENT_SPKI_SHA256=1111111111111111111111111111111111111111111111111111111111111111', 'DEEP_PRIVACY_PEER_1_NEXT_SPKI_SHA256=2222222222222222222222222222222222222222222222222222222222222222',
        'DEEP_PRIVACY_PEER_2_ROUTER_ID=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc', 'DEEP_PRIVACY_PEER_2_BASE_URL=https://peer-2.deep.test/', 'DEEP_PRIVACY_PEER_2_CURRENT_SPKI_SHA256=3333333333333333333333333333333333333333333333333333333333333333', 'DEEP_PRIVACY_PEER_2_NEXT_SPKI_SHA256=4444444444444444444444444444444444444444444444444444444444444444',
        'DEEP_PRIVACY_PEER_3_ROUTER_ID=dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd', 'DEEP_PRIVACY_PEER_3_BASE_URL=https://peer-3.deep.test/', 'DEEP_PRIVACY_PEER_3_CURRENT_SPKI_SHA256=5555555555555555555555555555555555555555555555555555555555555555', 'DEEP_PRIVACY_PEER_3_NEXT_SPKI_SHA256=6666666666666666666666666666666666666666666666666666666666666666',
        "DEEP_NODE_BLS_PRIVATE_KEY_FILE=$secretPath/node-bls", 'DEEP_NODE_VLESS_CLIENT_ID=00000000-0000-4000-8000-000000000001',
        'DEEP_NODE_REALITY_SERVER_NAME=www.microsoft.com', 'DEEP_NODE_REALITY_PUBLIC_KEY=lab-public', 'DEEP_NODE_REALITY_PRIVATE_KEY=lab-private', 'DEEP_NODE_REALITY_SHORT_ID=0123456789abcdef', 'DEEP_QUORUM_COORDINATOR_CIDR=111.235.151.150/32',
        'DEEP_OPERATOR_ADDRESS=0x0000000000000000000000000000000000000001', 'DEEP_REWARDS_ADDRESS=0x0000000000000000000000000000000000000001',
        'DEEP_SERVICE_NODE_REWARDS_ADDRESS=0x0000000000000000000000000000000000000001', 'DEEP_STAKING_BACKEND_URL=https://staking.deep.test'
    )
    [IO.File]::WriteAllLines($envFile, $envLines, [Text.UTF8Encoding]::new($false))
    Protect-Key $envFile

    $composeArgs = @('compose', '--project-name', $project, '--env-file', $envFile, '-f', $compose, '-f', $override)
    Invoke-Docker ($composeArgs + @('config', '--quiet'))
    Invoke-Docker ($composeArgs + @('up', '-d', '--wait', '--wait-timeout', '90'))

    $ca = Join-Path $secretRoot 'ca.crt'
    $allowed = & curl.exe -fsS --ssl-no-revoke --cacert $ca --resolve "node.deep.test:${port}:127.0.0.1" -H 'X-Forwarded-For: attacker' "https://node.deep.test:${port}/api/bootstrap/client"
    $allowedJson = $allowed | ConvertFrom-Json
    if (-not $allowedJson.ok -or $allowedJson.port -ne 8080 -or $allowedJson.forwardedForPresent -or $allowedJson.forwardedProto -ne 'https') { throw 'Allowed HTTPS route or forwarding-header sanitation failed.' }
    $statusCode = & curl.exe -sS -o NUL -w '%{http_code}' --ssl-no-revoke --cacert $ca --resolve "node.deep.test:${port}:127.0.0.1" "https://node.deep.test:${port}/status"
    if ($statusCode -ne '404') { throw 'A forbidden status endpoint became public.' }
    $quorumStatus = & curl.exe -sS -o NUL -w '%{http_code}' --ssl-no-revoke --cacert $ca --resolve "node.deep.test:${port}:127.0.0.1" -H 'content-type: application/json' -d '{}' "https://node.deep.test:${port}/api/staking/quorum/sign"
    if ($quorumStatus -ne '404') { throw 'Quorum signing was exposed outside its source CIDR.' }
    $reality = & curl.exe -fsSk --resolve "www.microsoft.com:${port}:127.0.0.1" "https://www.microsoft.com:${port}/"
    if (($reality | ConvertFrom-Json).port -ne 443) { throw 'Reality SNI passthrough did not reach the Xray lane.' }
    $tlsProbe = & node (Join-Path $PSScriptRoot 'production-ingress-tls-probe.mjs') --address 127.0.0.1 --port $port --host node.deep.test --ca $ca --expected-pin $currentPinPath | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0 -or $tlsProbe.status -ne 'ok') { throw 'Served SPKI did not match the protected current pin.' }
    $published = (& docker @composeArgs ps --format json | ConvertFrom-Json)
    $backendPublished = @($published | Where-Object { $_.Service -in @('xnode', 'storage-service') -and @($_.Publishers | Where-Object { $_.PublishedPort -gt 0 }).Count -gt 0 })
    if ($backendPublished.Count -ne 0) { throw 'A backend service has a host-published port.' }

    [IO.File]::WriteAllText($currentPinPath, "$('0' * 64)`n", [Text.UTF8Encoding]::new($false))
    Invoke-ExpectedFailure { & docker @composeArgs up -d --wait --wait-timeout 15 --force-recreate --no-deps ingress } 'Ingress accepted a stale preflight attestation.'
    [IO.File]::WriteAllText($currentPinPath, $currentPinValue, [Text.UTF8Encoding]::new($false))
    Invoke-Docker ($composeArgs + @('up', '--force-recreate', 'ingress-preflight'))
    Invoke-Docker ($composeArgs + @('up', '-d', '--wait', '--wait-timeout', '30', '--force-recreate', '--no-deps', 'ingress'))
    $tlsProbeAfterRefresh = & node (Join-Path $PSScriptRoot 'production-ingress-tls-probe.mjs') --address 127.0.0.1 --port $port --host node.deep.test --ca $ca --expected-pin $currentPinPath | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0 -or $tlsProbeAfterRefresh.status -ne 'ok') { throw 'Ingress did not recover after mandatory preflight refresh.' }

    $summary = [ordered]@{
        schema = 'deep-production-ingress-integration.v1'; profile = 'operator-managed-lab'
        httpsStatus = 200; deniedStatusPath = 404; deniedQuorumOutsideCidr = 404; forwardingHeadersStripped = $true; realitySniPassthrough = $true
        backendHostPorts = 0; spkiPreflight = (($preflight | Out-String | ConvertFrom-Json).status); servedSpkiMatchesProtectedCurrent = $true
        mismatchedSpkiRejected = $true; broadQuorumCidrRejected = $true; unsafeTimeoutRejected = $true; cnFallbackRejected = $true
        staleAttestationRejected = $true; refreshedAttestationAccepted = $true; secretsIncluded = $false
    }
}
finally {
    $cleanupFailure = $null
    if (Test-Path -LiteralPath $envFile) {
        $preference = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try { & docker compose --project-name $project --env-file $envFile -f $compose -f $override down --volumes --remove-orphans 2>$null | Out-Null; if ($LASTEXITCODE -ne 0) { $cleanupFailure = 'Compose cleanup failed.' } }
        finally { $ErrorActionPreference = $preference }
    }
    $leftovers = @(& docker ps -aq --filter "label=com.docker.compose.project=$project") + @(& docker network ls -q --filter "label=com.docker.compose.project=$project") + @(& docker volume ls -q --filter "label=com.docker.compose.project=$project")
    if (@($leftovers | Where-Object { $_ }).Count -ne 0) { $cleanupFailure = 'Docker project resources remain after cleanup.' }
    if ($cleanupFailure) { throw "$cleanupFailure Protected lab secrets were retained at $secretRoot." }
    if (Test-Path -LiteralPath $secretRoot) { Remove-Item -LiteralPath $secretRoot -Recurse -Force }
    if (Test-Path -LiteralPath $secretRoot) { throw 'Protected lab secret cleanup could not be verified.' }
}

if ($null -eq $summary) { throw 'Integration completed without a result.' }
$summary.status = 'ok'
$summary.cleanupVerified = $true
$summary.checkedAtUtc = [DateTimeOffset]::UtcNow.ToString('O')
$summary | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $evidenceRoot 'summary.json') -Encoding UTF8
$summary | ConvertTo-Json -Depth 4
