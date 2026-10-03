[CmdletBinding()]
param(
    [string]$RegistryRoot = (Join-Path $PSScriptRoot '../../deep-registry-api'),
    [ValidatePattern('^[a-z0-9][a-z0-9-]{0,47}$')]
    [string]$Lane = 'registry-postgres',
    [string]$Filter = ''
)

# Local provider-integration lane, not TLS/UAT/physical release evidence.
# Uses the same approved PostgreSQL image as docker-compose.deep-dev.yml.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
function Test-LocalDockerEndpoint([string]$Endpoint) {
    # A UNC named pipe on another Windows host is not a local engine.
    return $Endpoint -match '^unix:///[^/]' -or $Endpoint -match '^npipe:/{2,4}\./pipe/[^/]'
}
$registryPath = (Resolve-Path -LiteralPath $RegistryRoot).Path
if (!(Test-Path -LiteralPath (Join-Path $registryPath 'Deep.Registry.Api.slnx'))) {
    throw 'RegistryRoot must identify the Registry checkout.'
}
$dockerEndpoint = & docker context inspect --format '{{.Endpoints.docker.Host}}'
if ($LASTEXITCODE -ne 0 -or !(Test-LocalDockerEndpoint $dockerEndpoint)) {
    throw 'This disposable lane requires a local Docker engine; remote contexts are rejected.'
}
if ($env:DOCKER_HOST -and !(Test-LocalDockerEndpoint $env:DOCKER_HOST)) {
    throw 'This disposable lane rejects a remote DOCKER_HOST override.'
}
$invocation = [Guid]::NewGuid().ToString('N')
$containerName = 'deep-s00-registry-' + $invocation
$image = 'postgres@sha256:dc17045ccfd343b49600570ea734b9c4991cf1c3f3302e67df51e3b402dd55c4'
$resultsPath = Join-Path $registryPath ('artifacts/s00/' + $Lane + '-' + $invocation)
$containerId = $null
$testExitCode = 1
$savedEnvironment = @{}
try {
    # Prevent ambient external/prod inputs from activating opt-in tests or DBs.
    foreach ($entry in Get-ChildItem Env: | Where-Object {
        $_.Name -like 'DEEP_TEST_*' -or $_.Name -match '(ConnectionString|POSTGRES)'
    }) {
        $savedEnvironment[$entry.Name] = $entry.Value
        [Environment]::SetEnvironmentVariable($entry.Name, $null, 'Process')
    }
    $runArguments = @('run', '--detach', '--rm', '--name', $containerName,
        '--label', ('deep.test.invocation=' + $invocation),
        '--label', 'deep.test.owner=s00-registry',
        '--tmpfs', '/var/lib/postgresql/data:rw',
        '--publish', '127.0.0.1::5432',
        '--env', 'POSTGRES_HOST_AUTH_METHOD=trust',
        '--env', 'POSTGRES_DB=deep_s00', '--env', 'POSTGRES_USER=deep_s00',
        '--health-cmd', 'pg_isready -U deep_s00 -d deep_s00',
        '--health-interval', '1s', '--health-timeout', '3s', '--health-retries', '20', $image)
    $containerId = (& docker @runArguments | Select-Object -Last 1)
    if ($LASTEXITCODE -ne 0 -or $containerId -notmatch '^[a-f0-9]{64}$') {
        throw 'Could not start the disposable PostgreSQL container.'
    }
    $deadline = [DateTime]::UtcNow.AddSeconds(60)
    do {
        $health = & docker inspect --format '{{.State.Health.Status}}' $containerId
        if ($LASTEXITCODE -ne 0) { throw 'Disposable PostgreSQL container disappeared.' }
        if ($health -eq 'healthy') { break }
        if ($health -eq 'unhealthy') { throw 'Disposable PostgreSQL failed readiness.' }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    if ($health -ne 'healthy') { throw 'Disposable PostgreSQL readiness timed out.' }
    $port = & docker inspect --format '{{(index (index .NetworkSettings.Ports "5432/tcp") 0).HostPort}}' $containerId
    if ($LASTEXITCODE -ne 0 -or $port -notmatch '^\d{1,5}$') { throw 'Invalid loopback test port.' }
    $connection = "Host=127.0.0.1;Port=$port;Database=deep_s00;Username=deep_s00;Pooling=false;Timeout=5"
    foreach ($name in @('DEEP_TEST_DID2_FLOOR_POSTGRES', 'DEEP_TEST_DID2_ROUTE_POSTGRES', 'DEEP_TEST_DID2_GRANT_POSTGRES')) {
        if (!$savedEnvironment.ContainsKey($name)) { $savedEnvironment[$name] = $null }
        [Environment]::SetEnvironmentVariable($name, $connection, 'Process')
    }
    Write-Host "Disposable PostgreSQL ready; invocation=$invocation; external test origins disabled."
    Write-Host 'DB uses loopback-only trust for ephemeral synthetic data; this is not production TLS evidence.'
    $testArguments = @('test', (Join-Path $registryPath 'Deep.Registry.Api.slnx'),
        '-c', 'Release', '-p:DeepProtocolLocalCutover=true', '-p:DeepProtocolSourceCutover=true',
        '--logger', 'trx', '--results-directory', $resultsPath, '--verbosity', 'quiet')
    if ($Filter) { $testArguments += @('--filter', $Filter) }
    & dotnet @testArguments
    $testExitCode = $LASTEXITCODE
}
finally {
    foreach ($name in $savedEnvironment.Keys) {
        [Environment]::SetEnvironmentVariable($name, $savedEnvironment[$name], 'Process')
    }
    if ($containerId -match '^[a-f0-9]{64}$') {
        $owner = & docker inspect --format '{{index .Config.Labels "deep.test.invocation"}}' $containerId
        if ($LASTEXITCODE -ne 0 -or $owner -ne $invocation) {
            throw 'Cleanup refused: disposable container ownership could not be verified.'
        }
        & docker stop --time 10 $containerId | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Disposable PostgreSQL cleanup failed.' }
        Write-Host 'Disposable test container and tmpfs DB removed; rerun recreates them. No named volume was used.'
    }
}
exit $testExitCode
