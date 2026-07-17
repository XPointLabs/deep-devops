param(
    [string] $ArtifactDir = ""
)

$ErrorActionPreference = "Continue"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$DevopsDir = Resolve-Path (Join-Path $ScriptDir "..")

if ([string]::IsNullOrWhiteSpace($ArtifactDir)) {
    $ArtifactDir = Join-Path $DevopsDir "artifacts"
}

New-Item -ItemType Directory -Force $ArtifactDir | Out-Null

function Join-UrlPath {
    param(
        [string] $BaseUrl,
        [string] $Path
    )

    if ([string]::IsNullOrWhiteSpace($BaseUrl)) {
        return $null
    }

    return "{0}/{1}" -f $BaseUrl.TrimEnd('/'), $Path.TrimStart('/')
}

function Get-ExternalStatsUrl {
    param(
        [string] $ExplicitStatsUrl,
        [string] $ServiceUrl,
        [string] $FallbackUrl
    )

    if (-not [string]::IsNullOrWhiteSpace($ExplicitStatsUrl)) {
        return $ExplicitStatsUrl
    }

    if (-not [string]::IsNullOrWhiteSpace($ServiceUrl)) {
        return (Join-UrlPath -BaseUrl $ServiceUrl -Path "/stats")
    }

    return $FallbackUrl
}

function Get-Snapshot {
    param(
        [string] $Name,
        [string] $Url,
        [string] $Method = "GET",
        [object] $Body = $null
    )

    $result = [ordered]@{
        name = $Name
        method = $Method
        url = $Url
        capturedAtUtc = [DateTimeOffset]::UtcNow.ToString("o")
        ok = $false
    }

    try {
        if ($Method -eq "POST") {
            $jsonBody = $null
            if ($null -ne $Body) {
                $jsonBody = $Body | ConvertTo-Json -Compress -Depth 20
            }

            $response = Invoke-WebRequest -Uri $Url -Method Post -ContentType "application/json" -Body $jsonBody -TimeoutSec 8 -UseBasicParsing
        }
        else {
            $response = Invoke-WebRequest -Uri $Url -Method Get -TimeoutSec 8 -UseBasicParsing
        }

        $result.status = [int]$response.StatusCode
        $result.ok = $response.StatusCode -ge 200 -and $response.StatusCode -lt 300

        if ([string]::IsNullOrWhiteSpace($response.Content)) {
            $result.body = $null
        }
        else {
            try {
                $result.body = $response.Content | ConvertFrom-Json
            }
            catch {
                $result.body = $response.Content
            }
        }
    }
    catch {
        $result.error = $_.Exception.Message

        $statusCode = $null
        if ($_.Exception.Response -and $_.Exception.Response.StatusCode) {
            $statusCode = [int]$_.Exception.Response.StatusCode
        }

        if ($null -ne $statusCode) {
            $result.status = $statusCode
        }
    }

    return $result
}

function Protect-EvidenceValue {
    param(
        [object] $Value,
        [string] $PropertyName = ""
    )

    if ($PropertyName -match '(?i)(mnemonic|seed.?phrase|private.?key|private.?seed|private.?scalar|password|passwd|secret|authorization|bearer|token|api.?key)') {
        return "<redacted>"
    }

    if ($null -eq $Value) {
        return $null
    }

    if ($Value -is [string]) {
        $safe = [string]$Value
        $safe = $safe -replace '(?i)(https?://[^/\s:@]+):[^/\s@]{8,}@', '$1:<redacted>@'
        $safe = $safe -replace '(?i)([?&](?:access_token|token|api_key|key|secret|signature)=)[^&#\s"]+', '$1<redacted>'
        $safe = $safe -replace '(?i)\b(gh[pousr]_|github_pat_)[A-Za-z0-9_]{20,}\b', '<redacted>'
        $safe = $safe -replace '(?i)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----', '<redacted>'
        return $safe
    }

    if ($Value -is [System.Collections.IDictionary]) {
        $safeMap = [ordered]@{}
        foreach ($key in $Value.Keys) {
            $safeMap[[string]$key] = Protect-EvidenceValue -Value $Value[$key] -PropertyName ([string]$key)
        }
        return $safeMap
    }

    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
        return @($Value | ForEach-Object { Protect-EvidenceValue -Value $_ })
    }

    $properties = @($Value.PSObject.Properties | Where-Object { $_.MemberType -in @("NoteProperty", "Property") })
    if ($properties.Count -gt 0 -and $Value -isnot [ValueType]) {
        $safeObject = [ordered]@{}
        foreach ($property in $properties) {
            $safeObject[$property.Name] = Protect-EvidenceValue -Value $property.Value -PropertyName $property.Name
        }
        return $safeObject
    }

    return $Value
}

$backendMode = if ([string]::IsNullOrWhiteSpace($env:DEEP_BACKEND_MODE)) {
    "compat"
}
else {
    $env:DEEP_BACKEND_MODE
}

$storageStatsName = if ($backendMode -eq "external") { "storage-external-stats" } else { "storage-product-stats" }
$fileStatsName = if ($backendMode -eq "external") { "file-external-stats" } else { "file-product-stats" }
$pushStatsName = if ($backendMode -eq "external") { "push-external-stats" } else { "push-compat-stats" }
$callsStatsName = if ($backendMode -eq "external") { "calls-external-stats" } else { "calls-product-stats" }

$storageStatsUrl = if ($backendMode -eq "external") {
    Get-ExternalStatsUrl -ExplicitStatsUrl $env:DEEP_STORAGE_STATS_URL -ServiceUrl $env:DEEP_STORAGE_URL -FallbackUrl "http://127.0.0.1:18100/stats"
}
else {
    "http://127.0.0.1:18100/stats"
}

$fileStatsUrl = if ($backendMode -eq "external") {
    Get-ExternalStatsUrl -ExplicitStatsUrl $env:DEEP_FILE_STATS_URL -ServiceUrl $env:DEEP_FILE_URL -FallbackUrl "http://127.0.0.1:18101/stats"
}
else {
    "http://127.0.0.1:18101/stats"
}

$pushStatsUrl = if ($backendMode -eq "external") {
    Get-ExternalStatsUrl -ExplicitStatsUrl $env:DEEP_PUSH_STATS_URL -ServiceUrl $env:DEEP_PUSH_URL -FallbackUrl "http://127.0.0.1:18102/stats"
}
else {
    "http://127.0.0.1:18102/stats"
}

$callsStatsUrl = if ($backendMode -eq "external") {
    Get-ExternalStatsUrl -ExplicitStatsUrl $env:DEEP_CALL_STATS_URL -ServiceUrl $env:DEEP_CALL_SIGNALING_BASE_URL -FallbackUrl $null
}
else {
    "http://127.0.0.1:18103/stats"
}

$snapshots = @(
    (Get-Snapshot -Name "router-health-ready" -Url "http://127.0.0.1:18081/health/ready"),
    (Get-Snapshot -Name "registry-health-live" -Url "http://127.0.0.1:18080/health/live"),
    (Get-Snapshot -Name "registry-runtime" -Url "http://127.0.0.1:18080/api/nodes/runtime"),
    (Get-Snapshot -Name "staking-health-live" -Url "http://127.0.0.1:18082/health/live"),
    (Get-Snapshot -Name "staking-events-stats" -Url "http://127.0.0.1:18082/api/events/stats"),
    (Get-Snapshot -Name $storageStatsName -Url $storageStatsUrl),
    (Get-Snapshot -Name $fileStatsName -Url $fileStatsUrl),
    (Get-Snapshot -Name $pushStatsName -Url $pushStatsUrl),
    (Get-Snapshot -Name "contracts-devnet-chainid" -Url "http://127.0.0.1:18545" -Method "POST" -Body @{
        jsonrpc = "2.0"
        id = 1
        method = "eth_chainId"
        params = @()
    })
)

if (-not [string]::IsNullOrWhiteSpace($callsStatsUrl)) {
    $snapshots += (Get-Snapshot -Name $callsStatsName -Url $callsStatsUrl)
}

$payload = Protect-EvidenceValue -Value ([ordered]@{
    capturedAtUtc = [DateTimeOffset]::UtcNow.ToString("o")
    backendMode = $backendMode
    snapshots = $snapshots
})

$targetPath = Join-Path $ArtifactDir "runtime.snapshot.json"
$payload | ConvertTo-Json -Depth 30 | Out-File -Encoding utf8 $targetPath

$failedCount = @($snapshots | Where-Object { -not $_.ok }).Count
Write-Host "runtime snapshot saved to $targetPath (failed checks: $failedCount)"
