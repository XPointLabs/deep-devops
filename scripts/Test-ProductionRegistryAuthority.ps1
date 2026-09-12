[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^https://')][string] $RegistryOrigin,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{32}$')][string] $NetworkIdHex
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Write-U64BigEndian([byte[]] $Buffer, [int] $Offset, [UInt64] $Value) {
    for ($index = 7; $index -ge 0; $index--) {
        $Buffer[$Offset + $index] = [byte]($Value -band 0xff)
        $Value = $Value -shr 8
    }
}

function Test-EqualRange([byte[]] $Left, [int] $Offset, [byte[]] $Right) {
    if ($Offset -lt 0 -or $Offset -gt $Left.Length - $Right.Length) { return $false }
    $different = 0
    for ($index = 0; $index -lt $Right.Length; $index++) {
        $different = $different -bor ($Left[$Offset + $index] -bxor $Right[$index])
    }
    return $different -eq 0
}

$network = [Convert]::FromHexString($NetworkIdHex)
if ($network.Length -ne 16 -or @($network | Where-Object { $_ -ne 0 }).Count -eq 0) {
    throw 'NetworkIdHex must be one nonzero canonical 16-byte value.'
}
$request = [byte[]]::new(84)
[Text.Encoding]::ASCII.GetBytes('CDQ1').CopyTo($request, 0)
$request[5] = 1
$request[11] = 84
$network.CopyTo($request, 12)
$nonce = [Security.Cryptography.RandomNumberGenerator]::GetBytes(32)
$boot = [Security.Cryptography.RandomNumberGenerator]::GetBytes(16)
$nonce.CopyTo($request, 28)
$boot.CopyTo($request, 60)
$monotonic = [UInt64][Math]::Max(1, [Environment]::TickCount64 / 1000)
Write-U64BigEndian $request 76 $monotonic

$client = [Net.Http.HttpClient]::new()
$client.Timeout = [TimeSpan]::FromSeconds(45)
try {
    $content = [Net.Http.ByteArrayContent]::new($request)
    $content.Headers.ContentType = [Net.Http.Headers.MediaTypeHeaderValue]::Parse(
        'application/vnd.deep.contact-resolve-directory-request.v1')
    try {
        $uri = [Uri]::new(([Uri]::new($RegistryOrigin.TrimEnd('/') + '/')),
            'api/v1/directory/contact-resolve-packages')
        $response = $client.PostAsync($uri, $content).GetAwaiter().GetResult()
        try {
            $body = $response.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult()
            if (-not $response.IsSuccessStatusCode) {
                throw "Registry authority returned HTTP $([int]$response.StatusCode)."
            }
            if ([string]$response.Content.Headers.ContentType.MediaType -cne
                'application/vnd.deep.contact-resolve-directory.v1') {
                throw 'Registry authority returned an unexpected media type.'
            }
            if ($body.Length -lt 84 -or $body.Length -gt 71565312 -or
                [Text.Encoding]::ASCII.GetString($body, 0, 4) -cne 'CDR1' -or
                $body[4] -ne 0 -or $body[5] -ne 1) {
                throw 'Registry authority returned a malformed CDR1 envelope.'
            }
            $declared = ([uint32]$body[8] -shl 24) -bor ([uint32]$body[9] -shl 16) -bor
                ([uint32]$body[10] -shl 8) -bor [uint32]$body[11]
            $monotonicBytes = [byte[]]$request[76..83]
            if ($declared -ne $body.Length -or
                -not (Test-EqualRange $body 12 $network) -or
                -not (Test-EqualRange $body 28 $nonce) -or
                -not (Test-EqualRange $body 60 $boot) -or
                -not (Test-EqualRange $body 76 $monotonicBytes)) {
                throw 'Registry authority response does not echo the exact bounded request.'
            }
            $cacheControl = @($response.Headers.CacheControl.ToString()) -join ','
            if ($cacheControl -notmatch 'no-store' -or
                -not $response.Headers.Contains('X-Content-Type-Options')) {
                throw 'Registry authority response lacks required no-store/nosniff headers.'
            }
            [ordered]@{
                schema = 'deep-production-registry-authority-smoke.v1'
                status = 'ok'
                registryOrigin = $uri.GetLeftPart([UriPartial]::Authority)
                responseBytes = $body.Length
                requestEchoVerified = $true
                transportHeadersVerified = $true
                cryptographicClosureVerification = 'delegated-to-xnode-readiness'
            } | ConvertTo-Json
        } finally { $response.Dispose() }
    } finally { $content.Dispose() }
} finally {
    $client.Dispose()
    [Security.Cryptography.CryptographicOperations]::ZeroMemory($request)
    [Security.Cryptography.CryptographicOperations]::ZeroMemory($nonce)
    [Security.Cryptography.CryptographicOperations]::ZeroMemory($boot)
    [Security.Cryptography.CryptographicOperations]::ZeroMemory($network)
}
