using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using Deep.Protocol.XPointNetworkV1;
using static BootstrapIo;

// Transport/shape audit only. It opens no custody, account or protected floor
// and never claims that distributed signed records are currently authoritative.
internal static class NetworkDistributionAudit
{
    internal static async Task RunAsync(Arguments arguments, HttpClient http)
    {
        var origin = new Uri(arguments.Required("--audit-network-distribution"), UriKind.Absolute);
        if (origin.Scheme != Uri.UriSchemeHttps || origin.IsLoopback ||
            origin.AbsolutePath != "/" || origin.Query.Length != 0 ||
            origin.Fragment.Length != 0 || origin.UserInfo.Length != 0)
            throw new ArgumentException("Distribution audit requires one non-loopback HTTPS origin.");
        var network = Hex(arguments.Required("--network-id-hex"), 16, "independent network scope");
        var expected = Hex(arguments.Required("--expected-bundle-sha256"), 32, "independent public bundle hash");
        var request = XPointNetworkClosureWireCodec.EncodeRequest(network);
        var endpoint = new Uri(origin, "api/v2/network/closure");
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        using var response = await SendAsync(endpoint, request,
            XPointNetworkClosureWireCodec.RequestMediaType);
        Require(response.StatusCode == HttpStatusCode.OK &&
            response.Content.Headers.ContentType?.ToString() == XPointNetworkClosureWireCodec.ResponseMediaType &&
            response.Headers.CacheControl?.NoStore == true &&
            response.Content.Headers.ContentLength is >= 28 and <= XPointNetworkClosureWireCodec.MaximumResponseLength,
            "HTTPS distribution response has an unexpected status, media, cache policy or length.");
        var length = response.Content.Headers.ContentLength!.Value;
        var body = new byte[checked((int)length)];
        await using var stream = await response.Content.ReadAsStreamAsync(deadline.Token);
        await stream.ReadExactlyAsync(body, deadline.Token);
        Require(await stream.ReadAsync(new byte[1], deadline.Token) == 0,
            "HTTPS distribution response exceeds its declared length.");
        var raw = XPointNetworkClosureWireCodec.DecodeResponse(body);
        Require(CryptographicOperations.FixedTimeEquals(raw.NetworkId.Span, network) &&
            CryptographicOperations.FixedTimeEquals(SHA256.HashData(body), expected),
            "HTTPS distribution differs from the independently exported public bundle.");

        var wrongNetwork = network.ToArray();
        wrongNetwork[^1] ^= 1;
        if (wrongNetwork.AsSpan().IndexOfAnyExcept((byte)0) < 0) wrongNetwork[0] = 1;
        await RejectAsync(endpoint, XPointNetworkClosureWireCodec.EncodeRequest(wrongNetwork),
            XPointNetworkClosureWireCodec.RequestMediaType, HttpStatusCode.NotFound);
        await RejectAsync(new Uri(endpoint.AbsoluteUri + "?unexpected=1"), request,
            XPointNetworkClosureWireCodec.RequestMediaType, HttpStatusCode.BadRequest);
        await RejectAsync(endpoint, request, "application/octet-stream", HttpStatusCode.UnsupportedMediaType);
        var malformed = request.ToArray();
        malformed.AsSpan(0, 4).Clear();
        await RejectAsync(endpoint, malformed, XPointNetworkClosureWireCodec.RequestMediaType,
            HttpStatusCode.BadRequest);
        Console.WriteLine($"HTTPS public distribution audit passed: bytes={length}, sha256={Convert.ToHexString(expected)}, negativeChecks=4; not current network authority or device E2E evidence.");

        async Task<HttpResponseMessage> SendAsync(Uri uri, byte[] frame, string media)
        {
            using var message = new HttpRequestMessage(HttpMethod.Post, uri);
            message.Content = new ByteArrayContent(frame);
            message.Content.Headers.ContentType = new MediaTypeHeaderValue(media);
            return await http.SendAsync(message, HttpCompletionOption.ResponseHeadersRead, deadline.Token);
        }
        async Task RejectAsync(Uri uri, byte[] frame, string media, HttpStatusCode status)
        {
            using var rejected = await SendAsync(uri, frame, media);
            Require(rejected.StatusCode == status, "HTTPS negative distribution check did not reject as expected.");
        }
    }

    private static void Require(bool condition, string message)
    {
        if (!condition) throw new InvalidDataException(message);
    }
}
