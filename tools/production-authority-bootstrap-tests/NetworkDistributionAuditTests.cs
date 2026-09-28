using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using Deep.Protocol.XPointNetworkV1;

internal static class NetworkDistributionAuditTests
{
    internal static async Task RunAsync(byte[] bundle, byte[] network)
    {
        var args = new[] { "--audit-network-distribution", "https://registry.invalid/",
            "--network-id-hex", Convert.ToHexString(network),
            "--expected-bundle-sha256", Convert.ToHexString(SHA256.HashData(bundle)) };
        using (var handler = new Handler(bundle, network, "valid"))
        using (var http = new HttpClient(handler))
        {
            await NetworkDistributionAudit.RunAsync(Arguments.Parse(args), http);
            if (handler.Calls != 5) throw new Exception("Distribution audit skipped negative checks.");
        }
        foreach (var fault in new[] { "redirect", "media", "cache", "oversize",
                     "hash", "trailing", "negative" })
        {
            using var handler = new Handler(bundle, network, fault);
            using var http = new HttpClient(handler);
            await RejectAsync<InvalidDataException>(args, http);
        }
        foreach (var origin in new[] { "http://registry.invalid/", "https://127.0.0.1/",
                     "https://registry.invalid/path", "https://registry.invalid/?query=1",
                     "https://registry.invalid/#fragment", "https://user@registry.invalid/" })
        {
            var invalid = args.ToArray();
            invalid[1] = origin;
            using var handler = new Handler(bundle, network, "valid");
            using var http = new HttpClient(handler);
            await RejectAsync<ArgumentException>(invalid, http);
            if (handler.Calls != 0) throw new Exception("Unsafe origin dispatched HTTP.");
        }
        foreach (var extra in new[] { "--authority-root", "--output", "--export-network-genesis" })
        {
            try { _ = Arguments.Parse([.. args, extra, "synthetic"]); }
            catch (ArgumentException) { continue; }
            throw new Exception("Transport-only audit admitted custody or write mode arguments.");
        }
    }

    private static async Task RejectAsync<T>(string[] args, HttpClient http) where T : Exception
    {
        try { await NetworkDistributionAudit.RunAsync(Arguments.Parse(args), http); }
        catch (T) { return; }
        throw new Exception($"Expected {typeof(T).Name} distribution audit rejection.");
    }

    // Synthetic handler only: this fixture does not claim a real TLS exchange.
    private sealed class Handler(byte[] bundle, byte[] network, string fault) : HttpMessageHandler
    {
        internal int Calls { get; private set; }
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            Calls++;
            var bytes = await request.Content!.ReadAsByteArrayAsync(cancellationToken);
            var status = HttpStatusCode.OK;
            if (request.RequestUri!.Query.Length != 0) status = HttpStatusCode.BadRequest;
            else if (request.Content.Headers.ContentType?.ToString() != XPointNetworkClosureWireCodec.RequestMediaType)
                status = HttpStatusCode.UnsupportedMediaType;
            else
            {
                try
                {
                    if (!XPointNetworkClosureWireCodec.DecodeRequest(bytes).AsSpan().SequenceEqual(network))
                        status = HttpStatusCode.NotFound;
                }
                catch (FormatException) { status = HttpStatusCode.BadRequest; }
            }
            if (Calls > 1 && fault == "negative") status = HttpStatusCode.OK;
            var response = new HttpResponseMessage(Calls == 1 && fault == "redirect"
                ? HttpStatusCode.TemporaryRedirect : status);
            var body = bundle.ToArray();
            if (fault == "hash") body[^1] ^= 1;
            if (fault == "trailing") body = [.. body, 1];
            response.Content = new ByteArrayContent(body);
            response.Content.Headers.ContentType = new MediaTypeHeaderValue(fault == "media"
                ? "application/octet-stream" : XPointNetworkClosureWireCodec.ResponseMediaType);
            response.Headers.CacheControl = new CacheControlHeaderValue { NoStore = fault != "cache" };
            if (fault == "oversize") response.Content.Headers.ContentLength =
                XPointNetworkClosureWireCodec.MaximumResponseLength + 1L;
            if (fault == "trailing") response.Content.Headers.ContentLength = bundle.Length;
            return response;
        }
    }
}
