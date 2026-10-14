using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text.Json;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.XPointNetworkV1;

// One retained exact request, no account regeneration or synthesized checkpoint.
// Admission receipt is not freshness: each node must acquire its own live proof.
internal static class DevObserverAdmission
{
    internal static async Task RunAsync(string publicRoot, string admissionFile)
    {
        if (!OperatingSystem.IsLinux() || publicRoot != "/run/deep-public" || admissionFile != "/run/deep-observer/admission.dga2")
            throw new ArgumentException("Observer admission requires exact isolated development mounts.");
        using var manifest = JsonDocument.Parse(Read(Path.Combine(publicRoot, "deep-dev.json"), 16_384));
        var project = DevTopology.ForProject(manifest.RootElement.GetProperty("projectName").GetString()!);
        if (manifest.RootElement.GetProperty("schema").GetString() != "deep-dev.v1" ||
            manifest.RootElement.GetProperty("nodeCount").GetInt32() != 3 ||
            manifest.RootElement.GetProperty("containerIpv4Prefix").GetString() != project.Ipv4Prefix ||
            manifest.RootElement.GetProperty("deviceEvidence").GetBoolean())
            throw new InvalidDataException("Not the owned current development network.");
        var network = Convert.FromHexString(manifest.RootElement.GetProperty("networkIdHex").GetString()!);
        var closure = XPointNetworkClosureWireCodec.DecodeResponse(Read(Path.Combine(publicRoot, "network.ncp2"), XPointNetworkClosureWireCodec.MaximumResponseLength));
        var pin = new XPointNetworkGenesisPin(network, Convert.FromHexString(manifest.RootElement.GetProperty("genesisAuthorityCoreHashHex").GetString()!));
        _ = XPointNetworkAuthorityVerifier.Verify(pin, closure.ExactAuthorityChain, closure.ExactTimePolicyChain);
        if (!closure.NetworkId.Span.SequenceEqual(network)) throw new CryptographicException("Observer network differs.");
        var body = Read(admissionFile, DeepIdV2GenesisAdmissionWireCodec.MaximumRequestLength);
        try
        {
            var request = DeepIdV2GenesisAdmissionWireCodec.DecodeRequest(body);
            if (!request.Admission.ExactDid2.Span.SequenceEqual(Read(Path.Combine(publicRoot, "observer.did2"), 65_535)))
                throw new CryptographicException("Prepared admission does not bind the configured observer.");
            using var handler = new SocketsHttpHandler { AllowAutoRedirect = false, UseCookies = false, AutomaticDecompression = DecompressionMethods.None };
            using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(60));
            for (var attempt = 0; ; attempt++)
            {
                using var message = new HttpRequestMessage(HttpMethod.Post, "https://registry/api/v2/account-directory/genesis-admissions");
                message.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(DeepIdV2GenesisAdmissionWireCodec.ResponseMediaType));
                message.Content = new ByteArrayContent(body);
                message.Content.Headers.ContentType = new MediaTypeHeaderValue(DeepIdV2GenesisAdmissionWireCodec.RequestMediaType);
                try
                {
                    using var response = await client.SendAsync(message, HttpCompletionOption.ResponseHeadersRead, deadline.Token);
                    if (response.StatusCode is HttpStatusCode.TooManyRequests or HttpStatusCode.ServiceUnavailable && attempt < 5)
                    { await Task.Delay(TimeSpan.FromSeconds(5), deadline.Token); continue; }
                    if (response.StatusCode != HttpStatusCode.OK || response.Content.Headers.ContentType?.MediaType != DeepIdV2GenesisAdmissionWireCodec.ResponseMediaType ||
                        response.Content.Headers.ContentLength is not { } length || length is < 1 || length > DeepIdV2GenesisAdmissionWireCodec.MaximumResponseLength)
                        throw new InvalidDataException("Observer admission transport rejected.");
                    var bytes = new byte[checked((int)length)];
                    await using var stream = await response.Content.ReadAsStreamAsync(deadline.Token);
                    await stream.ReadExactlyAsync(bytes, deadline.Token);
                    if (stream.ReadByte() != -1) throw new InvalidDataException("Trailing observer admission bytes.");
                    var receipt = DeepIdV2GenesisAdmissionWireCodec.DecodeReceipt(bytes);
                    var head = AccountDirectoryAdh1Codec.Decode(receipt.ExactAdh1.Span);
                    if (!receipt.OperationId.Span.SequenceEqual(request.OperationId.Span) || !head.NetworkId.Span.SequenceEqual(network))
                        throw new CryptographicException("Observer receipt binding differs.");
                    Console.WriteLine("Retained development observer admission accepted; receipt is not current proof or device evidence.");
                    return;
                }
                catch (HttpRequestException) when (attempt < 5 && !deadline.IsCancellationRequested)
                { await Task.Delay(TimeSpan.FromSeconds(5), deadline.Token); }
            }
        }
        finally { CryptographicOperations.ZeroMemory(body); }
    }

    private static byte[] Read(string file, int bound)
    {
        using var stream = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete);
        if (stream.Length is < 1 || stream.Length > bound) throw new InvalidDataException("Unbounded observer input.");
        var bytes = new byte[checked((int)stream.Length)]; stream.ReadExactly(bytes);
        if (stream.ReadByte() != -1) throw new IOException("Observer input changed.");
        return bytes;
    }
}
