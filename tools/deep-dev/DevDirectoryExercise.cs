using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text.Json;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Services;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.XPointNetworkV1;

// Real, disposable account admissions for the explicitly owned development
// network. Receipt shape/binding is checked, but receipt bytes are never proof
// authority. The running nodes independently verify the complete catch-up.
internal static class DevDirectoryExercise
{
    internal static async Task RunAsync(string publicRoot)
    {
        if (!OperatingSystem.IsLinux() || publicRoot != "/run/deep-public")
            throw new InvalidOperationException("Directory exercise requires the fixed development mount.");
        using var manifest = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(publicRoot,"deep-dev.json")));
        if (manifest.RootElement.GetProperty("schema").GetString() != "deep-dev.v1" ||
            manifest.RootElement.GetProperty("nodeCount").GetInt32() != 3 ||
            manifest.RootElement.GetProperty("deviceEvidence").GetBoolean())
            throw new InvalidDataException("Not the owned development network.");
        var network = Convert.FromHexString(manifest.RootElement.GetProperty("networkIdHex").GetString()!);
        _ = XPointNetworkBootstrapAuthor.VerifyExistingGenesis(
            File.ReadAllBytes(Path.Combine(publicRoot,"genesis.xna1")),
            File.ReadAllBytes(Path.Combine(publicRoot,"genesis.dts1")),
            new XPointNetworkGenesisPin(network,Convert.FromHexString(manifest.RootElement.GetProperty("genesisAuthorityCoreHashHex").GetString()!)));
        using var handler = new SocketsHttpHandler { AllowAutoRedirect=false,UseCookies=false,AutomaticDecompression=DecompressionMethods.None };
        using var client = new HttpClient(handler) { Timeout=TimeSpan.FromSeconds(30) };
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(12));
        ulong? first = null; ulong last = 0;
        for (var index = 0; index < 130; index++) {
            // Scratch databases and in-memory keys belong only to this disposable
            // --rm probe container, never a retained node/user account namespace.
            using var storage = new InMemoryDeepSecureStorage();
            var scratch = Path.Combine("/tmp/deep-dev-directory-exercise",index.ToString());
            Directory.CreateDirectory(scratch);
            var accounts = new DeepIdV2AccountService(storage,scratch,network,1,
                new SystemClock(),DeepMlDsa65CandidateVerifierFactory.OpenForCurrentProcess);
            _ = await accounts.CreateAsync("Development catch-up fixture",deadline.Token);
            var body = await accounts.PrepareGenesisAdmissionAsync(deadline.Token);
            var request = DeepIdV2GenesisAdmissionWireCodec.DecodeRequest(body);
            try {
                for (var attempt = 0; ; attempt++) {
                    using var message = new HttpRequestMessage(HttpMethod.Post,"https://registry/api/v2/account-directory/genesis-admissions");
                    message.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(DeepIdV2GenesisAdmissionWireCodec.ResponseMediaType));
                    message.Content = new ByteArrayContent(body);
                    message.Content.Headers.ContentType = new MediaTypeHeaderValue(DeepIdV2GenesisAdmissionWireCodec.RequestMediaType);
                    using var response = await client.SendAsync(message,HttpCompletionOption.ResponseHeadersRead,deadline.Token);
                    if (response.StatusCode is HttpStatusCode.TooManyRequests or HttpStatusCode.ServiceUnavailable && attempt < 5) {
                        var retry = response.Headers.RetryAfter?.Delta?.TotalSeconds ?? 10;
                        await Task.Delay(TimeSpan.FromSeconds(Math.Clamp(retry,10,60)),deadline.Token); continue;
                    }
                    if (response.StatusCode != HttpStatusCode.OK || response.Content.Headers.ContentType?.MediaType != DeepIdV2GenesisAdmissionWireCodec.ResponseMediaType ||
                        response.Content.Headers.ContentLength is not { } length || length < 1 || length > DeepIdV2GenesisAdmissionWireCodec.MaximumResponseLength)
                        throw new InvalidDataException("Development admission transport rejected.");
                    var bytes = new byte[checked((int)length)];
                    await using var stream = await response.Content.ReadAsStreamAsync(deadline.Token);
                    await stream.ReadExactlyAsync(bytes,deadline.Token);
                    if (stream.ReadByte() != -1) throw new InvalidDataException("Trailing admission bytes.");
                    var receipt = DeepIdV2GenesisAdmissionWireCodec.DecodeReceipt(bytes);
                    var head = AccountDirectoryAdh1Codec.Decode(receipt.ExactAdh1.Span);
                    if (!receipt.OperationId.Span.SequenceEqual(request.OperationId.Span) || !head.NetworkId.Span.SequenceEqual(network) ||
                        first is not null && head.LogGeneration <= last) throw new CryptographicException("Development receipt binding rejected.");
                    first ??= head.LogGeneration; last=head.LogGeneration; break;
                }
            } finally { CryptographicOperations.ZeroMemory(body); }
            if ((index+1)%10 == 0) Console.WriteLine($"Development directory admissions completed: {index+1}/130.");
        }
        if (last-first < 129) throw new CryptographicException("Development directory did not advance beyond two 64-head pages.");
        Console.WriteLine(JsonSerializer.Serialize(new {schema="deep-dev-directory-exercise.v1",admittedFixtures=130,observedSuccessorSpan=last-first,
            receiptIsFreshnessAuthority=false,deviceEvidence=false,messageDeliveryEvidence=false}));
    }
}
