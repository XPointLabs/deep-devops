using System.Text;
using System.Text.Json;
using Deep.Client.Shared.Services;

var routerUrls = GetRouterUrls(args);
using var identity = new SessionIdentityProvider($"uat onion smoke {Guid.NewGuid():N}");
var targetKey = identity.SessionId.Value;
var pubkeyEd25519 = Convert.ToHexString(identity.GetEd25519PublicKey()).ToLowerInvariant();

using var httpClient = new HttpClient
{
    Timeout = TimeSpan.FromSeconds(20)
};
var router = new XNodeRpcClient(
    httpClient,
    new XNodeRpcClientOptions(routerUrls));

var payloadText = "uat-onion-smoke:" + Guid.NewGuid().ToString("N");
var timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
var storeSignature = Convert.ToBase64String(identity.SignDetached(Encoding.UTF8.GetBytes($"store{timestamp}")));
await router.PostStorageAsync("storage_store", new
{
    pubkey = targetKey,
    pubkey_ed25519 = pubkeyEd25519,
    @namespace = 0,
    timestamp,
    ttl = 60_000,
    data = Convert.ToBase64String(Encoding.UTF8.GetBytes(payloadText)),
    idempotency_key = Guid.NewGuid().ToString("N"),
    signature = storeSignature
}, targetKey);

var retrieveTimestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
var retrieveSignature = Convert.ToBase64String(identity.SignDetached(Encoding.UTF8.GetBytes($"retrieve{retrieveTimestamp}")));
var retrieved = await router.PostStorageAsync("storage_retrieve", new
{
    pubkey = targetKey,
    pubkey_ed25519 = pubkeyEd25519,
    @namespace = 0,
    timestamp = retrieveTimestamp,
    signature = retrieveSignature,
    last_hash = (string?)null
}, targetKey);

var route = router.CurrentRoute;
if (route is null || route.Mode != "onion-storage" || route.Nodes.Count != 3)
{
    throw new InvalidOperationException("Expected a 3-hop onion-storage route.");
}

var expectedData = Convert.ToBase64String(Encoding.UTF8.GetBytes(payloadText));
var found = retrieved.TryGetProperty("messages", out var messages) &&
            messages.ValueKind == JsonValueKind.Array &&
            messages.EnumerateArray().Any(message =>
                message.TryGetProperty("data", out var data) &&
                string.Equals(data.GetString(), expectedData, StringComparison.Ordinal));

if (!found)
{
    throw new InvalidOperationException("The onion smoke message was not retrieved from storage.");
}

Console.WriteLine(JsonSerializer.Serialize(new
{
    ok = true,
    targetKey,
    route = route.Nodes.Select(node => new
    {
        node.Index,
        node.RouterId,
        node.Endpoint,
        node.RpcEndpoint
    })
}, new JsonSerializerOptions(JsonSerializerDefaults.Web)
{
    WriteIndented = true
}));

static IReadOnlyList<PinnedRouterEndpoint> GetRouterUrls(string[] args)
{
    var fromArgs = GetOption(args, "--routers");
    var raw = fromArgs
        ?? Environment.GetEnvironmentVariable("XNODE_URLS")
        ?? "fe8f458267a9c92015b143d395807a0b99be7303b89af0cee60f37cbaf7941e3|http://127.0.0.1:29281,"
           + "c1f667cb6bba5fbf80c3bc39a32e13e3fea26add89db5b73d752e477d11f208d|http://127.0.0.1:29282,"
           + "950462de6f917f4f28725daf96178bba68afbc766739566aec18e3ef407ca406|http://127.0.0.1:29283";
    return raw
        .Split([',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
        .Select(value =>
        {
            var separator = value.IndexOf('|');
            if (separator <= 0 || separator == value.Length - 1)
            {
                throw new InvalidOperationException("XNODE_URLS entries must use '<router-id>|<absolute-url>'.");
            }

            return new PinnedRouterEndpoint(value[(separator + 1)..], value[..separator]);
        })
        .ToArray();
}

static string? GetOption(string[] args, string name)
{
    for (var index = 0; index < args.Length - 1; index++)
    {
        if (string.Equals(args[index], name, StringComparison.OrdinalIgnoreCase))
        {
            return args[index + 1];
        }
    }

    return null;
}
