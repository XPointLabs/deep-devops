using System.Text;
using System.Text.Json;
using Deep.Client.Shared.Services;

var routerUrls = GetRouterUrls(args);
var targetKey = GetOption(args, "--target")
    ?? Environment.GetEnvironmentVariable("DEEP_ONION_SMOKE_TARGET")
    ?? "05uat-onion-smoke";

using var httpClient = new HttpClient
{
    Timeout = TimeSpan.FromSeconds(20)
};
var router = new XNodeRpcClient(
    httpClient,
    new XNodeRpcClientOptions(routerUrls));

var payloadText = "uat-onion-smoke:" + Guid.NewGuid().ToString("N");
var timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
await router.PostStorageAsync("storage_store", new
{
    pubkey = targetKey,
    @namespace = 0,
    timestamp,
    ttl = 60_000,
    data = Convert.ToBase64String(Encoding.UTF8.GetBytes(payloadText)),
    idempotency_key = Guid.NewGuid().ToString("N")
}, targetKey);

var retrieved = await router.PostStorageAsync("storage_retrieve", new
{
    pubkey = targetKey,
    @namespace = 0,
    timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
    signature = "deep-uat-onion-smoke",
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

static IReadOnlyList<string> GetRouterUrls(string[] args)
{
    var fromArgs = GetOption(args, "--routers");
    var raw = fromArgs
        ?? Environment.GetEnvironmentVariable("XNODE_URLS")
        ?? "http://127.0.0.1:29281,http://127.0.0.1:29282,http://127.0.0.1:29283";
    return raw.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
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
