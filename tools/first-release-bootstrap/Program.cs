using System.Net;
using System.Text.Json;
using XNode.Registry;

var values = ParseArguments(args);
var privateKeyPath = Path.GetFullPath(Required(values, "--private-key-file"));
var outputPath = Path.GetFullPath(Required(values, "--output"));
var routerId = CanonicalHex(Required(values, "--router-id"), 32, "router id");
var operatorAddress = "0x" + CanonicalHex(
    Required(values, "--operator-address"), 20, "operator address");
var domainAddress = "0x" + CanonicalHex(
    Required(values, "--domain-address"), 20, "BLS domain address");
var rpcUri = new Uri(Required(values, "--rpc-url"), UriKind.Absolute);

if (rpcUri.Scheme != Uri.UriSchemeHttp
    || !(rpcUri.Host.Equals("localhost", StringComparison.OrdinalIgnoreCase)
        || IPAddress.TryParse(rpcUri.Host, out var rpcAddress) && IPAddress.IsLoopback(rpcAddress)))
{
    throw new InvalidOperationException("The bootstrap BLS RPC must be a loopback HTTP endpoint.");
}
if (!File.Exists(privateKeyPath))
{
    throw new InvalidOperationException("The BLS private-key file is missing.");
}
if (File.Exists(outputPath))
{
    throw new InvalidOperationException("The BLS public proof output already exists.");
}

using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(15) };
var service = new Bls12381RegistrationProofService(http);
var options = new RegistryRegistrationOptions
{
    BlsPrivateKeyPath = privateKeyPath,
    EthereumRpcUrl = rpcUri.AbsoluteUri,
    ServiceNodeRewardsAddress = domainAddress,
    OperatorAddress = operatorAddress,
    ChainId = 31_337
};
var proof = await service.CreateProofAsync(options, routerId, CancellationToken.None);
var publicKey = CanonicalHex(proof.PublicKey, 128, "BLS public key");
var signature = CanonicalHex(proof.Signature, 256, "BLS proof of possession");

var encoded = JsonSerializer.Serialize(
    new { publicKey, signature },
    new JsonSerializerOptions { WriteIndented = true });
await File.WriteAllTextAsync(outputPath, encoded + Environment.NewLine);
Console.WriteLine("BLS public key and proof generated with the XNode implementation.");

static Dictionary<string, string> ParseArguments(string[] arguments)
{
    if (arguments.Length == 0 || arguments.Length % 2 != 0)
    {
        throw new ArgumentException("Expected name/value argument pairs.");
    }

    var allowed = new HashSet<string>(StringComparer.Ordinal)
    {
        "--private-key-file", "--output", "--router-id", "--operator-address",
        "--domain-address", "--rpc-url"
    };
    var result = new Dictionary<string, string>(StringComparer.Ordinal);
    for (var index = 0; index < arguments.Length; index += 2)
    {
        var name = arguments[index];
        if (!allowed.Contains(name) || !result.TryAdd(name, arguments[index + 1]))
        {
            throw new ArgumentException("Unknown or duplicate bootstrap argument.");
        }
    }
    return result;
}

static string Required(IReadOnlyDictionary<string, string> values, string name) =>
    values.TryGetValue(name, out var value) && !string.IsNullOrWhiteSpace(value)
        ? value
        : throw new ArgumentException($"Missing {name}.");

static string CanonicalHex(string value, int bytes, string name)
{
    var normalized = value.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
        ? value[2..]
        : value;
    if (normalized.Length != bytes * 2
        || normalized.Any(character => character is not (>= '0' and <= '9' or >= 'a' and <= 'f')))
    {
        throw new InvalidOperationException($"The {name} must be canonical lowercase {bytes}-byte hex.");
    }
    return normalized;
}
