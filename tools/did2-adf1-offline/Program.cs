using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.XPointNetworkV1;
using Sodium;

// Run only in Mr. X's offline custody environment. The Registry imports the
// exact output file; neither this tool nor the root seed is deployed there.
var options = Options.Parse(args);
var authorityRoot = Path.GetFullPath(options.Required("--authority-root"));
var output = Path.GetFullPath(options.Required("--output"));
var artifactRoot = Path.Combine(authorityRoot, "artifacts") +
    Path.DirectorySeparatorChar;
if (!Directory.Exists(authorityRoot) ||
    !output.StartsWith(artifactRoot, StringComparison.OrdinalIgnoreCase) ||
    !Directory.Exists(Path.GetDirectoryName(output)) || File.Exists(output))
    throw new InvalidOperationException(
        "ADF1 output must be a new file below the existing offline authority artifacts directory.");

var manifestBytes = Options.ReadBounded(Path.Combine(authorityRoot, "public",
    "custody-manifest.v1.json"), 65_536);
using var document = JsonDocument.Parse(manifestBytes);
var manifest = document.RootElement;
if (manifest.GetProperty("schema").GetString() !=
        "deep-production-authority-custody.v1" ||
    manifest.GetProperty("environment").GetString() != "prod" ||
    manifest.GetProperty("authorityOwner").GetString() != "Mr. X")
    throw new InvalidDataException("The approved production custody manifest is required.");
var network = Options.Hex(manifest.GetProperty("networkIdHex").GetString(),
    16, "custody network");
var roots = manifest.GetProperty("roles").EnumerateArray()
    .Where(static role => role.GetProperty("role").GetString() ==
        "offline-root-1").ToArray();
if (roots.Length != 1)
    throw new InvalidDataException("The offline root custody role is not unique.");
var role = roots[0];
var rootId = Options.Hex(role.GetProperty("authorityIdHex").GetString(),
    32, "custody root ID");
var expectedPublic = Options.Hex(
    role.GetProperty("ed25519PublicKeyHex").GetString(),
    32, "custody root public key");
var xnaPin = Options.Hex(options.Required("--xna1-core-hash"),
    32, "independent XNA1 pin");
var sourcePin = Options.Hex(options.Required("--source-adh1-core-hash"),
    32, "independent source ADH1 pin");
var targetPin = Options.Hex(options.Required("--target-adh1-core-hash"),
    32, "independent target ADH1 pin");
var xna = Options.ReadBounded(options.Required("--xna1"), 65_535);
var dts = Options.ReadBounded(options.Required("--dts1"), 65_535);
var authority = XPointNetworkAuthorityVerifier.Verify(
    new XPointNetworkGenesisPin(network, xnaPin),
    [(ReadOnlyMemory<byte>)xna], [(ReadOnlyMemory<byte>)dts]);
if (authority.RootThreshold != 1 || authority.RootKeys.Count != 1 ||
    !CryptographicOperations.FixedTimeEquals(
        rootId, authority.RootKeys[0].Id.Span) ||
    !CryptographicOperations.FixedTimeEquals(
        expectedPublic, authority.RootKeys[0].Ed25519PublicKey.Span))
    throw new CryptographicException(
        "The exact XNA1 root threshold/key differs from offline custody.");

var source = DeepIdV2DirectoryBootstrapVerifier.RestoreGenesis(authority,
    Options.ReadBounded(options.Required("--source-adh1"), 4096), sourcePin);
var target = AccountDirectoryProtectedLkgFactory.Restore(authority,
    Options.ReadBounded(options.Required("--target-adh1"), 4096), targetPin);
var issuedAt = ulong.Parse(options.Required("--issued-at-unix"),
    NumberStyles.None, CultureInfo.InvariantCulture);
var reader = ushort.Parse(options.Required("--minimum-reader"),
    NumberStyles.None, CultureInfo.InvariantCulture);
var localNow = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
if (localNow <= 0 || issuedAt > checked((ulong)localNow + 60) ||
    checked(issuedAt + 300) < (ulong)localNow)
    throw new CryptographicException(
        "Offline ADF1 issue time is not within the current five-minute ceremony window.");

var seed = Options.ReadSeed(Path.Combine(authorityRoot, "private",
    "offline-root-1.ed25519.seed"));
try
{
    using var signer = new RootSigner(rootId, expectedPublic, seed);
    var exact = await AccountDirectoryAdf1OfflineAuthor.AuthorInitialAsync(
        authority, source, target, issuedAt, reader, [signer]);
    // A decode/re-encode round trip is an independent canonical-file check;
    // the author already verified every signer result against exact XNA1.
    var parsed = AccountDirectoryAdf1Codec.Decode(exact);
    if (!CryptographicOperations.FixedTimeEquals(exact,
        AccountDirectoryAdf1Codec.Encode(parsed)))
        throw new CryptographicException("The signed ADF1 is non-canonical.");
    using var stream = new FileStream(output, FileMode.CreateNew,
        FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough);
    await stream.WriteAsync(exact);
    stream.Flush(flushToDisk: true);
    Console.WriteLine("PASS exact initial DID2 ADF1 signed under offline root custody.");
    Console.WriteLine($"Output SHA-256: {Convert.ToHexString(SHA256.HashData(exact))}");
    Console.WriteLine($"Source ADH1: {Convert.ToHexString(source.CoreHash.Span)}");
    Console.WriteLine($"Target ADH1: {Convert.ToHexString(target.CoreHash.Span)}");
}
finally { CryptographicOperations.ZeroMemory(seed); }

internal sealed class RootSigner : IAccountDirectoryAdf1RootSigner,
    IDisposable
{
    private readonly byte[] id;
    private readonly byte[] privateKey;

    internal RootSigner(ReadOnlySpan<byte> id, ReadOnlySpan<byte> expectedPublic,
        byte[] seed)
    {
        this.id = id.ToArray();
        var pair = PublicKeyAuth.GenerateKeyPair(seed);
        var generatedPrivate = pair.PrivateKey;
        try
        {
            if (!CryptographicOperations.FixedTimeEquals(
                expectedPublic, pair.PublicKey))
                throw new CryptographicException(
                    "The root seed differs from the custody manifest public key.");
            privateKey = generatedPrivate.ToArray();
        }
        finally { CryptographicOperations.ZeroMemory(generatedPrivate); }
    }

    public ReadOnlyMemory<byte> RootKeyId => id.ToArray();

    public ValueTask<int> SignAsync(ReadOnlyMemory<byte> signingInput,
        Memory<byte> signature64, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var signature = PublicKeyAuth.SignDetached(signingInput.ToArray(),
            privateKey);
        try
        {
            signature.CopyTo(signature64);
            return ValueTask.FromResult(signature.Length);
        }
        finally { CryptographicOperations.ZeroMemory(signature); }
    }

    public void Dispose() => CryptographicOperations.ZeroMemory(privateKey);
}

internal sealed class Options
{
    private readonly Dictionary<string, string> values;

    private Options(Dictionary<string, string> values) => this.values = values;

    internal static Options Parse(string[] args)
    {
        var expected = new HashSet<string>(StringComparer.Ordinal)
        {
            "--authority-root", "--output", "--xna1-core-hash", "--xna1",
            "--dts1", "--source-adh1", "--source-adh1-core-hash",
            "--target-adh1", "--target-adh1-core-hash",
            "--issued-at-unix", "--minimum-reader"
        };
        if (args.Length != expected.Count * 2)
            throw new ArgumentException("The exact offline ADF1 input set is required.");
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        for (var index = 0; index < args.Length; index += 2)
            if (!expected.Contains(args[index]) ||
                !values.TryAdd(args[index], args[index + 1]) ||
                string.IsNullOrWhiteSpace(args[index + 1]))
                throw new ArgumentException("An offline ADF1 input is absent or duplicate.");
        return new Options(values);
    }

    internal string Required(string name) => values[name];

    internal static byte[] ReadBounded(string path, long maximum)
    {
        var exact = Path.GetFullPath(path);
        var file = new FileInfo(exact);
        if (!file.Exists || (file.Attributes & FileAttributes.ReparsePoint) != 0 ||
            file.Length is <= 0 || file.Length > maximum)
            throw new InvalidDataException(
                "A required offline input is absent, redirected or oversized.");
        return File.ReadAllBytes(exact);
    }

    internal static byte[] ReadSeed(string path)
    {
        var bytes = ReadBounded(path, 68);
        if (bytes.Length == 32 && bytes.AsSpan().IndexOfAnyExcept((byte)0) >= 0)
            return bytes;
        try
        {
            var text = Encoding.ASCII.GetString(bytes).TrimEnd('\r', '\n');
            if (text.StartsWith("0x", StringComparison.Ordinal)) text = text[2..];
            return Hex(text, 32, "root seed");
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    internal static byte[] Hex(string? text, int length, string name)
    {
        if (text is null || text.Length != length * 2 ||
            text.Any(static value => value is not
                (>= '0' and <= '9' or >= 'a' and <= 'f' or >= 'A' and <= 'F')))
            throw new InvalidDataException($"The {name} is not exact hexadecimal data.");
        var bytes = Convert.FromHexString(text);
        if (bytes.AsSpan().IndexOfAnyExcept((byte)0) < 0)
            throw new InvalidDataException($"The {name} is zero.");
        return bytes;
    }
}
