using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.XPointNetworkV1;
using Sodium;
using static BootstrapIo;

var arguments = Arguments.Parse(args);
var authorityRoot = ExistingDirectory(arguments.Required("--authority-root"));
var outputRoot = NewDirectoryPath(arguments.Required("--output"));
var nodes = new[]
{
    NodeInput.Load("seed1", ExistingDirectory(arguments.Required("--seed1-root"))),
    NodeInput.Load("seed2", ExistingDirectory(arguments.Required("--seed2-root"))),
    NodeInput.Load("seed3", ExistingDirectory(arguments.Required("--seed3-root"))),
};
var observedUnix = arguments.RequiredU64("--observed-unix");
var bootId = Hex(arguments.Required("--boot-id"), 16, "boot ID");
var nonceCreated = arguments.RequiredU64("--nonce-created");
var responseReceived = arguments.RequiredU64("--response-received");
var currentSample = arguments.RequiredU64("--current-sample");
var previousBootstrapRoot = arguments.Optional("--previous-bootstrap-root");
var manifestPath = Path.Combine(authorityRoot, "public", "custody-manifest.v1.json");
var manifest = CustodyManifest.Load(manifestPath);
if (!string.Equals(manifest.AuthorityOwner, "Mr. X", StringComparison.Ordinal) ||
    !string.Equals(manifest.Environment, "prod", StringComparison.Ordinal))
    throw new InvalidDataException("The custody manifest is not the approved Mr. X production boundary.");

var privateRoot = ExistingDirectory(Path.Combine(authorityRoot, "private"));
using var root = FileSigner.Root(
    manifest.Role("offline-root-1"),
    ExistingFile(Path.Combine(privateRoot, "offline-root-1.ed25519.seed")));
using var witness1 = FileSigner.Witness(
    manifest.Role("registry-dtt-signer-1"),
    ExistingFile(Path.Combine(privateRoot, "registry-dtt-signer-1.ed25519.seed")));
using var witness2 = FileSigner.Witness(
    manifest.Role("registry-dtt-signer-2"),
    ExistingFile(Path.Combine(privateRoot, "registry-dtt-signer-2.ed25519.seed")));
using var witness3 = FileSigner.Witness(
    manifest.Role("registry-dtt-signer-3"),
    ExistingFile(Path.Combine(privateRoot, "registry-dtt-signer-3.ed25519.seed")));
var witnesses = new[] { witness1, witness2, witness3 };
var network = Hex(manifest.NetworkIdHex, 16, "network ID");
var ceremony = HashDomain("Deep/XPoint/V1/production-genesis-ceremony", network);
var notBefore = checked(observedUnix - 60);
var authorityExpires = checked(notBefore + 34_560_000);
var timePolicyExpires = checked(notBefore + 2_592_000);
var operationalExpires = checked(notBefore + 86_400);
var timeSources = new[]
{
    TimeSource("time.cloudflare.com", "cloudflare", "48f93d4f1ecaf8e2323bc2e5be015b331d65cb8e40a1b28be50eb4ba9230e789"),
    TimeSource("nts.netnod.se", "netnod", "bd44c55cfd57e38da3a6aea80bf65f9c441b63fbd8667e057b0f112fc3211efa"),
}.OrderBy(static value => value.SourceId.ToArray(), ByteArrayComparer.Instance).ToArray();
var queryLeaf = HashDomain(
    "Deep/XPoint/V1/contact-authority-bootstrap-leaf",
    manifest.Role("contact-xpk").PublicKey());
VerifiedXPointNetworkBootstrap bootstrap;
if (string.IsNullOrWhiteSpace(previousBootstrapRoot))
{
    var bootstrapRequest = new XPointNetworkGenesisAuthoringRequest(
        ceremony,
        network,
        [new XPointNetworkBootstrapRootKey(
            root.RootKeyId.Span, root.KeyGeneration, root.Ed25519PublicKey.Span,
            root.CustodyDomainHash.Span)],
        1,
        witnesses.Select(static value => new XPointNetworkBootstrapWitnessKey(
            value.SignerId.Span, value.KeyGeneration, value.Ed25519PublicKey.Span,
            value.FailureDomainHash.Span)).ToArray(),
        2,
        timeSources,
        5,
        10,
        notBefore,
        notBefore,
        authorityExpires,
        notBefore,
        timePolicyExpires,
        1,
        1);
    bootstrap = await XPointNetworkBootstrapAuthor.AuthorGenesisAsync(
        bootstrapRequest, [root]);
}
else
{
    bootstrap = LoadExistingBootstrap(previousBootstrapRoot, network, queryLeaf);
}
var nodeRecords = nodes.Select(node => node.ToOperationalNode(network)).ToArray();
var snapshotNonce = RandomNumberGenerator.GetBytes(32);
try
{
    var operationalRequest = new XPointNetworkOperationalGenesisRequest(
        ceremony,
        bootstrap,
        [root],
        witnesses,
        nodeRecords,
        queryLeaf,
        HashDomain("Deep/XPoint/V1/XCC1/first-release-profile", network),
        HashDomain("Deep/XPoint/V1/XCB1/first-release-carrier-set", network),
        HashDomain("Deep/XPoint/V1/PMA2/first-release-placement", network),
        notBefore,
        notBefore,
        operationalExpires,
        snapshotNonce,
        bootId,
        nonceCreated,
        responseReceived,
        currentSample,
        observedUnix,
        5,
        1);
    var authored = await XPointNetworkOperationalGenesisAuthor.AuthorAsync(operationalRequest);
    Directory.CreateDirectory(outputRoot);
    var bootstrapDirectory = Path.Combine(outputRoot, "bootstrap");
    Directory.CreateDirectory(bootstrapDirectory);
    var artifacts = new List<(string Role, byte[] Bytes)>
    {
        ("xna1", authored.ExactXna1.ToArray()),
        ("dts1", authored.ExactDts1.ToArray()),
        ("adh1", authored.ExactAdh1.ToArray()),
        ("snapshot-dtt1", authored.ExactDtt1.ToArray()),
        ("snapshot-adp1", authored.ExactAdp1.ToArray()),
        ("xvp1", authored.ExactXvp1.ToArray()),
        ("xnv1", authored.ExactXnv1.ToArray()),
        ("xnh1", authored.ExactXnh1.ToArray()),
        ("pmt2", authored.ExactPmt2.ToArray()),
        ("response-adp1", authored.ExactAdp1.ToArray()),
    };
    artifacts.AddRange(authored.ExactXnd1.Select(static value => ("xnd1", value.ToArray())));
    var entries = WriteArtifacts(bootstrapDirectory, artifacts);
    var inventory = new ArtifactInventory(
        "deep-contact-resolve-readonly-v1",
        Convert.ToHexString(network).ToLowerInvariant(),
        Convert.ToHexString(bootstrap.GenesisPin.AuthorityCoreHash.Span).ToLowerInvariant(),
        1,
        Convert.ToHexString(snapshotNonce).ToLowerInvariant(),
        Convert.ToHexString(queryLeaf).ToLowerInvariant(),
        Convert.ToHexString(bootId).ToLowerInvariant(),
        nonceCreated,
        responseReceived,
        currentSample,
        entries);
    WriteNew(Path.Combine(bootstrapDirectory, "inventory.json"),
        JsonSerializer.SerializeToUtf8Bytes(inventory));
    var publicManifest = new PublicBootstrapManifest(
        "deep-production-authority-bootstrap.v1",
        "Mr. X",
        Convert.ToHexString(network).ToLowerInvariant(),
        Convert.ToHexString(bootstrap.GenesisPin.AuthorityCoreHash.Span).ToLowerInvariant(),
        Convert.ToHexString(queryLeaf).ToLowerInvariant(),
        notBefore,
        operationalExpires,
        entries);
    WriteNew(Path.Combine(outputRoot, "public-manifest.v1.json"),
        JsonSerializer.SerializeToUtf8Bytes(publicManifest, new JsonSerializerOptions { WriteIndented = true }));
    Console.WriteLine("Production authority bootstrap authored and independently verified.");
    Console.WriteLine($"Genesis authority core hash: {publicManifest.GenesisAuthorityCoreHashHex}");
    Console.WriteLine($"Directory bootstrap leaf key: {publicManifest.DirectoryLeafKeyHex}");
}
catch
{
    if (Directory.Exists(outputRoot))
        Console.Error.WriteLine("The incomplete output directory must be reviewed before removal or retry.");
    throw;
}
finally
{
    foreach (var node in nodes) node.Dispose();
    CryptographicOperations.ZeroMemory(snapshotNonce);
    CryptographicOperations.ZeroMemory(bootId);
    CryptographicOperations.ZeroMemory(network);
    CryptographicOperations.ZeroMemory(ceremony);
    CryptographicOperations.ZeroMemory(queryLeaf);
}

static AccountDirectoryDts1Source TimeSource(string host, string family, string spkiHex) => new(
    HashDomain("Deep/XPoint/V1/NTS/source-id", Encoding.ASCII.GetBytes(host)),
    HashDomain("Deep/XPoint/V1/NTS/failure-family", Encoding.ASCII.GetBytes(family)),
    1,
    host,
    4460,
    Hex(spkiHex, 32, $"{host} SPKI"),
    5);

static int ArtifactRoleOrder(string role) => role switch
{
    "xna1" => 0,
    "dts1" => 1,
    "adh1" => 2,
    "snapshot-dtt1" => 3,
    "snapshot-adp1" => 4,
    "xvp1" => 5,
    "xnv1" => 6,
    "xnh1" => 7,
    "xnd1" => 8,
    "pmt2" => 9,
    "response-adp1" => 10,
    "caller-adh1" => 11,
    _ => throw new InvalidDataException("The production artifact role is unknown."),
};

static VerifiedXPointNetworkBootstrap LoadExistingBootstrap(
    string previousRoot,
    ReadOnlySpan<byte> expectedNetwork,
    ReadOnlySpan<byte> expectedDirectoryLeaf)
{
    previousRoot = ExistingDirectory(previousRoot);
    var manifestBytes = File.ReadAllBytes(
        ExistingFile(Path.Combine(previousRoot, "public-manifest.v1.json")));
    try
    {
        var manifest = JsonSerializer.Deserialize<PublicBootstrapManifest>(manifestBytes,
                           new JsonSerializerOptions { PropertyNameCaseInsensitive = true })
                       ?? throw new InvalidDataException(
                           "The previous public bootstrap manifest is empty.");
        if (!string.Equals(manifest.Schema, "deep-production-authority-bootstrap.v1",
                StringComparison.Ordinal) ||
            !string.Equals(manifest.AuthorityOwner, "Mr. X", StringComparison.Ordinal))
            throw new InvalidDataException(
                "The previous bootstrap is outside the approved production boundary.");
        var network = Hex(manifest.NetworkIdHex, 16, "previous network ID");
        var genesis = Hex(manifest.GenesisAuthorityCoreHashHex, 32, "previous genesis pin");
        var directoryLeaf = Hex(manifest.DirectoryLeafKeyHex, 32, "previous directory leaf key");
        try
        {
            if (!CryptographicOperations.FixedTimeEquals(network, expectedNetwork) ||
                !CryptographicOperations.FixedTimeEquals(directoryLeaf, expectedDirectoryLeaf))
                throw new CryptographicException(
                    "The previous bootstrap belongs to a different production authority.");
            var bootstrapRoot = ExistingDirectory(Path.Combine(previousRoot, "bootstrap"));
            var xna = File.ReadAllBytes(
                ExistingFile(Path.Combine(bootstrapRoot, "xna1.0000.bin")));
            var dts = File.ReadAllBytes(
                ExistingFile(Path.Combine(bootstrapRoot, "dts1.0000.bin")));
            try
            {
                return XPointNetworkBootstrapAuthor.VerifyExistingGenesis(
                    xna, dts, new XPointNetworkGenesisPin(network, genesis));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(xna);
                CryptographicOperations.ZeroMemory(dts);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(network);
            CryptographicOperations.ZeroMemory(genesis);
            CryptographicOperations.ZeroMemory(directoryLeaf);
        }
    }
    finally
    {
        CryptographicOperations.ZeroMemory(manifestBytes);
    }
}

static IReadOnlyList<ArtifactEntry> WriteArtifacts(
    string directory,
    IReadOnlyList<(string Role, byte[] Bytes)> artifacts)
{
    var entries = new List<ArtifactEntry>();
    foreach (var group in artifacts
                 .GroupBy(static value => value.Role, StringComparer.Ordinal)
                 .OrderBy(static group => ArtifactRoleOrder(group.Key)))
    {
        var ordinal = 0;
        foreach (var artifact in group)
        {
            var file = $"{group.Key}.{ordinal:D4}.bin";
            WriteNew(Path.Combine(directory, file), artifact.Bytes);
            entries.Add(new ArtifactEntry(
                group.Key,
                ordinal++,
                file,
                artifact.Bytes.Length,
                Convert.ToHexString(SHA256.HashData(artifact.Bytes)).ToLowerInvariant()));
        }
    }
    return entries;
}

sealed class Arguments
{
    private readonly IReadOnlyDictionary<string, string> values;
    private Arguments(IReadOnlyDictionary<string, string> values) => this.values = values;

    internal static Arguments Parse(string[] args)
    {
        if (args.Length == 0 || (args.Length & 1) != 0)
            throw new ArgumentException("Expected exact name/value argument pairs.");
        var allowed = new HashSet<string>(StringComparer.Ordinal)
        {
            "--authority-root", "--seed1-root", "--seed2-root", "--seed3-root", "--output",
            "--observed-unix", "--boot-id", "--nonce-created", "--response-received", "--current-sample",
            "--previous-bootstrap-root",
        };
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        for (var index = 0; index < args.Length; index += 2)
            if (!allowed.Contains(args[index]) || string.IsNullOrWhiteSpace(args[index + 1]) ||
                !values.TryAdd(args[index], args[index + 1]))
                throw new ArgumentException("An authority bootstrap argument is unknown, empty, or duplicated.");
        var required = allowed.Where(static value =>
            !string.Equals(value, "--previous-bootstrap-root", StringComparison.Ordinal));
        if (required.Any(value => !values.ContainsKey(value)))
            throw new ArgumentException("The authority bootstrap argument set is incomplete.");
        return new Arguments(values);
    }

    internal string Required(string name) => values[name];
    internal string? Optional(string name) => values.TryGetValue(name, out var value) ? value : null;
    internal ulong RequiredU64(string name) => ulong.TryParse(values[name], out var parsed)
        ? parsed
        : throw new ArgumentException($"{name} is not an unsigned integer.");
}

sealed record CustodyRole(
    string Role,
    string AuthorityIdHex,
    ulong KeyGeneration,
    string Ed25519PublicKeyHex,
    string CustodyDomainHashHex)
{
    internal byte[] Id() => Hex(AuthorityIdHex, 32, $"{Role} authority ID");
    internal byte[] PublicKey() => Hex(Ed25519PublicKeyHex, 32, $"{Role} public key");
    internal byte[] CustodyDomain() => Hex(CustodyDomainHashHex, 32, $"{Role} custody domain");
}

sealed record CustodyManifest(
    string Schema,
    string Environment,
    string AuthorityOwner,
    string NetworkIdHex,
    IReadOnlyList<CustodyRole> Roles)
{
    internal static CustodyManifest Load(string path)
    {
        var bytes = File.ReadAllBytes(ExistingFile(path));
        try
        {
            return JsonSerializer.Deserialize<CustodyManifest>(bytes,
                       new JsonSerializerOptions { PropertyNameCaseInsensitive = true })
                   ?? throw new InvalidDataException("The custody manifest is empty.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    internal CustodyRole Role(string role) => Roles.Single(value =>
        string.Equals(value.Role, role, StringComparison.Ordinal));
}

sealed class FileSigner :
    IXPointNetworkBootstrapRootSigner,
    IXPointNetworkWitnessSigner,
    IDisposable
{
    private readonly byte[] id;
    private readonly byte[] publicKey;
    private readonly byte[] custodyDomain;
    private readonly byte[] signingKeyBytes;
    private readonly bool root;

    private FileSigner(CustodyRole role, string seedPath, bool root)
    {
        this.root = root;
        id = role.Id();
        custodyDomain = role.CustodyDomain();
        KeyGeneration = role.KeyGeneration;
        var seed = ReadSeed(seedPath);
        try
        {
            var pair = PublicKeyAuth.GenerateKeyPair(seed);
            publicKey = pair.PublicKey.ToArray();
            signingKeyBytes = pair.PrivateKey.ToArray();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(seed);
        }
        var expected = role.PublicKey();
        try
        {
            if (!CryptographicOperations.FixedTimeEquals(expected, publicKey))
                throw new CryptographicException("A private signer seed differs from its custody manifest public key.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(expected);
        }
    }

    internal static FileSigner Root(CustodyRole role, string seedPath) => new(role, seedPath, true);
    internal static FileSigner Witness(CustodyRole role, string seedPath) => new(role, seedPath, false);

    public ReadOnlyMemory<byte> RootKeyId => root ? id.ToArray() : [];
    public ReadOnlyMemory<byte> SignerId => !root ? id.ToArray() : [];
    public ReadOnlyMemory<byte> WitnessId => !root ? id.ToArray() : [];
    public ulong KeyGeneration { get; }
    public ReadOnlyMemory<byte> Ed25519PublicKey => publicKey.ToArray();
    public ReadOnlyMemory<byte> CustodyDomainHash => root ? custodyDomain.ToArray() : [];
    public ReadOnlyMemory<byte> FailureDomainHash => !root ? custodyDomain.ToArray() : [];

    public ValueTask<int> SignAsync(
        XPointNetworkRootSigningRequest request,
        Memory<byte> signature64,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!root || !request.RootKeyId.Span.SequenceEqual(id) ||
            !request.ExpectedEd25519PublicKey.Span.SequenceEqual(publicKey) ||
            !request.CustodyDomainHash.Span.SequenceEqual(custodyDomain) ||
            request.KeyGeneration != KeyGeneration ||
            request.Purpose is not (XPointNetworkRootSignaturePurpose.GenesisAuthority or
                XPointNetworkRootSignaturePurpose.DirectoryTimeSourcePolicy or
                XPointNetworkRootSignaturePurpose.NetworkPolicy))
            throw new CryptographicException("The offline root rejected an out-of-policy signing request.");
        return Sign(request.SigningInput, signature64);
    }

    public ValueTask<int> SignAsync(
        XPointNetworkOperationalSigningRequest request,
        Memory<byte> signature64,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (root || !request.SignerId.Span.SequenceEqual(id) ||
            !request.ExpectedEd25519PublicKey.Span.SequenceEqual(publicKey) ||
            request.KeyGeneration != KeyGeneration ||
            request.Purpose is not (XPointNetworkOperationalSignaturePurpose.NetworkView or
                XPointNetworkOperationalSignaturePurpose.NetworkHead or
                XPointNetworkOperationalSignaturePurpose.DirectoryHead or
                XPointNetworkOperationalSignaturePurpose.MailboxTopology))
            throw new CryptographicException("The Registry witness rejected an out-of-policy signing request.");
        return Sign(request.SigningInput, signature64);
    }

    public ValueTask<ReadOnlyMemory<byte>> SignDtt1Async(
        ReadOnlyMemory<byte> signingInput,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (root) throw new CryptographicException("The offline root cannot sign DTT1.");
        return ValueTask.FromResult<ReadOnlyMemory<byte>>(
            PublicKeyAuth.SignDetached(signingInput.ToArray(), signingKeyBytes));
    }

    private ValueTask<int> Sign(ReadOnlyMemory<byte> input, Memory<byte> destination)
    {
        var signature = PublicKeyAuth.SignDetached(input.ToArray(), signingKeyBytes);
        try
        {
            signature.CopyTo(destination);
            return ValueTask.FromResult(signature.Length);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(signature);
        }
    }

    public void Dispose()
    {
        CryptographicOperations.ZeroMemory(signingKeyBytes);
        CryptographicOperations.ZeroMemory(id);
        CryptographicOperations.ZeroMemory(publicKey);
        CryptographicOperations.ZeroMemory(custodyDomain);
    }
}

sealed class NodeInput : IDisposable
{
    private readonly string name;
    private readonly string root;
    private readonly IDictionary<string, string> environment;
    private readonly byte[] ed25519Seed;
    private readonly byte[] ed25519SigningKeyBytes;
    private readonly byte[] publicKey;
    private readonly byte[] currentX25519;
    private readonly byte[] nextX25519;
    private readonly byte[][] roleSeeds;
    private readonly byte[][] rolePublicKeys;

    private NodeInput(string name, string root)
    {
        this.name = name;
        this.root = root;
        environment = ReadEnvironment(Path.Combine(root, ".env.node.prod"));
        var secrets = ExistingDirectory(Path.Combine(root, "secrets"));
        ed25519Seed = ReadSeed(Path.Combine(secrets, "key_ed25519"));
        var pair = PublicKeyAuth.GenerateKeyPair(ed25519Seed);
        publicKey = pair.PublicKey.ToArray();
        ed25519SigningKeyBytes = pair.PrivateKey.ToArray();
        if (!string.Equals(environment["DEEP_NODE_ED25519_PUBLIC_KEY"],
                Convert.ToHexString(publicKey).ToLowerInvariant(), StringComparison.Ordinal))
            throw new CryptographicException($"{name} Ed25519 seed does not match its public environment binding.");
        currentX25519 = ReadSeed(Path.Combine(secrets, "key_x25519"));
        nextX25519 = ReadOrCreateSeed(Path.Combine(secrets, "key_x25519_next"), hexEnvelope: true);
        var roleRoot = Path.Combine(secrets, "role-keys");
        Directory.CreateDirectory(roleRoot);
        roleSeeds = Enumerable.Range(0, 5).Select(index =>
            ReadOrCreateSeed(Path.Combine(roleRoot, $"role-{index}.ed25519.seed"), hexEnvelope: false)).ToArray();
        rolePublicKeys = roleSeeds.Select(static seed => PublicKeyAuth.GenerateKeyPair(seed).PublicKey.ToArray()).ToArray();
    }

    internal static NodeInput Load(string name, string root) => new(name, root);

    internal XPointNetworkOperationalNode ToOperationalNode(byte[] network)
    {
        var ip = IPAddress.Parse(environment["DEEP_NODE_PUBLIC_IP"]);
        var spkiRoot = ExistingDirectory(Path.Combine(root, "secrets", "ingress"));
        var currentSpki = ReadHexText(Path.Combine(spkiRoot, "current.spki-sha256"), 32, "current ingress SPKI");
        var nextSpki = ReadHexText(Path.Combine(spkiRoot, "next.spki-sha256"), 32, "next ingress SPKI");
        var identity = new NodeSigner(publicKey, ed25519SigningKeyBytes);
        var address = ip.GetAddressBytes();
        return new XPointNetworkOperationalNode(
            identity,
            HashDomain("Deep/XPoint/V1/staking-identity", publicKey),
            HashDomain("Deep/XPoint/V1/operator-id", Encoding.ASCII.GetBytes(environment["DEEP_OPERATOR_ADDRESS"])),
            HashDomain("Deep/XPoint/V1/host-id", address),
            HashDomain("Deep/XPoint/V1/provider-id", Encoding.ASCII.GetBytes("mr-x-self-operated")),
            0,
            0,
            HashDomain("Deep/XPoint/V1/origin-id", Encoding.ASCII.GetBytes(environment["DEEP_NODE_PUBLIC_HOST"])),
            ip,
            443,
            currentSpki,
            nextSpki,
            ScalarMult.Base(currentX25519),
            ScalarMult.Base(nextX25519),
            rolePublicKeys.Select(static key => (ReadOnlyMemory<byte>)key).ToArray());
    }

    private static IDictionary<string, string> ReadEnvironment(string path)
    {
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var line in File.ReadLines(ExistingFile(path)))
        {
            if (string.IsNullOrWhiteSpace(line) || line.StartsWith('#')) continue;
            var separator = line.IndexOf('=');
            if (separator <= 0 || !result.TryAdd(line[..separator], line[(separator + 1)..]))
                throw new InvalidDataException("A node production environment line is invalid or duplicated.");
        }
        foreach (var required in new[]
                 {
                     "DEEP_NODE_ED25519_PUBLIC_KEY", "DEEP_NODE_PUBLIC_IP", "DEEP_NODE_PUBLIC_HOST",
                     "DEEP_OPERATOR_ADDRESS",
                 })
            if (!result.TryGetValue(required, out var value) || string.IsNullOrWhiteSpace(value))
                throw new InvalidDataException($"A node production environment is missing {required}.");
        return result;
    }

    private static byte[] ReadHexText(string path, int length, string name) =>
        Hex(File.ReadAllText(ExistingFile(path)).TrimEnd('\r', '\n'), length, name);

    private static byte[] ReadOrCreateSeed(string path, bool hexEnvelope)
    {
        if (File.Exists(path)) return ReadSeed(path);
        var seed = RandomNumberGenerator.GetBytes(32);
        try
        {
            if (hexEnvelope)
                WriteNew(path, Encoding.ASCII.GetBytes(Convert.ToHexString(seed).ToLowerInvariant() + "\n"));
            else
                WriteNew(path, seed);
            return seed.ToArray();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(seed);
        }
    }

    public void Dispose()
    {
        CryptographicOperations.ZeroMemory(ed25519Seed);
        CryptographicOperations.ZeroMemory(ed25519SigningKeyBytes);
        CryptographicOperations.ZeroMemory(publicKey);
        CryptographicOperations.ZeroMemory(currentX25519);
        CryptographicOperations.ZeroMemory(nextX25519);
        foreach (var value in roleSeeds) CryptographicOperations.ZeroMemory(value);
        foreach (var value in rolePublicKeys) CryptographicOperations.ZeroMemory(value);
    }
}

sealed class NodeSigner(byte[] publicKey, byte[] signingKeyBytes) : IXPointNetworkOperationalSigner
{
    public ReadOnlyMemory<byte> SignerId => publicKey.ToArray();
    public ulong KeyGeneration => 0;
    public ReadOnlyMemory<byte> Ed25519PublicKey => publicKey.ToArray();

    public ValueTask<int> SignAsync(
        XPointNetworkOperationalSigningRequest request,
        Memory<byte> signature64,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (request.Purpose != XPointNetworkOperationalSignaturePurpose.NodeDescriptor ||
            !request.SignerId.Span.SequenceEqual(publicKey) ||
            !request.ExpectedEd25519PublicKey.Span.SequenceEqual(publicKey) ||
            request.KeyGeneration != 0)
            throw new CryptographicException("A node identity rejected an out-of-policy signing request.");
        var signature = PublicKeyAuth.SignDetached(request.SigningInput.ToArray(), signingKeyBytes);
        try
        {
            signature.CopyTo(signature64);
            return ValueTask.FromResult(signature.Length);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(signature);
        }
    }
}

sealed record ArtifactEntry(string Role, int Ordinal, string FileName, int Length, string Sha256Hex);
sealed record ArtifactInventory(
    string Format,
    string NetworkIdHex,
    string GenesisAuthorityCoreHashHex,
    ushort SupportedReader,
    string SnapshotNonceHex,
    string SnapshotQueryLeafHex,
    string SnapshotBootIdHex,
    ulong SnapshotNonceCreatedAt,
    ulong SnapshotResponseReceivedAt,
    ulong SnapshotCurrentSample,
    IReadOnlyList<ArtifactEntry> Artifacts);
sealed record PublicBootstrapManifest(
    string Schema,
    string AuthorityOwner,
    string NetworkIdHex,
    string GenesisAuthorityCoreHashHex,
    string DirectoryLeafKeyHex,
    ulong NotBeforeUnixSeconds,
    ulong ExpiresAtUnixSeconds,
    IReadOnlyList<ArtifactEntry> Artifacts);

sealed class ByteArrayComparer : IComparer<byte[]>
{
    internal static readonly ByteArrayComparer Instance = new();
    public int Compare(byte[]? left, byte[]? right) => left.AsSpan().SequenceCompareTo(right);
}

static class BootstrapIo
{
    internal static string NewDirectoryPath(string value)
    {
        var path = Path.GetFullPath(value);
        if (File.Exists(path) || Directory.Exists(path))
            throw new IOException("The production bootstrap output already exists.");
        var parent = Path.GetDirectoryName(path);
        if (string.IsNullOrEmpty(parent) || !Directory.Exists(parent) ||
            (File.GetAttributes(parent) & FileAttributes.ReparsePoint) != 0)
            throw new InvalidDataException("The production bootstrap output parent is unavailable.");
        return path;
    }

    internal static string ExistingDirectory(string value)
    {
        var path = Path.GetFullPath(value);
        if (!Directory.Exists(path) || (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new InvalidDataException("A required protected directory is unavailable.");
        return path;
    }

    internal static string ExistingFile(string path)
    {
        path = Path.GetFullPath(path);
        if (!File.Exists(path) || (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new InvalidDataException("A required protected file is unavailable.");
        return path;
    }

    internal static byte[] ReadSeed(string path)
    {
        var bytes = File.ReadAllBytes(ExistingFile(path));
        if (bytes.Length == 32 && bytes.AsSpan().IndexOfAnyExcept((byte)0) >= 0)
            return bytes;
        try
        {
            var text = Encoding.ASCII.GetString(bytes).TrimEnd('\r', '\n');
            if (text.StartsWith("0x", StringComparison.Ordinal)) text = text[2..];
            var parsed = Hex(text, 32, "Ed25519/X25519 seed");
            CryptographicOperations.ZeroMemory(bytes);
            return parsed;
        }
        catch
        {
            CryptographicOperations.ZeroMemory(bytes);
            throw;
        }
    }

    internal static byte[] Hex(string exact, int length, string name)
    {
        if (exact.Length != length * 2 || exact.Any(static value =>
            value is not (>= '0' and <= '9' or >= 'a' and <= 'f' or >= 'A' and <= 'F')))
            throw new InvalidDataException($"The {name} is not exact {length}-byte hexadecimal data.");
        var value = Convert.FromHexString(exact);
        if (value.AsSpan().IndexOfAnyExcept((byte)0) < 0)
            throw new InvalidDataException($"The {name} must be non-zero.");
        return value;
    }

    internal static byte[] HashDomain(string domain, ReadOnlySpan<byte> value)
    {
        var label = Encoding.ASCII.GetBytes(domain);
        var input = new byte[label.Length + 1 + value.Length];
        label.CopyTo(input, 0);
        value.CopyTo(input.AsSpan(label.Length + 1));
        var result = SHA256.HashData(input);
        CryptographicOperations.ZeroMemory(input);
        return result;
    }

    internal static void WriteNew(string path, ReadOnlySpan<byte> bytes)
    {
        using var stream = new FileStream(
            path, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough);
        stream.Write(bytes);
        stream.Flush(true);
    }
}
