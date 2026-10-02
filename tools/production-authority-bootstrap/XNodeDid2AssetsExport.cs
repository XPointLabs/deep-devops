using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.Identity;
using Deep.Protocol.XPointNetworkV1;
using static BootstrapIo;

// Public install inputs only. Neither this export nor its Enabled flags mint
// freshness/receive authority; the UAT host must obtain its own nonce-fresh proof.
internal static class XNodeDid2AssetsExport
{
    private const string Mount = "/run/did2-network/";

    internal static void Run(Arguments arguments)
    {
        var output = NewDirectoryPath(arguments.Required("--output"));
        RejectLinks(output);
        var network = Hex(arguments.Required("--network-id-hex"), 16, "network scope");
        var genesis = Hex(arguments.Required("--genesis-core-hash"), 32, "authority genesis pin");
        var headPin = Hex(arguments.Required("--genesis-head-core-hash"), 32, "directory genesis pin");
        var expected = Hex(arguments.Required("--expected-bundle-sha256"), 32, "public bundle digest");
        var body = ReadBounded(arguments.Required("--export-xnode-did2-assets"),
            XPointNetworkClosureWireCodec.MaximumResponseLength);
        if (!CryptographicOperations.FixedTimeEquals(SHA256.HashData(body), expected))
            throw new CryptographicException("The public network bundle differs from its independent digest.");
        var bundle = XPointNetworkClosureWireCodec.DecodeResponse(body);
        if (!bundle.NetworkId.Span.SequenceEqual(network))
            throw new CryptographicException("The public network bundle belongs to another scope.");
        var authority = XPointNetworkAuthorityVerifier.Verify(
            new XPointNetworkGenesisPin(network, genesis),
            bundle.ExactAuthorityChain, bundle.ExactTimePolicyChain);
        var head = ReadBounded(arguments.Required("--genesis-head-path"),
            XPointNetworkClosureWireCodec.MaximumRecordLength);
        _ = DeepIdV2DirectoryBootstrapVerifier.RestoreGenesis(authority, head, headPin);
        var observer = ReadObserver(arguments.Required("--observer-contact-file"));
        var origin = arguments.Required("--registry-origin");
        if (!Uri.TryCreate(origin, UriKind.Absolute, out var uri) ||
            uri.Scheme != Uri.UriSchemeHttps || uri.UserInfo.Length != 0 ||
            uri.Query.Length != 0 || uri.Fragment.Length != 0 ||
            uri.AbsolutePath != "/" || uri.AbsoluteUri != origin)
            throw new InvalidDataException("Registry requires a canonical HTTPS root origin.");

        // Validate all inputs before creating any output. Move a complete unique
        // sibling directory into place; an existing target is never rewritten.
        var staging = output + ".staging-" + Guid.NewGuid().ToString("N");
        Directory.CreateDirectory(staging);
        try
        {
            var records = new List<ArtifactEntry>();
            string[] Export(string role, IReadOnlyList<ReadOnlyMemory<byte>> values)
            {
                var paths = new string[values.Count];
                for (var ordinal = 0; ordinal < values.Count; ordinal++)
                {
                    var name = $"{role}.{ordinal:D4}.bin";
                    WriteNew(Path.Combine(staging, name), values[ordinal].Span);
                    paths[ordinal] = Mount + name;
                    records.Add(new(role, ordinal, name, values[ordinal].Length,
                        Convert.ToHexString(SHA256.HashData(values[ordinal].Span))));
                }
                return paths;
            }
            var authorities = Export("xna1", bundle.ExactAuthorityChain);
            var timePolicies = Export("dts1", bundle.ExactTimePolicyChain);
            var policies = Export("xvp1", bundle.ExactNetworkPolicyChain);
            var views = Export("xnv1", bundle.ExactViewChain);
            var heads = Export("xnh1", bundle.ExactHeadChain);
            var nodes = Export("xnd1", bundle.ExactActiveNodeDescriptors);
            var projections = Export("pmt2", bundle.ExactPlacementTopologyChain);
            _ = Export("pma2", bundle.ExactMailboxAuthorityChain);
            WriteNew(Path.Combine(staging, "genesis.adh1"), head);
            WriteNew(Path.Combine(staging, "observer.did2"), observer);
            var configuration = new
            {
                DeepIdV2DirectoryProof = new
                {
                    Enabled = true, RegistryOrigin = origin,
                    NetworkIdHex = Convert.ToHexString(network),
                    GenesisAuthorityCoreHashHex = Convert.ToHexString(genesis),
                    ExactAuthorityPaths = authorities, ExactTimePolicyPaths = timePolicies,
                    GenesisHeadPath = Mount + "genesis.adh1",
                    GenesisHeadCoreHashHex = Convert.ToHexString(headPin),
                    StateRelativeDirectory = "did2-proof-state",
                    DataProtectionKeysRelativeDirectory = "did2-proof-keys",
                    DeploymentProfileId = 1, RequestTimeoutSeconds = 10,
                },
                DeepIdV2NetworkPlacement = new
                {
                    Enabled = true, ExactPolicyPaths = policies, ExactViewPaths = views,
                    ExactHeadPaths = heads, ExactActiveNodePaths = nodes,
                    ExactMailboxProjectionPaths = projections,
                    PublicObservationDid2Path = Mount + "observer.did2",
                },
                DeepIdV2ReplicaStage = new { Enabled = true },
            };
            var exactConfiguration = JsonSerializer.SerializeToUtf8Bytes(configuration,
                new JsonSerializerOptions { WriteIndented = true });
            WriteNew(Path.Combine(staging, "xnode.did2.json"), exactConfiguration);
            WriteNew(Path.Combine(staging, "public-assets.v2.json"),
                JsonSerializer.SerializeToUtf8Bytes(new
                {
                    schema = "deep-xnode-did2-public-assets.v2", authorityOwner = "Mr. X",
                    bundleSha256 = Convert.ToHexString(expected), artifacts = records,
                    genesisHeadSha256 = Convert.ToHexString(SHA256.HashData(head)),
                    observerDid2Sha256 = Convert.ToHexString(SHA256.HashData(observer)),
                    configurationSha256 = Convert.ToHexString(SHA256.HashData(exactConfiguration)),
                    currentTimeEvidence = false, deploymentEvidence = false,
                }));
            Directory.Move(staging, output);
            Console.WriteLine($"Public DID2 host assets exported: records={records.Count}, views={views.Length}; no freshness or deployment evidence.");
        }
        finally
        {
            // Only our random, newly created staging directory is eligible.
            if (Directory.Exists(staging)) Directory.Delete(staging, recursive: true);
        }
    }

    private static byte[] ReadObserver(string path)
    {
        var bytes = ReadBounded(path, 8_192);
        try
        {
            var text = new UTF8Encoding(false, true).GetString(bytes).Replace("\r\n", "\n");
            if (text.EndsWith('\n')) text = text[..^1];
            var lines = text.Split('\n');
            if (lines.Length != 2 || lines[0].Length != 90 ||
                lines[1].Length != DeepIdV2Codec.Did2Length * 2)
                throw new InvalidDataException("Observer input requires exactly one descriptor and public DID2.");
            var exact = Hex(lines[1], DeepIdV2Codec.Did2Length, "public observer DID2");
            if (!DeepPermanentIdV2.ParseCanonical(lines[0]).MatchesExactCredential(
                    DeepIdV2Codec.DecodeDid2(exact)))
                throw new CryptographicException("The observer descriptor does not bind the public DID2.");
            // The descriptor/read capability and all account/device secrets
            // are deliberately excluded from the install directory.
            return exact;
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    private static byte[] ReadBounded(string path, int maximum)
    {
        path = Path.GetFullPath(path);
        RejectLinks(path);
        using var stream = new FileStream(ExistingFile(path), FileMode.Open,
            FileAccess.Read, FileShare.Read);
        if (stream.Length is < 1 || stream.Length > maximum)
            throw new InvalidDataException("A public install input exceeds its size bound.");
        var bytes = new byte[checked((int)stream.Length)];
        stream.ReadExactly(bytes);
        if (stream.ReadByte() != -1)
            throw new InvalidDataException("A public install input changed while reading.");
        return bytes;
    }

    private static void RejectLinks(string path)
    {
        for (string? current = Path.GetFullPath(path); !string.IsNullOrEmpty(current);
             current = Path.GetDirectoryName(current))
            if ((File.Exists(current) || Directory.Exists(current)) &&
                (File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                throw new InvalidDataException("Public host asset paths must not traverse links.");
    }
}
