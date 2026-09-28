using System.Security.Cryptography;
using Deep.Protocol.XPointNetworkV1;
using static BootstrapIo;

/// <summary>Copies exact public signed records into NCP2, retaining every
/// predecessor. No signer, account proof, clock or protected floor is opened.
/// This verifies the configured genesis and inventory/prefix binding only;
/// clients must independently verify the complete closure and live freshness.</summary>
internal static class NetworkClosureExport
{
    internal static void Run(Arguments arguments)
    {
        var network = Hex(arguments.Required("--network-id-hex"), 16, "independent network ID");
        var genesis = Hex(arguments.Required("--genesis-core-hash"), 32, "independent genesis core hash");
        var pin = new XPointNetworkGenesisPin(network, genesis);
        var output = Path.GetFullPath(arguments.Required("--output"));
        RejectLinks(output);
        _ = ExistingDirectory(Path.GetDirectoryName(output)!);
        if (File.Exists(output) || Directory.Exists(output))
            throw new IOException("The public network bundle output already exists.");
        byte[] exact;
        if (arguments.IsNetworkClosureExport && !arguments.IsNetworkClosureExtension)
        {
            var source = Source(arguments.Required("--export-network-genesis"), pin,
                "deep-production-authority-bootstrap.v1");
            exact = XPointNetworkClosureWireCodec.EncodeResponse(network,
                Single(source.One("xna1")), Single(source.One("dts1")),
                Single(source.One("xvp1")), Single(source.One("xnv1")),
                Single(source.One("xnh1")), Memories(source.Many("xnd1")),
                Single(source.One("pmt2")));
        }
        else
        {
            var basePath = Path.GetFullPath(arguments.Required("--extend-network-closure"));
            RejectLinks(basePath);
            _ = ExistingFile(basePath);
            using var stream = new FileStream(basePath, FileMode.Open, FileAccess.Read, FileShare.Read);
            if (stream.Length is < 28 or > XPointNetworkClosureWireCodec.MaximumResponseLength)
                throw new InvalidDataException("The public base network bundle exceeds its bound.");
            var body = new byte[checked((int)stream.Length)];
            stream.ReadExactly(body);
            if (stream.ReadByte() != -1)
                throw new InvalidDataException("The public base network bundle changed while reading.");
            var prior = XPointNetworkClosureWireCodec.DecodeResponse(body);
            if (!Fixed(prior.NetworkId.Span, network))
                throw new CryptographicException("The public base network belongs to another scope.");
            _ = XPointNetworkAuthorityVerifier.Verify(pin,
                prior.ExactAuthorityChain, prior.ExactTimePolicyChain);
            var source = Source(arguments.Required("--network-successor-source"), pin,
                "deep-production-operational-successor.v1");
            exact = Extend(prior, source, pin);
        }
        WriteNew(output, exact);
        Console.WriteLine($"Public NCP2 bundle exported: bytes={exact.Length}, sha256={Convert.ToHexString(SHA256.HashData(exact))}; not current-time or deployment evidence.");
    }

    private static SuccessorCeremony.SourceArtifacts Source(string root,
        XPointNetworkGenesisPin pin, string schema)
    {
        root = Path.GetFullPath(root);
        RejectLinks(root);
        // ReadSource checks every manifest length/hash/canonical path. Check
        // all ancestors as well; a public input must not traverse custody links.
        RejectLinks(Path.Combine(root, "bootstrap"));
        var source = SuccessorCeremony.ReadSource(ExistingDirectory(root),
            XPointNetworkClosureWireCodec.MaximumResponseLength);
        if (source.Manifest.Schema != schema || source.Manifest.AuthorityOwner != "Mr. X" ||
            !Fixed(Hex(source.Manifest.NetworkIdHex, 16, "source network"), pin.NetworkId.Span) ||
            !Fixed(Hex(source.Manifest.GenesisAuthorityCoreHashHex, 32, "source genesis"),
                pin.AuthorityCoreHash.Span))
            throw new CryptographicException("The public source differs from the independent genesis scope.");
        _ = XPointNetworkBootstrapAuthor.VerifyExistingGenesis(source.One("xna1"),
            source.One("dts1"), pin);
        return source;
    }

    internal static byte[] Extend(XPointNetworkClosureWireArtifacts prior,
        SuccessorCeremony.SourceArtifacts source, XPointNetworkGenesisPin pin)
    {
        // Operational successor exports retain the complete XNV1 prefix but
        // only the latest XNH1/XVP1/PMT2. Never manufacture missing history.
        var views = source.Many("xnv1");
        var previousAuthority = prior.ExactAuthorityChain;
        var previousTime = prior.ExactTimePolicyChain;
        var previousViews = prior.ExactViewChain;
        if (!Fixed(prior.NetworkId.Span, pin.NetworkId.Span) ||
            previousAuthority.Count != 1 || previousTime.Count != 1 ||
            !Fixed(previousAuthority[0].Span, source.One("xna1")) ||
            !Fixed(previousTime[0].Span, source.One("dts1")) ||
            views.Count != previousViews.Count + 1 ||
            views.Take(previousViews.Count).Where((view, index) =>
                !Fixed(view, previousViews[index].Span)).Any())
            throw new CryptographicException("The public successor is not an exact one-step extension of retained history.");
        return XPointNetworkClosureWireCodec.EncodeResponse(pin.NetworkId.Span,
            previousAuthority, previousTime,
            Append(prior.ExactNetworkPolicyChain, source.One("xvp1")), Memories(views),
            Append(prior.ExactHeadChain, source.One("xnh1")), Memories(source.Many("xnd1")),
            Append(prior.ExactPlacementTopologyChain, source.One("pmt2")));
    }

    private static IReadOnlyList<ReadOnlyMemory<byte>> Append(
        IReadOnlyList<ReadOnlyMemory<byte>> prior, byte[] current) =>
        Fixed(prior[^1].Span, current) ? prior : [.. prior, current];
    private static ReadOnlyMemory<byte>[] Single(byte[] value) => [value];
    private static ReadOnlyMemory<byte>[] Memories(IReadOnlyList<byte[]> values) =>
        values.Select(static value => (ReadOnlyMemory<byte>)value).ToArray();
    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);

    private static void RejectLinks(string path)
    {
        for (string? current = Path.GetFullPath(path); !string.IsNullOrEmpty(current);
             current = Path.GetDirectoryName(current))
            if ((File.Exists(current) || Directory.Exists(current)) &&
                (File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                throw new InvalidDataException("Public network bundle paths must not traverse links.");
    }
}
