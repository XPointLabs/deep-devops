using System.Security.Cryptography;
using Deep.Protocol.XPointNetworkV1;
using static BootstrapIo;

// Offline prepared bytes only. Operational completion and distribution remain
// separate commands; this never publishes to Registry or advances a host floor.
internal static class AuthorityRenewalCeremony
{
    internal static async Task RunAsync(Arguments arguments)
    {
        var sourceRoot = ExistingDirectory(arguments.Required("--renew-authority-from"));
        var custodyRoot = ExistingDirectory(arguments.Required("--authority-root"));
        var output = NewDirectoryPath(arguments.Required("--output"));
        var network = Hex(arguments.Required("--network-id-hex"), 16, "independent network");
        var genesis = Hex(arguments.Required("--genesis-core-hash"), 32, "independent genesis");
        var expectedAuthority = Hex(arguments.Required("--protected-authority-core-hash"), 32, "accepted authority hash");
        var expectedPolicy = Hex(arguments.Required("--protected-dts1-policy-hash"), 32, "accepted DTS policy hash");
        var observed = arguments.RequiredU64("--observed-unix");
        var authorityExpires = arguments.RequiredU64("--authority-expires-unix");
        var policyExpires = arguments.RequiredU64("--time-policy-expires-unix");
        var source = SuccessorCeremony.ReadSource(sourceRoot);
        var manifest = CustodyManifest.Load(Path.Combine(custodyRoot, "public", "custody-manifest.v1.json"));
        if (manifest.Schema != "deep-production-authority-custody.v1" ||
            manifest.Roles is null || manifest.Roles.Count is < 1 or > 256 ||
            manifest.Roles.Any(static role => role is null) ||
            manifest.Roles.Count(static role => role.Role == "offline-root-1") != 1 ||
            manifest.Environment != "prod" || manifest.AuthorityOwner != "Mr. X" ||
            source.Manifest.AuthorityOwner != "Mr. X" ||
            !Fixed(Hex(manifest.NetworkIdHex, 16, "custody network"), network) ||
            !Fixed(Hex(source.Manifest.NetworkIdHex, 16, "source network"), network) ||
            !Fixed(Hex(source.Manifest.GenesisAuthorityCoreHashHex, 32, "source genesis"), genesis))
            throw new CryptographicException("Offline authority renewal scope differs from independent pins/custody.");
        var predecessor = source.VerifyAuthority(new XPointNetworkGenesisPin(network, genesis));
        if (!Fixed(predecessor.AuthorityCoreHash.Span, expectedAuthority) ||
            !Fixed(predecessor.TimeSourcePolicyHash.Span, expectedPolicy))
            throw new CryptographicException("Offline renewal source differs from independently accepted predecessor hashes.");
        // Check public ownership before even opening the private root file.
        var role = manifest.Role("offline-root-1");
        if (predecessor.RootThreshold != 1 || !predecessor.RootKeys.Any(key =>
                key.Generation == role.KeyGeneration && Fixed(key.Id.Span, role.Id()) &&
                Fixed(key.Ed25519PublicKey.Span, role.PublicKey())))
            throw new CryptographicException("This offline command requires the existing single-root custody; it cannot collapse a threshold.");
        var policies = source.Many("dts1").Select(static value => (ReadOnlyMemory<byte>)value).ToArray();
        if (policies.Length >= XPointNetworkClosureWireCodec.MaximumChainCount)
            throw new InvalidDataException("Authority renewal cannot exceed the distribution history bound.");
        using var root = FileSigner.Root(role, ExistingFile(Path.Combine(custodyRoot, "private", "offline-root-1.ed25519.seed")));
        var ceremony = HashDomain("Deep/XPoint/V1/offline-authority-renewal-ceremony",
            [.. network, .. expectedAuthority, .. expectedPolicy,
             .. U64(observed), .. U64(authorityExpires), .. U64(policyExpires)]);
        var authored = await XPointNetworkBootstrapAuthor.AuthorSameKeyRenewalAsync(ceremony,
            predecessor, policies, observed, observed, authorityExpires, observed, policyExpires, [root]);
        var authorities = source.Many("xna1").Select(static value => (ReadOnlyMemory<byte>)value).ToArray();
        _ = XPointNetworkAuthorityVerifier.Verify(new XPointNetworkGenesisPin(network, genesis),
            [.. authorities, authored.ExactXna1], [.. policies, authored.ExactDts1]);
        var records = new List<(string Role, byte[] Bytes)>();
        foreach (var name in source.Manifest.Artifacts.Select(entry => entry.Role).Distinct(StringComparer.Ordinal))
        {
            records.AddRange(source.Many(name).Select(value => (name, value)));
            if (name == "xna1") records.Add((name, authored.ExactXna1.ToArray()));
            if (name == "dts1") records.Add((name, authored.ExactDts1.ToArray()));
        }
        if (records.Count > 8192 || records.Sum(static item => (long)item.Bytes.Length) >
            XPointNetworkClosureWireCodec.MaximumResponseLength)
            throw new InvalidDataException("Prepared authority inventory exceeds its existing source bound.");
        SuccessorCeremony.WritePublicInventory(output, source, SuccessorCeremony.PreparedAuthoritySchema,
            records, observed, authorityExpires);
        Console.WriteLine("Offline same-key authority renewal prepared; no operational activation, publication or floor advance.");
    }

    private static byte[] U64(ulong value)
    {
        var bytes = new byte[8];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(bytes, value);
        return bytes;
    }
    private static bool Fixed(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b) =>
        a.Length == b.Length && CryptographicOperations.FixedTimeEquals(a, b);
}
