using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ContactV1;
using Deep.Protocol.XPointNetworkV1;
using Sodium;
using static BootstrapIo;

internal static class SuccessorCeremony
{
    private const string GenesisSchema = "deep-production-authority-bootstrap.v1";
    private const string SuccessorSchema = "deep-production-operational-successor.v1";
    private static readonly HashSet<string> AllowedSourceRoles = new(StringComparer.Ordinal)
    {
        "xna1", "dts1", "adh1", "snapshot-dtt1", "snapshot-adp1", "response-adp1",
        "xvp1", "xnd1", "xnv1", "xnh1", "pma2", "pmt2", "caller-adh1",
    };

    internal static async Task RunAsync(Arguments arguments)
    {
        var authorityRoot = ExistingDirectory(arguments.Required("--authority-root"));
        var sourceRoot = ExistingDirectory(arguments.Required("--successor-from"));
        var rolloverRoot = ExistingDirectory(arguments.Required("--rollover-root"));
        var outputRoot = NewDirectoryPath(arguments.Required("--output"));
        var observedUnix = arguments.RequiredU64("--observed-unix");
        if (observedUnix <= 60)
            throw new ArgumentOutOfRangeException(nameof(observedUnix));
        var notBefore = observedUnix - 60;
        var expiresAt = checked(notBefore + 86_400);
        var expectedHeadHash = Hex(arguments.Required("--protected-head-core-hash"), 32, "protected head core hash");
        var expectedPmtHash = Hex(arguments.Required("--protected-pmt-artifact-hash"), 32, "protected PMT artifact hash");
        var expectedAdhHash = Hex(arguments.Required("--current-adh1-core-hash"), 32, "current ADH1 core hash");
        var exactAdh = File.ReadAllBytes(ExistingFile(arguments.Required("--current-adh1-path")));
        try
        {
            var manifest = CustodyManifest.Load(Path.Combine(authorityRoot, "public", "custody-manifest.v1.json"));
            if (!string.Equals(manifest.Environment, "prod", StringComparison.Ordinal) ||
                !string.Equals(manifest.AuthorityOwner, "Mr. X", StringComparison.Ordinal))
                throw new InvalidDataException("The successor custody manifest is outside the approved production boundary.");
            var network = Hex(manifest.NetworkIdHex, 16, "network ID");
            var source = ReadSource(sourceRoot);
            var sourceNetwork = Hex(source.Manifest.NetworkIdHex, 16, "source network ID");
            var genesisHash = Hex(source.Manifest.GenesisAuthorityCoreHashHex, 32, "source genesis hash");
            try
            {
                if (!CryptographicOperations.FixedTimeEquals(network, sourceNetwork) ||
                    !string.Equals(source.Manifest.AuthorityOwner, "Mr. X", StringComparison.Ordinal))
                    throw new CryptographicException("The protected source belongs to another production authority.");
                var bootstrap = XPointNetworkBootstrapAuthor.VerifyExistingGenesis(
                    source.One("xna1"), source.One("dts1"),
                    new XPointNetworkGenesisPin(network, genesisHash));
                var adh = AccountDirectoryAdh1Codec.Decode(exactAdh);
                var actualAdhHash = XPointNetworkOperationalSuccessorAuthor.ComputeAdh1CoreHash(exactAdh);
                if (!CryptographicOperations.FixedTimeEquals(actualAdhHash, expectedAdhHash) ||
                    !adh.NetworkId.Span.SequenceEqual(network))
                    throw new CryptographicException("The exact ADH1 does not match the independently supplied current directory head.");
                var queryLeaf = HashDomain(
                    "Deep/XPoint/V1/contact-authority-bootstrap-leaf",
                    manifest.Role("contact-xpk").PublicKey());
                if (!string.Equals(Convert.ToHexString(queryLeaf),
                        source.Manifest.DirectoryLeafKeyHex, StringComparison.OrdinalIgnoreCase))
                    throw new CryptographicException("The source directory leaf key differs from current custody.");

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
                using var seed1 = NodeRolloverCustody.Load(
                    "seed1", arguments.Required("--seed1-root"), rolloverRoot, notBefore, expiresAt);
                using var seed2 = NodeRolloverCustody.Load(
                    "seed2", arguments.Required("--seed2-root"), rolloverRoot, notBefore, expiresAt);
                using var seed3 = NodeRolloverCustody.Load(
                    "seed3", arguments.Required("--seed3-root"), rolloverRoot, notBefore, expiresAt);
                var ceremony = HashDomain("Deep/XPoint/V1/operational-successor-ceremony",
                    Join(network, expectedHeadHash, expectedPmtHash, U64(observedUnix)));
                var request = new XPointNetworkOperationalSuccessorRequest(
                    ceremony, bootstrap, [root], [witness1, witness2, witness3],
                    [seed1.Rollover, seed2.Rollover, seed3.Rollover],
                    source.One("xvp1"),
                    source.Many("xnd1").Select(static value => (ReadOnlyMemory<byte>)value).ToArray(),
                    source.Many("xnv1").Select(static value => (ReadOnlyMemory<byte>)value).ToArray(),
                    source.One("xnh1"), source.One("pma2"), source.One("pmt2"),
                    expectedHeadHash, expectedPmtHash,
                    CoreReference("ADH1", actualAdhHash),
                    notBefore, notBefore, expiresAt);
                var authored = await XPointNetworkOperationalSuccessorAuthor.AuthorAsync(request);
                WriteOutput(outputRoot, source, authored, exactAdh, notBefore, expiresAt);
                Console.WriteLine("A monotonic operational successor was authored; no host or Registry state was changed.");
                Console.WriteLine($"Protected predecessor XNH1 core: {Convert.ToHexString(expectedHeadHash)}");
                Console.WriteLine($"Successor XNH1 core: {Convert.ToHexString(
                    XPointNetworkOperationalSuccessorAuthor.ComputeXnh1CoreHash(authored.ExactXnh1.Span))}");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(network);
                CryptographicOperations.ZeroMemory(sourceNetwork);
                CryptographicOperations.ZeroMemory(genesisHash);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(expectedHeadHash);
            CryptographicOperations.ZeroMemory(expectedPmtHash);
            CryptographicOperations.ZeroMemory(expectedAdhHash);
            CryptographicOperations.ZeroMemory(exactAdh);
        }
    }

    internal static SourceArtifacts ReadSource(string sourceRoot,
        long maximumArtifactBytes = long.MaxValue)
    {
        if (maximumArtifactBytes < 1) throw new ArgumentOutOfRangeException(nameof(maximumArtifactBytes));
        var manifestPath = ExistingFile(Path.Combine(sourceRoot, "public-manifest.v1.json"));
        var manifest = JsonSerializer.Deserialize<PublicBootstrapManifest>(
                           ReadBounded(manifestPath, 4_194_304),
                           new JsonSerializerOptions { PropertyNameCaseInsensitive = true })
                       ?? throw new InvalidDataException("The prior public artifact manifest is empty.");
        if (manifest.Schema is not (GenesisSchema or SuccessorSchema) ||
            manifest.Artifacts is null || manifest.Artifacts.Count is < 1 or > 8192 ||
            manifest.Artifacts.Any(static entry => entry.Length is < 1 or > 1_048_576) ||
            manifest.Artifacts.Sum(static entry => (long)entry.Length) > maximumArtifactBytes)
            throw new InvalidDataException("The prior artifact manifest has an unsupported schema or empty inventory.");
        var bootstrapDir = ExistingDirectory(Path.Combine(sourceRoot, "bootstrap"));
        var artifacts = new Dictionary<(string Role, int Ordinal), byte[]>();
        foreach (var entry in manifest.Artifacts)
        {
            if (!AllowedSourceRoles.Contains(entry.Role) ||
                entry.Ordinal < 0 || entry.Length is < 1 or > 1_048_576 ||
                !string.Equals(entry.FileName, $"{entry.Role}.{entry.Ordinal:D4}.bin", StringComparison.Ordinal) ||
                !artifacts.TryAdd((entry.Role, entry.Ordinal), []))
                throw new InvalidDataException("A protected source artifact has a duplicate or noncanonical path.");
            var path = ExistingFile(Path.Combine(bootstrapDir, entry.FileName));
            var bytes = ReadBounded(path, 1_048_576, entry.Length);
            if (bytes.Length != entry.Length ||
                !string.Equals(Convert.ToHexString(SHA256.HashData(bytes)),
                    entry.Sha256Hex, StringComparison.OrdinalIgnoreCase))
                throw new CryptographicException("A protected source artifact differs from its inventory hash.");
            artifacts[(entry.Role, entry.Ordinal)] = bytes;
        }
        return new SourceArtifacts(manifest, artifacts);
    }

    private static byte[] ReadBounded(string path, int maximum, int? expectedLength = null)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (expectedLength is not null && stream.Length != expectedLength)
            throw new CryptographicException("A protected source artifact differs from its inventory length.");
        if (stream.Length is < 1 || stream.Length > maximum)
            throw new InvalidDataException("A public source file exceeds its read bound.");
        var bytes = new byte[checked((int)stream.Length)];
        stream.ReadExactly(bytes);
        if (stream.ReadByte() != -1)
            throw new InvalidDataException("A public source file changed while reading.");
        return bytes;
    }

    private static void WriteOutput(
        string outputRoot,
        SourceArtifacts source,
        AuthoredXPointNetworkOperationalSuccessor authored,
        ReadOnlySpan<byte> exactAdh,
        ulong notBefore,
        ulong expiresAt)
    {
        Directory.CreateDirectory(outputRoot);
        var bootstrapDir = Path.Combine(outputRoot, "bootstrap");
        Directory.CreateDirectory(bootstrapDir);
        var artifacts = new List<(string Role, byte[] Bytes)>
        {
            ("xna1", source.One("xna1")),
            ("dts1", source.One("dts1")),
            ("adh1", exactAdh.ToArray()),
            ("xvp1", authored.ExactXvp1.ToArray()),
        };
        artifacts.AddRange(source.Many("xnv1").Select(static value => ("xnv1", value.ToArray())));
        artifacts.Add(("xnv1", authored.ExactXnv1.ToArray()));
        artifacts.Add(("xnh1", authored.ExactXnh1.ToArray()));
        artifacts.AddRange(authored.ExactXnd1.Select(static value => ("xnd1", value.ToArray())));
        artifacts.Add(("pma2", authored.ExactPma2.ToArray()));
        artifacts.Add(("pmt2", authored.ExactPmt2.ToArray()));
        var entries = new List<ArtifactEntry>();
        foreach (var group in artifacts.GroupBy(static value => value.Role, StringComparer.Ordinal)
                     .OrderBy(static value => RoleOrder(value.Key)))
        {
            var ordinal = 0;
            foreach (var artifact in group)
            {
                var filename = $"{group.Key}.{ordinal:D4}.bin";
                WriteNew(Path.Combine(bootstrapDir, filename), artifact.Bytes);
                entries.Add(new ArtifactEntry(group.Key, ordinal++, filename, artifact.Bytes.Length,
                    Convert.ToHexString(SHA256.HashData(artifact.Bytes)).ToLowerInvariant()));
            }
        }
        var manifest = new PublicBootstrapManifest(
            SuccessorSchema, "Mr. X", source.Manifest.NetworkIdHex,
            source.Manifest.GenesisAuthorityCoreHashHex,
            source.Manifest.DirectoryLeafKeyHex,
            notBefore, expiresAt, entries);
        WriteNew(Path.Combine(outputRoot, "public-manifest.v1.json"),
            JsonSerializer.SerializeToUtf8Bytes(manifest, new JsonSerializerOptions { WriteIndented = true }));
    }

    private static int RoleOrder(string role) => role switch
    {
        "xna1" => 0, "dts1" => 1, "adh1" => 2, "xvp1" => 3,
        "xnv1" => 4, "xnh1" => 5, "xnd1" => 6, "pma2" => 7, "pmt2" => 8,
        _ => throw new InvalidDataException("The successor artifact role is unknown."),
    };

    private static byte[] Join(params byte[][] values)
    {
        var output = new byte[values.Sum(static value => value.Length)];
        var offset = 0;
        foreach (var value in values)
        {
            value.CopyTo(output, offset);
            offset += value.Length;
        }
        return output;
    }

    private static byte[] U64(ulong value)
    {
        var output = new byte[8];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(output, value);
        return output;
    }

    private static byte[] CoreReference(string magic, ReadOnlySpan<byte> hash)
    {
        if (magic.Length != 4 || hash.Length != 32)
            throw new ArgumentException("A core reference requires a four-byte magic and 32-byte hash.");
        var output = new byte[38];
        Encoding.ASCII.GetBytes(magic).CopyTo(output, 0);
        output[5] = 1;
        hash.CopyTo(output.AsSpan(6));
        return output;
    }

    internal sealed class SourceArtifacts(
        PublicBootstrapManifest manifest,
        IReadOnlyDictionary<(string Role, int Ordinal), byte[]> artifacts)
    {
        internal PublicBootstrapManifest Manifest => manifest;

        internal byte[] One(string role)
        {
            var values = Many(role);
            if (values.Count != 1)
                throw new InvalidDataException($"The source requires exactly one {role} artifact.");
            return values[0].ToArray();
        }

        internal IReadOnlyList<byte[]> Many(string role)
        {
            var values = artifacts.Where(value => string.Equals(value.Key.Role, role, StringComparison.Ordinal))
                .OrderBy(static value => value.Key.Ordinal).ToArray();
            if (values.Length == 0 || values.Select(static value => value.Key.Ordinal)
                    .Where((ordinal, index) => ordinal != index).Any())
                throw new InvalidDataException($"The source {role} history is absent or noncontiguous.");
            return values.Select(static value => value.Value.ToArray()).ToArray();
        }
    }

    private sealed class NodeRolloverCustody : IDisposable
    {
        private readonly byte[] identitySeed;
        private readonly byte[] identityPrivate;
        private readonly byte[] currentOnionSeed;
        private readonly byte[] nextOnionSeed;

        private NodeRolloverCustody(
            byte[] identitySeed,
            byte[] identityPrivate,
            byte[] currentOnionSeed,
            byte[] nextOnionSeed,
            XPointNetworkOperationalNodeRollover rollover)
        {
            this.identitySeed = identitySeed;
            this.identityPrivate = identityPrivate;
            this.currentOnionSeed = currentOnionSeed;
            this.nextOnionSeed = nextOnionSeed;
            Rollover = rollover;
        }

        internal XPointNetworkOperationalNodeRollover Rollover { get; }

        internal static NodeRolloverCustody Load(
            string name, string nodeRoot, string rolloverRoot, ulong notBefore, ulong expiresAt)
        {
            byte[]? identitySeed = null;
            byte[]? identityPrivate = null;
            byte[]? currentOnionSeed = null;
            byte[]? nextOnionSeed = null;
            try
            {
                nodeRoot = ExistingDirectory(nodeRoot);
                var rolloverPath = ExistingDirectory(Path.Combine(rolloverRoot, name));
                var environment = File.ReadLines(ExistingFile(Path.Combine(nodeRoot, ".env.node.prod")))
                    .Where(static line => line.StartsWith("DEEP_NODE_ED25519_PUBLIC_KEY=", StringComparison.Ordinal))
                    .ToArray();
                if (environment.Length != 1)
                    throw new InvalidDataException("A registered node identity binding is absent or duplicated.");
                identitySeed = ReadSeed(Path.Combine(nodeRoot, "secrets", "key_ed25519"));
                var pair = PublicKeyAuth.GenerateKeyPair(identitySeed);
                identityPrivate = pair.PrivateKey.ToArray();
                var identityPublic = pair.PublicKey.ToArray();
                if (!string.Equals(environment[0]["DEEP_NODE_ED25519_PUBLIC_KEY=".Length..],
                        Convert.ToHexString(identityPublic), StringComparison.OrdinalIgnoreCase))
                    throw new CryptographicException("A node identity seed does not match its registered environment binding.");
                currentOnionSeed = ReadSeed(Path.Combine(rolloverPath, "current.x25519.seed"));
                nextOnionSeed = ReadSeed(Path.Combine(rolloverPath, "next.x25519.seed"));
                var currentSpki = VerifyOriginCertificate(
                    Path.Combine(rolloverPath, "current-origin.cer"), notBefore, expiresAt);
                var nextSpki = VerifyOriginCertificate(
                    Path.Combine(rolloverPath, "next-origin.cer"), notBefore, expiresAt);
                var rollover = new XPointNetworkOperationalNodeRollover(
                    new NodeSigner(identityPublic, identityPrivate), currentSpki, nextSpki,
                    ScalarMult.Base(currentOnionSeed), ScalarMult.Base(nextOnionSeed));
                return new NodeRolloverCustody(
                    identitySeed, identityPrivate, currentOnionSeed, nextOnionSeed, rollover);
            }
            catch
            {
                if (identitySeed is not null) CryptographicOperations.ZeroMemory(identitySeed);
                if (identityPrivate is not null) CryptographicOperations.ZeroMemory(identityPrivate);
                if (currentOnionSeed is not null) CryptographicOperations.ZeroMemory(currentOnionSeed);
                if (nextOnionSeed is not null) CryptographicOperations.ZeroMemory(nextOnionSeed);
                throw;
            }
        }

        public void Dispose()
        {
            CryptographicOperations.ZeroMemory(identitySeed);
            CryptographicOperations.ZeroMemory(identityPrivate);
            CryptographicOperations.ZeroMemory(currentOnionSeed);
            CryptographicOperations.ZeroMemory(nextOnionSeed);
        }
    }

    internal static byte[] VerifyOriginCertificate(string path, ulong notBefore, ulong expiresAt)
    {
        using var certificate = X509Certificate2.CreateFromPemFile(
            ExistingFile(path), ExistingFile(Path.ChangeExtension(path, ".key")));
        if (!certificate.HasPrivateKey)
            throw new CryptographicException("A rollover origin certificate has no matching installable private key.");
        var start = DateTimeOffset.FromUnixTimeSeconds(checked((long)notBefore)).UtcDateTime;
        var end = DateTimeOffset.FromUnixTimeSeconds(checked((long)expiresAt)).UtcDateTime;
        if (certificate.NotBefore.ToUniversalTime() > start || certificate.NotAfter.ToUniversalTime() < end)
            throw new CryptographicException("A rollover origin certificate does not cover the successor interval.");
        using var rsa = certificate.GetRSAPublicKey();
        if (rsa is not null) return SHA256.HashData(rsa.ExportSubjectPublicKeyInfo());
        using var ecdsa = certificate.GetECDsaPublicKey();
        if (ecdsa is not null) return SHA256.HashData(ecdsa.ExportSubjectPublicKeyInfo());
        throw new CryptographicException("A rollover origin certificate has an unsupported TLS public key.");
    }

}
