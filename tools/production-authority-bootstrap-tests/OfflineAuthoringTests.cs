using System.Net;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text.Json;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.Identity;
using Deep.Protocol.XPointNetworkV1;
using Sodium;

internal static class OfflineAuthoringTests
{
    internal static void Run()
    {
        var rootDirectory = Path.Combine(Path.GetTempPath(), "deep-synthetic-author-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(rootDirectory);
        try { RunAsync(rootDirectory).GetAwaiter().GetResult(); }
        finally { Directory.Delete(rootDirectory, recursive: true); }
    }

    private static async Task RunAsync(string directory)
    {
        using var root = Signer("root", 0x20, 0x21, 0x22, true);
        using var witness1 = Signer("witness1", 0x30, 0x40, 0x50, false);
        using var witness2 = Signer("witness2", 0x31, 0x41, 0x51, false);
        using var witness3 = Signer("witness3", 0x32, 0x42, 0x52, false);
        FileSigner[] witnesses = [witness1, witness2, witness3];
        var sources = new[]
        {
            new AccountDirectoryDts1Source(B(32, 0x60), B(32, 0x61), 1, "time1.invalid", 4460, B(32, 0x62), 5),
            new AccountDirectoryDts1Source(B(32, 0x63), B(32, 0x64), 1, "time2.invalid", 4460, B(32, 0x65), 5),
        };
        var bootstrap = await XPointNetworkBootstrapAuthor.AuthorGenesisAsync(
            new XPointNetworkGenesisAuthoringRequest(B(32, 0x12), B(16, 0x11),
                [new XPointNetworkBootstrapRootKey(root.RootKeyId.Span, 0,
                    root.Ed25519PublicKey.Span, root.CustodyDomainHash.Span)], 1,
                witnesses.Select(value => new XPointNetworkBootstrapWitnessKey(
                    value.SignerId.Span, 0, value.Ed25519PublicKey.Span, value.FailureDomainHash.Span)).ToArray(),
                2, sources, 5, 10, 900, 900, 10_000, 900, 9_000, 1, 1), [root]);
        var nodes = Enumerable.Range(0, 3).Select(index =>
        {
            var pair = PublicKeyAuth.GenerateKeyPair(B(32, (byte)(0x70 + index)));
            return new XPointNetworkOperationalNode(new NodeSigner(pair.PublicKey, pair.PrivateKey),
                B(32, (byte)(0x80 + index)), B(32, (byte)(0x90 + index)),
                B(32, (byte)(0xa0 + index)), B(32, (byte)(0xb0 + index)), (uint)(64_500 + index), 840,
                B(32, (byte)(0xc0 + index)), IPAddress.Parse($"192.0.2.{index + 1}"), 443,
                B(32, (byte)(0xd0 + index)), B(32, (byte)(0xd8 + index)),
                ScalarMult.Base(B(32, (byte)(0xe0 + index))), ScalarMult.Base(B(32, (byte)(0xe8 + index))),
                Enumerable.Range(0, 5).Select(role => (ReadOnlyMemory<byte>)
                    PublicKeyAuth.GenerateKeyPair(B(32, (byte)(0x10 + index * 5 + role))).PublicKey).ToArray());
        }).ToArray();
        var genesis = await XPointNetworkOperationalGenesisAuthor.AuthorAsync(
            new XPointNetworkOperationalGenesisRequest(B(32, 0x12), bootstrap, [root], witnesses, nodes,
                B(32, 0xf1), H("xcc"), H("xcb"), H("pma"),
                PublicKeyAuth.GenerateKeyPair(B(32, 0x31)).PublicKey,
                PublicKeyAuth.GenerateKeyPair(B(32, 0x32)).PublicKey,
                990, 1_000, 1_500, B(32, 0xf2), B(16, 0xf3), 100, 101, 102, 1_100, 5,
                rootPolicyExpiresAtUnixSeconds: 9_000));
        genesis.VerifiedNetwork.EnsureCurrent();
        await TestCheckpointAuditAsync(directory, bootstrap, genesis);
        var rollovers = nodes.Select((node, index) => new XPointNetworkOperationalNodeRollover(
            node.IdentitySigner, H($"current-{index}"), H($"next-{index}"),
            ScalarMult.Base(B(32, (byte)(0x30 + index))), ScalarMult.Base(B(32, (byte)(0x80 + index))))).ToArray();
        var adhReference = new byte[38];
        "ADH1"u8.CopyTo(adhReference);
        adhReference[5] = 1;
        XPointNetworkOperationalSuccessorAuthor.ComputeAdh1CoreHash(genesis.ExactAdh1.Span)
            .CopyTo(adhReference, 6);
        var successor = await XPointNetworkOperationalSuccessorAuthor.AuthorAsync(
            new XPointNetworkOperationalSuccessorRequest(H("successor"), bootstrap, [root], witnesses, rollovers,
                genesis.ExactXvp1, genesis.ExactXnd1, [genesis.ExactXnv1], genesis.ExactXnh1,
                genesis.ExactPma2, genesis.ExactPmt2,
                XPointNetworkOperationalSuccessorAuthor.ComputeXnh1CoreHash(genesis.ExactXnh1.Span),
                ContactCodec.Decode("PMT2", genesis.ExactPmt2.Span).ArtifactHash.Span,
                adhReference, 1_200, 1_210, 1_400));
        if (successor.ExactXnd1.Count != 3 || successor.ExactXnh1.IsEmpty || successor.ExactPma2.IsEmpty)
            throw new Exception("The operator signers did not author a complete successor.");
        var did2Genesis = await DeepIdV2DirectoryHeadAuthor.AuthorGenesisAsync(
            bootstrap.Authority, 990, 1_500,
            witnesses.Select(value => (IAccountDirectoryAdh1WitnessSigner)new AdhWitness(value)).ToArray());
        TestPublicNetworkExport(directory, bootstrap, genesis, successor, did2Genesis);
        await TestDelegatedRenewalAsync(bootstrap, genesis, nodes, witnesses, adhReference);

        FileSigner Signer(string name, byte id, byte seedValue, byte domain, bool isRoot)
        {
            var seed = B(32, seedValue);
            var pair = PublicKeyAuth.GenerateKeyPair(seed);
            var path = Path.Combine(directory, name + ".seed");
            File.WriteAllBytes(path, seed);
            var role = new CustodyRole(name, Convert.ToHexString(B(32, id)), 0,
                Convert.ToHexString(pair.PublicKey), Convert.ToHexString(B(32, domain)));
            CryptographicOperations.ZeroMemory(seed);
            CryptographicOperations.ZeroMemory(pair.PrivateKey);
            return isRoot ? FileSigner.Root(role, path) : FileSigner.Witness(role, path);
        }
    }

    private static byte[] B(int length, byte value) => Enumerable.Repeat(value, length).ToArray();
    private static byte[] H(string value) => SHA256.HashData(System.Text.Encoding.ASCII.GetBytes(value));

    private static async Task TestDelegatedRenewalAsync(VerifiedXPointNetworkBootstrap bootstrap,
        AuthoredXPointNetworkOperationalGenesis genesis, XPointNetworkOperationalNode[] nodes,
        FileSigner[] witnesses, byte[] adhReference)
    {
        var counters = nodes.Select(node => new CountingSigner(node.IdentitySigner)).ToArray();
        var rollovers = nodes.Select((node,index) => new XPointNetworkOperationalNodeRollover(
            counters[index], node.NextOriginSpkiSha256.Span, H($"delegated-next-{index}"),
            node.NextOnionX25519PublicKey.Span, ScalarMult.Base(B(32,(byte)(0x80+index))))).ToArray();
        XPointNetworkOperationalSuccessorRequest Request(ulong from = 2_000, ulong until = 2_200,
            ReadOnlyMemory<byte>? policy = null, ReadOnlyMemory<byte>? head = null,
            IReadOnlyList<XPointNetworkOperationalNodeRollover>? keys = null) => new(
                H("delegated"), bootstrap, [], witnesses, keys ?? rollovers,
                policy ?? genesis.ExactXvp1, genesis.ExactXnd1, [genesis.ExactXnv1],
                head ?? genesis.ExactXnh1, genesis.ExactPma2, genesis.ExactPmt2,
                XPointNetworkOperationalSuccessorAuthor.ComputeXnh1CoreHash(genesis.ExactXnh1.Span),
                ContactCodec.Decode("PMT2",genesis.ExactPmt2.Span).ArtifactHash.Span,
                adhReference,from,from,until);
        var delegated = await XPointNetworkOperationalSuccessorAuthor.AuthorDelegatedAsync(Request());
        if (!delegated.ExactXvp1.Span.SequenceEqual(genesis.ExactXvp1.Span) ||
            !delegated.ExactPma2.Span.SequenceEqual(genesis.ExactPma2.Span) ||
            BinaryPrimitives.ReadUInt64BigEndian(ContactCodec.Decode("PMT2",delegated.ExactPmt2.Span).Field(2).Span) != 1 ||
            delegated.ExactXnd1.Any(exact => ReadU64Field(exact.Span,21) != 2))
            throw new Exception("Delegated renewal changed offline policy or skipped announced key epoch.");
        var calls = counters.Sum(signer => signer.Calls);
        await Reject(Request(9_001,9_100));
        var badPolicy = genesis.ExactXvp1.ToArray(); badPolicy[^1] ^= 1;
        await Reject(Request(policy:badPolicy));
        var badHead = genesis.ExactXnh1.ToArray(); badHead[^1] ^= 1;
        await Reject(Request(head:badHead));
        var wrongKeys = nodes.Select((node,index) => new XPointNetworkOperationalNodeRollover(
            counters[index],H($"unannounced-current-{index}"),H($"unannounced-next-{index}"),
            ScalarMult.Base(B(32,(byte)(0x30+index))),ScalarMult.Base(B(32,(byte)(0x80+index))))).ToArray();
        await Reject(Request(keys:wrongKeys));
        if (counters.Sum(signer => signer.Calls) != calls)
            throw new Exception("Rejected delegated predecessor reached a node signer callback.");

        static async Task Reject(XPointNetworkOperationalSuccessorRequest request)
        {
            try { await XPointNetworkOperationalSuccessorAuthor.AuthorDelegatedAsync(request); }
            catch (Exception exception) when (exception is CryptographicException or
                Deep.Protocol.DeepExtension.PrivacyRouting.OnionBoundaryException) { return; }
            throw new Exception("Hostile delegated renewal accepted.");
        }
        static ulong ReadU64Field(ReadOnlySpan<byte> exact, ushort tag)
        {
            for (var offset = 12; offset < exact.Length;)
            {
                var fieldTag = BinaryPrimitives.ReadUInt16BigEndian(exact[offset..]);
                var length = checked((int)BinaryPrimitives.ReadUInt32BigEndian(exact[(offset+4)..]));
                if (fieldTag == tag) return BinaryPrimitives.ReadUInt64BigEndian(exact[(offset+8)..]);
                offset += 8 + length;
            }
            throw new Exception("Missing epoch field in authored test record.");
        }
    }

    private sealed class CountingSigner(IXPointNetworkOperationalSigner inner) : IXPointNetworkOperationalSigner
    {
        internal int Calls;
        public ReadOnlyMemory<byte> SignerId => inner.SignerId;
        public ulong KeyGeneration => inner.KeyGeneration;
        public ReadOnlyMemory<byte> Ed25519PublicKey => inner.Ed25519PublicKey;
        public ValueTask<int> SignAsync(XPointNetworkOperationalSigningRequest request,
            Memory<byte> signature64,CancellationToken cancellationToken)
        {
            Calls++;
            return inner.SignAsync(request,signature64,cancellationToken);
        }
    }

    private sealed class AdhWitness(FileSigner signer) : IAccountDirectoryAdh1WitnessSigner
    {
        public ReadOnlyMemory<byte> WitnessId => signer.WitnessId;
        public ValueTask<ReadOnlyMemory<byte>> SignAdh1Async(
            ReadOnlyMemory<byte> input, CancellationToken cancellationToken) =>
            signer.SignDtt1Async(input, cancellationToken);
    }

    // Genuine signed ceremony records, but export is distribution only: no
    // nonce-fresh DID2 proof, live network capability, TLS or device claim.
    private static void TestPublicNetworkExport(string directory,
        VerifiedXPointNetworkBootstrap bootstrap, AuthoredXPointNetworkOperationalGenesis genesis,
        AuthoredXPointNetworkOperationalSuccessor successor,
        AuthoredAccountDirectoryHeadMutation did2Genesis)
    {
        var network = Convert.ToHexString(bootstrap.GenesisPin.NetworkId.Span);
        var pin = Convert.ToHexString(bootstrap.GenesisPin.AuthorityCoreHash.Span);
        var initial = Path.Combine(directory, "network-initial");
        var next = Path.Combine(directory, "network-next");
        WriteSource(initial, false);
        WriteSource(next, true);
        var initialOutput = Path.Combine(directory, "network-initial.ncp2");
        var output = Path.Combine(directory, "network-current.ncp2");
        var initialArgs = new[] { "--export-network-genesis", initial, "--network-id-hex", network,
            "--genesis-core-hash", pin, "--output", initialOutput };
        NetworkClosureExport.Run(Arguments.Parse(initialArgs));
        Reject<IOException>(() => NetworkClosureExport.Run(Arguments.Parse(initialArgs)));
        var args = new[] { "--extend-network-closure", initialOutput, "--network-successor-source", next,
            "--network-id-hex", network, "--genesis-core-hash", pin, "--output", output };
        NetworkClosureExport.Run(Arguments.Parse(args));
        var decoded = XPointNetworkClosureWireCodec.DecodeResponse(File.ReadAllBytes(output));
        NetworkDistributionAuditTests.RunAsync(File.ReadAllBytes(output),
            bootstrap.GenesisPin.NetworkId.ToArray()).GetAwaiter().GetResult();
        if (decoded.ExactViewChain.Count != 2 || decoded.ExactHeadChain.Count != 2 ||
            decoded.ExactNetworkPolicyChain.Count != 2 || decoded.ExactPlacementTopologyChain.Count != 2 ||
            decoded.ExactActiveNodeDescriptors.Count != 3 ||
            decoded.ExactMailboxAuthorityChain.Count != 1 ||
            !decoded.ExactMailboxAuthorityChain[0].Span.SequenceEqual(genesis.ExactPma2.Span) ||
            !decoded.ExactHeadChain[0].Span.SequenceEqual(genesis.ExactXnh1.Span) ||
            !decoded.ExactHeadChain[1].Span.SequenceEqual(successor.ExactXnh1.Span) ||
            !decoded.ExactPlacementTopologyChain[0].Span.SequenceEqual(genesis.ExactPmt2.Span) ||
            !decoded.ExactPlacementTopologyChain[1].Span.SequenceEqual(successor.ExactPmt2.Span))
            throw new Exception("Public network export lost or changed exact signed history.");
        TestPublicHostAssets(directory, output, network, pin, did2Genesis);
        Reject<IOException>(() => NetworkClosureExport.Run(Arguments.Parse(args)));
        args[^1] = Path.Combine(directory, "network-rejected.ncp2");
        args[7] = new string('1', 64);
        Reject<XPointNetworkAuthorityVerificationException>(() =>
            NetworkClosureExport.Run(Arguments.Parse(args)));
        args[7] = pin;
        args[1] = output; // Replay the same successor against an advanced base.
        Reject<CryptographicException>(() => NetworkClosureExport.Run(Arguments.Parse(args)));
        args[1] = initialOutput;
        WriteSource(next, true, omitPrefix: true);
        Reject<CryptographicException>(() => NetworkClosureExport.Run(Arguments.Parse(args)));
        WriteSource(next, true, alterPrefix: true);
        Reject<CryptographicException>(() => NetworkClosureExport.Run(Arguments.Parse(args)));
        WriteSource(next, true);
        var descriptorPath = Path.Combine(next, "bootstrap", "xnd1.0000.bin");
        var changed = File.ReadAllBytes(descriptorPath);
        changed[^1] ^= 1;
        File.WriteAllBytes(descriptorPath, changed);
        Reject<CryptographicException>(() => NetworkClosureExport.Run(Arguments.Parse(args)));
        WriteSource(next, true);
        var manifestPath = Path.Combine(next, "public-manifest.v1.json");
        var manifest = JsonSerializer.Deserialize<PublicBootstrapManifest>(File.ReadAllBytes(manifestPath))!;
        var oversized = Enumerable.Range(0, 69).Select(index => new ArtifactEntry("xnd1", index,
            $"xnd1.{index:D4}.bin", 1_048_576, new string('1', 64))).ToList();
        File.WriteAllBytes(manifestPath, JsonSerializer.SerializeToUtf8Bytes(manifest with { Artifacts = oversized }));
        Reject<InvalidDataException>(() => NetworkClosureExport.Run(Arguments.Parse(args)));
        if (File.Exists(args[^1])) throw new Exception("Rejected public export wrote an output.");

        void WriteSource(string path, bool isSuccessor, bool omitPrefix = false, bool alterPrefix = false)
        {
            var artifacts = Path.Combine(path, "bootstrap");
            Directory.CreateDirectory(artifacts);
            var views = new List<ReadOnlyMemory<byte>>();
            if (!omitPrefix)
            {
                var priorView = genesis.ExactXnv1.ToArray();
                if (alterPrefix) priorView[^1] ^= 1;
                views.Add(priorView);
            }
            if (isSuccessor) views.Add(successor.ExactXnv1);
            var roles = new (string Role, IReadOnlyList<ReadOnlyMemory<byte>> Values)[]
            {
                ("xna1", [genesis.ExactXna1]), ("dts1", [genesis.ExactDts1]),
                ("xvp1", [isSuccessor ? successor.ExactXvp1 : genesis.ExactXvp1]),
                ("xnv1", views), ("xnh1", [isSuccessor ? successor.ExactXnh1 : genesis.ExactXnh1]),
                ("xnd1", isSuccessor ? successor.ExactXnd1 : genesis.ExactXnd1),
                ("pmt2", [isSuccessor ? successor.ExactPmt2 : genesis.ExactPmt2]),
                ("pma2", [genesis.ExactPma2]),
            };
            var entries = new List<ArtifactEntry>();
            foreach (var role in roles)
                for (var ordinal = 0; ordinal < role.Values.Count; ordinal++)
                {
                    var value = role.Values[ordinal];
                    var file = $"{role.Role}.{ordinal:D4}.bin";
                    File.WriteAllBytes(Path.Combine(artifacts, file), value.ToArray());
                    entries.Add(new(role.Role, ordinal, file, value.Length,
                        Convert.ToHexString(SHA256.HashData(value.Span))));
                }
            File.WriteAllBytes(Path.Combine(path, "public-manifest.v1.json"),
                JsonSerializer.SerializeToUtf8Bytes(new PublicBootstrapManifest(isSuccessor
                    ? "deep-production-operational-successor.v1" : "deep-production-authority-bootstrap.v1",
                    "Mr. X", network, pin, Convert.ToHexString(B(32, 0xf1)), 990, 1_500, entries)));
        }

        static void Reject<T>(Action action) where T : Exception
        {
            try { action(); }
            catch (T) { return; }
            throw new Exception($"Expected {typeof(T).Name} public network export rejection.");
        }
    }

    private static void TestPublicHostAssets(string directory, string bundle,
        string network, string pin, AuthoredAccountDirectoryHeadMutation genesis)
    {
        var head = Path.Combine(directory, "did2-genesis.adh1");
        File.WriteAllBytes(head, genesis.ExactAdh1.ToArray());
        // This is a structural public descriptor fixture, not a PQ identity
        // verification or account admission claim. The ADH1 uses real signatures.
        var read = B(16, 0x44);
        var did2 = DeepIdV2Codec.AuthorDid2(B(32, 0x55), B(1952, 0x66), read);
        var descriptor = DeepPermanentIdV2.FromCredential(did2, read).CanonicalText;
        var contact = Path.Combine(directory, "observer-contact.txt");
        File.WriteAllText(contact, descriptor + "\n" + Convert.ToHexString(did2.CanonicalBytes.Span) + "\n");
        var target = Path.Combine(directory, "host-assets");
        var args = new[] { "--export-xnode-did2-assets", bundle, "--network-id-hex", network,
            "--genesis-core-hash", pin, "--expected-bundle-sha256",
            Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(bundle))),
            "--genesis-head-path", head, "--genesis-head-core-hash",
            Convert.ToHexString(genesis.CoreHash.Span), "--observer-contact-file", contact,
            "--registry-origin", "https://registry.invalid/", "--output", target };
        XNodeDid2AssetsExport.Run(Arguments.Parse(args));
        if (!File.ReadAllBytes(Path.Combine(target, "observer.did2")).AsSpan()
                .SequenceEqual(did2.CanonicalBytes.Span))
            throw new Exception("Observer credential changed during public export.");
        if (!File.ReadAllBytes(Path.Combine(target, "pma2.0000.bin")).AsSpan().SequenceEqual(
                XPointNetworkClosureWireCodec.DecodeResponse(File.ReadAllBytes(bundle)).ExactMailboxAuthorityChain[0].Span))
            throw new Exception("Host assets lost exact public mailbox issuer authority.");
        using var config = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(target, "xnode.did2.json")));
        var placement = config.RootElement.GetProperty("DeepIdV2NetworkPlacement");
        if (placement.GetProperty("ExactViewPaths").GetArrayLength() != 2 ||
            placement.GetProperty("ExactHeadPaths").GetArrayLength() != 2 ||
            !File.ReadAllBytes(Path.Combine(target, "xnh1.0000.bin")).AsSpan().SequenceEqual(
                XPointNetworkClosureWireCodec.DecodeResponse(File.ReadAllBytes(bundle)).ExactHeadChain[0].Span))
            throw new Exception("Host assets lost signed predecessor history.");
        foreach (var file in Directory.GetFiles(target))
            if (System.Text.Encoding.UTF8.GetString(File.ReadAllBytes(file)).Contains(descriptor, StringComparison.Ordinal))
                throw new Exception("Observer read capability was exported with host assets.");
        using var manifest = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(target, "public-assets.v2.json")));
        if (manifest.RootElement.GetProperty("currentTimeEvidence").GetBoolean() ||
            manifest.RootElement.GetProperty("deploymentEvidence").GetBoolean())
            throw new Exception("Public host export claimed live authority.");
        Reject<IOException>(() => XNodeDid2AssetsExport.Run(Arguments.Parse(args)));

        Negative<CryptographicException>("--expected-bundle-sha256", new string('1', 64));
        Negative<CryptographicException>("--network-id-hex", new string('2', 32));
        Negative<XPointNetworkAuthorityVerificationException>("--genesis-core-hash", new string('1', 64));
        Negative<AccountDirectoryFreshnessVerificationException>("--genesis-head-core-hash", new string('1', 64));
        Negative<InvalidDataException>("--registry-origin", "http://registry.invalid/");
        Negative<InvalidDataException>("--registry-origin", "https://registry.invalid/?credential=not-allowed");
        File.WriteAllText(contact, descriptor + "\n" + Convert.ToHexString(
            DeepIdV2Codec.AuthorDid2(B(32, 0x77), B(1952, 0x66), read).CanonicalBytes.Span));
        Negative<CryptographicException>("--observer-contact-file", contact);
        File.WriteAllBytes(contact, new byte[8_193]);
        Negative<InvalidDataException>("--observer-contact-file", contact);

        void Negative<T>(string argument, string replacement) where T : Exception
        {
            var invalid = args.ToArray();
            invalid[Array.IndexOf(invalid, argument) + 1] = replacement;
            invalid[^1] = Path.Combine(directory, "host-rejected");
            Reject<T>(() => XNodeDid2AssetsExport.Run(Arguments.Parse(invalid)));
            if (Directory.Exists(invalid[^1])) throw new Exception("Rejected host assets wrote an output.");
        }
        static void Reject<T>(Action action) where T : Exception
        {
            try { action(); }
            catch (T) { return; }
            throw new Exception($"Expected {typeof(T).Name} public host asset rejection.");
        }
    }

    private static async Task TestCheckpointAuditAsync(string directory,
        VerifiedXPointNetworkBootstrap bootstrap, AuthoredXPointNetworkOperationalGenesis genesis)
    {
        var source = Path.Combine(directory, "checkpoint");
        var artifactDirectory = Path.Combine(source, "bootstrap");
        Directory.CreateDirectory(artifactDirectory);
        var values = new List<(string Role, byte[] Bytes)>
        {
            ("xna1", genesis.ExactXna1.ToArray()), ("dts1", genesis.ExactDts1.ToArray()),
            ("adh1", genesis.ExactAdh1.ToArray()), ("snapshot-dtt1", genesis.ExactDtt1.ToArray()),
            ("snapshot-adp1", genesis.ExactAdp1.ToArray()), ("xvp1", genesis.ExactXvp1.ToArray()),
            ("xnv1", genesis.ExactXnv1.ToArray()), ("xnh1", genesis.ExactXnh1.ToArray()),
            ("pma2", genesis.ExactPma2.ToArray()), ("pmt2", genesis.ExactPmt2.ToArray()),
        };
        values.AddRange(genesis.ExactXnd1.Select(static bytes => ("xnd1", bytes.ToArray())));
        var entries = new List<ArtifactEntry>();
        foreach (var group in values.GroupBy(static value => value.Role))
        {
            var ordinal = 0;
            foreach (var value in group)
            {
                var file = $"{group.Key}.{ordinal:D4}.bin";
                File.WriteAllBytes(Path.Combine(artifactDirectory, file), value.Bytes);
                entries.Add(new ArtifactEntry(group.Key, ordinal++, file, value.Bytes.Length,
                    Convert.ToHexString(SHA256.HashData(value.Bytes))));
            }
        }
        var networkHex = Convert.ToHexString(B(16, 0x11));
        var genesisHex = Convert.ToHexString(bootstrap.GenesisPin.AuthorityCoreHash.Span);
        var leafHex = Convert.ToHexString(B(32, 0xf1));
        WriteManifest();
        File.WriteAllBytes(Path.Combine(artifactDirectory, "inventory.json"),
            JsonSerializer.SerializeToUtf8Bytes(new ArtifactInventory("deep-contact-resolve-readonly-v2",
                networkHex, genesisHex, 1, Convert.ToHexString(B(32, 0xf2)), leafHex,
                Convert.ToHexString(B(16, 0xf3)), 100, 101, 102, entries)));
        var output = Path.Combine(directory, "audit.json");
        var args = new[] { "--audit-genesis-source", source, "--network-id-hex", networkHex,
            "--genesis-core-hash", genesisHex, "--expected-xnv1-artifact-hash",
            Convert.ToHexString(SHA256.HashData(genesis.ExactXnv1.Span)), "--output", output };
        await CheckpointAudit.RunAsync(Arguments.Parse(args));
        using (var report = JsonDocument.Parse(File.ReadAllBytes(output)))
        {
            if (report.RootElement.GetProperty("currentTimeEvidence").GetBoolean() ||
                report.RootElement.GetProperty("replacesProtectedLkg").GetBoolean())
                throw new Exception("Historical audit claimed current readiness or LKG replacement.");
        }
        await RejectAsync<IOException>(args);
        args[9] = Path.Combine(directory, "rejected-audit.json");
        args[7] = new string('1', 64);
        await RejectAsync<CryptographicException>(args);
        args[7] = Convert.ToHexString(SHA256.HashData(genesis.ExactXnv1.Span));
        var pma = genesis.ExactPma2.ToArray();
        pma[^1] ^= 1;
        File.WriteAllBytes(Path.Combine(artifactDirectory, "pma2.0000.bin"), pma);
        var index = entries.FindIndex(static entry => entry.Role == "pma2");
        entries[index] = entries[index] with { Sha256Hex = Convert.ToHexString(SHA256.HashData(pma)) };
        WriteManifest();
        await RejectAsync<CryptographicException>(args);
        if (File.Exists(args[9])) throw new Exception("Rejected audit wrote an output.");

        void WriteManifest() => File.WriteAllBytes(Path.Combine(source, "public-manifest.v1.json"),
            JsonSerializer.SerializeToUtf8Bytes(new PublicBootstrapManifest(
                "deep-production-authority-bootstrap.v1", "Mr. X", networkHex, genesisHex,
                leafHex, 990, 1_500, entries)));

        static async Task RejectAsync<T>(string[] arguments) where T : Exception
        {
            try { await CheckpointAudit.RunAsync(Arguments.Parse(arguments)); }
            catch (T) { return; }
            throw new Exception($"Expected {typeof(T).Name} checkpoint rejection.");
        }
    }
}
