using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.Identity;
using Deep.Protocol.XPointNetworkV1;
using Sodium;

// Synthetic signed public closure and disposable test keys. No retained dev
// custody, live NTS result, Build execution or runtime activation is involved.
internal static class DevRetainedBuildTests
{
    internal static async Task RunAsync()
    {
        var directory = Path.Combine(Path.GetTempPath(), "deep-retained-build-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var signers = new List<Signer>();
        try
        {
            Signer Key(string name, bool isRoot = false, bool isNode = false)
            { var signer = Signer.Create(Path.Combine(directory, name + ".seed"), isRoot, isNode); signers.Add(signer); return signer; }
            var root = Key("root", isRoot: true);
            var witnesses = Enumerable.Range(1, 3).Select(i => Key("witness" + i)).ToArray();
            var nodes = Enumerable.Range(1, 3).Select(i => Key("node" + i, isNode: true)).Select((s, i) =>
                new XPointNetworkOperationalNode(s, B(20 + i), B(30), B(40 + i), B(50 + i), (uint)(64_500 + i), 840,
                    B(60 + i), IPAddress.Parse($"172.31.241.{11 + i}"), 443, B(70 + i), B(80 + i),
                    ScalarMult.Base(B(90 + i)), ScalarMult.Base(B(100 + i)), Enumerable.Range(0, 5).Select(role =>
                        (ReadOnlyMemory<byte>)PublicKeyAuth.GenerateKeyPair(B(110 + i * 5 + role)).PublicKey).ToArray())).ToArray();
            AccountDirectoryDts1Source[] sources = [new(B(1), B(2), 1, "time1.invalid", 4460, B(3), 5),
                new(B(4), B(5), 1, "time2.invalid", 4460, B(6), 5)];
            var bootstrap = await XPointNetworkBootstrapAuthor.AuthorGenesisAsync(new(B(7), B(8)[..16],
                [new(root.RootKeyId.Span, 0, root.Ed25519PublicKey.Span, root.CustodyDomainHash.Span)], 1,
                witnesses.Select(w => new XPointNetworkBootstrapWitnessKey(w.SignerId.Span, 0,
                    w.Ed25519PublicKey.Span, w.FailureDomainHash.Span)).ToArray(), 2, sources, 5, 10,
                900, 900, 10_000, 900, 9_000, 1, 1), [root]);
            var pending = await XPointNetworkOperationalGenesisAuthor.AuthorNetworkCandidateAsync(new(B(10), bootstrap,
                [root], witnesses, nodes, B(11), B(12), B(13), PublicKeyAuth.GenerateKeyPair(B(14)).PublicKey,
                PublicKeyAuth.GenerateKeyPair(B(15)).PublicKey, 990, 1_000, 1_500, rootPolicyExpiresAtUnixSeconds: 9_000));
            using var phrase = DeepRecoveryV1.Generate(); var did2 = DeepIdV2Root.DeriveDid2(phrase);
            var head = await DeepIdV2DirectoryHeadAuthor.AuthorGenesisAsync(bootstrap.Authority, 990, 1_500,
                witnesses.Select(w => (IAccountDirectoryAdh1WitnessSigner)w).ToArray());
            var lookup = DeepIdV2AccountDirectoryLookupCodec.Author(did2, bootstrap.Authority.NetworkId.Span,
                head.ProtectedHead.LogGeneration, head.CoreHash.Span, 1, new byte[38], new byte[32]);
            var query = VerifiedDeepIdV2DirectoryQuery.VerifyDid2(lookup, did2);
            var material = DeepIdV2DirectoryProofMaterialAuthor.Create(head.ProtectedHead, [], [], query.DirectoryLeafKey.Span, head.ProtectedHead);
            var clock = new DevGenesisMonotonicClock(); var sent = await clock.ReadAsync(default); var nonce = B(16);
            using var pq = DeepMlDsa65CandidateVerifierFactory.OpenForCurrentProcess();
            var proof = await DeepIdV2DirectoryProofAuthor.IssueGenesisAsync(bootstrap.Authority, new(
                bootstrap.Authority.NetworkId.Span, nonce, sent.BootId.Span, sent.SampleSeconds, head.ExactAdh1.Span,
                pending.ExactXnv1.Span, 1_100, 5, 1_100, 1_130, AccountDirectoryDtt1IssuanceEpoch.Derive(bootstrap.Authority, 1_100, 5), 2),
                material, witnesses, 1, pq);
            var received = await clock.ReadAsync(default);
            var freshness = DeepIdV2DirectoryCurrentProofVerifier.VerifyRequestedDid2(bootstrap.Authority, proof.ExactAdh1,
                proof.ExactDtt1, proof.ExactAdp1V2, nonce, query, new(sent.BootId.Span, sent.SampleSeconds,
                    received.SampleSeconds, received.SampleSeconds), head.ProtectedHead, 1, 2, pq);
            var operational = await XPointNetworkOperationalGenesisAuthor.CompleteDid2Async(pending, freshness, new OnionTrustedTimeAuthority(clock));
            IReadOnlyList<ReadOnlyMemory<byte>>[] chains = [[bootstrap.ExactXna1], [bootstrap.ExactDts1], [operational.ExactXvp1],
                [operational.ExactXnv1], [operational.ExactXnh1], operational.ExactXnd1, [operational.ExactPmt2], [operational.ExactPma2]];
            byte[] Encode(IReadOnlyList<ReadOnlyMemory<byte>>[] value, byte[]? network = null) =>
                XPointNetworkClosureWireCodec.EncodeResponse(network ?? bootstrap.Authority.NetworkId.ToArray(),
                    value[0], value[1], value[2], value[3], value[4], value[5], value[6], value[7]);
            void Verify(byte[] exact) => XPointNetworkHistoricalClosureVerifier.Verify(bootstrap.GenesisPin,
                XPointNetworkClosureWireCodec.DecodeResponse(exact));
            var bundle = Encode(chains);
            var beforeKeys = Directory.GetFiles(directory, "*.seed").ToDictionary(path => Path.GetFileName(path)!, File.ReadAllBytes);
            Verify(bundle); Pass("expired signed full closure is historical Build input without a current capability");
            for (var chain = 0; chain < chains.Length; chain++)
            {
                var changed = chains.Select(value => (IReadOnlyList<ReadOnlyMemory<byte>>)value.ToArray()).ToArray();
                var record = changed[chain][0].ToArray(); record[^1] ^= 1;
                changed[chain] = [record, .. changed[chain].Skip(1)];
                Reject(() => Verify(Encode(changed)), "historical chain signature " + chain);
            }
            var duplicateNodes = chains.ToArray(); duplicateNodes[5] = [chains[5][0], chains[5][0], chains[5][2]];
            Reject(() => Verify(Encode(duplicateNodes)), "valid signed descriptor substituted into another active node slot");
            Reject(() => Verify(Encode(chains, B(17)[..16])), "foreign envelope network with unchanged signed records");
            var publicRoot = Path.Combine(directory, "public"); Directory.CreateDirectory(publicRoot);
            File.WriteAllBytes(Path.Combine(publicRoot, "deep-dev.json"), JsonSerializer.SerializeToUtf8Bytes(new {
                schema = "deep-dev.v1", projectName = "deep-dev-current", nodeCount = 3, deviceEvidence = false,
                networkIdHex = Convert.ToHexString(bootstrap.Authority.NetworkId.Span),
                genesisAuthorityCoreHashHex = Convert.ToHexString(bootstrap.GenesisPin.AuthorityCoreHash.Span) }));
            File.WriteAllBytes(Path.Combine(publicRoot, "network.ncp2"), bundle);
            File.WriteAllBytes(Path.Combine(publicRoot, "genesis.xna1"), bootstrap.ExactXna1.ToArray());
            File.WriteAllBytes(Path.Combine(publicRoot, "genesis.dts1"), bootstrap.ExactDts1.ToArray());
            var observations = 0;
            try
            {
                _ = await DevNodeMailboxProvisioning.PolicyAsync(publicRoot, "synthetic-observer", (_, actual) => {
                    observations++; if (actual.Length != sources.Length) throw new InvalidOperationException("Wrong original source policy.");
                    return Task.FromResult(20_000UL);
                });
                throw new InvalidOperationException("Expired policy became current authority.");
            }
            catch (XPointNetworkAuthorityVerificationException) { Pass("current PolicyAsync still rejects expired signed authority"); }
            catch (CryptographicException) { Pass("current PolicyAsync still rejects expired signed authority"); }
            if (observations != 1 || !File.ReadAllBytes(Path.Combine(publicRoot, "network.ncp2")).AsSpan().SequenceEqual(bundle) ||
                beforeKeys.Any(pair => !File.ReadAllBytes(Path.Combine(directory, pair.Key!)).AsSpan().SequenceEqual(pair.Value)))
                throw new InvalidOperationException("Read-only historical/current checks changed source custody or skipped independent observation.");
            Pass("historical and rejected current checks preserve original synthetic seeds and exact public ancestry");
            foreach (var key in beforeKeys.Values) CryptographicOperations.ZeroMemory(key);
        }
        finally
        {
            foreach (var signer in signers) signer.Dispose();
            if (Path.GetDirectoryName(Path.GetFullPath(directory)) != Path.GetFullPath(Path.GetTempPath()).TrimEnd(Path.DirectorySeparatorChar) ||
                !Path.GetFileName(directory).StartsWith("deep-retained-build-tests-", StringComparison.Ordinal)) throw new IOException("Unexpected test cleanup target.");
            Directory.Delete(directory, recursive: true);
        }
    }
    private static byte[] B(int value) => Enumerable.Repeat(checked((byte)value), 32).ToArray();
    private static void Pass(string name) => Console.WriteLine("PASS " + name);
    private static void Reject(Action action, string name)
    {
        try { action(); }
        catch (Exception error) when (error is ArgumentException or FormatException or CryptographicException or InvalidDataException or OnionBoundaryException)
        { Pass("reject " + name); return; }
        throw new InvalidOperationException("Hostile historical closure accepted: " + name);
    }
}
