using System.Security.Cryptography;
using System.Text.Json;
using System.Net;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.Identity;
using Deep.Protocol.XPointNetworkV1;
using Sodium;

// Isolated real-signature tests with fixed fixture time, not NTS/runtime evidence.
var directory = Path.Combine(Path.GetTempPath(), "deep-dev-offline-tests-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(directory);
try
{
    Check(DevTopology.ForProject("deep-dev").Ipv4Prefix == "172.31.240" &&
        DevTopology.ForProject("deep-dev-current").Ipv4Prefix == "172.31.241", "separate current topology addresses");
    await Reject(() => { _ = DevTopology.ForProject("production"); return Task.CompletedTask; }, "unknown dev project");
    using var root = Signer.Create(Path.Combine(directory, "root.seed"), rootSigner: true);
    using var other = Signer.Create(Path.Combine(directory, "other.seed"), rootSigner: true);
    using var witness1 = Signer.Create(Path.Combine(directory, "witness1.seed"));
    using var witness2 = Signer.Create(Path.Combine(directory, "witness2.seed"));
    using var witness3 = Signer.Create(Path.Combine(directory, "witness3.seed"));
    var network = RandomNumberGenerator.GetBytes(16);
    var sources = new[] {
        new AccountDirectoryDts1Source(B(1), B(2), 1, "time1.invalid", 4460, B(3), 5),
        new AccountDirectoryDts1Source(B(4), B(5), 1, "time2.invalid", 4460, B(6), 5)
    };
    var genesis = await XPointNetworkBootstrapAuthor.AuthorGenesisAsync(new(
        RandomNumberGenerator.GetBytes(32), network,
        [new(root.RootKeyId.Span, 0, root.Ed25519PublicKey.Span, root.CustodyDomainHash.Span)], 1,
        new[] { witness1, witness2, witness3 }.Select(w => new XPointNetworkBootstrapWitnessKey(
            w.SignerId.Span, 0, w.Ed25519PublicKey.Span, w.FailureDomainHash.Span)).ToArray(),
        2, sources, 5, 10, 900, 900, 10_000, 900, 9_000, 1, 1), [root]);
    using var loaded = Signer.LoadRoot(Path.Combine(directory, "root.seed"));
    var original = File.ReadAllBytes(Path.Combine(directory, "root.seed"));
    var digest = new string('a', 64);
    var first = await DevOfflineAuthorityRenewal.AuthorPairAsync(genesis.GenesisPin,
        [genesis.ExactXna1], [genesis.ExactDts1], 20_000, loaded, digest);
    Check(first.Schema == "deep-dev-offline-authority.v1" && first.AuthorityGeneration == 1 &&
        first.TimePolicyGeneration == 1 && first.Observed == 20_000 && first.PriorBundleSha256 == digest,
        "exact paired successor metadata");
    Check(first.ExactAuthorityChain[0].AsSpan().SequenceEqual(genesis.ExactXna1.Span) &&
        first.ExactTimePolicyChain[0].AsSpan().SequenceEqual(genesis.ExactDts1.Span), "original prefix retained");
    var nextXna = first.ExactAuthorityChain.Select(b => (ReadOnlyMemory<byte>)b).ToArray();
    var nextDts = first.ExactTimePolicyChain.Select(b => (ReadOnlyMemory<byte>)b).ToArray();
    var authority = XPointNetworkAuthorityVerifier.Verify(genesis.GenesisPin, nextXna, nextDts);
    Check(authority.RootKeys[0].Ed25519PublicKey.Span.SequenceEqual(root.Ed25519PublicKey.Span) &&
        authority.RootThreshold == genesis.Authority.RootThreshold && authority.WitnessThreshold == genesis.Authority.WitnessThreshold &&
        authority.NotBefore == 20_000 && authority.Dts1ExpiresAt == 624_800, "same keys and honest seven-day horizon");
    var second = await DevOfflineAuthorityRenewal.AuthorPairAsync(genesis.GenesisPin,
        nextXna, nextDts, 700_000, loaded, digest);
    Check(second.ExactAuthorityChain.Length == 3 && second.AuthorityGeneration == 2 &&
        second.ExactAuthorityChain[1].AsSpan().SequenceEqual(first.ExactAuthorityChain[1]), "second expired handover preserves middle");
    await Reject(() => DevOfflineAuthorityRenewal.AuthorPairAsync(genesis.GenesisPin,
        nextXna, nextDts, 19_999, loaded, digest), "backward observation");
    await Reject(() => DevOfflineAuthorityRenewal.AuthorPairAsync(genesis.GenesisPin,
        nextXna, nextDts, 700_000, other, digest), "wrong root custody");
    using var ordinary = Signer.Load(Path.Combine(directory, "root.seed"));
    await Reject(() => DevOfflineAuthorityRenewal.AuthorPairAsync(genesis.GenesisPin,
        nextXna, nextDts, 700_000, ordinary, digest), "online signer cannot act as root");
    var corrupt = first.ExactTimePolicyChain.Select(b => (ReadOnlyMemory<byte>)b.ToArray()).ToArray();
    var altered = corrupt[^1].ToArray(); altered[^1] ^= 1; corrupt[^1] = altered;
    await Reject(() => DevOfflineAuthorityRenewal.AuthorPairAsync(genesis.GenesisPin,
        nextXna, corrupt, 700_000, loaded, digest), "corrupt predecessor receipt");
    await Reject(() => DevOfflineAuthorityRenewal.AuthorPairAsync(genesis.GenesisPin,
        [nextXna[^1]], [nextDts[^1]], 700_000, loaded, digest), "truncated genesis history");
    await Reject(() => DevOfflineAuthorityRenewal.AuthorPairAsync(genesis.GenesisPin,
        nextXna, nextDts, ulong.MaxValue, loaded, digest), "overflow observation");
    await Reject(() => DevOfflineAuthorityRenewal.AuthorPairAsync(genesis.GenesisPin,
        nextXna, nextDts, 700_000, loaded, "not-a-digest"), "unbound prior-public digest");
    var observed = false;
    await Reject(() => DevOfflineAuthorityRenewal.PrepareAsync(directory, "unused", (_, _) => {
        observed = true; return Task.FromResult(700_000UL);
    }), "outside development scope");
    Check(!observed && File.ReadAllBytes(Path.Combine(directory, "root.seed")).AsSpan().SequenceEqual(original),
        "no external observation or custody mutation on rejected path");
    await TestFileCeremonyAsync(genesis, root, [witness1, witness2, witness3]);
    Console.WriteLine("Development offline paired-authority tests passed; runtime/device activation not tested.");
}
finally
{
    var expected = Path.Combine(Path.GetTempPath(), Path.GetFileName(directory));
    if (Path.GetFullPath(directory) != Path.GetFullPath(expected) ||
        !Path.GetFileName(directory).StartsWith("deep-dev-offline-tests-", StringComparison.Ordinal))
        throw new IOException("Unexpected test cleanup target.");
    Directory.Delete(directory, recursive: true);
}

static byte[] B(byte value) => Enumerable.Repeat(value, 32).ToArray();
static void Check(bool condition, string name) { if (!condition) throw new Exception(name); Console.WriteLine("PASS " + name); }
static async Task Reject(Func<Task> run, string name)
{
    try { await run(); }
    catch (Exception e) when (e is ArgumentException or FormatException or CryptographicException or OverflowException or IOException)
    { Console.WriteLine("PASS reject " + name); return; }
    throw new Exception("Hostile fixture accepted: " + name);
}

static async Task TestFileCeremonyAsync(VerifiedXPointNetworkBootstrap bootstrap, Signer root, Signer[] witnesses)
{
    // Separate synthetic private DEV fixture, never the retained deep-dev tree.
    var parent = Path.GetFullPath("C:/Work/DeepSession/secrets/dev");
    var name = "offline-authority-test-" + Guid.NewGuid().ToString("N");
    var fixture = Path.Combine(parent, name);
    if (!OperatingSystem.IsWindows() || !Directory.Exists(parent))
        throw new PlatformNotSupportedException("File ceremony test requires the scoped Windows dev root.");
    for (string? p = parent; p is not null; p = Path.GetDirectoryName(p))
        if ((File.GetAttributes(p) & FileAttributes.ReparsePoint) != 0) throw new IOException("Test parent contains a link.");
    if (Directory.Exists(fixture)) throw new IOException("Test fixture already exists.");
    Directory.CreateDirectory(fixture);
    var nodeSigners = Enumerable.Range(1, 3).Select(i => Signer.Create(Path.Combine(fixture, $"node-{i}.seed"), nodeSigner: true)).ToArray();
    try
    {
        var nodes = nodeSigners.Select((s, i) => new XPointNetworkOperationalNode(s,
            B((byte)(20 + i)), B(30), B((byte)(40 + i)), B((byte)(50 + i)), (uint)(64_500 + i), 840,
            B((byte)(60 + i)), IPAddress.Parse($"192.0.2.{i + 1}"), 443,
            B((byte)(70 + i)), B((byte)(80 + i)),
            ScalarMult.Base(B((byte)(90 + i))), ScalarMult.Base(B((byte)(100 + i))),
            Enumerable.Range(0, 5).Select(role => (ReadOnlyMemory<byte>)PublicKeyAuth.GenerateKeyPair(B((byte)(110 + i * 5 + role))).PublicKey).ToArray())).ToArray();
        var pending = await XPointNetworkOperationalGenesisAuthor.AuthorNetworkCandidateAsync(new(
            B(10), bootstrap, [root], witnesses, nodes, B(11), B(12), B(13),
            PublicKeyAuth.GenerateKeyPair(B(14)).PublicKey, PublicKeyAuth.GenerateKeyPair(B(15)).PublicKey,
            990, 1_000, 1_500, rootPolicyExpiresAtUnixSeconds: 9_000));
        using var phrase = DeepRecoveryV1.Generate();
        var did2 = DeepIdV2Root.DeriveDid2(phrase);
        var head = await DeepIdV2DirectoryHeadAuthor.AuthorGenesisAsync(bootstrap.Authority, 990, 1_500,
            witnesses.Select(w => (IAccountDirectoryAdh1WitnessSigner)w).ToArray());
        var lookup = DeepIdV2AccountDirectoryLookupCodec.Author(did2, bootstrap.Authority.NetworkId.Span,
            head.ProtectedHead.LogGeneration, head.CoreHash.Span, 1, new byte[38], new byte[32]);
        var query = VerifiedDeepIdV2DirectoryQuery.VerifyDid2(lookup, did2);
        var material = DeepIdV2DirectoryProofMaterialAuthor.Create(head.ProtectedHead, [], [], query.DirectoryLeafKey.Span, head.ProtectedHead);
        var clock = new DevGenesisMonotonicClock();
        var sent = await clock.ReadAsync(default);
        var nonce = B(16);
        var request = new AccountDirectoryProofAuthoringRequest(bootstrap.Authority.NetworkId.Span,
            nonce, sent.BootId.Span, sent.SampleSeconds, head.ExactAdh1.Span, pending.ExactXnv1.Span,
            1_100, 5, 1_100, 1_130, AccountDirectoryDtt1IssuanceEpoch.Derive(bootstrap.Authority, 1_100, 5), 2);
        using var pq = DeepMlDsa65CandidateVerifierFactory.OpenForCurrentProcess();
        var proof = await DeepIdV2DirectoryProofAuthor.IssueGenesisAsync(bootstrap.Authority, request, material, witnesses, 1, pq);
        var received = await clock.ReadAsync(default);
        var freshness = DeepIdV2DirectoryCurrentProofVerifier.VerifyRequestedDid2(bootstrap.Authority,
            proof.ExactAdh1, proof.ExactDtt1, proof.ExactAdp1V2, nonce, query,
            new(sent.BootId.Span, sent.SampleSeconds, received.SampleSeconds, received.SampleSeconds), head.ProtectedHead, 1, 2, pq);
        var operational = await XPointNetworkOperationalGenesisAuthor.CompleteDid2Async(pending, freshness, new OnionTrustedTimeAuthority(clock));
        var publicRoot = Path.Combine(fixture, "public"); var offline = Path.Combine(fixture, "offline-root");
        Directory.CreateDirectory(publicRoot); Directory.CreateDirectory(offline);
        var bundle = XPointNetworkClosureWireCodec.EncodeResponse(bootstrap.Authority.NetworkId.Span,
            [bootstrap.ExactXna1], [bootstrap.ExactDts1], [operational.ExactXvp1], [operational.ExactXnv1],
            [operational.ExactXnh1], operational.ExactXnd1, [operational.ExactPmt2], [operational.ExactPma2]);
        var manifest = JsonSerializer.SerializeToUtf8Bytes(new { schema = "deep-dev.v1", nodeCount = 3,
            networkIdHex = Convert.ToHexString(bootstrap.Authority.NetworkId.Span),
            genesisAuthorityCoreHashHex = Convert.ToHexString(bootstrap.GenesisPin.AuthorityCoreHash.Span) });
        File.WriteAllBytes(Path.Combine(publicRoot, "deep-dev.json"), manifest);
        File.WriteAllBytes(Path.Combine(publicRoot, "network.ncp2"), bundle);
        File.WriteAllBytes(Path.Combine(publicRoot, "genesis.xna1"), bootstrap.ExactXna1.ToArray());
        File.WriteAllBytes(Path.Combine(publicRoot, "genesis.dts1"), bootstrap.ExactDts1.ToArray());
        File.WriteAllBytes(Path.Combine(offline, "root.seed"), root.Seed);
        var observations = 0;
        var completed = await DevOfflineAuthorityRenewal.PrepareAsync(fixture, "fixture-observer", (_, sources) => {
            Check(sources.Length == 2 && sources[0].HostAscii == "time1.invalid", "exact authenticated observer source policy");
            observations++; return Task.FromResult(20_000UL);
        });
        Check(observations == 1 && File.Exists(Path.Combine(completed, "authority-pair.json")) &&
            !Directory.Exists(completed + ".pending"), "file ceremony completes one public-only staging directory");
        var prepared = JsonSerializer.Deserialize<DevOfflineAuthorityRenewal.PreparedPair>(File.ReadAllBytes(Path.Combine(completed, "authority-pair.json")))!;
        _ = XPointNetworkAuthorityVerifier.Verify(bootstrap.GenesisPin,
            prepared.ExactAuthorityChain.Select(b => (ReadOnlyMemory<byte>)b).ToArray(),
            prepared.ExactTimePolicyChain.Select(b => (ReadOnlyMemory<byte>)b).ToArray());
        Check(prepared.PriorBundleSha256 == Convert.ToHexStringLower(SHA256.HashData(bundle)) &&
            Directory.GetFiles(completed).Length == 1 && File.ReadAllBytes(Path.Combine(publicRoot, "network.ncp2")).AsSpan().SequenceEqual(bundle) &&
            File.ReadAllBytes(Path.Combine(offline, "root.seed")).AsSpan().SequenceEqual(root.Seed), "source and root retained; exact public-only binding");
        await Reject(() => DevOfflineAuthorityRenewal.PrepareAsync(fixture, "unused", (_, _) => {
            File.WriteAllBytes(Path.Combine(publicRoot, "deep-dev.json"), [.. manifest, (byte)' ']);
            return Task.FromResult(20_000UL);
        }), "source mutation during observation");
        File.WriteAllBytes(Path.Combine(publicRoot, "deep-dev.json"), manifest);
        using (var lease = new FileStream(Path.Combine(offline, "authority-renewal.lease"), FileMode.Open, FileAccess.ReadWrite, FileShare.None))
            await Reject(() => DevOfflineAuthorityRenewal.PrepareAsync(fixture, "unused", (_, _) => throw new Exception("Observer must not run")), "concurrent offline ceremony");
        var malformed = bundle.ToArray(); malformed[9] = 7;
        File.WriteAllBytes(Path.Combine(publicRoot, "network.ncp2"), malformed);
        await Reject(() => DevOfflineAuthorityRenewal.PrepareAsync(fixture, "unused", (_, _) => throw new Exception("Observer must not run")), "retired seven-chain closure");
        Check(Directory.GetDirectories(Path.Combine(offline, "renewals")).Length == 1, "rejected ceremonies create no candidate");
    }
    finally
    {
        foreach (var node in nodeSigners) node.Dispose();
        if (Path.GetFullPath(fixture) != Path.Combine(parent, name) ||
            !Path.GetFullPath(fixture).StartsWith(parent + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            throw new IOException("Unexpected development test cleanup target.");
        Directory.Delete(fixture, recursive: true);
    }
}
