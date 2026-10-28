using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.XPointNetworkV1;
using Sodium;

internal static class DevTimeSourceTests
{
    internal static async Task RunAsync()
    {
        using var root = new RootSigner();
        AccountDirectoryDts1Source[] sources = [Source(1, 11), Source(2, 12), Source(3, 13)];
        var witnesses = new[] { 21, 22, 23 }.Select(value => new XPointNetworkBootstrapWitnessKey(
            Bytes(value), 0, PublicKeyAuth.GenerateKeyPair(Bytes(value + 10)).PublicKey, Bytes(value + 20))).ToArray();
        var genesis = await XPointNetworkBootstrapAuthor.AuthorGenesisAsync(new(
            Bytes(70), Enumerable.Repeat((byte)71, 16).ToArray(),
            [new(root.RootKeyId.Span, 0, root.Ed25519PublicKey.Span, root.CustodyDomainHash.Span)], 1,
            witnesses, 2, sources[..2], 5, 10, 900, 900, 10_000, 900, 9_000, 1, 1), [root]);
        var oldPolicy = AccountDirectoryDts1Codec.Decode(genesis.ExactDts1.Span);
        Check(DevTimeSourceUpdate.Capture(null, oldPolicy) is null, "omitted source file retains the exact existing signed sources");
        var sameSources = await DevOfflineAuthorityRenewal.AuthorPairAsync(genesis.GenesisPin,
            [genesis.ExactXna1], [genesis.ExactDts1], 20_000, root, new string('b', 64));
        var samePolicy = AccountDirectoryDts1Codec.Decode(sameSources.ExactTimePolicyChain[^1]);
        var sameAuthority = XPointNetworkAuthorityVerifier.Verify(genesis.GenesisPin,
            sameSources.ExactAuthorityChain.Select(bytes => (ReadOnlyMemory<byte>)bytes).ToArray(),
            sameSources.ExactTimePolicyChain.Select(bytes => (ReadOnlyMemory<byte>)bytes).ToArray());
        Check(samePolicy.Sources.Count == oldPolicy.Sources.Count &&
            samePolicy.Sources.Zip(oldPolicy.Sources).All(pair => SameSource(pair.First, pair.Second)) &&
            samePolicy.RequiredSourceCount == oldPolicy.RequiredSourceCount &&
            samePolicy.RequiredDistinctFailureFamilies == oldPolicy.RequiredDistinctFailureFamilies &&
            samePolicy.MaximumSourceSampleAgeSeconds == oldPolicy.MaximumSourceSampleAgeSeconds &&
            samePolicy.MaximumIntervalWidthSeconds == oldPolicy.MaximumIntervalWidthSeconds &&
            sameAuthority.RootKeys[0].Ed25519PublicKey.Span.SequenceEqual(root.Ed25519PublicKey.Span) &&
            sameSources.ExactAuthorityChain[0].AsSpan().SequenceEqual(genesis.ExactXna1.Span) &&
            sameSources.ExactTimePolicyChain[0].AsSpan().SequenceEqual(genesis.ExactDts1.Span),
            "same-source renewal after expiry preserves original keys, exact ancestry and every source tuple and limit");
        var sourceFile = EncodeSources(sources);
        var parsed = DevTimeSourceUpdate.Parse(sourceFile, oldPolicy);
        Check(parsed.Length == 3, "closed canonical three-source file");
        Check(Observe(sources, sources) == 1_000, "three healthy sources");
        foreach (var unavailable in Enumerable.Range(0, 3))
            Check(Observe(sources, sources.Where((_, i) => i != unavailable).ToArray()) == 1_000,
                "two independent sources survive one unavailable source");
        Reject(() => Observe(sources, [sources[0], sources[0]]), "duplicate observation");
        Reject(() => Observe(sources, [sources[0], Source(4, 14)]), "unknown observation");
        Reject(() => Observe(sources, [sources[0]]), "one observation");
        Reject(() => Observe(sources, [.. sources, Source(4, 14)]), "oversized observation list");
        var sameFamily = new[] { Source(1, 11), Source(2, 11), Source(3, 13) };
        Reject(() => Observe(sameFamily, sameFamily[..2]), "same-family quorum");
        Reject(() => Observe(sources, sources, timeStep: 100), "conflicting intervals");
        Reject(() => Observe(sources, sources, radius: 0), "zero radius");
        Reject(() => Observe(sources, sources, radius: 11), "oversized radius");
        Reject(() => Observe(sources, sources, radius: 9, elapsed: TimeSpan.FromSeconds(2)), "radius plus actual age");
        Reject(() => Observe(sources, sources, elapsed: TimeSpan.FromMilliseconds(10_001)), "expired monotonic age");
        Reject(() => Observe(sources, sources, elapsed: TimeSpan.FromSeconds(-1)), "negative monotonic age");
        Reject(() => DevNtsObservation.Parse("{\"observations\":[],\"unknown\":0}"u8.ToArray(), sources, TimeSpan.Zero), "unknown response field");
        Reject(() => DevNtsObservation.Parse("{\"observations\":[],\"observations\":[]}"u8.ToArray(), sources, TimeSpan.Zero), "duplicate response field");
        Reject(() => DevTimeSourceUpdate.Parse(EncodeSources(sources.Reverse().ToArray()), oldPolicy), "unsorted source file");
        Reject(() => DevTimeSourceUpdate.Parse(EncodeSources([sources[0], sources[0], sources[2]]), oldPolicy), "duplicate source file");
        Reject(() => DevTimeSourceUpdate.Parse(EncodeSources(Enumerable.Repeat(sources[0], 9).ToArray()), oldPolicy), "oversized source file");
        Reject(() => DevTimeSourceUpdate.Parse(Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(sourceFile).Replace("\"schema\":", "\"extra\":0,\"schema\":")), oldPolicy), "unknown source file field");
        Reject(() => DevTimeSourceUpdate.Parse(Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(sourceFile).Replace("\"protocol\":1", "\"protocol\":1,\"protocol\":1")), oldPolicy), "duplicate source tuple field");

        var pair = await DevOfflineAuthorityRenewal.AuthorPairAsync(genesis.GenesisPin,
            [genesis.ExactXna1], [genesis.ExactDts1], 20_000, root, new string('a', 64), parsed);
        await RejectAsync(() => DevOfflineAuthorityRenewal.AuthorPairAsync(genesis.GenesisPin,
            [genesis.ExactXna1], [genesis.ExactDts1], 20_000, root, new string('a', 64), [sources[0], sources[2]]),
            "provided successor sources cannot remove an original source");
        var verified = XPointNetworkAuthorityVerifier.Verify(genesis.GenesisPin,
            pair.ExactAuthorityChain.Select(bytes => (ReadOnlyMemory<byte>)bytes).ToArray(),
            pair.ExactTimePolicyChain.Select(bytes => (ReadOnlyMemory<byte>)bytes).ToArray());
        var nextPolicy = AccountDirectoryDts1Codec.Decode(pair.ExactTimePolicyChain[^1]);
        Check(nextPolicy.Sources.Count == 3 && nextPolicy.Sources.Take(2).Zip(oldPolicy.Sources).All(pair => SameSource(pair.First, pair.Second)) &&
            nextPolicy.RequiredSourceCount == 2 &&
            nextPolicy.RequiredDistinctFailureFamilies == 2 && nextPolicy.MaximumSourceSampleAgeSeconds == oldPolicy.MaximumSourceSampleAgeSeconds &&
            nextPolicy.MaximumIntervalWidthSeconds == oldPolicy.MaximumIntervalWidthSeconds &&
            verified.RootKeys[0].Ed25519PublicKey.Span.SequenceEqual(root.Ed25519PublicKey.Span) &&
            pair.ExactAuthorityChain[0].AsSpan().SequenceEqual(genesis.ExactXna1.Span) &&
            pair.ExactTimePolicyChain[0].AsSpan().SequenceEqual(genesis.ExactDts1.Span), "root-signed additive successor retains key genesis and limits");
        pair.ExactTimePolicyChain[^1][^1] ^= 1;
        Reject(() => XPointNetworkAuthorityVerifier.Verify(genesis.GenesisPin,
            pair.ExactAuthorityChain.Select(bytes => (ReadOnlyMemory<byte>)bytes).ToArray(),
            pair.ExactTimePolicyChain.Select(bytes => (ReadOnlyMemory<byte>)bytes).ToArray()), "changed successor root receipt");

        var temp = Path.Combine(Path.GetTempPath(), "deep-time-sources-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(temp);
        try {
            var path = Path.Combine(temp, "sources.json");
            Reject(() => DevTimeSourceUpdate.Capture("", oldPolicy)!, "provided empty source path is not same-source renewal");
            Reject(() => DevTimeSourceUpdate.Capture(path, oldPolicy)!, "provided absent source file is not same-source renewal");
            File.WriteAllBytes(path, "{}"u8.ToArray());
            Reject(() => DevTimeSourceUpdate.Capture(path, oldPolicy)!, "provided malformed source file is not same-source renewal");
            File.WriteAllBytes(path, sourceFile);
            var captured = DevTimeSourceUpdate.Capture(path, oldPolicy)!;
            captured.RequireUnchanged();
            File.WriteAllBytes(path, [.. sourceFile, (byte)' ']);
            Reject(() => { captured.RequireUnchanged(); return 0; }, "source-file callback mutation");
        }
        finally { File.Delete(Path.Combine(temp, "sources.json")); Directory.Delete(temp); }
        await DevRetainedBuildTests.RunAsync();
        Console.WriteLine("Offline time-source tests passed; synthetic signed fixtures are not live NTS or activation evidence.");
    }

    private static ulong Observe(AccountDirectoryDts1Source[] policy, AccountDirectoryDts1Source[] observations,
        uint radius = 1, int timeStep = 0, TimeSpan? elapsed = null) => DevNtsObservation.Parse(
        JsonSerializer.SerializeToUtf8Bytes(new { observations = observations.Select((source, index) => new {
            id = Convert.ToHexStringLower(source.SourceId.Span), unixSeconds = 1_000 + index * timeStep, radiusSeconds = radius }) }),
        policy, elapsed ?? TimeSpan.FromMilliseconds(1));

    private static byte[] EncodeSources(AccountDirectoryDts1Source[] sources) => JsonSerializer.SerializeToUtf8Bytes(new {
        schema = "deep-dev-time-sources.v1", sources = sources.Select(source => new {
            id = Convert.ToHexStringLower(source.SourceId.Span), family = Convert.ToHexStringLower(source.FailureFamilyHash.Span),
            protocol = source.Protocol, host = source.HostAscii, port = source.Port,
            pin = Convert.ToHexStringLower(source.TlsSpkiSha256.Span), radius = source.MaximumRadiusSeconds }) });
    private static AccountDirectoryDts1Source Source(int id, int family) => new(Bytes(id), Bytes(family), 1, $"time{id}.invalid", 4460, Bytes(id + 50), 10);
    private static bool SameSource(AccountDirectoryDts1Source left, AccountDirectoryDts1Source right) =>
        left.SourceId.Span.SequenceEqual(right.SourceId.Span) && left.FailureFamilyHash.Span.SequenceEqual(right.FailureFamilyHash.Span) &&
        left.Protocol == right.Protocol && left.HostAscii == right.HostAscii && left.Port == right.Port &&
        left.TlsSpkiSha256.Span.SequenceEqual(right.TlsSpkiSha256.Span) && left.MaximumRadiusSeconds == right.MaximumRadiusSeconds;
    private static byte[] Bytes(int value) => Enumerable.Repeat(checked((byte)value), 32).ToArray();
    private static void Check(bool condition, string name) { if (!condition) throw new InvalidOperationException(name); Console.WriteLine("PASS " + name); }
    private static void Reject(Func<object> action, string name)
    {
        try { _ = action(); }
        catch (Exception error) when (error is ArgumentException or FormatException or CryptographicException or IOException or InvalidDataException or XPointNetworkAuthorityVerificationException)
        { Console.WriteLine("PASS reject " + name); return; }
        throw new InvalidOperationException("Hostile fixture accepted: " + name);
    }
    private static async Task RejectAsync(Func<Task> action, string name)
    {
        try { await action(); }
        catch (Exception error) when (error is ArgumentException or FormatException or CryptographicException or IOException or InvalidDataException or XPointNetworkAuthorityVerificationException)
        { Console.WriteLine("PASS reject " + name); return; }
        throw new InvalidOperationException("Hostile fixture accepted: " + name);
    }
    private sealed class RootSigner : IXPointNetworkBootstrapRootSigner, IDisposable
    {
        private readonly KeyPair key = PublicKeyAuth.GenerateKeyPair(Bytes(80));
        public ReadOnlyMemory<byte> RootKeyId => Bytes(81);
        public ulong KeyGeneration => 0;
        public ReadOnlyMemory<byte> Ed25519PublicKey => key.PublicKey;
        public ReadOnlyMemory<byte> CustodyDomainHash => Bytes(82);
        public ValueTask<int> SignAsync(XPointNetworkRootSigningRequest request, Memory<byte> destination, CancellationToken token)
        { token.ThrowIfCancellationRequested(); PublicKeyAuth.SignDetached(request.SigningInput.ToArray(), key.PrivateKey).CopyTo(destination); return ValueTask.FromResult(64); }
        public void Dispose() => CryptographicOperations.ZeroMemory(key.PrivateKey);
    }
}
