using System.Security.Cryptography;
using System.Text.Json;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.XPointNetworkV1;

// Host-only offline ceremony. Its result deliberately is NOT an NCP2 closure:
// old operational policy/PMA must not be distributed as current under a new root.
internal static class DevOfflineAuthorityRenewal
{
    internal sealed record PreparedPair(string Schema, string PriorBundleSha256,
        ulong Observed, ulong AuthorityGeneration, ulong TimePolicyGeneration,
        byte[][] ExactAuthorityChain, byte[][] ExactTimePolicyChain);

    internal static async Task<string> PrepareAsync(string custodyRoot, string executable,
        Func<string, AccountDirectoryDts1Source[], Task<ulong>> observe)
    {
        var root = Path.GetFullPath(custodyRoot);
        if (!OperatingSystem.IsWindows() || !root.StartsWith(
            Path.GetFullPath("C:/Work/DeepSession/secrets/dev") + Path.DirectorySeparatorChar,
            StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("Offline development renewal requires local dev custody.");
        RequireNoLinks(root);
        var publicRoot = Path.Combine(root, "public");
        var offlineRoot = Path.Combine(root, "offline-root");
        RequireNoLinks(publicRoot); RequireNoLinks(offlineRoot);
        var leasePath = Path.Combine(offlineRoot, "authority-renewal.lease");
        RequireNoLinks(leasePath);
        using var lease = new FileStream(leasePath,
            FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
        var manifestPath = Path.Combine(publicRoot, "deep-dev.json");
        var manifestBytes = Read(manifestPath, 16_384);
        using var manifest = JsonDocument.Parse(manifestBytes);
        if (manifest.RootElement.GetProperty("schema").GetString() != "deep-dev.v1" ||
            manifest.RootElement.GetProperty("nodeCount").GetInt32() != 3)
            throw new InvalidDataException("Not the owned three-node development environment.");
        var network = Convert.FromHexString(manifest.RootElement.GetProperty("networkIdHex").GetString()!);
        var pin = new XPointNetworkGenesisPin(network, Convert.FromHexString(
            manifest.RootElement.GetProperty("genesisAuthorityCoreHashHex").GetString()!));
        var bundlePath = Path.Combine(publicRoot, "network.ncp2");
        var priorBytes = Read(bundlePath, XPointNetworkClosureWireCodec.MaximumResponseLength);
        var closure = XPointNetworkClosureWireCodec.DecodeResponse(priorBytes);
        if (!closure.NetworkId.Span.SequenceEqual(network) ||
            closure.ExactAuthorityChain.Count >= XPointNetworkClosureWireCodec.MaximumChainCount ||
            !Read(Path.Combine(publicRoot, "genesis.xna1"), 65_535).AsSpan().SequenceEqual(closure.ExactAuthorityChain[0].Span) ||
            !Read(Path.Combine(publicRoot, "genesis.dts1"), 65_535).AsSpan().SequenceEqual(closure.ExactTimePolicyChain[0].Span))
            throw new InvalidDataException("Development genesis/history scope differs.");
        _ = XPointNetworkAuthorityVerifier.Verify(pin, closure.ExactAuthorityChain, closure.ExactTimePolicyChain);
        var sources = AccountDirectoryDts1Codec.Decode(closure.ExactTimePolicyChain[^1].Span).Sources.ToArray();
        // Even after expiry, only the authenticated retained source policy is
        // used to acquire time for the offline ceremony. This is not live DTT1.
        var observed = await observe(executable, sources);
        RequireUnchanged();
        var rootKeyPath = Path.Combine(offlineRoot, "root.seed");
        RequireNoLinks(rootKeyPath);
        using var signer = Signer.LoadRoot(rootKeyPath);
        var pair = await AuthorPairAsync(pin, closure.ExactAuthorityChain, closure.ExactTimePolicyChain,
            observed, signer, Convert.ToHexStringLower(SHA256.HashData(priorBytes)));
        RequireUnchanged();
        var directory = Path.Combine(offlineRoot, "renewals");
        RequireNoLinks(directory); Directory.CreateDirectory(directory); RequireNoLinks(directory);
        var staging = Path.Combine(directory, "authority-" + Guid.NewGuid().ToString("N") + ".pending");
        Directory.CreateDirectory(staging);
        var bytes = JsonSerializer.SerializeToUtf8Bytes(pair);
        using (var stream = new FileStream(Path.Combine(staging, "authority-pair.json"), FileMode.CreateNew,
            FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough)) { stream.Write(bytes); stream.Flush(true); }
        // A crash leaves an explicitly incomplete public-only candidate, never
        // an online partial commit. Completion is one same-parent rename.
        var complete = staging[..^8];
        Directory.Move(staging, complete);
        return complete;

        void RequireUnchanged()
        {
            if (!Read(bundlePath, XPointNetworkClosureWireCodec.MaximumResponseLength).AsSpan().SequenceEqual(priorBytes) ||
                !Read(manifestPath, 16_384).AsSpan().SequenceEqual(manifestBytes))
                throw new IOException("Development source changed during offline preparation; reacquire it.");
        }
    }

    internal static async Task<PreparedPair> AuthorPairAsync(XPointNetworkGenesisPin pin,
        IReadOnlyList<ReadOnlyMemory<byte>> xna, IReadOnlyList<ReadOnlyMemory<byte>> dts,
        ulong observed, IXPointNetworkBootstrapRootSigner signer, string priorBundleSha256)
    {
        if (priorBundleSha256.Length != 64 || priorBundleSha256.Any(c => !char.IsAsciiHexDigit(c)))
            throw new ArgumentException("Exact prior-public digest required.");
        var prior = XPointNetworkAuthorityVerifier.Verify(pin, xna, dts);
        var expiry = checked(observed + 7 * 86_400UL);
        var renewal = await XPointNetworkBootstrapAuthor.AuthorSameKeyRenewalAsync(
            RandomNumberGenerator.GetBytes(32), prior, dts, observed, observed,
            Math.Max(prior.ExpiresAt, expiry), observed, expiry, [signer]);
        ReadOnlyMemory<byte>[] nextXna = [.. xna, renewal.ExactXna1];
        ReadOnlyMemory<byte>[] nextDts = [.. dts, renewal.ExactDts1];
        var verified = XPointNetworkAuthorityVerifier.Verify(pin, nextXna, nextDts);
        return new("deep-dev-offline-authority.v1", priorBundleSha256.ToLowerInvariant(), observed,
            verified.AuthorityGeneration, verified.Dts1PolicyGeneration,
            nextXna.Select(b => b.ToArray()).ToArray(), nextDts.Select(b => b.ToArray()).ToArray());
    }

    internal static void RequireNoLinks(string path)
    {
        for (string? current = Path.GetFullPath(path); current is not null; current = Path.GetDirectoryName(current))
        {
            FileAttributes attributes;
            try { attributes = File.GetAttributes(current); }
            catch (FileNotFoundException) { continue; }
            catch (DirectoryNotFoundException) { continue; }
            if ((attributes & FileAttributes.ReparsePoint) != 0)
                throw new IOException("Development custody must not traverse links.");
        }
    }
    internal static byte[] Read(string path, int bound)
    {
        RequireNoLinks(path);
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete);
        if (stream.Length is < 1 || stream.Length > bound) throw new InvalidDataException("Unbounded development public input.");
        var bytes = new byte[checked((int)stream.Length)]; stream.ReadExactly(bytes);
        if (stream.ReadByte() != -1) throw new IOException("Development public input changed.");
        return bytes;
    }
}
