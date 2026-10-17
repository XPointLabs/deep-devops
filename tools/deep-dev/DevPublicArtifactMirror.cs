using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.XPointNetworkV1;
using static DevOfflineAuthorityRenewal;

// Rebuildable byte-identical PUBLIC distribution output, never authority or
// private custody. The existing publisher journal remains the sole producer.
internal static class DevPublicArtifactMirror
{
    internal const string Target = "/run/deep-public-native";

    internal static void Synchronize(string source, byte[] bundle)
    {
        if (!OperatingSystem.IsLinux() || source != "/run/deep-public" || !Directory.Exists(Target))
            throw new InvalidOperationException("The explicit native public-output mount is required.");
        RequireNoLinks(source); RequireNoLinks(Target);
        var closure = XPointNetworkClosureWireCodec.DecodeResponse(bundle);
        var files = new SortedDictionary<string, byte[]>(StringComparer.Ordinal);
        Add("genesis.xna1", closure.ExactAuthorityChain[0]);
        Add("genesis.dts1", closure.ExactTimePolicyChain[0]);
        Series("xna1", closure.ExactAuthorityChain);
        Series("dts1", closure.ExactTimePolicyChain);
        Series("xvp1", closure.ExactNetworkPolicyChain);
        Series("xnv1", closure.ExactViewChain);
        Series("xnh1", closure.ExactHeadChain);
        Series("xnd1", closure.ExactActiveNodeDescriptors);
        Series("pmt2", closure.ExactPlacementTopologyChain);
        Series("pma2", closure.ExactMailboxAuthorityChain);
        // Fixed, bounded public artifacts only. Never enumerate/copy a source
        // directory, configuration, operator input, key or recovery material.
        files.Add("genesis.adh1", Read(Path.Combine(source, "genesis.adh1"), 4_096));
        _ = XPointNetworkOperationalSuccessorAuthor.ComputeAdh1CoreHash(files["genesis.adh1"]);
        files.Add("observer.did2", Read(Path.Combine(source, "observer.did2"), 65_535));
        _ = DeepIdV2Codec.DecodeDid2(files["observer.did2"]);
        files.Add("dev-ca.crt", Read(Path.Combine(source, "dev-ca.crt"), 16_384));
        var pem = System.Text.Encoding.ASCII.GetString(files["dev-ca.crt"]);
        if (pem.Contains("PRIVATE KEY", StringComparison.Ordinal))
            throw new CryptographicException("Public certificate output cannot contain a private key.");
        using var ca = X509Certificate2.CreateFromPem(pem);
        if (ca.HasPrivateKey) throw new CryptographicException("Public certificate output has private custody.");
        var crl = Path.Combine(source, "dev-ca.crl");
        if (File.Exists(crl))
        {
            files.Add("dev-ca.crl", Read(crl, 65_536));
            DevPki.ValidateCrl(files["dev-ca.crl"], ca);
        }
        foreach (var pair in files) Copy(pair.Key, pair.Value);
        // These are the SAME exact signed bytes, not re-authored projections.
        // Commit the self-contained closure last; consumers still verify every
        // pin, signature, time, floor, source and issuer on their normal path.
        Copy("current.xnv1", closure.ExactViewChain[^1].ToArray());
        Copy("network.ncp2", bundle);

        void Add(string name, ReadOnlyMemory<byte> bytes) => files.Add(name, bytes.ToArray());
        void Series(string role, IReadOnlyList<ReadOnlyMemory<byte>> values)
        {
            for (var index = 0; index < values.Count; index++) Add($"{role}.{index:0000}.bin", values[index]);
        }
    }

    private static void Copy(string name, byte[] bytes)
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException("Native public output requires Linux.");
        var file = Path.Combine(Target, name); RequireNoLinks(file);
        if (File.Exists(file) && Read(file, XPointNetworkClosureWireCodec.MaximumResponseLength).AsSpan().SequenceEqual(bytes)) return;
        var stage = file + ".stage-" + Guid.NewGuid().ToString("N");
        using (var stream = new FileStream(stage, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
        { stream.Write(bytes); stream.Flush(true); }
        File.SetUnixFileMode(stage, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.OtherRead);
        RequireNoLinks(file); File.Move(stage, file, true);
        if (!Read(file, XPointNetworkClosureWireCodec.MaximumResponseLength).AsSpan().SequenceEqual(bytes))
            throw new IOException("Native public-output readback differs.");
    }
}
