using System.Net;
using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ContactV1;
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
                990, 1_000, 1_500, B(32, 0xf2), B(16, 0xf3), 100, 101, 102, 1_100, 5));
        genesis.VerifiedNetwork.EnsureCurrent();
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
}
