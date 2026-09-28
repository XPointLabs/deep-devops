using System.Security.Cryptography;
using System.Text.Json;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;
using static BootstrapIo;

/// <summary>
/// Read-only verification of a historical, generation-zero bootstrap. The
/// caller supplies the independently pinned genesis and the artifact hash
/// observed on the intended UAT runtime. This is never current-time evidence,
/// and cannot replace any protected network LKG already accepted by a reader.
/// </summary>
internal static class CheckpointAudit
{
    internal static async Task RunAsync(Arguments arguments)
    {
        var sourceRoot = ExistingDirectory(arguments.Required("--audit-genesis-source"));
        var output = Path.GetFullPath(arguments.Required("--output"));
        if (File.Exists(output) || Directory.Exists(output))
            throw new IOException("The audit output already exists.");
        _ = ExistingDirectory(Path.GetDirectoryName(output)!);
        var network = Hex(arguments.Required("--network-id-hex"), 16, "independent network ID");
        var genesis = Hex(arguments.Required("--genesis-core-hash"), 32, "independent genesis core hash");
        var expectedView = Hex(arguments.Required("--expected-xnv1-artifact-hash"), 32, "observed runtime XNV1 hash");
        var source = SuccessorCeremony.ReadSource(sourceRoot);
        if (source.Manifest.Schema != "deep-production-authority-bootstrap.v1" ||
            !string.Equals(source.Manifest.NetworkIdHex, Convert.ToHexString(network), StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(source.Manifest.GenesisAuthorityCoreHashHex, Convert.ToHexString(genesis), StringComparison.OrdinalIgnoreCase) ||
            !CryptographicOperations.FixedTimeEquals(SHA256.HashData(source.One("xnv1")), expectedView))
            throw new CryptographicException("The source is not the independently observed generation-zero bootstrap.");
        var inventoryPath = ExistingFile(Path.Combine(sourceRoot, "bootstrap", "inventory.json"));
        if (new FileInfo(inventoryPath).Length is < 1 or > 524_288)
            throw new InvalidDataException("The historical snapshot inventory exceeds its bound.");
        var inventory = JsonSerializer.Deserialize<ArtifactInventory>(File.ReadAllBytes(inventoryPath))
                        ?? throw new InvalidDataException("The historical snapshot inventory is empty.");
        if (inventory.Format != "deep-contact-resolve-readonly-v2" ||
            !string.Equals(inventory.NetworkIdHex, source.Manifest.NetworkIdHex, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(inventory.GenesisAuthorityCoreHashHex, source.Manifest.GenesisAuthorityCoreHashHex, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(inventory.SnapshotQueryLeafHex, source.Manifest.DirectoryLeafKeyHex, StringComparison.OrdinalIgnoreCase))
            throw new CryptographicException("The snapshot inventory belongs to another checkpoint.");
        var authority = XPointNetworkBootstrapAuthor.VerifyExistingGenesis(
            source.One("xna1"), source.One("dts1"), new XPointNetworkGenesisPin(network, genesis)).Authority;
        var boot = Hex(inventory.SnapshotBootIdHex, 16, "snapshot boot ID");
        var freshness = AccountDirectoryCurrentProofVerifier.Verify(
            authority, source.One("adh1"), source.One("snapshot-dtt1"), source.One("snapshot-adp1"),
            Hex(inventory.SnapshotNonceHex, 32, "snapshot nonce"),
            Hex(inventory.SnapshotQueryLeafHex, 32, "snapshot query leaf"),
            new AccountDirectoryMonotonicRequestWindow(boot, inventory.SnapshotNonceCreatedAt,
                inventory.SnapshotResponseReceivedAt, inventory.SnapshotCurrentSample),
            protectedLkg: null, currentCheckpoint: null, inventory.SupportedReader);
        _ = MailboxAuthorityV2Verifier.Verify(authority, source.One("pma2"),
            freshness.TrustedLowerUnixSeconds, freshness.TrustedUpperUnixSeconds);
        var verified = await OnionNetworkContextVerifier.VerifyAsync(authority, freshness,
            [source.One("xvp1")], [source.One("xnv1")], [source.One("xnh1")],
            source.Many("xnd1").Select(static bytes => (ReadOnlyMemory<byte>)bytes).ToArray(),
            [source.One("pmt2")], null,
            new OnionTrustedTimeAuthority(new SnapshotClock(boot, inventory.SnapshotCurrentSample)),
            CancellationToken.None);
        verified.EnsureCurrent(); // Current only inside the authenticated historical snapshot window.
        var report = new
        {
            schema = "deep-uat-historical-bootstrap-audit.v1",
            currentTimeEvidence = false,
            replacesProtectedLkg = false,
            observedRuntimeXnv1ArtifactHashHex = Convert.ToHexString(expectedView),
            protectedHeadCoreHashHex = Convert.ToHexString(
                XPointNetworkOperationalSuccessorAuthor.ComputeXnh1CoreHash(source.One("xnh1"))),
            protectedPmtArtifactHashHex = Convert.ToHexString(ContactCodec.Decode("PMT2", source.One("pmt2")).ArtifactHash.Span),
        };
        WriteNew(output, JsonSerializer.SerializeToUtf8Bytes(report, new JsonSerializerOptions { WriteIndented = true }));
        Console.WriteLine("Historical genesis closure verified against independent runtime/genesis bindings; this is not current readiness evidence.");
    }

    private sealed class SnapshotClock(byte[] boot, ulong sample) : IOnionMonotonicClock
    {
        public ValueTask<OnionMonotonicReading> ReadAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(new OnionMonotonicReading(boot, sample));
        }
    }
}
