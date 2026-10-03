using System.Diagnostics;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.Identity;
using Deep.Protocol.XPointNetworkV1;

// Offline ceremony only. A signed snapshot is not NTS acquisition, deployment,
// current readiness or permission to replace an initialized network's floors.
internal static class OfflineDid2GenesisAuthor
{
    internal static ParsedDid2 ReadRequestedCredential(string path)
    {
        using var input = new FileStream(BootstrapIo.ExistingFile(path), FileMode.Open, FileAccess.Read, FileShare.Read);
        if (input.Length != DeepIdV2Codec.Did2Length)
            throw new InvalidDataException("The requested DID2 credential has an invalid length.");
        var exact = new byte[DeepIdV2Codec.Did2Length];
        input.ReadExactly(exact);
        if (input.ReadByte() != -1)
            throw new InvalidDataException("The requested DID2 credential changed during reading.");
        return DeepIdV2Codec.DecodeDid2(exact);
    }

    internal static async Task<AuthoredXPointNetworkOperationalGenesis> CompleteAsync(
        PendingXPointNetworkOperationalGenesis pending, VerifiedXPointNetworkBootstrap bootstrap,
        ParsedDid2 requestedDid2, FileSigner[] witnesses, ulong from, ulong until,
        byte[] nonce, byte[] boot, ulong sent, ulong received, ulong current,
        ulong observedTime, CancellationToken ct = default)
    {
        var directory = await DeepIdV2DirectoryHeadAuthor.AuthorGenesisAsync(
            bootstrap.Authority, from, until, witnesses, ct);
        var lookup = DeepIdV2AccountDirectoryLookupCodec.Author(requestedDid2, bootstrap.Authority.NetworkId.Span,
            directory.ProtectedHead.LogGeneration, directory.CoreHash.Span, 1, new byte[38], new byte[32]);
        var query = VerifiedDeepIdV2DirectoryQuery.VerifyDid2(lookup, requestedDid2);
        var material = DeepIdV2DirectoryProofMaterialAuthor.Create(directory.ProtectedHead, [], [],
            query.DirectoryLeafKey.Span, directory.ProtectedHead);
        var request = new AccountDirectoryProofAuthoringRequest(bootstrap.Authority.NetworkId.Span, nonce, boot,
            sent, directory.ExactAdh1.Span, pending.ExactXnv1.Span, observedTime, 5,
            observedTime, checked(observedTime + 30),
            AccountDirectoryDtt1IssuanceEpoch.Derive(bootstrap.Authority, observedTime, 5), 2);
        using var pq = DeepMlDsa65CandidateVerifierFactory.OpenForCurrentProcess();
        var proof = await DeepIdV2DirectoryProofAuthor.IssueGenesisAsync(bootstrap.Authority, request, material,
            witnesses, 1, pq, ct);
        var freshness = DeepIdV2DirectoryCurrentProofVerifier.VerifyRequestedDid2(bootstrap.Authority,
            proof.ExactAdh1, proof.ExactDtt1, proof.ExactAdp1V2, nonce, query,
            new(boot, sent, received, current), directory.ProtectedHead, 1, 2, pq);
        return await XPointNetworkOperationalGenesisAuthor.CompleteDid2Async(pending, freshness,
            new(new OperatorSnapshotClock(boot, current)), ct);
    }

    // The supplied historical monotonic sample progresses during this ceremony.
    internal sealed class OperatorSnapshotClock(byte[] boot, ulong sample) : IOnionMonotonicClock
    {
        private readonly byte[] bootId = boot.ToArray();
        private readonly long started = Stopwatch.GetTimestamp();
        public ValueTask<OnionMonotonicReading> ReadAsync(CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            return ValueTask.FromResult(new OnionMonotonicReading(bootId,
                checked(sample + (ulong)Stopwatch.GetElapsedTime(started).TotalSeconds)));
        }
    }
}
