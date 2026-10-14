using System.Security.Cryptography;
using System.Text.Json;
using Deep.Protocol.ContactV1;
using Deep.Protocol.XPointNetworkV1;
using Sodium;

internal static partial class OfflineAuthoringTests
{
    private static async Task TestRenewedAuthorityExportAsync(string directory,
        VerifiedXPointNetworkBootstrap bootstrap, AuthoredXPointNetworkOperationalGenesis genesis,
        AuthoredXPointNetworkAuthorityRenewal firstRenewal,
        VerifiedXPointNetworkAuthority firstAuthority, AuthoredXPointNetworkOperationalSuccessor firstSuccessor,
        FileSigner root, FileSigner[] witnesses, XPointNetworkOperationalNode[] nodes, byte[] adhReference)
    {
        var genesisSource = SuccessorCeremony.ReadSource(Path.Combine(directory, "network-initial"));
        var initialBundle = Path.Combine(directory, "network-initial.ncp2");
        var firstInput = WriteAuthorityInput("authority-input-1", genesisSource,
            [genesis.ExactXna1, firstRenewal.ExactXna1],
            [genesis.ExactDts1, firstRenewal.ExactDts1]);
        if (firstInput.VerifyAuthority(bootstrap.GenesisPin).AuthorityGeneration != 1)
            throw new Exception("Operator source did not restore terminal renewed authority.");
        var firstOutput = Path.Combine(directory, "authority-output-1");
        SuccessorCeremony.WriteOutput(firstOutput, firstInput, firstSuccessor,
            genesis.ExactAdh1.Span, 8_500, 8_900);
        var originalManifest = File.ReadAllBytes(Path.Combine(firstOutput, "public-manifest.v1.json"));
        try
        {
            SuccessorCeremony.WriteOutput(firstOutput, firstInput, firstSuccessor,
                genesis.ExactAdh1.Span, 8_500, 8_900);
            throw new Exception("Successor writer replaced an existing output.");
        }
        catch (IOException)
        {
            if (!File.ReadAllBytes(Path.Combine(firstOutput, "public-manifest.v1.json")).AsSpan().SequenceEqual(originalManifest))
                throw new Exception("Rejected successor publication altered existing output.");
        }
        var firstBundle = Export(initialBundle, firstOutput, "authority-1.ncp2");
        RequireHistory(firstBundle, 2, 2, firstSuccessor, firstAuthority);

        var secondRenewal = await XPointNetworkBootstrapAuthor.AuthorSameKeyRenewalAsync(
            H("operator-authority-renewal-2"), firstAuthority,
            [genesis.ExactDts1, firstRenewal.ExactDts1],
            19_000, 19_000, 40_000, 19_000, 35_000, [root]);
        var secondAuthority = XPointNetworkAuthorityVerifier.Verify(bootstrap.GenesisPin,
            [genesis.ExactXna1, firstRenewal.ExactXna1, secondRenewal.ExactXna1],
            [genesis.ExactDts1, firstRenewal.ExactDts1, secondRenewal.ExactDts1]);
        var secondRollovers = nodes.Select((node, index) => new XPointNetworkOperationalNodeRollover(
            node.IdentitySigner, H($"second-current-{index}"), H($"second-next-{index}"),
            ScalarMult.Base(B(32, (byte)(0x50 + index))),
            ScalarMult.Base(B(32, (byte)(0x60 + index))))).ToArray();
        var secondSuccessor = await XPointNetworkOperationalSuccessorAuthor.AuthorAsync(new(
            H("operator-successor-2"), secondAuthority, [root], witnesses, secondRollovers,
            firstSuccessor.ExactXvp1, firstSuccessor.ExactXnd1,
            [genesis.ExactXnv1, firstSuccessor.ExactXnv1], firstSuccessor.ExactXnh1,
            firstSuccessor.ExactPma2, firstSuccessor.ExactPmt2,
            XPointNetworkOperationalSuccessorAuthor.ComputeXnh1CoreHash(firstSuccessor.ExactXnh1.Span),
            ContactCodec.Decode("PMT2", firstSuccessor.ExactPmt2.Span).ArtifactHash.Span,
            adhReference, 19_010, 19_010, 19_500));
        var secondInput = WriteAuthorityInput("authority-input-2", SuccessorCeremony.ReadSource(firstOutput),
            [genesis.ExactXna1, firstRenewal.ExactXna1, secondRenewal.ExactXna1],
            [genesis.ExactDts1, firstRenewal.ExactDts1, secondRenewal.ExactDts1]);
        var secondOutput = Path.Combine(directory, "authority-output-2");
        SuccessorCeremony.WriteOutput(secondOutput, secondInput, secondSuccessor,
            genesis.ExactAdh1.Span, 19_010, 19_500);
        var secondBundle = Export(firstBundle, secondOutput, "authority-2.ncp2");
        RequireHistory(secondBundle, 3, 3, secondSuccessor, secondAuthority);

        var delegatedRollovers = nodes.Select((node, index) => new XPointNetworkOperationalNodeRollover(
            node.IdentitySigner, secondRollovers[index].NextOriginSpkiSha256.Span, H($"third-next-{index}"),
            secondRollovers[index].NextOnionX25519PublicKey.Span,
            ScalarMult.Base(B(32, (byte)(0x90 + index))))).ToArray();
        var delegated = await XPointNetworkOperationalSuccessorAuthor.AuthorDelegatedAsync(new(
            H("operator-delegated-after-renewal"), secondAuthority, [], witnesses, delegatedRollovers,
            secondSuccessor.ExactXvp1, secondSuccessor.ExactXnd1,
            [genesis.ExactXnv1, firstSuccessor.ExactXnv1, secondSuccessor.ExactXnv1], secondSuccessor.ExactXnh1,
            secondSuccessor.ExactPma2, secondSuccessor.ExactPmt2,
            XPointNetworkOperationalSuccessorAuthor.ComputeXnh1CoreHash(secondSuccessor.ExactXnh1.Span),
            ContactCodec.Decode("PMT2", secondSuccessor.ExactPmt2.Span).ArtifactHash.Span,
            adhReference, 19_100, 19_100, 19_400));
        var delegatedSource = SuccessorCeremony.ReadSource(secondOutput);
        var delegatedOutput = Path.Combine(directory, "authority-output-delegated");
        SuccessorCeremony.WriteOutput(delegatedOutput, delegatedSource, delegated,
            genesis.ExactAdh1.Span, 19_100, 19_400);
        var delegatedBundle = Export(secondBundle, delegatedOutput, "authority-delegated.ncp2");
        RequireHistory(delegatedBundle, 3, 4, delegated, secondAuthority);
        // Exercise the existing distribution bound beyond64 without shortening
        // history or changing registered identities. Each actual delegated
        // producer activates previously announced traffic keys and signs the
        // next view/head/placement step; no fabricated generations are inserted.
        var sustainedSource = SuccessorCeremony.ReadSource(delegatedOutput);
        var sustainedModel = delegated;
        var sustainedKeys = delegatedRollovers;
        var sustainedBundle = delegatedBundle;
        for (var step = 0; step < 65; step++)
        {
            var nextKeys = nodes.Select((node, index) => new XPointNetworkOperationalNodeRollover(
                node.IdentitySigner, sustainedKeys[index].NextOriginSpkiSha256.Span,
                H($"retained-next-spki-{step}-{index}"), sustainedKeys[index].NextOnionX25519PublicKey.Span,
                ScalarMult.Base(H($"retained-next-onion-{step}-{index}")))).ToArray();
            var next = await XPointNetworkOperationalSuccessorAuthor.AuthorDelegatedAsync(new(
                H($"retained-view-{step}"), secondAuthority, [], witnesses, nextKeys,
                sustainedModel.ExactXvp1, sustainedModel.ExactXnd1,
                sustainedSource.Many("xnv1").Select(static value => (ReadOnlyMemory<byte>)value).ToArray(),
                sustainedModel.ExactXnh1, sustainedModel.ExactPma2, sustainedModel.ExactPmt2,
                XPointNetworkOperationalSuccessorAuthor.ComputeXnh1CoreHash(sustainedModel.ExactXnh1.Span),
                ContactCodec.Decode("PMT2", sustainedModel.ExactPmt2.Span).ArtifactHash.Span,
                adhReference, 19_150UL + (ulong)step, 19_150UL + (ulong)step, 19_400UL + (ulong)step));
            var nextOutput = Path.Combine(directory, $"retained-output-{step}");
            SuccessorCeremony.WriteOutput(nextOutput, sustainedSource, next, genesis.ExactAdh1.Span,
                19_150UL + (ulong)step, 19_400UL + (ulong)step);
            sustainedBundle = Export(sustainedBundle, nextOutput, $"retained-{step}.ncp2");
            sustainedSource = SuccessorCeremony.ReadSource(nextOutput);
            sustainedModel = next; sustainedKeys = nextKeys;
        }
        RequireHistory(sustainedBundle, 3, 69, sustainedModel, secondAuthority);
        var retained = SuccessorCeremony.ReadSource(delegatedOutput);

        // These inventory hashes match the hostile bytes. Failures must come
        // from actual paired signatures/generation or the exact retained prefix,
        // not merely an unsigned manifest hash mismatch.
        WriteAuthorityInput("authority-missing-middle", retained,
            [genesis.ExactXna1, secondRenewal.ExactXna1],
            [genesis.ExactDts1, secondRenewal.ExactDts1]);
        RejectExport<XPointNetworkAuthorityVerificationException>(secondBundle, "missing-middle");
        var corrupt = secondRenewal.ExactDts1.ToArray(); corrupt[^1] ^= 1;
        WriteAuthorityInput("authority-invalid-receipt", retained,
            [genesis.ExactXna1, firstRenewal.ExactXna1, secondRenewal.ExactXna1],
            [genesis.ExactDts1, firstRenewal.ExactDts1, corrupt]);
        RejectExport<XPointNetworkAuthorityVerificationException>(secondBundle, "invalid-receipt");
        WriteAuthorityInput("authority-unpaired", retained,
            [genesis.ExactXna1, firstRenewal.ExactXna1, secondRenewal.ExactXna1],
            [genesis.ExactDts1, firstRenewal.ExactDts1]);
        RejectExport<XPointNetworkAuthorityVerificationException>(secondBundle, "unpaired");
        WriteAuthorityInput("authority-truncated", retained,
            [genesis.ExactXna1], [genesis.ExactDts1]);
        RejectExport<CryptographicException>(secondBundle, "truncated");

        var fork = await XPointNetworkBootstrapAuthor.AuthorSameKeyRenewalAsync(
            H("operator-fork"), bootstrap.Authority, [genesis.ExactDts1],
            8_510, 8_510, 31_000, 8_510, 21_000, [root]);
        var forkAuthority = XPointNetworkAuthorityVerifier.Verify(bootstrap.GenesisPin,
            [genesis.ExactXna1, fork.ExactXna1], [genesis.ExactDts1, fork.ExactDts1]);
        var forkNext = await XPointNetworkBootstrapAuthor.AuthorSameKeyRenewalAsync(
            H("operator-fork-next"), forkAuthority, [genesis.ExactDts1, fork.ExactDts1],
            19_500, 19_500, 45_000, 19_500, 36_000, [root]);
        var forkSource = WriteAuthorityInput("authority-forked-prefix", retained,
            [genesis.ExactXna1, fork.ExactXna1, forkNext.ExactXna1],
            [genesis.ExactDts1, fork.ExactDts1, forkNext.ExactDts1]);
        _ = forkSource.VerifyAuthority(bootstrap.GenesisPin); // Genuinely signed alternate chain.
        RejectExport<CryptographicException>(secondBundle, "forked-prefix");
        if (Directory.EnumerateDirectories(directory, ".deep-successor-*").Any())
            throw new Exception("Successful or pre-rejected publication left staging directories.");
        Console.WriteLine("PASS paired authority export: two same-key renewals, 69 retained views, delegated traffic-key rotations and hostile prefixes");

        SuccessorCeremony.SourceArtifacts WriteAuthorityInput(string name, SuccessorCeremony.SourceArtifacts prior,
            IReadOnlyList<ReadOnlyMemory<byte>> authorities, IReadOnlyList<ReadOnlyMemory<byte>> policies)
        {
            var path = Path.Combine(directory, name);
            var records = Path.Combine(path, "bootstrap"); Directory.CreateDirectory(records);
            var entries = new List<ArtifactEntry>();
            foreach (var role in prior.Manifest.Artifacts.Select(entry => entry.Role).Distinct(StringComparer.Ordinal))
            {
                IReadOnlyList<ReadOnlyMemory<byte>> values = role switch
                {
                    "xna1" => authorities,
                    "dts1" => policies,
                    _ => prior.Many(role).Select(static value => (ReadOnlyMemory<byte>)value).ToArray()
                };
                for (var index = 0; index < values.Count; index++)
                {
                    var file = $"{role}.{index:D4}.bin";
                    File.WriteAllBytes(Path.Combine(records, file), values[index].ToArray());
                    entries.Add(new(role, index, file, values[index].Length,
                        Convert.ToHexString(SHA256.HashData(values[index].Span))));
                }
            }
            File.WriteAllBytes(Path.Combine(path, "public-manifest.v1.json"),
                JsonSerializer.SerializeToUtf8Bytes(prior.Manifest with { Artifacts = entries }));
            return SuccessorCeremony.ReadSource(path);
        }

        string Export(string prior, string source, string name)
        {
            var output = Path.Combine(directory, name);
            NetworkClosureExport.Run(Arguments.Parse(ExportArgs(prior, source, output)));
            var previous = XPointNetworkClosureWireCodec.DecodeResponse(File.ReadAllBytes(prior));
            var current = XPointNetworkClosureWireCodec.DecodeResponse(File.ReadAllBytes(output));
            var histories = new[]
            {
                (previous.ExactAuthorityChain, current.ExactAuthorityChain),
                (previous.ExactTimePolicyChain, current.ExactTimePolicyChain),
                (previous.ExactNetworkPolicyChain, current.ExactNetworkPolicyChain),
                (previous.ExactViewChain, current.ExactViewChain),
                (previous.ExactHeadChain, current.ExactHeadChain),
                (previous.ExactPlacementTopologyChain, current.ExactPlacementTopologyChain),
                (previous.ExactMailboxAuthorityChain, current.ExactMailboxAuthorityChain)
            };
            foreach (var (oldChain, newChain) in histories)
                if (newChain.Count < oldChain.Count || oldChain.Where((bytes, index) =>
                        !bytes.Span.SequenceEqual(newChain[index].Span)).Any())
                    throw new Exception("Export altered an exact retained signed predecessor.");
            return output;
        }
        string[] ExportArgs(string prior, string source, string output) =>
            ["--extend-network-closure", prior, "--network-successor-source", source,
             "--network-id-hex", Convert.ToHexString(bootstrap.GenesisPin.NetworkId.Span),
             "--genesis-core-hash", Convert.ToHexString(bootstrap.GenesisPin.AuthorityCoreHash.Span), "--output", output];

        void RejectExport<T>(string prior, string name) where T : Exception
        {
            var path = Path.Combine(directory, "authority-" + name);
            // Each negative input was restored from actual hash-bound files.
            if (!Directory.Exists(path)) throw new Exception("Missing owned negative source directory.");
            var output = Path.Combine(directory, name + "-rejected.ncp2");
            try { NetworkClosureExport.Run(Arguments.Parse(ExportArgs(prior, path, output))); }
            catch (T)
            {
                if (File.Exists(output)) throw new Exception("Rejected authority export created an output.");
                return;
            }
            throw new Exception($"Expected {typeof(T).Name} for {name}.");
        }

        void RequireHistory(string path, int authorityCount, int viewCount,
            AuthoredXPointNetworkOperationalSuccessor terminal, VerifiedXPointNetworkAuthority expected)
        {
            var body = XPointNetworkClosureWireCodec.DecodeResponse(File.ReadAllBytes(path));
            var authority = XPointNetworkAuthorityVerifier.Verify(bootstrap.GenesisPin,
                body.ExactAuthorityChain, body.ExactTimePolicyChain);
            if (body.ExactAuthorityChain.Count != authorityCount || body.ExactTimePolicyChain.Count != authorityCount ||
                body.ExactViewChain.Count != viewCount || body.ExactHeadChain.Count != viewCount ||
                !authority.AuthorityCoreReference.Span.SequenceEqual(expected.AuthorityCoreReference.Span) ||
                !body.ExactAuthorityChain[0].Span.SequenceEqual(genesis.ExactXna1.Span) ||
                !body.ExactTimePolicyChain[0].Span.SequenceEqual(genesis.ExactDts1.Span) ||
                !body.ExactViewChain[0].Span.SequenceEqual(genesis.ExactXnv1.Span) ||
                !body.ExactHeadChain[0].Span.SequenceEqual(genesis.ExactXnh1.Span) ||
                !body.ExactViewChain[^1].Span.SequenceEqual(terminal.ExactXnv1.Span) ||
                !body.ExactHeadChain[^1].Span.SequenceEqual(terminal.ExactXnh1.Span) ||
                !body.ExactPlacementTopologyChain[^1].Span.SequenceEqual(terminal.ExactPmt2.Span))
                throw new Exception("Renewed export lost exact original/terminal authority or operational history.");
            _ = MailboxAuthorityV2Verifier.Verify(authority, body.ExactMailboxAuthorityChain[^1].Span,
                viewCount == 2 ? 8_520UL : 19_110UL, viewCount == 2 ? 8_521UL : 19_111UL);
            // The real author above uses the same three registered identity
            // signers at every step. Export must preserve its exact descriptors,
            // not parse a private codec or substitute a new node inventory.
            if (body.ExactActiveNodeDescriptors.Count != 3 || terminal.ExactXnd1.Count != 3 ||
                body.ExactActiveNodeDescriptors.Zip(terminal.ExactXnd1,
                    static (actual, expected) => actual.Span.SequenceEqual(expected.Span)).Any(static equal => !equal))
                throw new Exception("Operational export changed the authored registered-node descriptors.");
        }
    }
}
