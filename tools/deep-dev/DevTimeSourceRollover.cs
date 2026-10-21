using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.XPointNetworkV1;
using static DevOfflineAuthorityRenewal;

// Mailbox extension of the existing offline operational renewal. Registered
// identities and all journals remain; fresh TLS/traffic/issuer custody is normal.
internal static class DevTimeSourceRollover
{
    private static readonly JsonSerializerOptions Json = new() { UnmappedMemberHandling = System.Text.Json.Serialization.JsonUnmappedMemberHandling.Disallow };
    private sealed record Extension(string PriorHash, string CandidateHash, byte[] BeforeBinding, byte[] AfterBinding, byte[]? BeforeCrl, Dictionary<string, string> Hashes);
    private static readonly string[] ExtensionFiles = ["public/prior.pma2", "public/dev-ca.crl", "operator/revocation-roots.sql"];

    internal static async Task<string> PrepareAsync(string root, string observer,
        Func<string, AccountDirectoryDts1Source[], Task<ulong>> observe, string sourceFile)
    {
        root = Scope(root);
        var before = Read(Path.Combine(root, "public/network.ncp2"), XPointNetworkClosureWireCodec.MaximumResponseLength);
        var prior = XPointNetworkClosureWireCodec.DecodeResponse(before);
        var beforeBinding = Read(Path.Combine(root, "mailbox/node-bindings.json"), 16_384);
        using var manifest = JsonDocument.Parse(Read(Path.Combine(root, "public/deep-dev.json"), 16_384));
        var pin = Pin(manifest);
        var oldPma = ContactCodec.Decode("PMA2", prior.ExactMailboxAuthorityChain[^1].Span);
        RequireBinding(beforeBinding, prior.NetworkId.Span, oldPma.CoreHash.Span);
        var candidate = await DevOfflineOperationalRenewal.PrepareAsync(root, observer, observe, sourceFile);
        // Reuse full signed-prefix/key/certificate validation and sealed local
        // before-images; no new protocol author or duplicate installation plan.
        DevOperationalActivation.Execute(root, candidate, false);
        var key = Read(Path.Combine(root, "operator/renewal-integrity.key"), 32);
        try
        {
            var journal = DevPublisher.ReadJournal(Path.Combine(candidate, "operator/renewal.state"), key, pin.NetworkId.ToArray());
            var next = XPointNetworkClosureWireCodec.DecodeResponse(journal.Bundle);
            var authority = XPointNetworkAuthorityVerifier.Verify(pin, next.ExactAuthorityChain, next.ExactTimePolicyChain);
            var pma = MailboxAuthorityV2Verifier.Verify(authority, next.ExactMailboxAuthorityChain[^1].Span, journal.Observed, checked(journal.Observed + 1));
            if (Hash(before) != journal.PriorPublicHash || !Read(Path.Combine(root, "public/network.ncp2"), XPointNetworkClosureWireCodec.MaximumResponseLength).AsSpan().SequenceEqual(before) ||
                !Read(Path.Combine(root, "mailbox/node-bindings.json"), 16_384).AsSpan().SequenceEqual(beforeBinding)) throw new CryptographicException("Retained mailbox predecessor advanced.");
            WriteNew(Path.Combine(candidate, "public/prior.pma2"), prior.ExactMailboxAuthorityChain[^1].ToArray());
            WriteNew(Path.Combine(candidate, "operator/revocation-roots.sql"), System.Text.Encoding.ASCII.GetBytes(RootSql(oldPma, pma)));
            var crlPath = Path.Combine(root, "public/dev-ca.crl"); RequireNoLinks(crlPath);
            var beforeCrl = File.Exists(crlPath) ? Read(crlPath, 65_535) : null;
            using var caPublic = X509Certificate2.CreateFromPem(System.Text.Encoding.ASCII.GetString(Read(Path.Combine(candidate, "public/dev-ca.crt"), 16_384)));
            using var caKey = RSA.Create(); caKey.ImportFromPem(System.Text.Encoding.ASCII.GetString(Read(Path.Combine(root, "offline-root/dev-ca.key"), 16_384)));
            using var ca = caPublic.CopyWithPrivateKey(caKey);
            var number = System.Numerics.BigInteger.Zero;
            if (beforeCrl is not null) DevPki.ValidateCrl(beforeCrl, caPublic);
            var builder = beforeCrl is null ? new CertificateRevocationListBuilder() : CertificateRevocationListBuilder.Load(beforeCrl, out number);
            var crl = builder.Build(ca, number + 1, new DateTimeOffset(ca.NotAfter.ToUniversalTime()), HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1, DateTimeOffset.FromUnixTimeSeconds(checked((long)journal.Observed)).AddSeconds(-30));
            DevPki.ValidateCrl(crl, caPublic); WriteNew(Path.Combine(candidate, "public/dev-ca.crl"), crl);
            var afterBinding = JsonSerializer.SerializeToUtf8Bytes(new { NetworkIdHex = journal.Network, MailboxAuthorityCoreHashHex = Convert.ToHexStringLower(pma.CoreHash.Span) });
            var extension = new Extension(Hash(before), Hash(journal.Bundle), beforeBinding, afterBinding, beforeCrl,
                ExtensionFiles.ToDictionary(p => p, p => Hash(Read(Path.Combine(candidate, p), 65_535))));
            WriteNew(Path.Combine(candidate, "mailbox-extension.bin"), Protect(JsonSerializer.SerializeToUtf8Bytes(extension, Json), key));
            return candidate;
        }
        finally { CryptographicOperations.ZeroMemory(key); }
    }

    internal static void Install(string root, string candidate, bool install)
    {
        root = Scope(root); candidate = Path.GetFullPath(candidate); RequireNoLinks(candidate);
        if (!string.Equals(Path.GetDirectoryName(candidate), Path.Combine(root, "offline-root", "renewals"), StringComparison.Ordinal) ||
            !System.Text.RegularExpressions.Regex.IsMatch(Path.GetFileName(candidate), "^operational-[0-9a-f]{32}$")) throw new ArgumentException("Wrong complete operational candidate scope.");
        var key = Read(Path.Combine(root, "operator/renewal-integrity.key"), 32);
        try
        {
            var extension = JsonSerializer.Deserialize<Extension>(Unprotect(Read(Path.Combine(candidate, "mailbox-extension.bin"), 65_535), key), Json)!;
            if (extension.Hashes.Count != ExtensionFiles.Length || ExtensionFiles.Any(p => !extension.Hashes.TryGetValue(p, out var h) || h != Hash(Read(Path.Combine(candidate, p), 65_535)))) throw new CryptographicException("Mailbox extension whitelist differs.");
            using var manifest = JsonDocument.Parse(Read(Path.Combine(root, "public/deep-dev.json"), 16_384));
            var journal = DevPublisher.ReadJournal(Path.Combine(candidate, "operator/renewal.state"), key, Pin(manifest).NetworkId.ToArray());
            if (extension.PriorHash != journal.PriorPublicHash || extension.CandidateHash != Hash(journal.Bundle)) throw new CryptographicException("Mailbox extension predecessor differs.");
            var next = XPointNetworkClosureWireCodec.DecodeResponse(journal.Bundle);
            RequireBinding(extension.AfterBinding, next.NetworkId.Span, ContactCodec.Decode("PMA2", next.ExactMailboxAuthorityChain[^1].Span).CoreHash.Span);
            RequireBinding(extension.BeforeBinding, next.NetworkId.Span, ContactCodec.Decode("PMA2", Read(Path.Combine(candidate, "public/prior.pma2"), 65_535)).CoreHash.Span);
            var bindingPath = Path.Combine(root, "mailbox/node-bindings.json");
            var binding = Read(bindingPath, 16_384);
            if (!binding.AsSpan().SequenceEqual(extension.BeforeBinding) && !binding.AsSpan().SequenceEqual(extension.AfterBinding)) throw new CryptographicException("Retained node binding changed.");
            var crlPath = Path.Combine(root, "public/dev-ca.crl"); RequireNoLinks(crlPath);
            var crl = Read(Path.Combine(candidate, "public/dev-ca.crl"), 65_535);
            var currentCrl = File.Exists(crlPath) ? Read(crlPath, 65_535) : null;
            if (!(currentCrl is null && extension.BeforeCrl is null) && !(currentCrl is not null && (currentCrl.AsSpan().SequenceEqual(crl) || extension.BeforeCrl is not null && currentCrl.AsSpan().SequenceEqual(extension.BeforeCrl)))) throw new CryptographicException("Retained CRL changed.");
            DevOperationalActivation.Execute(root, candidate, install);
            if (install && !(currentCrl is not null && currentCrl.AsSpan().SequenceEqual(crl)))
            { var stage = crlPath + ".stage-" + Guid.NewGuid().ToString("N"); WriteNew(stage, crl); File.Move(stage, crlPath, true); }
            if (install && !binding.AsSpan().SequenceEqual(extension.AfterBinding))
            { var stage = bindingPath + ".stage-" + Guid.NewGuid().ToString("N"); WriteNew(stage, extension.AfterBinding); File.Move(stage, bindingPath, true); }
            if (install)
            {
                var marker = Path.Combine(root, "mailbox/operational-candidate.txt"); RequireNoLinks(marker);
                var stage = marker + ".stage-" + Guid.NewGuid().ToString("N"); WriteNew(stage, System.Text.Encoding.UTF8.GetBytes(candidate)); File.Move(stage, marker, true);
            }
        }
        finally { CryptographicOperations.ZeroMemory(key); }
    }

    internal static void ValidateInstalled(string root)
    {
        root = Scope(root);
        var candidate = System.Text.Encoding.UTF8.GetString(Read(Path.Combine(root, "mailbox/operational-candidate.txt"), 4096));
        if (!string.Equals(Path.GetDirectoryName(candidate), Path.Combine(root, "offline-root", "renewals"), StringComparison.Ordinal) ||
            !System.Text.RegularExpressions.Regex.IsMatch(Path.GetFileName(candidate), "^operational-[0-9a-f]{32}$")) throw new CryptographicException("Installed operational custody scope differs.");
        RequireNoLinks(candidate);
        var key = Read(Path.Combine(root, "operator/renewal-integrity.key"), 32);
        try
        {
            var plan = JsonSerializer.Deserialize<DevOperationalActivation.Plan>(Unprotect(Read(Path.Combine(candidate, "installation.state"), 4 * 1024 * 1024), key), Json)!;
            var extension = JsonSerializer.Deserialize<Extension>(Unprotect(Read(Path.Combine(candidate, "mailbox-extension.bin"), 65_535), key), Json)!;
            var bundle = Read(Path.Combine(candidate, "public/network.ncp2"), XPointNetworkClosureWireCodec.MaximumResponseLength);
            if (plan.CandidateHash != Hash(bundle) || extension.CandidateHash != plan.CandidateHash || extension.PriorHash != plan.PriorHash) throw new CryptographicException("Installed plan binding differs.");
            var hashes = JsonSerializer.Deserialize<Dictionary<string, string>>(Unprotect(Read(Path.Combine(candidate, "activation-seal.json"), 16_384), key), Json)!;
            if (hashes.Count != DevOperationalActivation.CandidateFiles.Length || DevOperationalActivation.CandidateFiles.Any(p => !hashes.TryGetValue(p, out var h) || h != Hash(Read(Path.Combine(candidate, p), 100 * 1024 * 1024)))) throw new CryptographicException("Installed candidate changed.");
            foreach (var file in plan.Files)
            {
                var path = Path.GetFullPath(Path.Combine(root, file.RelativePath));
                if (!path.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) || !Read(path, 262_144).AsSpan().SequenceEqual(file.After)) throw new CryptographicException("Installed operational image changed.");
            }
            if (extension.Hashes.Count != ExtensionFiles.Length || ExtensionFiles.Any(p => !extension.Hashes.TryGetValue(p, out var h) || h != Hash(Read(Path.Combine(candidate, p), 65_535))) ||
                !Read(Path.Combine(root, "mailbox/node-bindings.json"), 16_384).AsSpan().SequenceEqual(extension.AfterBinding) ||
                !Read(Path.Combine(root, "public/dev-ca.crl"), 65_535).AsSpan().SequenceEqual(Read(Path.Combine(candidate, "public/dev-ca.crl"), 65_535))) throw new CryptographicException("Installed mailbox extension changed.");
            var installed = XPointNetworkClosureWireCodec.DecodeResponse(bundle);
            var current = XPointNetworkClosureWireCodec.DecodeResponse(Read(Path.Combine(root, "public/network.ncp2"), XPointNetworkClosureWireCodec.MaximumResponseLength));
            if (!installed.NetworkId.Span.SequenceEqual(current.NetworkId.Span)) throw new CryptographicException("Installed network differs.");
            Prefix(installed.ExactAuthorityChain, current.ExactAuthorityChain); Prefix(installed.ExactTimePolicyChain, current.ExactTimePolicyChain);
            Prefix(installed.ExactNetworkPolicyChain, current.ExactNetworkPolicyChain); Prefix(installed.ExactViewChain, current.ExactViewChain);
            Prefix(installed.ExactHeadChain, current.ExactHeadChain); Prefix(installed.ExactMailboxAuthorityChain, current.ExactMailboxAuthorityChain);
            Prefix(installed.ExactPlacementTopologyChain, current.ExactPlacementTopologyChain);
        }
        finally { CryptographicOperations.ZeroMemory(key); }
        static void Prefix(IReadOnlyList<ReadOnlyMemory<byte>> before, IReadOnlyList<ReadOnlyMemory<byte>> after)
        { if (after.Count < before.Count || before.Where((bytes, i) => !bytes.Span.SequenceEqual(after[i].Span)).Any()) throw new CryptographicException("Installed operational publication is not a retained prefix."); }
    }

    internal static string RootSql(ContactRecord prior, VerifiedMailboxAuthorityV2 next)
    {
        var network = Convert.ToHexString(next.NetworkId.Span);
        if (!prior.Field(1).Span.SequenceEqual(next.NetworkId.Span)) throw new CryptographicException("Revocation network differs.");
        var oldRef = Convert.ToHexString([.. "PMA2"u8, 0, 1, .. prior.CoreHash.Span]);
        var newRef = Convert.ToHexString([.. "PMA2"u8, 0, 1, .. next.CoreHash.Span]);
        string Predicate(string reference) => $"network_id=decode('{network}','hex') AND policy_reference=decode('{reference}','hex')";
        var oldKeys = $"((role=1 AND issuer_key=decode('{Convert.ToHexString(prior.Field(5).Span)}','hex')) OR (role=2 AND issuer_key=decode('{Convert.ToHexString(prior.Field(6).Span)}','hex')))";
        var newKeys = $"((role=1 AND issuer_key=decode('{Convert.ToHexString(next.ResolveIssuer(MailboxCapabilityDomain.Deposit).PublicKey.Span)}','hex')) OR (role=2 AND issuer_key=decode('{Convert.ToHexString(next.ResolveIssuer(MailboxCapabilityDomain.Retrieve).PublicKey.Span)}','hex')))";
        var inserts = string.Join('\n', DevMailboxPreparation.RootSql(next).Split('\n').Skip(1));
        return $"BEGIN; LOCK TABLE deep_mailbox_revocation_scope IN SHARE ROW EXCLUSIVE MODE; DO $rollover$ BEGIN " +
            $"IF (SELECT count(*) FROM deep_did2_grant_journal_network WHERE network_id=decode('{network}','hex'))<>1 THEN RAISE EXCEPTION 'Retained grant root absent'; END IF; " +
            $"IF (SELECT count(*) FROM deep_mailbox_revocation_scope WHERE {Predicate(oldRef)})<>2 OR (SELECT count(*) FROM deep_mailbox_revocation_scope WHERE {Predicate(oldRef)} AND {oldKeys} AND committed_generation>0)<>2 THEN RAISE EXCEPTION 'Retained revocation roots differ'; END IF; " +
            $"IF (SELECT count(*) FROM deep_mailbox_revocation_scope WHERE {Predicate(newRef)})=0 THEN {inserts} " +
            $"ELSIF (SELECT count(*) FROM deep_mailbox_revocation_scope WHERE {Predicate(newRef)})<>2 OR (SELECT count(*) FROM deep_mailbox_revocation_scope WHERE {Predicate(newRef)} AND {newKeys})<>2 THEN RAISE EXCEPTION 'Successor roots differ'; END IF; END $rollover$; COMMIT;";
    }

    private static void RequireBinding(byte[] bytes, ReadOnlySpan<byte> network, ReadOnlySpan<byte> policy)
    { using var json = JsonDocument.Parse(bytes); var m = json.RootElement; if (m.EnumerateObject().Count() != 2 || !Convert.FromHexString(m.GetProperty("NetworkIdHex").GetString()!).AsSpan().SequenceEqual(network) || !Convert.FromHexString(m.GetProperty("MailboxAuthorityCoreHashHex").GetString()!).AsSpan().SequenceEqual(policy)) throw new CryptographicException("Mailbox binding scope differs."); }
    private static string Scope(string root) { root = Path.GetFullPath(root); if (!OperatingSystem.IsWindows() || !root.StartsWith(Path.GetFullPath("C:/Work/DeepSession/secrets/dev") + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) throw new ArgumentException("Explicit retained dev custody required."); RequireNoLinks(root); if (!File.Exists(Path.Combine(root, "mailbox/nodes-enabled"))) throw new InvalidDataException("Retained mailbox enrollment required."); return root; }
    private static XPointNetworkGenesisPin Pin(JsonDocument manifest) { var m = manifest.RootElement; if (m.GetProperty("schema").GetString() != "deep-dev.v1" || m.GetProperty("nodeCount").GetInt32() != 3) throw new InvalidDataException("Wrong dev identity."); _ = DevTopology.ForProject(m.GetProperty("projectName").GetString()!); return new(Convert.FromHexString(m.GetProperty("networkIdHex").GetString()!), Convert.FromHexString(m.GetProperty("genesisAuthorityCoreHashHex").GetString()!)); }
    private static string Hash(byte[] value) => Convert.ToHexStringLower(SHA256.HashData(value));
    private static byte[] Protect(byte[] bytes, byte[] key) => [.. HMACSHA256.HashData(key, bytes), .. bytes];
    private static byte[] Unprotect(byte[] bytes, byte[] key) { if (bytes.Length <= 32 || !CryptographicOperations.FixedTimeEquals(bytes.AsSpan(0, 32), HMACSHA256.HashData(key, bytes.AsSpan(32)))) throw new CryptographicException("Operator integrity rejected."); return bytes[32..]; }
    private static void WriteNew(string path, byte[] bytes) { RequireNoLinks(path); Directory.CreateDirectory(Path.GetDirectoryName(path)!); using var file = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough); file.Write(bytes); file.Flush(true); }
}
