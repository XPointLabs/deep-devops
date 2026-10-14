using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.XPointNetworkV1;
using static DevOfflineAuthorityRenewal;

// Explicit operator preparation only. No key authoring, signatures, database
// connection or implicit restore-floor/journal enrollment happens here.
internal static class DevMailboxPreparation
{
    internal static async Task PrepareAsync(string custodyRoot, string executable,
        Func<string, AccountDirectoryDts1Source[], Task<ulong>> observe)
    {
        var root = Path.GetFullPath(custodyRoot);
        if (!OperatingSystem.IsWindows() || !root.StartsWith(Path.GetFullPath("C:/Work/DeepSession/secrets/dev") +
            Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) throw new ArgumentException("Not local dev custody.");
        RequireNoLinks(root);
        using var manifest = JsonDocument.Parse(Read(Path.Combine(root,"public/deep-dev.json"),16_384));
        var m = manifest.RootElement;
        if (m.GetProperty("schema").GetString() != "deep-dev.v1" || m.GetProperty("projectName").GetString() != "deep-dev-current" ||
            m.GetProperty("containerIpv4Prefix").GetString() != DevTopology.ForProject("deep-dev-current").Ipv4Prefix ||
            m.GetProperty("nodeCount").GetInt32() != 3 || m.GetProperty("deviceEvidence").GetBoolean())
            throw new InvalidDataException("Mailbox activation requires the owned current three-node dev contour.");
        var network = Convert.FromHexString(m.GetProperty("networkIdHex").GetString()!);
        var closure = XPointNetworkClosureWireCodec.DecodeResponse(Read(Path.Combine(root,"public/network.ncp2"),XPointNetworkClosureWireCodec.MaximumResponseLength));
        var pin = new XPointNetworkGenesisPin(network,Convert.FromHexString(m.GetProperty("genesisAuthorityCoreHashHex").GetString()!));
        if (!closure.NetworkId.Span.SequenceEqual(network) ||
            !Read(Path.Combine(root,"public/genesis.xna1"),65_535).AsSpan().SequenceEqual(closure.ExactAuthorityChain[0].Span) ||
            !Read(Path.Combine(root,"public/genesis.dts1"),65_535).AsSpan().SequenceEqual(closure.ExactTimePolicyChain[0].Span))
            throw new CryptographicException("Original genesis/network differs.");
        var authority = XPointNetworkAuthorityVerifier.Verify(pin,closure.ExactAuthorityChain,closure.ExactTimePolicyChain);
        var timePolicy = AccountDirectoryDts1Codec.Decode(closure.ExactTimePolicyChain[^1].Span);
        ulong observed;
        try { observed = await observe(executable,timePolicy.Sources.ToArray()); }
        catch (CryptographicException) { Console.Error.WriteLine("Mailbox preparation rejected authenticated NTS observation."); throw; }
        VerifiedMailboxAuthorityV2 policy;
        try { policy = MailboxAuthorityV2Verifier.Verify(authority,closure.ExactMailboxAuthorityChain[^1].Span,observed,checked(observed+1)); }
        catch (CryptographicException) { Console.Error.WriteLine("Mailbox preparation rejected current signed policy/time binding."); throw; }
        if (!policy.BindsProjection(closure.ExactPlacementTopologyChain[^1].Span)) throw new CryptographicException("Mailbox policy/projection differs.");
        foreach (var (name,domain) in new[]{("deposit",MailboxCapabilityDomain.Deposit),("retrieve",MailboxCapabilityDomain.Retrieve)}) {
            var seedFile = Path.Combine(root,$"registry/secrets/mailbox-{name}.seed"); RequireNoLinks(seedFile);
            using var signer = Signer.Load(seedFile);
            if (!signer.Ed25519PublicKey.Span.SequenceEqual(policy.ResolveIssuer(domain).PublicKey.Span))
                throw new CryptographicException("Installed role seed differs from signed policy.");
        }
        var directory = Path.Combine(root,"mailbox"); RequireNoLinks(directory); Directory.CreateDirectory(directory);
        foreach (var role in new[]{"deposit","retrieve"}) {
            var config = JsonSerializer.SerializeToUtf8Bytes(new { MailboxRoleSigner = new { Role=role,
                NetworkIdHex=Convert.ToHexString(network),SeedPath="/run/role-secrets/role.seed",
                SocketPath=$"/run/role-socket/{role}.sock",AllowedPeerUserId=0 } });
            WriteExact(Path.Combine(directory,$"{role}.json"),config);
        }
        WriteExact(Path.Combine(directory,"roots.sql"),Encoding.ASCII.GetBytes(RootSql(policy)));
        Console.WriteLine("Current dev mailbox preparation verified existing role keys and produced private operator inputs; not activated.");
    }

    internal static string RootSql(VerifiedMailboxAuthorityV2 policy)
    {
        ArgumentNullException.ThrowIfNull(policy);
        var network = Convert.ToHexString(policy.NetworkId.Span);
        var coreReference = new byte[38]; "PMA2\0\x01"u8.CopyTo(coreReference); policy.CoreHash.Span.CopyTo(coreReference.AsSpan(6));
        var reference = Convert.ToHexString(coreReference);
        var sql = $"INSERT INTO deep_did2_grant_journal_network (network_id,entry_count,maximum_entries) VALUES (decode('{network}','hex'),0,1048576);\n";
        foreach(var role in new[]{MailboxCapabilityDomain.Deposit,MailboxCapabilityDomain.Retrieve}) {
            var key = Convert.ToHexString(policy.ResolveIssuer(role).PublicKey.Span);
            sql += $"INSERT INTO deep_mailbox_revocation_scope (network_id,policy_reference,role,issuer_key,committed_generation,entry_count,maximum_entries,cumulative_serials) VALUES (decode('{network}','hex'),decode('{reference}','hex'),{(byte)role},decode('{key}','hex'),0,0,1048576,decode('','hex'));\n";
        }
        return sql;
    }
    private static void WriteExact(string file,byte[] bytes)
    {
        RequireNoLinks(file);
        if(File.Exists(file)) { if(!Read(file,16_384).AsSpan().SequenceEqual(bytes)) throw new IOException("Prepared mailbox input differs; no overwrite."); return; }
        using var stream = new FileStream(file,FileMode.CreateNew,FileAccess.Write,FileShare.None,4096,FileOptions.WriteThrough);
        stream.Write(bytes);stream.Flush(true);
    }
}
