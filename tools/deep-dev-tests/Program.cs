using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
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
    await Reject(() => { DevNodeMailboxProvisioning.ProvisionKeys("/run/contact-keys"); return Task.CompletedTask; }, "mailbox key provision rejects contact mount");
    await Reject(() => { DevNodeMailboxProvisioning.ProvisionContactKeys("/run/mailbox-keys"); return Task.CompletedTask; }, "contact key provision rejects mailbox mount");
    var coordinationSql=DevContactCoordinationPreparation.RootSql(Enumerable.Repeat((byte)1,16).ToArray());
    Check(coordinationSql.Split("INSERT INTO ").Length==3 && !coordinationSql.Contains("CONFLICT",StringComparison.Ordinal) &&
        !coordinationSql.Contains("DELETE",StringComparison.Ordinal) && !coordinationSql.Contains("UPDATE",StringComparison.Ordinal),"explicit coordination roots are insert-only");
    await Reject(()=>{_ = DevContactCoordinationPreparation.RootSql(new byte[16]);return Task.CompletedTask;},"zero coordination network");
    await Reject(()=>{_ = DevContactCoordinationPreparation.RootSql(new byte[15]);return Task.CompletedTask;},"short coordination network");
    await Reject(()=>DevOwnedMailboxExercise.RunAsync("/run/operator"),"owned client rejects custody mount");
    using(var control=new HttpResponseMessage(HttpStatusCode.OK)) {
        control.Content=new ByteArrayContent(new byte[MailboxGrantRevocationV1Codec.MinimumBytes]);
        control.Content.Headers.ContentType=new("application/vnd.deep.mailbox-grant-revocation.v1+octet-stream");
        control.Headers.CacheControl=new(){NoStore=true};control.Headers.Add("X-Content-Type-Options","nosniff");
        Check(DevNodeMailboxProvisioning.ValidateControlFraming(control)==MailboxGrantRevocationV1Codec.MinimumBytes,"closed control transport framing");
        control.Content.Headers.ContentType.Parameters.Add(new("charset","utf-8"));
        await Reject(()=>{_ = DevNodeMailboxProvisioning.ValidateControlFraming(control);return Task.CompletedTask;},"control media parameters");
        control.Content.Headers.ContentType.Parameters.Clear();control.Content.Headers.ContentEncoding.Add("gzip");
        await Reject(()=>{_ = DevNodeMailboxProvisioning.ValidateControlFraming(control);return Task.CompletedTask;},"control content encoding");
        control.Content.Headers.ContentEncoding.Clear();control.Headers.CacheControl.NoStore=false;
        await Reject(()=>{_ = DevNodeMailboxProvisioning.ValidateControlFraming(control);return Task.CompletedTask;},"control cache policy");
        control.Headers.CacheControl.NoStore=true;control.Headers.Remove("X-Content-Type-Options");
        await Reject(()=>{_ = DevNodeMailboxProvisioning.ValidateControlFraming(control);return Task.CompletedTask;},"control missing nosniff");
        control.Headers.Add("X-Content-Type-Options","nosniff");control.Content.Headers.ContentLength=MailboxGrantRevocationV1Codec.MaximumBytes+1;
        await Reject(()=>{_ = DevNodeMailboxProvisioning.ValidateControlFraming(control);return Task.CompletedTask;},"control hostile length");
        control.StatusCode=HttpStatusCode.ServiceUnavailable;
        await Reject(()=>{_ = DevNodeMailboxProvisioning.ValidateControlFraming(control);return Task.CompletedTask;},"control unavailable response");
    }
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
    await Reject(() => DevMailboxPreparation.PrepareAsync(directory,"unused",(_,_)=> {
        observed=true;return Task.FromResult(700_000UL);
    }),"mailbox preparation outside development scope");
    Check(!observed,"mailbox scope rejection before NTS or writes");
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
static byte[] U64(ulong value) { var bytes=new byte[8];System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(bytes,value);return bytes; }
static void Check(bool condition, string name) { if (!condition) throw new Exception(name); Console.WriteLine("PASS " + name); }
static async Task Reject(Func<Task> run, string name)
{
    try { await run(); }
    catch (Exception e) when (e is ArgumentException or FormatException or CryptographicException or OverflowException or IOException or InvalidDataException)
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
            B((byte)(60 + i)), IPAddress.Parse($"172.31.240.{11 + i}"), 443,
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
            projectName = "deep-dev", containerIpv4Prefix = "172.31.240",
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
        File.WriteAllBytes(Path.Combine(publicRoot, "network.ncp2"), bundle);
        File.WriteAllBytes(Path.Combine(publicRoot, "genesis.adh1"), head.ExactAdh1.ToArray());
        var operatorRoot = Path.Combine(fixture, "operator"); Directory.CreateDirectory(operatorRoot);
        for (var i = 0; i < 3; i++) {
            File.WriteAllBytes(Path.Combine(operatorRoot, $"witness-{i + 1}.seed"), witnesses[i].Seed);
            File.WriteAllBytes(Path.Combine(operatorRoot, $"node-{i + 1}.seed"), nodeSigners[i].Seed);
        }
        var integrity = RandomNumberGenerator.GetBytes(32);
        try {
            File.WriteAllBytes(Path.Combine(operatorRoot, "renewal-integrity.key"), integrity);
            using var caKey = RSA.Create(2048);
            var caRequest = new CertificateRequest("CN=Isolated development test CA", caKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            caRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            caRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
            using var ca = caRequest.CreateSelfSigned(DateTimeOffset.FromUnixTimeSeconds(800), DateTimeOffset.FromUnixTimeSeconds(10_000));
            File.WriteAllText(Path.Combine(publicRoot, "dev-ca.crt"), ca.ExportCertificatePem());
            File.WriteAllText(Path.Combine(offline, "dev-ca.key"), caKey.ExportPkcs8PrivateKeyPem());
            var candidate = await DevOfflineOperationalRenewal.PrepareAsync(fixture, "fixture-observer", (_, _) => Task.FromResult(1_800_000_000UL));
            var next = XPointNetworkClosureWireCodec.DecodeResponse(File.ReadAllBytes(Path.Combine(candidate, "public/network.ncp2")));
            var nextAuthority = XPointNetworkAuthorityVerifier.Verify(bootstrap.GenesisPin, next.ExactAuthorityChain, next.ExactTimePolicyChain);
            Check(next.ExactViewChain.Count == 2 && next.ExactAuthorityChain.Count == 2 &&
                next.ExactViewChain[0].Span.SequenceEqual(operational.ExactXnv1.Span) &&
                next.ExactMailboxAuthorityChain[0].Span.SequenceEqual(operational.ExactPma2.Span), "operational file candidate retains complete original signed prefix");
            var policy = MailboxAuthorityV2Verifier.Verify(nextAuthority, next.ExactMailboxAuthorityChain[^1].Span, 1_800_000_010, 1_800_000_011);
            using var deposit = Signer.Load(Path.Combine(candidate, "online/registry/mailbox-deposit.seed"));
            using var retrieve = Signer.Load(Path.Combine(candidate, "online/registry/mailbox-retrieve.seed"));
            Check(policy.ResolveIssuer(Deep.Protocol.DeepExtension.MailboxCapabilities.MailboxCapabilityDomain.Deposit).PublicKey.Span.SequenceEqual(deposit.Ed25519PublicKey.Span) &&
                policy.ResolveIssuer(Deep.Protocol.DeepExtension.MailboxCapabilities.MailboxCapabilityDomain.Retrieve).PublicKey.Span.SequenceEqual(retrieve.Ed25519PublicKey.Span) &&
                policy.MinimumGrantGeneration == 2 && policy.BindsProjection(next.ExactPlacementTopologyChain[^1].Span), "signed new role keys match staged private custody and projection");
            var rootsSql=DevMailboxPreparation.RootSql(policy);
            Check(rootsSql.Split("INSERT INTO ").Length==4 && rootsSql.Contains(Convert.ToHexString(policy.CoreHash.Span),StringComparison.Ordinal) &&
                rootsSql.Contains(Convert.ToHexString(deposit.Ed25519PublicKey.Span),StringComparison.Ordinal) &&
                rootsSql.Contains(Convert.ToHexString(retrieve.Ed25519PublicKey.Span),StringComparison.Ordinal) &&
                !rootsSql.Contains("CONFLICT",StringComparison.Ordinal) && !rootsSql.Contains("DELETE",StringComparison.Ordinal),
                "explicit new journal roots bind verified policy and both roles without reset/upsert");
            ReadOnlyMemory<byte>[] mgrFields=[policy.NetworkId,new byte[]{(byte)'P',(byte)'M',(byte)'A',(byte)'2',0,1}.Concat(policy.CoreHash.ToArray()).ToArray(),
                new byte[]{1},deposit.Ed25519PublicKey,U64(1),new byte[32],U64(1_800_000_010),U64(1_800_000_010),U64(1_800_000_200),new byte[4],Array.Empty<byte>()];
            var mgrInput=MailboxGrantRevocationV1Codec.CreateSignatureInput(mgrFields);
            var mgr=MailboxGrantRevocationV1Codec.Encode(mgrFields,(await deposit.SignDtt1Async(mgrInput,default)).Span);
            DevNodeMailboxProvisioning.ValidateControl(policy,Deep.Protocol.DeepExtension.MailboxCapabilities.MailboxCapabilityDomain.Deposit,mgr);
            Check(true,"captured canonical MGR signature/scope matches the verified policy without claiming enrollment");
            await Reject(()=>{DevNodeMailboxProvisioning.ValidateControl(policy,Deep.Protocol.DeepExtension.MailboxCapabilities.MailboxCapabilityDomain.Retrieve,mgr);return Task.CompletedTask;},"captured control wrong role");
            var alteredMgr=mgr.ToArray();alteredMgr[^1]^=1;
            await Reject(()=>{DevNodeMailboxProvisioning.ValidateControl(policy,Deep.Protocol.DeepExtension.MailboxCapabilities.MailboxCapabilityDomain.Deposit,alteredMgr);return Task.CompletedTask;},"captured control changed signature");
            var encoded = File.ReadAllBytes(Path.Combine(candidate, "operator/renewal.state"));
            Check(CryptographicOperations.FixedTimeEquals(encoded.AsSpan(0, 32), HMACSHA256.HashData(integrity, encoded.AsSpan(32))), "candidate journal uses retained integrity key");
            var journal = DevPublisher.ReadJournal(Path.Combine(candidate, "operator/renewal.state"), integrity, bootstrap.Authority.NetworkId.ToArray());
            var originalJournal = new DevPublisher.Journal("deep-dev-renewal.v1", Convert.ToHexStringLower(bootstrap.Authority.NetworkId.Span),
                0, 1_100, new string('0',64), bundle);
            DevPublisher.ValidatePreparedImport(bootstrap.GenesisPin, originalJournal, journal);
            Check(journal.Generation == 1, "owner import validates exact signed one-step candidate");
            await Reject(() => { DevPublisher.ValidatePreparedImport(bootstrap.GenesisPin, originalJournal,
                journal with { PriorPublicHash = new string('0',64) }); return Task.CompletedTask; }, "stale import public digest");
            await Reject(() => { DevPublisher.ValidatePreparedImport(bootstrap.GenesisPin, originalJournal,
                journal with { Generation = 2 }); return Task.CompletedTask; }, "skipped import generation");
            var badEncoded = encoded.ToArray(); badEncoded[^1] ^= 1;
            File.WriteAllBytes(Path.Combine(candidate, "operator/hostile.state"), badEncoded);
            await Reject(() => { _ = DevPublisher.ReadJournal(Path.Combine(candidate, "operator/hostile.state"), integrity, bootstrap.Authority.NetworkId.ToArray());
                return Task.CompletedTask; }, "corrupt candidate journal");
            using var crt = X509Certificate2.CreateFromPemFile(Path.Combine(candidate, "online/node-1/server.crt"), Path.Combine(candidate, "online/node-1/server.key"));
            Check(crt.HasPrivateKey && crt.MatchesHostname("node-1") && crt.MatchesHostname("172.31.240.11") &&
                File.ReadAllBytes(Path.Combine(publicRoot, "network.ncp2")).AsSpan().SequenceEqual(bundle), "installable staged TLS and unchanged live source");
            foreach (var service in new[] { "registry", "node-1", "node-2", "node-3" }) {
                var configDirectory = Path.Combine(fixture, service); Directory.CreateDirectory(configDirectory);
                var section = new { NetworkIdHex = Convert.ToHexString(bootstrap.Authority.NetworkId.Span),
                    GenesisAuthorityCoreHashHex = Convert.ToHexString(bootstrap.GenesisPin.AuthorityCoreHash.Span) };
                var config = service == "registry" ? new Dictionary<string, object> { ["DeepIdV2DirectoryAuthority"] = section } :
                    new Dictionary<string, object> { ["DeepIdV2DirectoryProof"] = section, ["PrivacyRouting"] = new {
                        Peers = Enumerable.Range(1, 3).Where(i => service != $"node-{i}").Select(i => new {
                            BaseUrl = $"https://172.31.240.{10 + i}/", RouterId = Convert.ToHexString(nodeSigners[i - 1].Ed25519PublicKey.Span),
                            CurrentSpkiSha256 = new string('a',64), NextSpkiSha256 = new string('b',64) }).ToArray() } };
                File.WriteAllBytes(Path.Combine(configDirectory, "appsettings.Development.json"), JsonSerializer.SerializeToUtf8Bytes(config));
            }
            var registryConfig = File.ReadAllBytes(Path.Combine(fixture, "registry/appsettings.Development.json"));
            DevOperationalActivation.Execute(fixture, candidate, install: false);
            Check(File.Exists(Path.Combine(candidate, "installation.state")) &&
                File.ReadAllBytes(Path.Combine(fixture, "registry/appsettings.Development.json")).AsSpan().SequenceEqual(registryConfig), "activation validation stages protected before-images without live writes");
            var traffic = Path.Combine(candidate, "online/node-1/key_x25519"); var originalTraffic = File.ReadAllBytes(traffic);
            File.WriteAllText(traffic, new string('f', 64));
            await Reject(() => { DevOperationalActivation.Execute(fixture, candidate, false); return Task.CompletedTask; }, "changed sealed traffic custody");
            File.WriteAllBytes(traffic, originalTraffic);
            File.WriteAllText(Path.Combine(fixture, "registry/appsettings.Development.json"), "{}");
            await Reject(() => { DevOperationalActivation.Execute(fixture, candidate, true); return Task.CompletedTask; }, "changed retained target before any install");
            File.WriteAllBytes(Path.Combine(fixture, "registry/appsettings.Development.json"), registryConfig);
            DevOperationalActivation.Execute(fixture, candidate, true);
            DevOperationalActivation.Execute(fixture, candidate, true);
            Check(File.ReadAllBytes(Path.Combine(publicRoot, "network.ncp2")).AsSpan().SequenceEqual(bundle) &&
                File.ReadAllBytes(Path.Combine(offline, "root.seed")).AsSpan().SequenceEqual(root.Seed) &&
                File.ReadAllBytes(Path.Combine(fixture, "node-1/secrets/key_x25519")).AsSpan().SequenceEqual(originalTraffic), "repeatable whitelist install leaves publisher closure and root custody unchanged");
            File.WriteAllBytes(Path.Combine(publicRoot, "network.ncp2"), journal.Bundle);
            DevOperationalActivation.Execute(fixture, candidate, true);
            Check(true, "exact committed candidate installation can resume without a new generation");
        } finally { CryptographicOperations.ZeroMemory(integrity); }
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
