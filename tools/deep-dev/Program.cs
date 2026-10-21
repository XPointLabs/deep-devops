using System.Diagnostics;
using System.Data.Common;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Services;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;
using Sodium;

try {
    if (args is ["prepare-time-sources", var timeRoot, var timeObserver, var timeFile]) {
        _ = await DevTimeSourceRollover.PrepareAsync(timeRoot, timeObserver, ReadNtsAsync, timeFile);
        Console.WriteLine("Offline current-dev time-source successor prepared; not installed or activated.");
    }
    else if (args is ["validate-time-sources" or "install-time-sources", var installRoot, var timeCandidate]) {
        DevTimeSourceRollover.Install(installRoot, timeCandidate, args[0] == "install-time-sources");
        Console.WriteLine("Sealed time-source installation checked; publisher and native owner activation remain separate.");
    }
    else if (args is ["validate-retained-operational", var retainedRoot, var retainedObserver]) {
        DevTimeSourceRollover.ValidateInstalled(retainedRoot);
        _ = await DevNodeMailboxProvisioning.PolicyAsync(Path.Combine(retainedRoot, "public"), retainedObserver, ReadNtsAsync);
        Console.WriteLine("Retained operational images and current signed policy verified; runtime unchanged.");
    }
    else if (args.Length == 2 && args[0] == "configure") ConfigureAtomicBundle(args[1]);
    else if (args.Length == 3 && args[0] == "prepare-mailbox")
        await DevMailboxPreparation.PrepareAsync(args[1], args[2], ReadNtsAsync);
    else if (args.Length == 2 && args[0] == "provision-node-mailbox-keys")
        DevNodeMailboxProvisioning.ProvisionKeys(args[1]);
    else if (args.Length == 2 && args[0] == "provision-node-contact-keys")
        DevNodeMailboxProvisioning.ProvisionContactKeys(args[1]);
    else if (args.Length == 4 && args[0] == "fetch-node-mailbox-control")
        await DevNodeMailboxProvisioning.FetchControlAsync(args[1], args[2], args[3], ReadNtsAsync);
    else if (args.Length == 3 && args[0] == "prepare-node-mailbox")
        await DevNodeMailboxProvisioning.PrepareAsync(args[1], args[2], ReadNtsAsync);
    else if (args.Length == 3 && args[0] == "prepare-contact-coordination")
        await DevContactCoordinationPreparation.PrepareAsync(args[1], args[2], ReadNtsAsync);
    else if (args.Length == 3 && args[0] == "prepare-dev-pki") await DevPki.PrepareAsync(args[1],args[2],ReadNtsAsync);
    else if (args.Length == 4 && args[0] == "prepare-physical-ingress") await DevPhysicalIngress.PrepareAsync(args[1],args[2],args[3],ReadNtsAsync);
    else if (args.Length == 3 && args[0] == "validate-physical-ingress") {
        _ = DevPhysicalIngress.Validate(args[1]);
        _ = await DevNodeMailboxProvisioning.PolicyAsync(Path.Combine(args[1],"public"),args[2],ReadNtsAsync);
        Console.WriteLine("Sealed physical candidate and current policy verified; runtime unchanged.");
    }
    else if (args.Length == 2 && args[0] == "install-physical-ingress") DevPhysicalIngress.InstallFiles(args[1]);
    else if (args.Length == 2 && args[0] == "mark-physical-ingress") DevPhysicalIngress.MarkInstalled(args[1]);
    else if (args.Length == 2 && args[0] == "validate-dev-pki") { _=DevPki.Validate(args[1]);Console.WriteLine("Sealed same-key dev PKI candidate validated; runtime unchanged."); }
    else if (args.Length == 2 && args[0] == "install-dev-pki") DevPki.Install(args[1]);
    else if (args.Length == 2 && args[0] == "cache-windows-dev-crl") await DevPki.CacheWindowsCrlAsync(args[1]);
    else if (args.Length == 3 && args[0] is "validate-operational-install" or "install-operational")
        DevOperationalActivation.Execute(args[1], args[2], args[0] == "install-operational");
    else if (args.Length == 4 && args[0] == "publish") await DevPublisher.RunAsync(args[1], args[2], args[3], ReadNtsAsync);
    else if (args.Length == 4 && args[0] == "publish-with-crl") await DevPkiPublisher.RunAsync(args[1],args[2],args[3],ReadNtsAsync);
    else if (args.Length == 5 && args[0] == "publish-physical-ingress")
        await DevPublisher.RunAsync(args[1],args[2],args[3],ReadNtsAsync,singlePublication:true,physicalRoot:args[4]);
    else if (args.Length == 4 && args[0] == "publish-short-view") await DevPublisher.RunAsync(args[1], args[2], args[3], ReadNtsAsync, operationalLifetimeSeconds:180, singlePublication:true);
    else if (args.Length == 2 && args[0] == "exercise-directory") await DevDirectoryExercise.RunAsync(args[1]);
    else if (args.Length == 2 && args[0] == "exercise-owned-mailbox") await DevOwnedMailboxExercise.RunAsync(args[1]);
    else if (args.Length == 3 && args[0] == "exercise-owned-mailbox" && args[2] is ("contact-diagnostic" or "contact-replication" or "contact-acceptance"))
        await DevOwnedMailboxExercise.RunAsync(args[1], args[2]);
    else if (args.Length == 3 && args[0] == "admit-observer") await DevObserverAdmission.RunAsync(args[1], args[2]);
    else if ((args.Length == 3 || args.Length == 5 && args[3] == "--time-sources") && args[0] == "prepare-operational") {
        _ = await DevOfflineOperationalRenewal.PrepareAsync(args[1], args[2], ReadNtsAsync, args.Length == 5 ? args[4] : null);
        Console.WriteLine("Offline development operational successor prepared with staged role/traffic/TLS custody; not activated.");
    }
    else if (args.Length == 5 && args[0] == "import-operational")
        await DevPublisher.ImportPreparedAsync(args[1], args[2], args[3], args[4], ReadNtsAsync);
    else if (args.Length == 3 && args[0] == "prepare-authority") {
        _ = await DevOfflineAuthorityRenewal.PrepareAsync(args[1], args[2], ReadNtsAsync);
        Console.WriteLine("Development paired authority renewal prepared offline; no runtime, journal, key or floor was changed.");
    }
    else await InitializeAsync(args);
}
catch (Exception exception) {
    Console.Error.WriteLine($"Development provisioning failed closed ({exception.GetType().Name}); retained private staging is not deployment evidence.");
    if (args.Length > 0 && (args[0].Contains("physical-ingress",StringComparison.Ordinal) || args[0].Contains("time-sources", StringComparison.Ordinal)))
    {
        if (args[0].Contains("physical-ingress", StringComparison.Ordinal))
            Console.Error.WriteLine($"Physical ingress failure category: {DevPhysicalIngress.FailureCategory(exception)}.");
        // Code-owned location only; no exception text/Data, source file path,
        // authority bytes, endpoint or private staging content.
        var trace = new StackTrace(exception, false);
        foreach (var frame in trace.GetFrames().Take(24))
        {
            var method = frame.GetMethod(); var owner = method?.DeclaringType;
            if (owner?.Assembly.GetName().Name is not ("Deep.Dev" or "Deep.Protocol" or "Deep.Protocol.MembershipRoutes")) continue;
            var location = owner.FullName + "." + method!.Name;
            if (location.Length <= 240 && location.All(ch => char.IsAsciiLetterOrDigit(ch) || "_.+<>`".Contains(ch)))
            {
                Console.Error.WriteLine($"Physical ingress failure location: method={location}; il={Math.Clamp(frame.GetILOffset(), -1, 1048575)}.");
                break;
            }
        }
    }
    Environment.ExitCode = 2;
}

static void ConfigureAtomicBundle(string custodyRoot)
{
    var root = Path.GetFullPath(custodyRoot);
    if (!OperatingSystem.IsWindows() || !root.StartsWith(Path.GetFullPath("C:/Work/DeepSession/secrets/dev") + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
        throw new ArgumentException("Configuration updates are restricted to local dev custody.");
    for (string? p = root; p is not null; p = Path.GetDirectoryName(p))
        if (Directory.Exists(p) && (File.GetAttributes(p) & FileAttributes.ReparsePoint) != 0) throw new IOException("Custody must not traverse links.");
    using var manifest = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(root, "public/deep-dev.json")));
    if (manifest.RootElement.GetProperty("schema").GetString() != "deep-dev.v1" || manifest.RootElement.GetProperty("nodeCount").GetInt32() != 3)
        throw new InvalidDataException("Not the owned three-node development environment.");
    var topology = DevTopology.ForProject(manifest.RootElement.GetProperty("projectName").GetString()!);
    if (manifest.RootElement.GetProperty("containerIpv4Prefix").GetString() != topology.Ipv4Prefix)
        throw new InvalidDataException("Development topology differs from its owned manifest.");
    var closureFile = Path.Combine(root, "public/network.ncp2");
    using (var source = new FileStream(closureFile, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete)) {
        if (source.Length is < 1 || source.Length > XPointNetworkClosureWireCodec.MaximumResponseLength)
            throw new InvalidDataException("Development public closure is unbounded.");
        var bytes = new byte[checked((int)source.Length)]; source.ReadExactly(bytes);
        var closure = XPointNetworkClosureWireCodec.DecodeResponse(bytes);
        var pin = new XPointNetworkGenesisPin(
            Convert.FromHexString(manifest.RootElement.GetProperty("networkIdHex").GetString()!),
            Convert.FromHexString(manifest.RootElement.GetProperty("genesisAuthorityCoreHashHex").GetString()!));
        if (!closure.NetworkId.Span.SequenceEqual(pin.NetworkId.Span)) throw new InvalidDataException("Development network differs.");
        _ = XPointNetworkAuthorityVerifier.Verify(pin, closure.ExactAuthorityChain, closure.ExactTimePolicyChain);
    }
    for (var i = 1; i <= 3; i++) {
        var file = Path.Combine(root, $"node-{i}/appsettings.Development.json");
        var config = JsonNode.Parse(File.ReadAllText(file))!.AsObject();
        if (config["DeepIdV2DirectoryProof"]!["NetworkIdHex"]!.GetValue<string>() != manifest.RootElement.GetProperty("networkIdHex").GetString())
            throw new InvalidDataException("Node configuration has a different development identity.");
        config.Remove("ContactAuthority");
        config.Remove("GroupControlAuthority");
        var placement = config["DeepIdV2NetworkPlacement"]!.AsObject();
        foreach (var field in new[] { "ExactPolicyPaths", "ExactViewPaths", "ExactHeadPaths", "ExactActiveNodePaths", "ExactMailboxProjectionPaths", "ExactMailboxAuthorityPaths" }) placement.Remove(field);
        config["PrivacyRouting"]!["NextX25519PrivateKeyPath"] = "/run/secrets/key_x25519_next";
        placement["PublicBundlePath"] = "/run/deep-public/network.ncp2";
        foreach (var peer in config["PrivacyRouting"]!["Peers"]!.AsArray()) {
            peer!.AsObject().Remove("AllowPrivateResolvedAddresses");
            foreach (var pin in new[] { "CurrentSpkiSha256", "NextSpkiSha256" })
                peer![pin] = Convert.ToHexStringLower(Convert.FromHexString(peer[pin]!.GetValue<string>()));
        }
        // Only canonicalize the owned fresh-dev textual representation. The
        // private bytes and all already-announced public keys remain unchanged.
        foreach (var name in new[] { "key_x25519", "key_x25519_next", "key_ed25519" }) {
            var keyFile = Path.Combine(root, $"node-{i}/secrets/{name}");
            var seed = Convert.FromHexString(File.ReadAllText(keyFile).Trim());
            try {
                if (seed.Length != 32) throw new InvalidDataException("Development key has the wrong size.");
                var canonical = Convert.ToHexStringLower(seed);
                if (File.ReadAllText(keyFile) != canonical) {
                    using var f = new FileStream(keyFile, FileMode.Open, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough);
                    var encoded = Encoding.ASCII.GetBytes(canonical); f.Write(encoded); f.SetLength(encoded.Length); f.Flush(true);
                }
            } finally { CryptographicOperations.ZeroMemory(seed); }
        }
        var staging = file + ".stage-" + Guid.NewGuid().ToString("N");
        using (var stream = new FileStream(staging, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough)) {
            var bytes = JsonSerializer.SerializeToUtf8Bytes(config, new JsonSerializerOptions { WriteIndented = true }); stream.Write(bytes); stream.Flush(true);
        }
        File.Move(staging, file, true);
    }
    DevPublisher.PrepareLocalCustody(root);
    Console.WriteLine("Development node configurations now read one atomic public closure; keys and protected state retained.");
}

static async Task InitializeAsync(string[] args)
{
// Private dev operator inputs never share production custody or offline root mounts.
if (args.Length != 4 || args[0] != "init") throw new ArgumentException("Expected init DEV_ROOT NTS_OBSERVER PROJECT_NAME.");
var topology = DevTopology.ForProject(args[3]);
var root = Path.GetFullPath(args[1]);
var requiredParent = Path.GetFullPath("C:/Work/DeepSession/secrets/dev");
if (OperatingSystem.IsWindows() && !root.StartsWith(requiredParent + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
    throw new ArgumentException("Development custody must be beneath secrets/dev.");
if (Directory.Exists(root)) throw new IOException("Existing dev custody cannot be overwritten.");
var target = root;
root = target + ".provision-" + Guid.NewGuid().ToString("N");
for (string? p = Path.GetDirectoryName(root); p is not null; p = Path.GetDirectoryName(p))
    if (Directory.Exists(p) && (File.GetAttributes(p) & FileAttributes.ReparsePoint) != 0) throw new IOException("Custody must not traverse links.");
Directory.CreateDirectory(root);
var network = RandomNumberGenerator.GetBytes(16);
var registrySecrets = Dir("registry/secrets");
var publicRoot = Dir("public");
var operatorRoot = Dir("operator");
var offlineRoot = Dir("offline-root");
using var signer = Signer.Create(Path.Combine(offlineRoot, "root.seed"), rootSigner: true);
var witnesses = Enumerable.Range(1, 3).Select(i => Signer.Create(Path.Combine(operatorRoot, $"witness-{i}.seed"))).ToArray();
var nodes = Enumerable.Range(1, 3).Select(i => Signer.Create(Path.Combine(operatorRoot, $"node-{i}.seed"), nodeSigner: true)).ToArray();
// Keep independent role custody. A public key whose seed was discarded can
// never become an operational mailbox signer after bootstrap.
using var depositIssuer = Signer.Create(Path.Combine(registrySecrets, "mailbox-deposit.seed"));
using var retrieveIssuer = Signer.Create(Path.Combine(registrySecrets, "mailbox-retrieve.seed"));
try
{
    // Real native PQ provider and account persistence, not a synthetic public credential.
    using var secure = new InMemoryDeepSecureStorage();
    var observer = new DeepIdV2AccountService(secure, Dir("observer"), network, 1,
        new SystemClock(), DeepMlDsa65CandidateVerifierFactory.OpenForCurrentProcess);
    _ = await observer.CreateAsync("Local network observer");
    var observerAdmission = await observer.PrepareGenesisAdmissionAsync();
    Write("observer/admission.dga2", observerAdmission);
    // This disposable dev observer is not a persisted user recovery account.
    // It is a disposable development account; its public admission is sufficient
    // for the network observer. It is never a user/device release account.
    var parsedObserver = DeepIdV2GenesisAdmissionWireCodec.DecodeRequest(observerAdmission);
    Write("public/observer.did2", parsedObserver.Admission.ExactDid2.Span);
    var sources = new[] {
        Source("time.cloudflare.com", "cloudflare", "48f93d4f1ecaf8e2323bc2e5be015b331d65cb8e40a1b28be50eb4ba9230e789"),
        Source("nts.netnod.se", "netnod", "bd44c55cfd57e38da3a6aea80bf65f9c441b63fbd8667e057b0f112fc3211efa")
    }.OrderBy(s => s.SourceId.ToArray(), Comparer<byte[]>.Create((a,b) => a.AsSpan().SequenceCompareTo(b))).ToArray();
    var observed = await ReadNtsAsync(args[2], sources);
    var before = observed - 30;
    var expiry = observed + 7 * 86_400;
    var bootstrap = await XPointNetworkBootstrapAuthor.AuthorGenesisAsync(new(
        RandomNumberGenerator.GetBytes(32), network,
        [new(signer.RootKeyId.Span, 0, signer.Ed25519PublicKey.Span, signer.CustodyDomainHash.Span)], 1,
        witnesses.Select(w => new XPointNetworkBootstrapWitnessKey(w.SignerId.Span, 0, w.Ed25519PublicKey.Span, w.FailureDomainHash.Span)).ToArray(),
        2, sources, 10, 30, before, before, expiry, before, expiry, 1, 1), [signer]);
    using var caKey = RSA.Create(3072);
    var caRequest = new CertificateRequest("CN=Deep development CA", caKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    caRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
    caRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
    using var ca = caRequest.CreateSelfSigned(DateTimeOffset.FromUnixTimeSeconds((long)before - 86_400), DateTimeOffset.FromUnixTimeSeconds((long)expiry + 86_400));
    Write("public/dev-ca.crt", Encoding.ASCII.GetBytes(ca.ExportCertificatePem()));
    Write("offline-root/dev-ca.key", Encoding.ASCII.GetBytes(caKey.ExportPkcs8PrivateKeyPem()));
    Certificate("registry", "registry", IPAddress.Loopback, ca);
    Certificate("floor", "floor", IPAddress.Loopback, ca);
    var nodeModels = new XPointNetworkOperationalNode[3];
    var onion = new byte[3][];
    for (var i = 0; i < 3; i++)
    {
        var name = $"node-{i+1}";
        var nodeDirectory = Dir(name + "/secrets");
        var address = IPAddress.Parse($"{topology.Ipv4Prefix}.{11+i}");
        var currentPin = Certificate(name, name, address, ca);
        var nextPin = Certificate(name + "-next", name, address, ca);
        onion[i] = RandomNumberGenerator.GetBytes(32);
        var next = RandomNumberGenerator.GetBytes(32);
        Write(name + "/secrets/key_x25519", Encoding.ASCII.GetBytes(Convert.ToHexStringLower(onion[i])));
        Write(name + "/secrets/key_x25519_next", Encoding.ASCII.GetBytes(Convert.ToHexStringLower(next)));
        Write(name + "/secrets/key_ed25519", Encoding.ASCII.GetBytes(Convert.ToHexStringLower(nodes[i].Seed)));
        Write(name + "/secrets/onion-state-protection.key", RandomNumberGenerator.GetBytes(32));
        Write(name + "/secrets/key_bls", Encoding.ASCII.GetBytes(NewBlsScalar()));
        var roleKeys = Enumerable.Range(0, 5).Select(role => {
            var seed = RandomNumberGenerator.GetBytes(32);
            try { Write(name + $"/secrets/role-{role}.seed", seed); return (ReadOnlyMemory<byte>)PublicKeyAuth.GenerateKeyPair(seed).PublicKey; }
            finally { CryptographicOperations.ZeroMemory(seed); }
        }).ToArray();
        nodeModels[i] = new(nodes[i], Hash("staking-dev-" + name), Hash("Mr. X"), Hash(name), Hash("local-docker"),
            64512, 0, Hash("origin-" + name), address, 443, currentPin, nextPin,
            ScalarMult.Base(onion[i]), ScalarMult.Base(next),
            roleKeys);
        CryptographicOperations.ZeroMemory(next);
    }
    var did2 = DeepIdV2Codec.DecodeDid2(parsedObserver.Admission.ExactDid2.Span);
    var pending = await XPointNetworkOperationalGenesisAuthor.AuthorNetworkCandidateAsync(new(
        RandomNumberGenerator.GetBytes(32), bootstrap, [signer], witnesses, nodeModels,
        Hash("deep-dev-carrier-candidate"), Hash("deep-dev-carrier-set-candidate"), Hash("deep-dev-mailbox"),
        depositIssuer.Ed25519PublicKey.Span,
        retrieveIssuer.Ed25519PublicKey.Span,
        before, before, observed + 3_600, rootPolicyExpiresAtUnixSeconds: expiry));
    var adh = await DeepIdV2DirectoryHeadAuthor.AuthorGenesisAsync(bootstrap.Authority, before, observed + 3_600,
        witnesses.Select(w => (IAccountDirectoryAdh1WitnessSigner)w).ToArray());
    var lookup = DeepIdV2AccountDirectoryLookupCodec.Author(did2, network,
        adh.ProtectedHead.LogGeneration, adh.CoreHash.Span, 1, new byte[38], new byte[32]);
    var query = VerifiedDeepIdV2DirectoryQuery.VerifyDid2(lookup, did2);
    var material = DeepIdV2DirectoryProofMaterialAuthor.Create(adh.ProtectedHead, [], [],
        query.DirectoryLeafKey.Span, adh.ProtectedHead);
    var nonce = RandomNumberGenerator.GetBytes(32);
    var clock = new DevGenesisMonotonicClock();
    var sent = await clock.ReadAsync(default);
    var proofRequest = new AccountDirectoryProofAuthoringRequest(network, nonce, sent.BootId.Span,
        sent.SampleSeconds, adh.ExactAdh1.Span, pending.ExactXnv1.Span, observed, 5,
        observed, checked(observed + 30),
        AccountDirectoryDtt1IssuanceEpoch.Derive(bootstrap.Authority, observed, 5), 2);
    using var pq = DeepMlDsa65CandidateVerifierFactory.OpenForCurrentProcess();
    var proof = await DeepIdV2DirectoryProofAuthor.IssueGenesisAsync(bootstrap.Authority,
        proofRequest, material, witnesses, 1, pq);
    var received = await clock.ReadAsync(default);
    var freshness = DeepIdV2DirectoryCurrentProofVerifier.VerifyRequestedDid2(bootstrap.Authority,
        proof.ExactAdh1, proof.ExactDtt1, proof.ExactAdp1V2, nonce, query,
        new(sent.BootId.Span, sent.SampleSeconds, received.SampleSeconds, received.SampleSeconds),
        adh.ProtectedHead, 1, 2, pq);
    var operational = await XPointNetworkOperationalGenesisAuthor.CompleteDid2Async(
        pending, freshness, new OnionTrustedTimeAuthority(clock));
    Write("public/genesis.adh1", adh.ExactAdh1.Span);
    Write("public/genesis.xna1", bootstrap.ExactXna1.Span); Write("public/genesis.dts1", bootstrap.ExactDts1.Span);
    Write("public/current.xnv1", operational.ExactXnv1.Span);
    Write("public/pma2.bin", operational.ExactPma2.Span);
    Write("public/network.ncp2", XPointNetworkClosureWireCodec.EncodeResponse(network, [bootstrap.ExactXna1], [bootstrap.ExactDts1],
        [operational.ExactXvp1], [operational.ExactXnv1], [operational.ExactXnh1], operational.ExactXnd1,
        [operational.ExactPmt2], [operational.ExactPma2]));
    var artifactPaths = new Dictionary<string, string[]>();
    foreach (var (role, values) in new (string, IReadOnlyList<ReadOnlyMemory<byte>>)[] {
        ("xvp1", [operational.ExactXvp1]), ("xnv1", [operational.ExactXnv1]), ("xnh1", [operational.ExactXnh1]),
        ("xnd1", operational.ExactXnd1), ("pmt2", [operational.ExactPmt2]) })
    {
        artifactPaths[role] = values.Select((value,index) => {
            var file = $"{role}.{index:0000}.bin"; Write("public/" + file, value.Span); return "/run/deep-public/" + file;
        }).ToArray();
    }
    foreach (var (w,index) in witnesses.Select((w,i) => (w,i))) Write($"registry/secrets/witness-{index+1}.seed", w.Seed);
    foreach (var name in new[] { "directory-integrity", "time-integrity", "proof-ledger-integrity", "request-ledger-integrity" })
        Write("registry/secrets/" + name + ".key", RandomNumberGenerator.GetBytes(32));
    Write("floor/secrets/password", Encoding.ASCII.GetBytes(Convert.ToHexString(RandomNumberGenerator.GetBytes(32))));
    var password = File.ReadAllText(Path.Combine(root, "floor/secrets/password"));
    var floorConnection = new DbConnectionStringBuilder {
        ["Host"] = "floor", ["Database"] = "deep_dev", ["Username"] = "postgres",
        ["Password"] = password, ["SSL Mode"] = "VerifyFull",
        ["Root Certificate"] = "/run/deep-public/dev-ca.crt",
        ["Timeout"] = 5, ["Command Timeout"] = 5,
    };
    var directory = new Dictionary<string, object> {
        ["Enabled"] = true, ["NetworkIdHex"] = Convert.ToHexString(network), ["GenesisAuthorityCoreHashHex"] = Convert.ToHexString(bootstrap.GenesisPin.AuthorityCoreHash.Span),
        ["ExactAuthorityPaths"] = new[] { "/run/deep-public/genesis.xna1" }, ["ExactTimePolicyPaths"] = new[] { "/run/deep-public/genesis.dts1" },
        ["GenesisHeadPath"] = "/run/deep-public/genesis.adh1", ["GenesisHeadCoreHashHex"] = Convert.ToHexString(adh.CoreHash.Span),
        ["StatePath"] = "/var/lib/registry/authority.ada2", ["IntegrityKeyPath"] = "/run/secrets/directory-integrity.key",
        ["LatestHeadFloorPostgreSqlConnectionString"] = floorConnection.ConnectionString,
        ["ProofEnabled"] = true, ["CurrentXnv1Path"] = "/run/deep-public/current.xnv1", ["ProofRequestLedgerRootPath"] = "/var/lib/registry/proof-ledger",
        ["ProofRequestLedgerIntegrityKeyPath"] = "/run/secrets/proof-ledger-integrity.key", ["HeadRenewalEnabled"] = true,
        ["HeadValiditySeconds"] = 3_600, ["HeadRenewalLeadSeconds"] = 300, ["HeadRenewalIntervalSeconds"] = 60
    };
    var registryConfiguration = new Dictionary<string, object> {
        ["Logging"] = Logging(), ["Urls"] = "https://0.0.0.0:443", ["Kestrel"] = Tls(),
        ["Registry"] = new { DataDirectory = "/var/lib/registry" },
        ["DeepIdV2DirectoryAuthority"] = directory,
        ["XPointNetworkClosureDistribution"] = new { Enabled = true, NetworkIdHex = Convert.ToHexString(network), BundlePath = "/run/deep-public/network.ncp2" },
        ["ContactResolveProductionAuthority"] = new {
            Enabled = true, NetworkIdHex = Convert.ToHexString(network), TrustedTimeStatePath = "/var/lib/registry/unused-manual-time.state",
            TrustedTimeIntegrityKeyPath = "/run/secrets/time-integrity.key", AutomaticTrustedTimeEnabled = true,
            NtsObserverExecutablePath = "/usr/local/bin/deep-nts-observer", NtsLowerFloorPath = "/var/lib/registry/nts-floor.state",
            RequestLedgerRootPath = "/var/lib/registry/request-ledger", RequestLedgerIntegrityKeyPath = "/run/secrets/request-ledger-integrity.key",
            Witnesses = witnesses.Select((w,i) => new { WitnessIdHex = Convert.ToHexString(w.SignerId.Span), KeyGeneration = 0, Ed25519SeedPath = $"/run/secrets/witness-{i+1}.seed" }).ToArray()
        }
    };
    Json("registry/appsettings.Development.json", registryConfiguration);
    foreach (var (model,i) in nodeModels.Select((m,i) => (m,i)))
    {
        var name = $"node-{i+1}";
        Json(name + "/appsettings.Development.json", new Dictionary<string,object> {
            ["Logging"] = Logging(), ["Kestrel"] = Tls(),
            ["Node"] = new { RouterId = Convert.ToHexString(model.IdentitySigner.Ed25519PublicKey.Span), Ed25519PrivateKeyPath = "/run/secrets/key_ed25519",
                DataDirectory = "/var/lib/xnode", IsRelay = true, ApiListenUrl = "http://0.0.0.0:8080", PeerRpcListenUrl = "http://0.0.0.0:8081", PrivacyPeerH2ListenUrl = "https://0.0.0.0:443" },
            ["Vless"] = new { Enabled = false, MockProcess = false }, ["RegistryHeartbeat"] = new { Enabled = false },
            ["ContactService"] = new { RuntimeActivation = false, MapReplicaEndpoint = false },
            ["GroupControlService"] = new { RuntimeActivation = false, MapReplicaEndpoint = false },
            ["RequiredTerminals"] = new { Contact = false, GroupControl = false },
            ["DeepIdV2DirectoryProof"] = new { Enabled = true, RegistryOrigin = "https://registry/", NetworkIdHex = Convert.ToHexString(network),
                GenesisAuthorityCoreHashHex = Convert.ToHexString(bootstrap.GenesisPin.AuthorityCoreHash.Span), ExactAuthorityPaths = new[] { "/run/deep-public/genesis.xna1" },
                ExactTimePolicyPaths = new[] { "/run/deep-public/genesis.dts1" }, GenesisHeadPath = "/run/deep-public/genesis.adh1", GenesisHeadCoreHashHex = Convert.ToHexString(adh.CoreHash.Span),
                StateRelativeDirectory = "did2-proof-state", DataProtectionKeysRelativeDirectory = "did2-proof-keys", DeploymentProfileId = 1, RequestTimeoutSeconds = 10 },
            ["DeepIdV2NetworkPlacement"] = new { Enabled = true, PublicBundlePath = "/run/deep-public/network.ncp2", PublicObservationDid2Path = "/run/deep-public/observer.did2" },
            ["DeepIdV2ReplicaStage"] = new { Enabled = true },
            ["PrivacyRouting"] = new { Enabled = true, X25519PrivateKeyPath = "/run/secrets/key_x25519", PublicPeerBaseUrl = $"https://{topology.Ipv4Prefix}.{11+i}/",
                StateProtectionKeyPath = "/run/secrets/onion-state-protection.key", ReplayStateRelativePath = "did2-onion-replay.state", EntropyStateRelativePath = "did2-onion-entropy.state",
                KeyVaultDirectoryRelativePath = "did2-onion-key-vault", AllowInsecureHttpPeerTransport = false,
                Peers = nodeModels.Where(m => m != model).Select(m => new { RouterId = Convert.ToHexString(m.IdentitySigner.Ed25519PublicKey.Span),
                    BaseUrl = $"https://{new IPAddress(m.OriginAddress.Span[..4])}/", CurrentSpkiSha256 = Convert.ToHexStringLower(m.CurrentOriginSpkiSha256.Span),
                    NextSpkiSha256 = Convert.ToHexStringLower(m.NextOriginSpkiSha256.Span) }).ToArray() }
        });
    }
    Json("public/deep-dev.json", new { schema = "deep-dev.v1", authorityOwner = "Mr. X", projectName = topology.ProjectName,
        containerIpv4Prefix = topology.Ipv4Prefix, networkIdHex = Convert.ToHexString(network),
        genesisAuthorityCoreHashHex = Convert.ToHexString(bootstrap.GenesisPin.AuthorityCoreHash.Span), genesisHeadCoreHashHex = Convert.ToHexString(adh.CoreHash.Span),
        nodeCount = 3, operatorModel = "single-operator-local", deviceEvidence = false, carrierEvidence = false });
    Directory.Move(root, target);
    Console.WriteLine("Deep development custody provisioned: 3 nodes; real NTS; no production keys or release evidence.");
}
finally { foreach (var s in witnesses.Concat(nodes)) s.Dispose(); }

string Dir(string relative) { var p = Path.Combine(root, relative); Directory.CreateDirectory(p); return p; }
void Write(string relative, ReadOnlySpan<byte> bytes)
{ var p = Path.Combine(root, relative); Directory.CreateDirectory(Path.GetDirectoryName(p)!); using var f = new FileStream(p, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough); f.Write(bytes); f.Flush(true); }
void Json(string relative, object value) => Write(relative, JsonSerializer.SerializeToUtf8Bytes(value, new JsonSerializerOptions { WriteIndented = true }));
object Logging() => new { LogLevel = new Dictionary<string,string> { ["Default"] = "Warning", ["Microsoft.AspNetCore"] = "Warning" } };
object Tls() => new { Certificates = new { Default = new { Path = "/run/secrets/server.crt", KeyPath = "/run/secrets/server.key" } } };
byte[] Certificate(string name, string dns, IPAddress address, X509Certificate2 ca)
{
    // OS time is used only by the X509 platform; it is not proof-time authority.
    using var key = RSA.Create(2048);
    var req = new CertificateRequest("CN=" + dns, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
    req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));
    req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new System.Security.Cryptography.OidCollection { new("1.3.6.1.5.5.7.3.1") }, true));
    var san = new SubjectAlternativeNameBuilder(); san.AddDnsName(dns); san.AddIpAddress(address); san.AddDnsName("localhost"); san.AddIpAddress(IPAddress.Loopback);
    req.CertificateExtensions.Add(san.Build());
    using var self = req.Create(ca, ca.NotBefore.ToUniversalTime().AddHours(1), ca.NotAfter.ToUniversalTime().AddHours(-1), RandomNumberGenerator.GetBytes(16));
    Write(name + "/secrets/server.crt", Encoding.ASCII.GetBytes(self.ExportCertificatePem()));
    Write(name + "/secrets/server.key", Encoding.ASCII.GetBytes(key.ExportPkcs8PrivateKeyPem()));
    return SHA256.HashData(key.ExportSubjectPublicKeyInfo());
}
}
static byte[] Hash(string value) => SHA256.HashData(Encoding.UTF8.GetBytes("Deep/Development/v1/" + value));
static AccountDirectoryDts1Source Source(string host, string family, string pin) => new(Hash(host), Hash(family), 1, host, 4460, Convert.FromHexString(pin), 10);
static string NewBlsScalar()
{
    var order = System.Numerics.BigInteger.Parse("073eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", System.Globalization.NumberStyles.HexNumber);
    while (true) { var b = RandomNumberGenerator.GetBytes(32); var n = new System.Numerics.BigInteger(b, true, true); if (n > 0 && n < order) return "0x" + Convert.ToHexString(b); }
}
static async Task<ulong> ReadNtsAsync(string executable, AccountDirectoryDts1Source[] sources)
{
    var started = Stopwatch.GetTimestamp();
    using var process = new Process { StartInfo = new(Path.GetFullPath(executable)) { RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true } };
    if (!process.Start()) throw new IOException("NTS observation process did not start.");
    try
    {
        var request = JsonSerializer.Serialize(new { sources = sources.Select(s => new { id = Convert.ToHexStringLower(s.SourceId.Span), host = s.HostAscii, port = s.Port, pin = Convert.ToHexStringLower(s.TlsSpkiSha256.Span), radius = s.MaximumRadiusSeconds }) });
        await process.StandardInput.WriteLineAsync(request); await process.StandardInput.FlushAsync();
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var buffer = new char[8192];
        string? line = null;
        for (var length = 0; length < buffer.Length; length++)
        {
            if (await process.StandardOutput.ReadAsync(buffer.AsMemory(length, 1), deadline.Token) != 1)
                throw new IOException("Authenticated NTS quorum is unavailable.");
            if (buffer[length] == '\n') { line = new string(buffer, 0, length); break; }
        }
        if (line is null) throw new IOException("Authenticated NTS observation exceeds its bound.");
        return DevNtsObservation.Parse(Encoding.UTF8.GetBytes(line), sources, Stopwatch.GetElapsedTime(started));
    }
    finally { if (!process.HasExited) process.Kill(entireProcessTree: true); await process.WaitForExitAsync(); }
}

sealed class DevGenesisMonotonicClock : IOnionMonotonicClock
{
    private readonly byte[] boot = RandomNumberGenerator.GetBytes(16);
    private readonly long started = Stopwatch.GetTimestamp();
    public ValueTask<OnionMonotonicReading> ReadAsync(CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        return ValueTask.FromResult(new OnionMonotonicReading(boot,
            checked(1 + (ulong)Stopwatch.GetElapsedTime(started).TotalSeconds)));
    }
}

sealed class Signer : IXPointNetworkBootstrapRootSigner, IXPointNetworkWitnessSigner, IAccountDirectoryAdh1WitnessSigner, IDisposable
{
    private readonly byte[] signingKey; private readonly bool root; private readonly bool node;
    internal byte[] Seed { get; }
    private Signer(byte[] seed, bool root, bool node) { Seed = seed; this.root = root; this.node = node; var pair = PublicKeyAuth.GenerateKeyPair(seed); signingKey = pair.PrivateKey; Ed25519PublicKey = pair.PublicKey; SignerId = node ? pair.PublicKey : HashLocal(pair.PublicKey); FailureDomainHash = HashLocal(SignerId.ToArray()); }
    internal static Signer Create(string file, bool rootSigner = false, bool nodeSigner = false)
    { var seed = RandomNumberGenerator.GetBytes(32); Directory.CreateDirectory(Path.GetDirectoryName(file)!); using var f = new FileStream(file, FileMode.CreateNew, FileAccess.Write, FileShare.None); f.Write(seed); f.Flush(true); return new(seed, rootSigner, nodeSigner); }
    internal static Signer Load(string file, bool nodeSigner = false)
    { return LoadExact(file, false, nodeSigner); }
    internal static Signer LoadRoot(string file) => LoadExact(file, true, false);
    private static Signer LoadExact(string file, bool rootSigner, bool nodeSigner)
    {
        using var stream = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (stream.Length != 32) throw new InvalidDataException("Wrong dev signer custody.");
        var bytes = new byte[32];
        try { stream.ReadExactly(bytes); return new(bytes, rootSigner, nodeSigner); }
        catch { CryptographicOperations.ZeroMemory(bytes); throw; }
    }
    public ReadOnlyMemory<byte> RootKeyId => root ? SignerId : default;
    public ReadOnlyMemory<byte> SignerId { get; }
    public ReadOnlyMemory<byte> WitnessId => SignerId;
    public ulong KeyGeneration => 0;
    public ReadOnlyMemory<byte> Ed25519PublicKey { get; }
    public ReadOnlyMemory<byte> FailureDomainHash { get; }
    public ReadOnlyMemory<byte> CustodyDomainHash => FailureDomainHash;
    public ValueTask<int> SignAsync(XPointNetworkRootSigningRequest request, Memory<byte> destination, CancellationToken token)
    { token.ThrowIfCancellationRequested(); if (!root || !request.RootKeyId.Span.SequenceEqual(SignerId.Span) || !request.ExpectedEd25519PublicKey.Span.SequenceEqual(Ed25519PublicKey.Span)) throw new CryptographicException("Root signing scope differs."); return Sign(request.SigningInput, destination); }
    public ValueTask<int> SignAsync(XPointNetworkOperationalSigningRequest request, Memory<byte> destination, CancellationToken token)
    { token.ThrowIfCancellationRequested(); if (root || !request.SignerId.Span.SequenceEqual(SignerId.Span) || !request.ExpectedEd25519PublicKey.Span.SequenceEqual(Ed25519PublicKey.Span) || node != (request.Purpose == XPointNetworkOperationalSignaturePurpose.NodeDescriptor)) throw new CryptographicException("Operational signing scope differs."); return Sign(request.SigningInput, destination); }
    public ValueTask<ReadOnlyMemory<byte>> SignDtt1Async(ReadOnlyMemory<byte> input, CancellationToken token)
    { token.ThrowIfCancellationRequested(); if (root || node) throw new CryptographicException("Wrong DTT witness."); return ValueTask.FromResult<ReadOnlyMemory<byte>>(PublicKeyAuth.SignDetached(input.ToArray(), signingKey)); }
    public ValueTask<ReadOnlyMemory<byte>> SignAdh1Async(ReadOnlyMemory<byte> input, CancellationToken token)
    { token.ThrowIfCancellationRequested(); if (root || node) throw new CryptographicException("Wrong ADH witness."); return ValueTask.FromResult<ReadOnlyMemory<byte>>(PublicKeyAuth.SignDetached(input.ToArray(), signingKey)); }
    private ValueTask<int> Sign(ReadOnlyMemory<byte> input, Memory<byte> destination) { var s = PublicKeyAuth.SignDetached(input.ToArray(), signingKey); try { s.CopyTo(destination); return ValueTask.FromResult(s.Length); } finally { CryptographicOperations.ZeroMemory(s); } }
    private static byte[] HashLocal(byte[] value) => SHA256.HashData(value);
    public void Dispose() { CryptographicOperations.ZeroMemory(signingKey); CryptographicOperations.ZeroMemory(Seed); }
}
