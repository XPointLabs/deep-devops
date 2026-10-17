using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Serialization;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.XPointNetworkV1;
using Sodium;

// Development-only single-operator renewal service. It never mounts an offline
// root, resets genesis, invents a release profile, or grants consumer authority.
internal static class DevPublisher
{
    private static readonly JsonSerializerOptions Json = new() { UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow };
    internal sealed record NodeKeys(string CurrentPin, string NextPin, string CurrentKey, string NextKey);
    internal sealed record Journal(string Schema, string Network, ulong Generation, ulong Observed,
        string PriorPublicHash, byte[] Bundle);

    internal static void PrepareLocalCustody(string root)
    {
        var keys = Enumerable.Range(1,3).Select(i => {
            var current = Convert.FromHexString(File.ReadAllText(Path.Combine(root,$"node-{i}/secrets/key_x25519")));
            var next = Convert.FromHexString(File.ReadAllText(Path.Combine(root,$"node-{i}/secrets/key_x25519_next")));
            try {
                using var crt = X509CertificateLoader.LoadCertificateFromFile(Path.Combine(root,$"node-{i}/secrets/server.crt"));
                using var nextCrt = X509CertificateLoader.LoadCertificateFromFile(Path.Combine(root,$"node-{i}-next/secrets/server.crt"));
                return new NodeKeys(Convert.ToHexStringLower(SHA256.HashData(crt.PublicKey.ExportSubjectPublicKeyInfo())),
                    Convert.ToHexStringLower(SHA256.HashData(nextCrt.PublicKey.ExportSubjectPublicKeyInfo())),
                    Convert.ToHexStringLower(ScalarMult.Base(current)), Convert.ToHexStringLower(ScalarMult.Base(next)));
            } finally { CryptographicOperations.ZeroMemory(current); CryptographicOperations.ZeroMemory(next); }
        }).ToArray();
        var file = Path.Combine(root,"operator/renewal-nodes.json");
        var bytes = JsonSerializer.SerializeToUtf8Bytes(keys,Json);
        if (File.Exists(file)) { if (!File.ReadAllBytes(file).AsSpan().SequenceEqual(bytes)) throw new InvalidDataException("Renewal custody changed."); }
        else Create(file,bytes);
        var secret = Path.Combine(root,"operator/renewal-integrity.key");
        if (!File.Exists(secret)) {
            var bundle = XPointNetworkClosureWireCodec.DecodeResponse(File.ReadAllBytes(Path.Combine(root,"public/network.ncp2")));
            if (bundle.ExactViewChain.Count != 1) throw new InvalidDataException("Missing renewal integrity custody cannot be regenerated.");
            var key = RandomNumberGenerator.GetBytes(32);
            try { Create(secret,key); } finally { CryptographicOperations.ZeroMemory(key); }
        }
    }

    internal static async Task RunAsync(string publicRoot, string operatorRoot, string executable,
        Func<string,AccountDirectoryDts1Source[],Task<ulong>> observe,
        uint operationalLifetimeSeconds = 3_600, bool singlePublication = false, CancellationToken stoppingToken = default,
        string? physicalRoot = null)
    {
        if (operationalLifetimeSeconds is < 180 or > 3_600) throw new ArgumentOutOfRangeException(nameof(operationalLifetimeSeconds));
        if (OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Run the dev publisher as its scoped Docker service.");
        publicRoot = Path.GetFullPath(publicRoot); operatorRoot = Path.GetFullPath(operatorRoot);
        if (publicRoot != "/run/deep-public" || operatorRoot != "/run/deep-operator") throw new ArgumentException("Wrong dev publisher scope.");
        var state = "/var/lib/deep-publisher/renewal.state";
        Directory.CreateDirectory(Path.GetDirectoryName(state)!);
        using var lease = new FileStream(state + ".lease", FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
        using var manifest = JsonDocument.Parse(Bounded(Path.Combine(publicRoot,"deep-dev.json"),16_384));
        if (manifest.RootElement.GetProperty("schema").GetString() != "deep-dev.v1") throw new InvalidDataException("Not dev custody.");
        var network = Convert.FromHexString(manifest.RootElement.GetProperty("networkIdHex").GetString()!);
        var pin = new XPointNetworkGenesisPin(network,Convert.FromHexString(manifest.RootElement.GetProperty("genesisAuthorityCoreHashHex").GetString()!));
        _ = XPointNetworkBootstrapAuthor.VerifyExistingGenesis(Bounded(Path.Combine(publicRoot,"genesis.xna1"),65_535),
            Bounded(Path.Combine(publicRoot,"genesis.dts1"),65_535),pin);
        var head = Bounded(Path.Combine(publicRoot,"genesis.adh1"),4096);
        var adhReference = new byte[38]; "ADH1"u8.CopyTo(adhReference); BinaryPrimitives.WriteUInt16BigEndian(adhReference.AsSpan(4),1);
        XPointNetworkOperationalSuccessorAuthor.ComputeAdh1CoreHash(head).CopyTo(adhReference,6);
        var keys = JsonSerializer.Deserialize<NodeKeys[]>(Bounded(Path.Combine(operatorRoot,"renewal-nodes.json"),16_384),Json)!;
        if (keys.Length != 3) throw new InvalidDataException("Wrong dev node custody count.");
        var integrity = Bounded(Path.Combine(operatorRoot,"renewal-integrity.key"),32);
        if (integrity.Length != 32 || integrity.AsSpan().IndexOfAnyExcept((byte)0) < 0) throw new InvalidDataException("Wrong renewal integrity key.");
        if (physicalRoot is not null && (!singlePublication || manifest.RootElement.GetProperty("projectName").GetString() != "deep-dev-current"))
            throw new ArgumentException("Physical relocation requires an explicit one-shot current-dev maintenance flight.");
        var physical = physicalRoot is null ? null : DevPhysicalIngress.ReadOnlineIntent(physicalRoot, integrity);
        var witnesses = Enumerable.Range(1,3).Select(i => Signer.Load(Path.Combine(operatorRoot,$"witness-{i}.seed"))).ToArray();
        var nodes = Enumerable.Range(1,3).Select(i => Signer.Load(Path.Combine(operatorRoot,$"node-{i}.seed"),true)).ToArray();
        using var stopping = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
        // The expiry fault lane has bounded acquisition and produces real
        // shorter-lived signed successors; it never edits a verifier's clock.
        if (singlePublication) stopping.CancelAfter(TimeSpan.FromMinutes(2));
        Console.CancelKeyPress += (_,e) => { e.Cancel = true; stopping.Cancel(); };
        try {
            // A protected pending commit is authoritative distribution state;
            // finish publication after a process crash before producing another.
            Journal? cursor = File.Exists(state) ? ReadJournal(state,integrity,network) : null;
            var file = Path.Combine(publicRoot,"network.ncp2");
            if (cursor is not null) Publish(cursor,file,publicRoot);
            if (physical is not null)
            {
                if (cursor is null) throw new InvalidDataException("Physical relocation requires the retained publisher journal.");
                var result = DevPhysicalIngress.ReadResult(physicalRoot!, physical, integrity);
                if (result is not null)
                {
                    var exact = result.Journal;
                    if (exact.Network != Convert.ToHexStringLower(network) || !XPointNetworkClosureWireCodec.DecodeResponse(exact.Bundle).NetworkId.Span.SequenceEqual(network))
                        throw new CryptographicException("Physical result belongs to another retained network.");
                    if (cursor.Generation == exact.Generation && cursor.Bundle.AsSpan().SequenceEqual(exact.Bundle))
                    { Publish(cursor,file,publicRoot); Console.WriteLine("Exact physical publication already committed; no re-authoring."); return; }
                    if (exact.Generation != checked(cursor.Generation + 1) ||
                        Convert.ToHexStringLower(SHA256.HashData(cursor.Bundle)) != physical.PriorBundleHash || exact.Observed < cursor.Observed)
                        throw new CryptographicException("Physical result cannot replace this publisher generation.");
                    WriteJournal(state,exact,integrity); Publish(exact,file,publicRoot);
                    Console.WriteLine("Exact physical publication resumed through the retained journal."); return;
                }
                if (Convert.ToHexStringLower(SHA256.HashData(cursor.Bundle)) != physical.PriorBundleHash)
                    throw new CryptographicException("Physical predecessor changed; no signature or publication.");
            }
            var expiryWarning = false;
            while (!stopping.IsCancellationRequested) {
                try {
                    var prior = cursor?.Bundle ?? Bounded(file,XPointNetworkClosureWireCodec.MaximumResponseLength);
                    var closure = XPointNetworkClosureWireCodec.DecodeResponse(prior);
                    if (cursor is null && closure.ExactViewChain.Count != 1) throw new InvalidDataException("Missing publisher state cannot become genesis.");
                    if (!closure.NetworkId.Span.SequenceEqual(network) ||
                        closure.ExactViewChain.Count >= XPointNetworkClosureWireCodec.MaximumChainCount)
                        throw new InvalidDataException("Development delegation/history scope is exhausted.");
                    // Original genesis authenticates the complete retained
                    // paired chain. Never keep using generation-zero keys or
                    // time policy after an offline operational handover.
                    var authority = XPointNetworkAuthorityVerifier.Verify(pin,
                        closure.ExactAuthorityChain,closure.ExactTimePolicyChain);
                    var policy = AccountDirectoryDts1Codec.Decode(closure.ExactTimePolicyChain[^1].Span);
                    var pma = closure.ExactMailboxAuthorityChain[^1];
                    var sources = policy.Sources.ToArray();
                    var observed = await observe(executable,sources);
                    if (cursor is not null && observed < cursor.Observed) throw new CryptographicException("Renewal clock regressed.");
                    var authorityHorizon = Math.Min(authority.ExpiresAt,policy.ExpiresAt);
                    if (observed >= authorityHorizon || authorityHorizon-observed < operationalLifetimeSeconds)
                        throw new InvalidOperationException("Development offline policy renewal required.");
                    var mailboxPolicy = MailboxAuthorityV2Verifier.Verify(authority,pma.Span,observed,checked(observed+1));
                    var policyHorizon = Math.Min(authorityHorizon,mailboxPolicy.ExpiresAtUnixSeconds);
                    // The supported offline producer couples XVP1/PMA2 expiry.
                    // AuthorDelegatedAsync still authenticates the exact XVP1
                    // window before callbacks; never copy its private parser.
                    if (observed >= policyHorizon || policyHorizon-observed < operationalLifetimeSeconds)
                        throw new InvalidOperationException("Development offline policy renewal required.");
                    if (policyHorizon-observed <= 86_400 && !expiryWarning)
                    {
                        Console.Error.WriteLine("Development offline policy expiry approaching; prepare an offline renewal, never reset custody.");
                        expiryWarning = true;
                    }
                    if (policyHorizon-observed > 86_400) expiryWarning = false;
                    var rollovers = nodes.Select((node,i) => new XPointNetworkOperationalNodeRollover(node,
                        Convert.FromHexString(keys[i].CurrentPin),Convert.FromHexString(keys[i].NextPin),
                        Convert.FromHexString(keys[i].CurrentKey),Convert.FromHexString(keys[i].NextKey),
                        physical is null ? null : [DevPhysicalIngress.Relocation(DevPhysicalIngress.RequireAddress(physical.Address), i + 1)])).ToArray();
                    // Renew installed current/announced-next slots. New private
                    // keys are never generated online or substituted into custody.
                    var next = await XPointNetworkOperationalSuccessorAuthor.AuthorDelegatedAsync(new(
                        RandomNumberGenerator.GetBytes(32),authority,[],witnesses,rollovers,
                        closure.ExactNetworkPolicyChain[^1],closure.ExactActiveNodeDescriptors,closure.ExactViewChain,
                        closure.ExactHeadChain[^1],pma,closure.ExactPlacementTopologyChain[^1],
                        XPointNetworkOperationalSuccessorAuthor.ComputeXnh1CoreHash(closure.ExactHeadChain[^1].Span),
                        SHA256.HashData(closure.ExactPlacementTopologyChain[^1].Span),adhReference,
                        observed-30,observed-30,checked(observed+operationalLifetimeSeconds-30)),stopping.Token);
                    var bundle = XPointNetworkClosureWireCodec.EncodeResponse(network,closure.ExactAuthorityChain,
                        closure.ExactTimePolicyChain,closure.ExactNetworkPolicyChain,[.. closure.ExactViewChain,next.ExactXnv1],
                        [.. closure.ExactHeadChain,next.ExactXnh1],next.ExactXnd1,[.. closure.ExactPlacementTopologyChain,next.ExactPmt2],
                        closure.ExactMailboxAuthorityChain);
                    var committed = new Journal("deep-dev-renewal.v1",Convert.ToHexStringLower(network),
                        checked((cursor?.Generation ?? 0)+1),observed,Convert.ToHexStringLower(SHA256.HashData(prior)),bundle);
                    if (physical is not null) DevPhysicalIngress.WriteResult(physicalRoot!, physical, committed, integrity);
                    WriteJournal(state,committed,integrity); // Durable before either public file.
                    cursor = committed;
                    Publish(committed,file,publicRoot);
                    Atomic("/tmp/deep-publisher-ready","ready"u8.ToArray());
                    Console.WriteLine($"Development operational view renewed (generation {committed.Generation}); offline policy retained.");
                    if (singlePublication) return;
                    await Task.Delay(TimeSpan.FromMinutes(15),stopping.Token);
                }
                catch (OperationCanceledException) when (stopping.IsCancellationRequested) { break; }
                catch (Exception error) when (error is IOException or CryptographicException or ArgumentException or FormatException or InvalidOperationException) {
                    if (physical is not null) throw; // Maintenance resumes its exact sealed result, never a new signed generation.
                    File.Delete("/tmp/deep-publisher-ready");
                    Console.Error.WriteLine($"Development operational renewal unavailable ({error.GetType().Name}). Custody and floors retained.");
                    await Task.Delay(TimeSpan.FromSeconds(error.Message == "Development offline policy renewal required." ? 60 : 10),stopping.Token);
                    if (cursor is not null) Publish(cursor,file,publicRoot);
                }
            }
            if (singlePublication) throw new TimeoutException("Short development view was not published within the acquisition bound.");
        } finally { foreach (var signer in nodes.Concat(witnesses)) signer.Dispose(); CryptographicOperations.ZeroMemory(integrity); }
    }

    private static void Publish(Journal journal,string file,string root)
    {
        var existing = Bounded(file,XPointNetworkClosureWireCodec.MaximumResponseLength);
        if (!existing.AsSpan().SequenceEqual(journal.Bundle) && Convert.ToHexStringLower(SHA256.HashData(existing)) != journal.PriorPublicHash)
            throw new CryptographicException("Publisher/public closure compare-exchange rejected.");
        if (!existing.AsSpan().SequenceEqual(journal.Bundle)) Atomic(file,journal.Bundle);
        var view = XPointNetworkClosureWireCodec.DecodeResponse(journal.Bundle).ExactViewChain[^1];
        Atomic(Path.Combine(root,"current.xnv1"),view.ToArray());
        if (!Bounded(file,XPointNetworkClosureWireCodec.MaximumResponseLength).AsSpan().SequenceEqual(journal.Bundle) ||
            !Bounded(Path.Combine(root,"current.xnv1"),65_535).AsSpan().SequenceEqual(view.Span)) throw new IOException("Published closure readback changed.");
        DevPublicArtifactMirror.Synchronize(root, journal.Bundle);
    }
    // Distribution-state adoption only. The offline candidate is authenticated
    // by retained operator integrity custody and actual root signatures; every
    // running consumer still independently acquires current proof/time.
    internal static async Task ImportPreparedAsync(string publicRoot, string operatorRoot, string preparedRoot,
        string executable, Func<string,AccountDirectoryDts1Source[],Task<ulong>> observe)
    {
        if (!OperatingSystem.IsLinux() || publicRoot != "/run/deep-public" || operatorRoot != "/run/deep-operator" ||
            preparedRoot != "/run/deep-renewal") throw new ArgumentException("Prepared import requires exact scoped development mounts.");
        const string state = "/var/lib/deep-publisher/renewal.state";
        using var lease = new FileStream(state + ".lease", FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        using var manifest = JsonDocument.Parse(Bounded(Path.Combine(publicRoot, "deep-dev.json"),16_384));
        if (manifest.RootElement.GetProperty("schema").GetString() != "deep-dev.v1" || manifest.RootElement.GetProperty("nodeCount").GetInt32() != 3)
            throw new InvalidDataException("Wrong development import scope.");
        var network = Convert.FromHexString(manifest.RootElement.GetProperty("networkIdHex").GetString()!);
        var pin = new XPointNetworkGenesisPin(network,Convert.FromHexString(manifest.RootElement.GetProperty("genesisAuthorityCoreHashHex").GetString()!));
        _ = XPointNetworkBootstrapAuthor.VerifyExistingGenesis(Bounded(Path.Combine(publicRoot,"genesis.xna1"),65_535),
            Bounded(Path.Combine(publicRoot,"genesis.dts1"),65_535),pin);
        var key = Bounded(Path.Combine(operatorRoot,"renewal-integrity.key"),32);
        try {
            if (key.Length != 32 || key.AsSpan().IndexOfAnyExcept((byte)0) < 0) throw new InvalidDataException("Retained publisher integrity key missing.");
            var current = ReadJournal(state,key,network);
            var candidate = ReadJournal(Path.Combine(preparedRoot,"renewal.state"),key,network);
            if (current.Schema == candidate.Schema && current.Network == candidate.Network && current.Generation == candidate.Generation &&
                current.Observed == candidate.Observed && current.PriorPublicHash == candidate.PriorPublicHash && current.Bundle.AsSpan().SequenceEqual(candidate.Bundle))
            {
                Publish(current,Path.Combine(publicRoot,"network.ncp2"),publicRoot);
                Console.WriteLine("Exact prepared development commit resumed; no new generation or current authority was minted.");
                return;
            }
            ValidatePreparedImport(pin,current,candidate);
            var closure = XPointNetworkClosureWireCodec.DecodeResponse(candidate.Bundle);
            var authority = XPointNetworkAuthorityVerifier.Verify(pin,closure.ExactAuthorityChain,closure.ExactTimePolicyChain);
            var observed = await observe(executable,AccountDirectoryDts1Codec.Decode(closure.ExactTimePolicyChain[^1].Span).Sources.ToArray());
            if (observed < candidate.Observed || observed < authority.NotBefore || observed >= Math.Min(authority.ExpiresAt,authority.Dts1ExpiresAt))
                throw new CryptographicException("Prepared import is outside current independently observed authority/time.");
            _ = MailboxAuthorityV2Verifier.Verify(authority,closure.ExactMailboxAuthorityChain[^1].Span,observed,checked(observed+1));
            var file = Path.Combine(publicRoot,"network.ncp2");
            Publish(current,file,publicRoot); // Finish an existing commit before compare-exchange.
            if (!Bounded(file,XPointNetworkClosureWireCodec.MaximumResponseLength).AsSpan().SequenceEqual(current.Bundle))
                throw new CryptographicException("Prepared import source compare-exchange rejected.");
            WriteJournal(state,candidate,key); // Same mutation owner, durable before publication.
            Publish(candidate,file,publicRoot);
            Console.WriteLine("Prepared development operational journal imported; independent runtime verification remains mandatory.");
        } finally { CryptographicOperations.ZeroMemory(key); }
    }

    internal static void ValidatePreparedImport(XPointNetworkGenesisPin pin, Journal current, Journal candidate)
    {
        if (current.Schema != "deep-dev-renewal.v1" || candidate.Schema != current.Schema ||
            candidate.Network != current.Network || candidate.Generation != checked(current.Generation+1) ||
            candidate.Observed < current.Observed || candidate.PriorPublicHash != Convert.ToHexStringLower(SHA256.HashData(current.Bundle)))
            throw new CryptographicException("Prepared journal is not the exact retained one-step successor.");
        var before = XPointNetworkClosureWireCodec.DecodeResponse(current.Bundle);
        var after = XPointNetworkClosureWireCodec.DecodeResponse(candidate.Bundle);
        if (before.ExactViewChain.Count != checked((int)current.Generation+1) || after.ExactViewChain.Count != checked((int)candidate.Generation+1) ||
            after.ExactActiveNodeDescriptors.Count != 3 || before.ExactActiveNodeDescriptors.Count != 3 ||
            !after.NetworkId.Span.SequenceEqual(pin.NetworkId.Span) || !before.NetworkId.Span.SequenceEqual(pin.NetworkId.Span))
            throw new CryptographicException("Prepared closure has a different genesis network.");
        var authority = XPointNetworkAuthorityVerifier.Verify(pin,after.ExactAuthorityChain,after.ExactTimePolicyChain);
        Prefix(before.ExactAuthorityChain,after.ExactAuthorityChain);
        Prefix(before.ExactTimePolicyChain,after.ExactTimePolicyChain);
        Prefix(before.ExactNetworkPolicyChain,after.ExactNetworkPolicyChain);
        Prefix(before.ExactViewChain,after.ExactViewChain);
        Prefix(before.ExactHeadChain,after.ExactHeadChain);
        Prefix(before.ExactPlacementTopologyChain,after.ExactPlacementTopologyChain);
        Prefix(before.ExactMailboxAuthorityChain,after.ExactMailboxAuthorityChain);
        var pma = MailboxAuthorityV2Verifier.Verify(authority,after.ExactMailboxAuthorityChain[^1].Span,candidate.Observed,checked(candidate.Observed+1));
        if (!pma.BindsProjection(after.ExactPlacementTopologyChain[^1].Span) ||
            pma.MinimumGrantGeneration < XPointNetworkOperationalSuccessorAuthor.ComputeNextMailboxGrantFloor(authority,before.ExactMailboxAuthorityChain[^1].Span))
            throw new CryptographicException("Prepared role policy/floor differs from its signed projection.");
        static void Prefix(IReadOnlyList<ReadOnlyMemory<byte>> prior,IReadOnlyList<ReadOnlyMemory<byte>> next) {
            if (next.Count != prior.Count+1 || prior.Where((b,i) => !b.Span.SequenceEqual(next[i].Span)).Any())
                throw new CryptographicException("Prepared import cannot truncate or rewrite retained signed history.");
        }
    }
    internal static Journal ReadJournal(string file,byte[] key,byte[] network)
    {
        var bytes = Bounded(file,100*1024*1024);
        if (bytes.Length <= 32 || !CryptographicOperations.FixedTimeEquals(bytes.AsSpan(0,32),HMACSHA256.HashData(key,bytes.AsSpan(32))))
            throw new CryptographicException("Publisher journal integrity rejected.");
        var journal = JsonSerializer.Deserialize<Journal>(bytes.AsSpan(32),Json)!;
        if (journal.Schema != "deep-dev-renewal.v1" || journal.Network != Convert.ToHexStringLower(network) || journal.Generation == 0 ||
            journal.Observed == 0 || journal.Bundle.Length > XPointNetworkClosureWireCodec.MaximumResponseLength ||
            XPointNetworkClosureWireCodec.DecodeResponse(journal.Bundle).ExactViewChain.Count != checked((int)journal.Generation+1))
            throw new InvalidDataException("Publisher journal scope rejected.");
        return journal;
    }
    private static void WriteJournal(string file,Journal journal,byte[] key)
    {
        var payload = JsonSerializer.SerializeToUtf8Bytes(journal,Json);
        var bytes = new byte[checked(payload.Length+32)];
        HMACSHA256.HashData(key,payload).CopyTo(bytes,0); payload.CopyTo(bytes,32); Atomic(file,bytes);
        _ = ReadJournal(file,key,Convert.FromHexString(journal.Network));
    }
    private static byte[] Bounded(string file,int bound)
    {
        using var f = new FileStream(file,FileMode.Open,FileAccess.Read,FileShare.Read|FileShare.Delete);
        if (f.Length is < 1 || f.Length > bound) throw new InvalidDataException("Dev custody/public input is unbounded.");
        var b = new byte[checked((int)f.Length)]; f.ReadExactly(b); if (f.ReadByte() != -1) throw new IOException("Dev input changed."); return b;
    }
    private static void Create(string file,byte[] bytes)
    { using var f = new FileStream(file,FileMode.CreateNew,FileAccess.Write,FileShare.None,4096,FileOptions.WriteThrough); f.Write(bytes); f.Flush(true); }
    private static void Atomic(string file,byte[] bytes)
    { var staging = file+".stage-"+Guid.NewGuid().ToString("N"); Create(staging,bytes); File.Move(staging,file,true); }
}
