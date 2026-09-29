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
        uint operationalLifetimeSeconds = 3_600, bool singlePublication = false)
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
        var bootstrap = XPointNetworkBootstrapAuthor.VerifyExistingGenesis(Bounded(Path.Combine(publicRoot,"genesis.xna1"),65_535),
            Bounded(Path.Combine(publicRoot,"genesis.dts1"),65_535),pin);
        var sources = AccountDirectoryDts1Codec.Decode(bootstrap.ExactDts1.Span).Sources.ToArray();
        var pma = Bounded(Path.Combine(publicRoot,"pma2.bin"),65_535);
        var head = Bounded(Path.Combine(publicRoot,"genesis.adh1"),4096);
        var adhReference = new byte[38]; "ADH1"u8.CopyTo(adhReference); BinaryPrimitives.WriteUInt16BigEndian(adhReference.AsSpan(4),1);
        XPointNetworkOperationalSuccessorAuthor.ComputeAdh1CoreHash(head).CopyTo(adhReference,6);
        var keys = JsonSerializer.Deserialize<NodeKeys[]>(Bounded(Path.Combine(operatorRoot,"renewal-nodes.json"),16_384),Json)!;
        if (keys.Length != 3) throw new InvalidDataException("Wrong dev node custody count.");
        var integrity = Bounded(Path.Combine(operatorRoot,"renewal-integrity.key"),32);
        if (integrity.Length != 32 || integrity.AsSpan().IndexOfAnyExcept((byte)0) < 0) throw new InvalidDataException("Wrong renewal integrity key.");
        var witnesses = Enumerable.Range(1,3).Select(i => Signer.Load(Path.Combine(operatorRoot,$"witness-{i}.seed"))).ToArray();
        var nodes = Enumerable.Range(1,3).Select(i => Signer.Load(Path.Combine(operatorRoot,$"node-{i}.seed"),true)).ToArray();
        using var stopping = new CancellationTokenSource();
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
            while (!stopping.IsCancellationRequested) {
                try {
                    var prior = cursor?.Bundle ?? Bounded(file,XPointNetworkClosureWireCodec.MaximumResponseLength);
                    var closure = XPointNetworkClosureWireCodec.DecodeResponse(prior);
                    if (cursor is null && closure.ExactViewChain.Count != 1) throw new InvalidDataException("Missing publisher state cannot become genesis.");
                    if (!closure.NetworkId.Span.SequenceEqual(network) || closure.ExactNetworkPolicyChain.Count != 1 ||
                        closure.ExactViewChain.Count >= XPointNetworkClosureWireCodec.MaximumChainCount)
                        throw new InvalidDataException("Development delegation/history scope is exhausted.");
                    var observed = await observe(executable,sources);
                    if (cursor is not null && observed < cursor.Observed) throw new CryptographicException("Renewal clock regressed.");
                    var rollovers = nodes.Select((node,i) => new XPointNetworkOperationalNodeRollover(node,
                        Convert.FromHexString(keys[i].CurrentPin),Convert.FromHexString(keys[i].NextPin),
                        Convert.FromHexString(keys[i].CurrentKey),Convert.FromHexString(keys[i].NextKey))).ToArray();
                    // Renew installed current/announced-next slots. New private
                    // keys are never generated online or substituted into custody.
                    var next = await XPointNetworkOperationalSuccessorAuthor.AuthorDelegatedAsync(new(
                        RandomNumberGenerator.GetBytes(32),bootstrap,[],witnesses,rollovers,
                        closure.ExactNetworkPolicyChain[^1],closure.ExactActiveNodeDescriptors,closure.ExactViewChain,
                        closure.ExactHeadChain[^1],pma,closure.ExactPlacementTopologyChain[^1],
                        XPointNetworkOperationalSuccessorAuthor.ComputeXnh1CoreHash(closure.ExactHeadChain[^1].Span),
                        SHA256.HashData(closure.ExactPlacementTopologyChain[^1].Span),adhReference,
                        observed-30,observed-30,checked(observed+operationalLifetimeSeconds-30)),stopping.Token);
                    var bundle = XPointNetworkClosureWireCodec.EncodeResponse(network,closure.ExactAuthorityChain,
                        closure.ExactTimePolicyChain,closure.ExactNetworkPolicyChain,[.. closure.ExactViewChain,next.ExactXnv1],
                        [.. closure.ExactHeadChain,next.ExactXnh1],next.ExactXnd1,[.. closure.ExactPlacementTopologyChain,next.ExactPmt2]);
                    var committed = new Journal("deep-dev-renewal.v1",Convert.ToHexStringLower(network),
                        checked((cursor?.Generation ?? 0)+1),observed,Convert.ToHexStringLower(SHA256.HashData(prior)),bundle);
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
                    File.Delete("/tmp/deep-publisher-ready");
                    Console.Error.WriteLine($"Development operational renewal unavailable ({error.GetType().Name}). Custody and floors retained.");
                    await Task.Delay(TimeSpan.FromSeconds(10),stopping.Token);
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
    }
    private static Journal ReadJournal(string file,byte[] key,byte[] network)
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
