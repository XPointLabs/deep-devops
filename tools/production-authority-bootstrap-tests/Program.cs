using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

// Synthetic local inputs only; production custody is never opened by this gate.
var tests = new (string Name, Action Run)[]
{
    ("exact mutually exclusive modes", TestArguments),
    ("canonical bounded source inventory", TestSourceInventory),
    ("installable origin key and validity", TestOriginCertificate),
    ("origin SAN repair retains exact keys and validity", TestOriginCertificateReissue),
    ("real operator signers author genesis and successor", OfflineAuthoringTests.Run),
};
foreach (var (name, run) in tests)
{
    run();
    Console.WriteLine($"PASS {name}");
}

static void TestArguments()
{
    var preparation = new[] { "--prepare-rollover", "true", "--authority-root", "synthetic",
        "--seed1-root", "synthetic", "--seed2-root", "synthetic", "--seed3-root", "synthetic",
        "--observed-unix", "1000" };
    if (!Arguments.Parse(preparation).IsRolloverPreparation)
        throw new Exception("Preparation mode was not selected.");
    Reject<ArgumentException>(() => Arguments.Parse([.. preparation, "--successor-from", "synthetic"]));
    Reject<ArgumentException>(() => Arguments.Parse([.. preparation, "--output", "synthetic"]));
    Reject<ArgumentException>(() => Arguments.Parse([.. preparation, "--authority-root", "duplicate"]));
    Reject<ArgumentException>(() => Arguments.Parse(["--previous-bootstrap-root", "retired"]));
    Reject<ArgumentException>(() => Arguments.Parse(["--successor-from", "incomplete"]));
    var invalid = preparation.ToArray();
    invalid[1] = "false";
    Reject<ArgumentException>(() => Arguments.Parse(invalid));
    var reissue = new[] { "--reissue-rollover-certificates", "true", "--authority-root", "synthetic",
        "--seed1-root", "synthetic", "--seed2-root", "synthetic", "--seed3-root", "synthetic",
        "--rollover-root", "synthetic", "--output", "synthetic" };
    if (!Arguments.Parse(reissue).IsRolloverCertificateReissue) throw new Exception("Explicit reissue mode was not selected.");
    Reject<ArgumentException>(() => Arguments.Parse([.. reissue, "--prepare-rollover", "true"]));
    Reject<ArgumentException>(() => Arguments.Parse([.. reissue, "--successor-from", "synthetic"]));
    Reject<ArgumentException>(() => Arguments.Parse([.. reissue, "--observed-unix", "1000"]));
    var nonExplicit = reissue.ToArray(); nonExplicit[1] = "false";
    Reject<ArgumentException>(() => Arguments.Parse(nonExplicit));
    var audit = new[] { "--audit-genesis-source", "synthetic",
        "--network-id-hex", "synthetic", "--genesis-core-hash", "synthetic",
        "--expected-xnv1-artifact-hash", "synthetic", "--requested-did2-path", "synthetic", "--output", "synthetic" };
    var selectedAudit = Arguments.Parse(audit);
    if (!selectedAudit.IsCheckpointAudit || selectedAudit.IsSuccessor || selectedAudit.IsRolloverPreparation)
        throw new Exception("Audit mode was not exclusively selected.");
    Reject<ArgumentException>(() => Arguments.Parse([.. audit, "--prepare-rollover", "true"]));
    Reject<ArgumentException>(() => Arguments.Parse([.. audit, "--successor-from", "synthetic"]));
    Reject<ArgumentException>(() => Arguments.Parse([.. audit, "--authority-root", "synthetic"]));
    Reject<ArgumentException>(() => Arguments.Parse(audit[..^2]));
    var network = new[] { "--export-network-genesis", "synthetic",
        "--network-id-hex", "synthetic", "--genesis-core-hash", "synthetic", "--output", "synthetic" };
    if (!Arguments.Parse(network).IsNetworkClosureExport || Arguments.Parse(network).IsNetworkClosureExtension)
        throw new Exception("Public network genesis export mode was not exclusively selected.");
    Reject<ArgumentException>(() => Arguments.Parse([.. network, "--authority-root", "synthetic"]));
    Reject<ArgumentException>(() => Arguments.Parse([.. network, "--successor-from", "synthetic"]));
    Reject<ArgumentException>(() => Arguments.Parse([.. network, "--extend-network-closure", "synthetic"]));
    Reject<ArgumentException>(() => Arguments.Parse(network[..^2]));
    var extension = new[] { "--extend-network-closure", "synthetic", "--network-successor-source", "synthetic",
        "--network-id-hex", "synthetic", "--genesis-core-hash", "synthetic", "--output", "synthetic" };
    if (!Arguments.Parse(extension).IsNetworkClosureExport || !Arguments.Parse(extension).IsNetworkClosureExtension)
        throw new Exception("Public network successor export mode was not selected.");
    Reject<ArgumentException>(() => Arguments.Parse([.. extension, "--prepare-rollover", "true"]));
    Reject<ArgumentException>(() => Arguments.Parse([.. extension, "--audit-genesis-source", "synthetic"]));
    Reject<ArgumentException>(() => Arguments.Parse(extension[..^2]));
    var assets = new[] { "--export-xnode-did2-assets", "synthetic",
        "--network-id-hex", "synthetic", "--genesis-core-hash", "synthetic",
        "--expected-bundle-sha256", "synthetic", "--genesis-head-path", "synthetic",
        "--genesis-head-core-hash", "synthetic", "--observer-contact-file", "synthetic",
        "--registry-origin", "synthetic", "--output", "synthetic" };
    if (!Arguments.Parse(assets).IsXNodeDid2AssetsExport || Arguments.Parse(assets).IsNetworkClosureExport)
        throw new Exception("Public DID2 host export mode was not exclusively selected.");
    Reject<ArgumentException>(() => Arguments.Parse([.. assets, "--prepare-rollover", "true"]));
    Reject<ArgumentException>(() => Arguments.Parse([.. assets, "--extend-network-closure", "synthetic"]));
    Reject<ArgumentException>(() => Arguments.Parse([.. assets, "--authority-root", "synthetic"]));
    Reject<ArgumentException>(() => Arguments.Parse(assets[..^2]));
}

static void TestSourceInventory()
{
    WithScratch(root =>
    {
        Directory.CreateDirectory(Path.Combine(root, "bootstrap"));
        var bytes = new byte[] { 1, 2, 3 };
        File.WriteAllBytes(Path.Combine(root, "bootstrap", "xna1.0000.bin"), bytes);
        var entry = new ArtifactEntry("xna1", 0, "xna1.0000.bin", bytes.Length,
            Convert.ToHexString(SHA256.HashData(bytes)));
        void Manifest(params ArtifactEntry[] entries) => File.WriteAllBytes(
            Path.Combine(root, "public-manifest.v1.json"),
            JsonSerializer.SerializeToUtf8Bytes(new PublicBootstrapManifest(
                "deep-production-authority-bootstrap.v1", "Mr. X", "synthetic", "synthetic",
                "synthetic", 1, 2, entries.ToList())));
        Manifest(entry);
        if (!SuccessorCeremony.ReadSource(root).One("xna1").AsSpan().SequenceEqual(bytes))
            throw new Exception("The exact source was changed.");
        Reject<InvalidDataException>(() => SuccessorCeremony.ReadSource(root).One("pmt2"));
        Manifest(entry with { Role = "../outside", FileName = "../outside.0000.bin" });
        Reject<InvalidDataException>(() => SuccessorCeremony.ReadSource(root));
        Manifest(entry with { FileName = "../xna1.0000.bin" });
        Reject<InvalidDataException>(() => SuccessorCeremony.ReadSource(root));
        Manifest(entry, entry);
        Reject<InvalidDataException>(() => SuccessorCeremony.ReadSource(root));
        Manifest(entry with { Length = 1_048_577 });
        Reject<InvalidDataException>(() => SuccessorCeremony.ReadSource(root));
        Manifest(entry with { Sha256Hex = new string('0', 64) });
        Reject<CryptographicException>(() => SuccessorCeremony.ReadSource(root));
        Manifest(entry with { Length = 2 });
        Reject<CryptographicException>(() => SuccessorCeremony.ReadSource(root));
        Manifest(entry with { Ordinal = 1, FileName = "xna1.0001.bin" });
        File.WriteAllBytes(Path.Combine(root, "bootstrap", "xna1.0001.bin"), bytes);
        Reject<InvalidDataException>(() => SuccessorCeremony.ReadSource(root).Many("xna1"));
    });
}

static void TestOriginCertificate()
{
    WithScratch(root =>
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=synthetic.invalid", key, HashAlgorithmName.SHA256);
        var observed = DateTimeOffset.UtcNow;
        using var certificate = request.CreateSelfSigned(observed.AddMinutes(-10), observed.AddDays(2));
        var certPath = Path.Combine(root, "current-origin.cer");
        var keyPath = Path.Combine(root, "current-origin.key");
        File.WriteAllText(certPath, certificate.ExportCertificatePem());
        File.WriteAllText(keyPath, key.ExportPkcs8PrivateKeyPem());
        var start = checked((ulong)observed.AddMinutes(-1).ToUnixTimeSeconds());
        var end = checked((ulong)observed.AddDays(1).ToUnixTimeSeconds());
        var expected = SHA256.HashData(key.ExportSubjectPublicKeyInfo());
        if (!SuccessorCeremony.VerifyOriginCertificate(certPath, start, end).AsSpan().SequenceEqual(expected))
            throw new Exception("The origin SPKI pin changed.");
        Reject<CryptographicException>(() => SuccessorCeremony.VerifyOriginCertificate(certPath, start, end + 172_800));
        Reject<CryptographicException>(() => SuccessorCeremony.VerifyOriginCertificate(certPath, start - 86_400, end));
        using var wrongKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        File.WriteAllText(keyPath, wrongKey.ExportPkcs8PrivateKeyPem());
        Reject<ArgumentException>(() => SuccessorCeremony.VerifyOriginCertificate(certPath, start, end));
    });
}

static void TestOriginCertificateReissue()
{
    WithScratch(root =>
    {
        File.WriteAllText(Path.Combine(root, ".env.node.prod"),
            "DEEP_NODE_PUBLIC_HOST=node.example\nDEEP_NODE_PUBLIC_IP=8.8.8.1\n");
        var origins = RolloverPreparation.ReadOrigins(root);
        if (!origins.SequenceEqual(new[] { "8.8.8.1", "node.example" })) throw new Exception("Exact origins changed.");
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=node.example", key, HashAlgorithmName.SHA256);
        var oldSan = new SubjectAlternativeNameBuilder(); oldSan.AddDnsName("node.example");
        request.CertificateExtensions.Add(oldSan.Build());
        var now = DateTimeOffset.UtcNow;
        using var old = request.CreateSelfSigned(now.AddMinutes(-10), now.AddDays(20));
        var certificatePath = Path.Combine(root, "current-origin.cer");
        var keyPath = Path.Combine(root, "current-origin.key");
        File.WriteAllText(certificatePath, old.ExportCertificatePem());
        File.WriteAllText(keyPath, key.ExportPkcs8PrivateKeyPem());
        var originalBytes = File.ReadAllBytes(certificatePath);
        var originalKey = File.ReadAllBytes(keyPath);
        if (old.MatchesHostname(origins[0], false, false)) throw new Exception("Negative IP-SAN fixture was not negative.");
        var repairedBytes = RolloverPreparation.ReissueCertificate(certificatePath, origins);
        using var repaired = X509Certificate2.CreateFromPem(System.Text.Encoding.ASCII.GetString(repairedBytes));
        using var repairedKey = repaired.GetECDsaPublicKey()!;
        if (origins.Any(host => !repaired.MatchesHostname(host, false, false)) ||
            !repairedKey.ExportSubjectPublicKeyInfo().AsSpan().SequenceEqual(key.ExportSubjectPublicKeyInfo()) ||
            old.NotBefore != repaired.NotBefore || old.NotAfter != repaired.NotAfter ||
            !File.ReadAllBytes(certificatePath).AsSpan().SequenceEqual(originalBytes) ||
            !File.ReadAllBytes(keyPath).AsSpan().SequenceEqual(originalKey))
            throw new Exception("SAN repair changed custody/key/time or failed exact host checks.");
        var authority = Path.Combine(root, "authority");
        Directory.CreateDirectory(Path.Combine(authority, "public"));
        var source = Path.Combine(authority, "private", "source");
        Directory.CreateDirectory(source);
        File.WriteAllText(Path.Combine(authority, "public", "custody-manifest.v1.json"),
            "{\"Schema\":\"fixture\",\"Environment\":\"prod\",\"AuthorityOwner\":\"Mr. X\",\"NetworkIdHex\":\"\",\"Roles\":[]}");
        var reissueArguments = new List<string> { "--reissue-rollover-certificates", "true", "--authority-root", authority,
            "--rollover-root", source, "--output", Path.Combine(authority, "private", "repaired") };
        for (var index = 1; index <= 3; index++)
        {
            var name = "seed" + index;
            var nodeRoot = Path.Combine(root, name);
            Directory.CreateDirectory(nodeRoot);
            File.WriteAllText(Path.Combine(nodeRoot, ".env.node.prod"),
                "DEEP_NODE_PUBLIC_HOST=node.example\nDEEP_NODE_PUBLIC_IP=8.8.8." + index + "\n");
            reissueArguments.AddRange(["--" + name + "-root", nodeRoot]);
            var custody = Path.Combine(source, name);
            Directory.CreateDirectory(custody);
            foreach (var role in new[] { "current", "next" })
            {
                File.WriteAllBytes(Path.Combine(custody, role + "-origin.cer"), originalBytes);
                File.WriteAllBytes(Path.Combine(custody, role + "-origin.key"), originalKey);
                File.WriteAllText(Path.Combine(custody, role + "-origin.spki-sha256"),
                    Convert.ToHexString(SHA256.HashData(key.ExportSubjectPublicKeyInfo())).ToLowerInvariant() + "\n");
                File.WriteAllBytes(Path.Combine(custody, role + ".x25519.seed"), RandomNumberGenerator.GetBytes(32));
            }
        }
        var parsedArguments = Arguments.Parse(reissueArguments.ToArray());
        RolloverPreparation.ReissueCertificates(parsedArguments);
        foreach (var originalFile in Directory.GetFiles(source, "*", SearchOption.AllDirectories))
        {
            var relative = Path.GetRelativePath(source, originalFile);
            var outputFile = Path.Combine(authority, "private", "repaired", relative);
            if (!relative.EndsWith(".cer", StringComparison.Ordinal) &&
                !File.ReadAllBytes(originalFile).AsSpan().SequenceEqual(File.ReadAllBytes(outputFile)))
                throw new Exception("Full reissue changed retained private material or pins.");
            if (relative.EndsWith(".cer", StringComparison.Ordinal))
            {
                using var actual = X509Certificate2.CreateFromPem(File.ReadAllText(outputFile));
                var nodeNumber = relative[4].ToString();
                if (!actual.MatchesHostname("8.8.8." + nodeNumber, false, false) ||
                    actual.NotBefore != old.NotBefore || actual.NotAfter != old.NotAfter)
                    throw new Exception("Full reissue did not retain time and repair the exact origin.");
            }
        }
        Reject<IOException>(() => RolloverPreparation.ReissueCertificates(parsedArguments));
        using var wrong = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        File.WriteAllText(keyPath, wrong.ExportPkcs8PrivateKeyPem());
        Reject<ArgumentException>(() => RolloverPreparation.ReissueCertificate(certificatePath, origins));
        File.AppendAllText(Path.Combine(root, ".env.node.prod"), "DEEP_NODE_PUBLIC_IP=8.8.8.2\n");
        Reject<InvalidDataException>(() => RolloverPreparation.ReadOrigins(root));
    });
}

static void Reject<T>(Action action) where T : Exception
{
    try { action(); }
    catch (T) { return; }
    throw new Exception($"Expected {typeof(T).Name} rejection.");
}

static void WithScratch(Action<string> action)
{
    var root = Path.Combine(Path.GetTempPath(), "deep-bootstrap-test-" + Guid.NewGuid().ToString("N"));
    Directory.CreateDirectory(root);
    try { action(root); }
    finally { Directory.Delete(root, recursive: true); }
}
