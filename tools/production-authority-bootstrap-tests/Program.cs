using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

// Synthetic local inputs only; production custody is never opened by this gate.
var tests = new (string Name, Action Run)[]
{
    ("exact mutually exclusive modes", TestArguments),
    ("canonical bounded source inventory", TestSourceInventory),
    ("installable origin key and validity", TestOriginCertificate),
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
