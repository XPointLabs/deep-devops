using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using static BootstrapIo;

internal static class RolloverPreparation
{
    internal static void Run(Arguments arguments)
    {
        var authorityRoot = ExistingDirectory(arguments.Required("--authority-root"));
        var manifest = CustodyManifest.Load(Path.Combine(authorityRoot, "public", "custody-manifest.v1.json"));
        if (!string.Equals(manifest.Environment, "prod", StringComparison.Ordinal) ||
            !string.Equals(manifest.AuthorityOwner, "Mr. X", StringComparison.Ordinal))
            throw new InvalidDataException("The rollover preparation is outside Mr. X production custody.");
        var privateRoot = ExistingDirectory(Path.Combine(authorityRoot, "private"));
        var observedUnix = arguments.RequiredU64("--observed-unix");
        if (observedUnix <= 600)
            throw new ArgumentOutOfRangeException(nameof(observedUnix));
        var output = NewDirectoryPath(Path.Combine(privateRoot, $"rollover-{observedUnix}"));
        var hosts = new[]
        {
            (Name: "seed1", Origins: ReadOrigins(arguments.Required("--seed1-root"))),
            (Name: "seed2", Origins: ReadOrigins(arguments.Required("--seed2-root"))),
            (Name: "seed3", Origins: ReadOrigins(arguments.Required("--seed3-root"))),
        };
        if (hosts.Select(static value => value.Origins[0]).Distinct(StringComparer.OrdinalIgnoreCase).Count() != hosts.Length)
            throw new CryptographicException("The three node origins must have distinct exact hosts.");
        var validFrom = DateTimeOffset.FromUnixTimeSeconds(checked((long)observedUnix - 600));
        var validUntil = validFrom.AddDays(825);
        Directory.CreateDirectory(output);
        try
        {
            foreach (var (name, origins) in hosts)
            {
                var nodeDirectory = Path.Combine(output, name);
                Directory.CreateDirectory(nodeDirectory);
                CreateKeyPair(nodeDirectory, "current", origins, validFrom, validUntil);
                CreateKeyPair(nodeDirectory, "next", origins, validFrom, validUntil);
            }
            Console.WriteLine("Three private node rollover bundles were prepared without changing existing node or Registry state.");
        }
        catch
        {
            Console.Error.WriteLine("The incomplete private rollover directory must be reviewed before any retry; it was not removed.");
            throw;
        }
    }

    internal static string[] ReadOrigins(string nodeRoot)
    {
        nodeRoot = ExistingDirectory(nodeRoot);
        AssertNoRedirects(nodeRoot);
        var environmentPath = ExistingFile(Path.Combine(nodeRoot, ".env.node.prod"));
        AssertNoRedirects(environmentPath);
        if (new FileInfo(environmentPath).Length > 65536)
            throw new InvalidDataException("The node origin configuration exceeds its closed bound.");
        var allLines = File.ReadAllLines(environmentPath);
        var lines = allLines
            .Where(static value => value.StartsWith("DEEP_NODE_PUBLIC_HOST=", StringComparison.Ordinal))
            .ToArray();
        if (lines.Length != 1)
            throw new InvalidDataException("A production node host binding is missing or duplicated.");
        var host = lines[0]["DEEP_NODE_PUBLIC_HOST=".Length..];
        var isIpv4 = IPAddress.TryParse(host, out var parsedAddress) &&
                     parsedAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork;
        var isDns = Regex.IsMatch(host,
            @"\A(?=.{1,253}\z)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\z",
            RegexOptions.CultureInvariant);
        if (!isIpv4 && !isDns)
            throw new InvalidDataException("A production node host binding is invalid.");
        var ipLines = allLines.Where(static value =>
            value.StartsWith("DEEP_NODE_PUBLIC_IP=", StringComparison.Ordinal)).ToArray();
        if (ipLines.Length != 1 || !IPAddress.TryParse(ipLines[0]["DEEP_NODE_PUBLIC_IP=".Length..], out var ip) ||
            ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork ||
            ip.ToString() != ipLines[0]["DEEP_NODE_PUBLIC_IP=".Length..])
            throw new InvalidDataException("The exact node IPv4 origin is missing or duplicated.");
        return new[] { ip.ToString(), host }.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
    }

    private static void CreateKeyPair(
        string directory, string role, string[] origins,
        DateTimeOffset validFrom, DateTimeOffset validUntil)
    {
        var onionSeed = RandomNumberGenerator.GetBytes(32);
        try
        {
            WriteNew(Path.Combine(directory, $"{role}.x25519.seed"), onionSeed);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(onionSeed);
        }

        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest(
            new X500DistinguishedName($"CN={origins[0]}"), key,
            HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature, true));
        var eku = new OidCollection { new("1.3.6.1.5.5.7.3.1") };
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(eku, true));
        var san = new SubjectAlternativeNameBuilder();
        foreach (var host in origins)
            if (IPAddress.TryParse(host, out var address)) san.AddIpAddress(address);
            else san.AddDnsName(host);
        request.CertificateExtensions.Add(san.Build());
        using var certificate = request.CreateSelfSigned(validFrom, validUntil);
        var certificatePem = certificate.ExportCertificatePem();
        var privateKeyPem = key.ExportPkcs8PrivateKeyPem();
        var pin = Convert.ToHexString(SHA256.HashData(key.ExportSubjectPublicKeyInfo())).ToLowerInvariant();
        WriteNew(Path.Combine(directory, $"{role}-origin.cer"), Encoding.ASCII.GetBytes(certificatePem));
        WriteNew(Path.Combine(directory, $"{role}-origin.key"), Encoding.ASCII.GetBytes(privateKeyPem));
        WriteNew(Path.Combine(directory, $"{role}-origin.spki-sha256"), Encoding.ASCII.GetBytes(pin + "\n"));
    }

    internal static byte[] ReissueCertificate(string path, string[] origins)
    {
        using var original = X509Certificate2.CreateFromPemFile(
            BoundedFile(path), BoundedFile(Path.ChangeExtension(path, ".key")));
        using var key = original.GetECDsaPrivateKey()
            ?? throw new CryptographicException("Only an existing matching ECDSA origin key may be reissued.");
        var request = new CertificateRequest(original.SubjectName, key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            new OidCollection { new("1.3.6.1.5.5.7.3.1") }, true));
        var san = new SubjectAlternativeNameBuilder();
        foreach (var host in origins)
            if (IPAddress.TryParse(host, out var address)) san.AddIpAddress(address);
            else san.AddDnsName(host);
        request.CertificateExtensions.Add(san.Build());
        // Repair SAN only; neither key/SPKI nor the validity interval advances.
        using var repaired = request.CreateSelfSigned(
            new DateTimeOffset(original.NotBefore.ToUniversalTime()),
            new DateTimeOffset(original.NotAfter.ToUniversalTime()));
        using var publicKey = repaired.GetECDsaPublicKey()!;
        if (!publicKey.ExportSubjectPublicKeyInfo().AsSpan().SequenceEqual(key.ExportSubjectPublicKeyInfo()) ||
            origins.Any(host => !repaired.MatchesHostname(host, allowWildcards: false, allowCommonName: false)))
            throw new CryptographicException("The repaired certificate changed its key or exact origin binding.");
        return Encoding.ASCII.GetBytes(repaired.ExportCertificatePem());
    }

    internal static void ReissueCertificates(Arguments arguments)
    {
        var authorityRoot = ExistingDirectory(arguments.Required("--authority-root"));
        var manifest = CustodyManifest.Load(Path.Combine(authorityRoot, "public", "custody-manifest.v1.json"));
        if (manifest.Environment != "prod" || manifest.AuthorityOwner != "Mr. X")
            throw new InvalidDataException("Certificate reissue is outside approved operator custody.");
        var privateRoot = ExistingDirectory(Path.Combine(authorityRoot, "private"));
        var source = ExistingDirectory(arguments.Required("--rollover-root"));
        var output = NewDirectoryPath(arguments.Required("--output"));
        AssertNoRedirects(source);
        AssertNoRedirects(Path.GetDirectoryName(output)!);
        var prefix = privateRoot + Path.DirectorySeparatorChar;
        var comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        if (!source.StartsWith(prefix, comparison) ||
            !output.StartsWith(prefix, comparison) ||
            output.StartsWith(source + Path.DirectorySeparatorChar, comparison))
            throw new InvalidDataException("Certificate reissue must create a separate private custody version.");
        var nodes = new[] { "seed1", "seed2", "seed3" }.Select(name =>
            (Name: name, Origins: ReadOrigins(arguments.Required("--" + name + "-root")))).ToArray();
        if (nodes.Select(static node => node.Origins[0]).Distinct(StringComparer.Ordinal).Count() != nodes.Length)
            throw new InvalidDataException("The three exact node origins must be distinct.");
        var copies = new List<(string Name, byte[] Bytes)>();
        try
        {
            foreach (var (name, origins) in nodes)
            {
                var node = ExistingDirectory(Path.Combine(source, name));
                foreach (var role in new[] { "current", "next" })
                {
                    var certificatePath = Path.Combine(node, role + "-origin.cer");
                    var pin = ReadBounded(Path.Combine(node, role + "-origin.spki-sha256"));
                    using var old = X509Certificate2.CreateFromPem(File.ReadAllText(BoundedFile(certificatePath)));
                    using var key = old.GetECDsaPublicKey() ?? throw new CryptographicException("Unsupported origin key.");
                    if (Encoding.ASCII.GetString(pin).Trim() !=
                        Convert.ToHexString(SHA256.HashData(key.ExportSubjectPublicKeyInfo())).ToLowerInvariant())
                        throw new CryptographicException("The retained protected SPKI pin does not match.");
                    copies.Add((Path.Combine(name, role + "-origin.spki-sha256"), pin));
                    copies.Add((Path.Combine(name, role + "-origin.cer"), ReissueCertificate(certificatePath, origins)));
                    copies.Add((Path.Combine(name, role + "-origin.key"), ReadBounded(Path.Combine(node, role + "-origin.key"))));
                    var seed = ReadBounded(Path.Combine(node, role + ".x25519.seed"));
                    if (seed.Length != 32 || seed.All(static b => b == 0))
                    {
                        CryptographicOperations.ZeroMemory(seed);
                        throw new InvalidDataException("The retained onion seed is invalid.");
                    }
                    copies.Add((Path.Combine(name, role + ".x25519.seed"), seed));
                }
            }
            Directory.CreateDirectory(output);
            if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(output, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            foreach (var (name, _) in nodes)
            {
                var directory = Path.Combine(output, name);
                Directory.CreateDirectory(directory);
                if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            }
            foreach (var (name, bytes) in copies)
            {
                var path = Path.Combine(output, name);
                WriteNew(path, bytes);
                if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }
            Console.WriteLine("Six exact-origin certificates reissued; keys, pins and validity retained; no deployment performed.");
        }
        finally { foreach (var (_, bytes) in copies) CryptographicOperations.ZeroMemory(bytes); }
    }

    private static byte[] ReadBounded(string path)
    {
        path = BoundedFile(path);
        var bytes = File.ReadAllBytes(path);
        if (bytes.Length is < 1 or > 16384)
        {
            CryptographicOperations.ZeroMemory(bytes);
            throw new InvalidDataException("A certificate custody input changed.");
        }
        return bytes;
    }

    private static string BoundedFile(string path)
    {
        path = ExistingFile(path);
        AssertNoRedirects(path);
        if (new FileInfo(path).Length is < 1 or > 16384)
            throw new InvalidDataException("A certificate custody input exceeds its closed bound.");
        return path;
    }

    private static void AssertNoRedirects(string path)
    {
        for (var current = Path.GetFullPath(path); current is not null; current = Path.GetDirectoryName(current))
            if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                throw new InvalidDataException("A custody path contains a redirected component.");
    }
}
