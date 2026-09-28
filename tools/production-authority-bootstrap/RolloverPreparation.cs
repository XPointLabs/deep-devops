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
            (Name: "seed1", Host: ReadHost(arguments.Required("--seed1-root"))),
            (Name: "seed2", Host: ReadHost(arguments.Required("--seed2-root"))),
            (Name: "seed3", Host: ReadHost(arguments.Required("--seed3-root"))),
        };
        if (hosts.Select(static value => value.Host).Distinct(StringComparer.OrdinalIgnoreCase).Count() != hosts.Length)
            throw new CryptographicException("The three node origins must have distinct exact hosts.");
        var validFrom = DateTimeOffset.FromUnixTimeSeconds(checked((long)observedUnix - 600));
        var validUntil = validFrom.AddDays(825);
        Directory.CreateDirectory(output);
        try
        {
            foreach (var (name, host) in hosts)
            {
                var nodeDirectory = Path.Combine(output, name);
                Directory.CreateDirectory(nodeDirectory);
                CreateKeyPair(nodeDirectory, "current", host, validFrom, validUntil);
                CreateKeyPair(nodeDirectory, "next", host, validFrom, validUntil);
            }
            Console.WriteLine("Three private node rollover bundles were prepared without changing existing node or Registry state.");
            Console.WriteLine($"Rollover directory: {output}");
        }
        catch
        {
            Console.Error.WriteLine("The incomplete private rollover directory must be reviewed before any retry; it was not removed.");
            throw;
        }
    }

    private static string ReadHost(string nodeRoot)
    {
        nodeRoot = ExistingDirectory(nodeRoot);
        var lines = File.ReadLines(ExistingFile(Path.Combine(nodeRoot, ".env.node.prod")))
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
        return host;
    }

    private static void CreateKeyPair(
        string directory, string role, string host,
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
            new X500DistinguishedName($"CN={host}"), key,
            HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature, true));
        var eku = new OidCollection { new("1.3.6.1.5.5.7.3.1") };
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(eku, true));
        var san = new SubjectAlternativeNameBuilder();
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
}
