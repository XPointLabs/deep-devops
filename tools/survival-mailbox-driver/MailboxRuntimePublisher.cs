using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;
using Sodium;

internal static class MailboxRuntimePublisher
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    internal static void Publish(string[] values)
    {
        string Required(string name)
        {
            var index = Array.IndexOf(values, name);
            if (index < 0 || index + 1 >= values.Length || string.IsNullOrWhiteSpace(values[index + 1]))
                throw new InvalidOperationException($"publish-runtime requires {name}.");
            return values[index + 1];
        }
        if (!values.Contains("--development-only", StringComparer.Ordinal))
            throw new InvalidOperationException("Runtime publication is DEV-LOCAL-ONLY.");

        var authorityPath = SafeFile(Required("--runtime-authority-public"));
        var authorityBytes = ReadExact(authorityPath, 4 * 1024 * 1024);
        var authorityHash = Hash(authorityBytes);
        Require(authorityHash == LowerHex(Required("--expected-runtime-authority-sha256"), 32),
            "Runtime authority hash differs from its independent pin.");
        using var authorityDocument = JsonDocument.Parse(authorityBytes);
        var authority = authorityDocument.RootElement;
        Exact(authority,
            ["schemaVersion", "scope", "protocol", "networkId", "issuerPublicKey",
             "minimumGeneration", "maximumGeneration", "issuerValidFromUnixSeconds",
             "issuerValidUntilUnixSeconds", "coordinatorUrl", "replicaIds",
             "replicaSigningPublicKeys", "epochs", "selections"], "runtime authority");
        var now = checked((ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        var validUntil = authority.GetProperty("issuerValidUntilUnixSeconds").GetUInt64();
        Require(authority.GetProperty("schemaVersion").GetInt32() == 2 &&
                authority.GetProperty("scope").GetString() == "DEV-LOCAL-ONLY" &&
                authority.GetProperty("protocol").GetString() ==
                    "P10E/MCP2/MAU2/MIP1/RIP1/PRQ2" &&
                authority.GetProperty("maximumGeneration").GetUInt64() ==
                    authority.GetProperty("minimumGeneration").GetUInt64() + 1 &&
                authority.GetProperty("epochs").GetArrayLength() == 2 &&
                authority.GetProperty("selections").GetArrayLength() == 0 &&
                authority.GetProperty("epochs").EnumerateArray().All(epoch =>
                    epoch.GetProperty("replicas").GetArrayLength() == 0) &&
                authority.GetProperty("issuerValidFromUnixSeconds").GetUInt64() <= now &&
                validUntil >= now + 1800,
            "Runtime authority is not a live minimized DEV authority.");
        var issuer = LowerHex(authority.GetProperty("issuerPublicKey").GetString()!, 32);

        var pairRoot = SafeDirectory(Required("--pair-directory"));
        RequireProtectedDirectory(pairRoot);
        var pointerBytes = ReadExact(
            SafeFile(Path.Combine(pairRoot, "current-generation.json")), 32 * 1024);
        using var pointerDocument = JsonDocument.Parse(pointerBytes);
        var pointer = pointerDocument.RootElement;
        Exact(pointer, ["schemaVersion", "developmentOnly", "generation", "pairManifestSha256"],
            "pair pointer");
        var generation = LowerHex(pointer.GetProperty("generation").GetString()!, 32);
        var manifestHash = LowerHex(pointer.GetProperty("pairManifestSha256").GetString()!, 32);
        Require(pointer.GetProperty("schemaVersion").GetInt32() == 1 &&
                pointer.GetProperty("developmentOnly").GetBoolean(),
            "Pair pointer is not DEV-local schema v1.");
        var generationRoot = SafeDirectory(Path.Combine(pairRoot, "generations", generation));
        var manifestPath = SafeFile(Path.Combine(generationRoot, "pair-manifest.v1.json"));
        var manifestBytes = ReadExact(manifestPath, 128 * 1024);
        Require(Hash(manifestBytes) == manifestHash, "Pair manifest hash is invalid.");
        using var manifestDocument = JsonDocument.Parse(manifestBytes);
        var manifest = manifestDocument.RootElement;
        Exact(manifest,
            ["schemaVersion", "developmentOnly", "generation", "authoritySha256",
             "issuerPublicKey", "androidHolderPublicKey", "windowsHolderPublicKey", "files"],
            "pair manifest");
        var androidHolder = LowerHex(Required("--android-holder-public-key"), 32);
        var windowsHolder = LowerHex(Required("--windows-holder-public-key"), 32);
        Require(manifest.GetProperty("authoritySha256").GetString() == authorityHash &&
                manifest.GetProperty("schemaVersion").GetInt32() == 1 &&
                manifest.GetProperty("developmentOnly").GetBoolean() &&
                manifest.GetProperty("issuerPublicKey").GetString() == issuer &&
                manifest.GetProperty("generation").GetString() == generation &&
                manifest.GetProperty("androidHolderPublicKey").GetString() == androidHolder &&
                manifest.GetProperty("windowsHolderPublicKey").GetString() == windowsHolder,
            "Pair manifest differs from the runtime authority and holders.");
        var files = manifest.GetProperty("files");
        Exact(files, ["android", "windows"], "pair manifest files");
        var androidBundleBytes = ReadExact(
            SafeFile(Path.Combine(generationRoot, "android.mailbox-credentials.v1.json")),
            4 * 1024 * 1024);
        var windowsBundleBytes = ReadExact(
            SafeFile(Path.Combine(generationRoot, "windows.mailbox-credentials.v1.json")),
            4 * 1024 * 1024);
        var androidBundleHash = Hash(androidBundleBytes);
        var windowsBundleHash = Hash(windowsBundleBytes);
        Require(files.GetProperty("android").GetString() == androidBundleHash &&
                files.GetProperty("windows").GetString() == windowsBundleHash &&
                generation == PairGeneration(authorityHash, androidBundleHash, windowsBundleHash),
            "Pair bundles do not match the single resolved manifest and generation.");

        var ttl = int.Parse(Required("--revocation-ttl-seconds"),
            System.Globalization.CultureInfo.InvariantCulture);
        Require(ttl is >= 1800 and <= 14400, "Revocation TTL must be between 1800 and 14400 seconds.");
        var revocationExpires = Math.Min(validUntil, checked(now + (ulong)ttl));
        Require(revocationExpires >= now + 1800, "Authority cannot cover the requested revocation window.");
        var revocationBytes = Json(new
        {
            schemaVersion = 1,
            authoritySha256 = authorityHash,
            issuerPublicKey = issuer,
            generatedAtUnixSeconds = now,
            expiresAtUnixSeconds = revocationExpires,
            revoked = Array.Empty<object>()
        });
        var revocationHash = Hash(revocationBytes);

        var privateKeyPath = SafeFile(Required("--mr-x-private-key"));
        var publicKeyPath = SafeFile(Required("--mr-x-public-key"));
        RequireProtectedDirectory(Path.GetDirectoryName(privateKeyPath)!);
        RequireProtectedDirectory(Path.GetDirectoryName(publicKeyPath)!);
        RequireProtectedFile(privateKeyPath);
        RequireProtectedFile(publicKeyPath);
        var privateKey = ReadExact(privateKeyPath, 64);
        var publicKey = ReadExact(publicKeyPath, 32);
        Require(privateKey.Length == 64 && publicKey.Length == 32,
            "The lab Mr. X key pair has invalid byte lengths.");
        try
        {
            PublishPlatform("android", Required("--android-runtime-root"), authorityBytes,
                pointerBytes, manifestBytes, androidBundleBytes, windowsBundleBytes,
                generation, authorityHash, issuer, androidHolder, windowsHolder,
                SessionId(androidHolder), SessionId(windowsHolder), manifestHash,
                revocationBytes, revocationHash, privateKey, publicKey);
            PublishPlatform("windows", Required("--windows-runtime-root"), authorityBytes,
                pointerBytes, manifestBytes, androidBundleBytes, windowsBundleBytes,
                generation, authorityHash, issuer, androidHolder, windowsHolder,
                SessionId(androidHolder), SessionId(windowsHolder), manifestHash,
                revocationBytes, revocationHash, privateKey, publicKey);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(privateKey);
        }
        Console.WriteLine(JsonSerializer.Serialize(new
        {
            schemaVersion = 1,
            phase = "publish-runtime",
            passed = true,
            details = new
            {
                developmentOnly = true,
                authoritySha256 = authorityHash,
                pairGeneration = generation,
                revocationSnapshotSha256 = revocationHash,
                revocationExpiresAtUnixSeconds = revocationExpires,
                mrXPublicKeySha256 = Hash(publicKey)
            }
        }));
    }

    private static void PublishPlatform(
        string platform, string targetPath, byte[] authorityBytes, byte[] pointerBytes,
        byte[] manifestBytes, byte[] androidBundleBytes, byte[] windowsBundleBytes,
        string generation, string authorityHash, string issuer,
        string androidHolder, string windowsHolder, string androidSession, string windowsSession,
        string manifestHash, byte[] revocations, string revocationHash,
        byte[] privateKey, byte[] publicKey)
    {
        var target = Path.GetFullPath(targetPath);
        var parent = SafeDirectory(Path.GetDirectoryName(target)!);
        RequireProtectedDirectory(parent);
        RequireNoReparse(target);
        var stage = Path.Combine(parent, $".{Path.GetFileName(target)}.stage-{Guid.NewGuid():N}");
        // One fixed protected rollback slot prevents failed repetitions from
        // accumulating credential-tree copies. These roots are offline host
        // staging inputs; devices consume them only after this command exits 0.
        var backup = Path.Combine(parent, $".{Path.GetFileName(target)}.previous");
        if (Directory.Exists(backup))
        {
            if (Directory.Exists(target)) Directory.Delete(backup, true);
            else Directory.Move(backup, target);
        }
        var published = false;
        Directory.CreateDirectory(Path.Combine(stage, "pair", "generations", generation));
        try
        {
            File.WriteAllBytes(Path.Combine(stage, "authority.public.json"), authorityBytes);
            File.WriteAllBytes(Path.Combine(stage, "revocations.v1.json"), revocations);
            File.WriteAllBytes(Path.Combine(stage, "pair", "current-generation.json"), pointerBytes);
            var stagedGeneration = Path.Combine(stage, "pair", "generations", generation);
            File.WriteAllBytes(Path.Combine(stagedGeneration, "android.mailbox-credentials.v1.json"),
                androidBundleBytes);
            File.WriteAllBytes(Path.Combine(stagedGeneration, "windows.mailbox-credentials.v1.json"),
                windowsBundleBytes);
            File.WriteAllBytes(Path.Combine(stagedGeneration, "pair-manifest.v1.json"), manifestBytes);

            var payload = Json(new
            {
                schemaVersion = 1,
                developmentOnly = true,
                lane = "android-windows-pair",
                platform,
                ownership = "user-managed",
                authoritySha256 = authorityHash,
                issuerPublicKey = issuer,
                androidHolderPublicKey = androidHolder,
                windowsHolderPublicKey = windowsHolder,
                androidSessionId = androidSession,
                windowsSessionId = windowsSession,
                pairGeneration = generation,
                pairManifestSha256 = manifestHash,
                revocationSnapshotSha256 = revocationHash
            });
            var signature = PublicKeyAuth.SignDetached(payload, privateKey);
            Require(PublicKeyAuth.VerifyDetached(signature, payload, publicKey),
                "The software-held lab Mr. X key pair does not match.");
            File.WriteAllBytes(Path.Combine(stage, "mr-x-mailbox-policy.payload.json"), payload);
            File.WriteAllBytes(Path.Combine(stage, "mr-x-mailbox-policy.signature"), signature);
            File.WriteAllBytes(Path.Combine(stage, "mr-x-mailbox-policy.public-key"), publicKey);
            var peerHolder = platform == "android" ? windowsHolder : androidHolder;
            var peerSession = platform == "android" ? windowsSession : androidSession;
            File.WriteAllBytes(Path.Combine(stage, "activation.v1.json"), Json(new
            {
                schemaVersion = 1,
                developmentOnly = true,
                platform,
                authoritySha256 = authorityHash,
                issuerPublicKey = issuer,
                pairGeneration = generation,
                pairManifestSha256 = manifestHash,
                peerHolderPublicKey = peerHolder,
                peerSessionId = peerSession,
                revocationSnapshotSha256 = revocationHash
            }));
            ProtectTree(stage);
            if (Directory.Exists(target)) Directory.Move(target, backup);
            try
            {
                Directory.Move(stage, target);
                published = true;
            }
            catch
            {
                if (Directory.Exists(backup) && !Directory.Exists(target))
                    Directory.Move(backup, target);
                throw;
            }
            if (Directory.Exists(backup)) Directory.Delete(backup, true);
        }
        finally
        {
            if (Directory.Exists(stage)) Directory.Delete(stage, true);
            // A failed post-swap cleanup is retried here. If the filesystem
            // still refuses deletion the command fails and the single fixed,
            // protected rollback slot is cleaned before any later mutation.
            if (published && Directory.Exists(target) && Directory.Exists(backup))
                Directory.Delete(backup, true);
        }
    }

    private static string SessionId(string ed25519Hex)
    {
        var curve = PublicKeyAuth.ConvertEd25519PublicKeyToCurve25519PublicKey(
            Convert.FromHexString(ed25519Hex));
        try { return "05" + Convert.ToHexStringLower(curve); }
        finally { CryptographicOperations.ZeroMemory(curve); }
    }

    private static string PairGeneration(
        string authorityHash, string androidHash, string windowsHash) =>
        Hash(Encoding.UTF8.GetBytes(
            $"deep.mailbox-pair-generation.v1\n{authorityHash}\n{androidHash}\n{windowsHash}\n"));

    private static byte[] Json(object value)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(value, JsonOptions);
        return [.. bytes, (byte)'\n'];
    }

    private static string Hash(byte[] bytes) => Convert.ToHexStringLower(SHA256.HashData(bytes));
    private static string LowerHex(string value, int bytes)
    {
        Require(value.Length == bytes * 2 && value.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f') &&
                Convert.FromHexString(value).AsSpan().IndexOfAnyExcept((byte)0) >= 0,
            "A required value is not canonical nonzero lowercase hexadecimal.");
        return value;
    }

    private static byte[] ReadExact(string path, int maximum)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        Require(stream.Length is > 0 && stream.Length <= maximum, "Protected input size is invalid.");
        var bytes = new byte[stream.Length];
        stream.ReadExactly(bytes);
        return bytes;
    }

    private static string SafeFile(string path)
    {
        var full = Path.GetFullPath(path);
        RequireNoReparse(full);
        Require(File.Exists(full), $"Required file is missing: {full}");
        return full;
    }

    private static string SafeDirectory(string path)
    {
        var full = Path.GetFullPath(path);
        RequireNoReparse(full);
        Require(Directory.Exists(full), $"Required directory is missing: {full}");
        return full.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
    }

    private static void RequireNoReparse(string path)
    {
        for (var current = Path.GetFullPath(path); !string.IsNullOrEmpty(current);
             current = Path.GetDirectoryName(current) ?? "")
            if ((File.Exists(current) || Directory.Exists(current)) &&
                (File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                throw new InvalidDataException("Runtime publication path traverses a reparse point.");
    }

    private static void RequireProtectedDirectory(string path)
    {
        if (!OperatingSystem.IsWindows())
        {
            Require(File.GetUnixFileMode(path) == (UnixFileMode.UserRead | UnixFileMode.UserWrite |
                    UnixFileMode.UserExecute), "Runtime output parent must have mode 0700.");
            return;
        }
        RequireProtectedWindowsDirectory(path);
    }

    private static void RequireProtectedFile(string path)
    {
        if (!OperatingSystem.IsWindows())
        {
            Require(File.GetUnixFileMode(path) ==
                    (UnixFileMode.UserRead | UnixFileMode.UserWrite),
                "Mr. X key files must have mode 0600.");
            return;
        }
        RequireProtectedWindowsFile(path);
    }

    [SupportedOSPlatform("windows")]
    private static void RequireProtectedWindowsFile(string path)
    {
        var current = WindowsIdentity.GetCurrent().User!;
        var security = new FileInfo(path).GetAccessControl();
        var owner = security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
        var allowed = new HashSet<string>(StringComparer.Ordinal)
        {
            current.Value, "S-1-5-18", "S-1-5-32-544"
        };
        var rules = security.GetAccessRules(true, true, typeof(SecurityIdentifier))
            .Cast<FileSystemAccessRule>().ToArray();
        Require(owner is not null && owner.Equals(current) && security.AreAccessRulesCanonical &&
                rules.Length == 3 && rules.All(rule =>
                    rule.AccessControlType == AccessControlType.Allow &&
                    allowed.Contains(((SecurityIdentifier)rule.IdentityReference).Value) &&
                    (rule.FileSystemRights & FileSystemRights.FullControl) ==
                        FileSystemRights.FullControl),
            "Mr. X key files must have the exact effective owner/DACL inherited from the protected lab root.");
    }

    [SupportedOSPlatform("windows")]
    private static void RequireProtectedWindowsDirectory(string path)
    {
        var current = WindowsIdentity.GetCurrent().User!;
        var security = new DirectoryInfo(path).GetAccessControl();
        var owner = security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
        var allowed = new HashSet<string>(StringComparer.Ordinal)
        {
            current.Value, "S-1-5-18", "S-1-5-32-544"
        };
        var rules = security.GetAccessRules(true, true, typeof(SecurityIdentifier))
            .Cast<FileSystemAccessRule>().ToArray();
        Require(owner is not null && owner.Equals(current) && security.AreAccessRulesProtected &&
                security.AreAccessRulesCanonical && rules.Length == 3 && rules.All(rule =>
                rule.AccessControlType == AccessControlType.Allow &&
                allowed.Contains(((SecurityIdentifier)rule.IdentityReference).Value) &&
                (rule.FileSystemRights & FileSystemRights.FullControl) == FileSystemRights.FullControl),
            "Runtime output parent must have the exact protected Mr. X/SYSTEM/Administrators DACL.");
    }

    private static void ProtectTree(string root)
    {
        if (!OperatingSystem.IsWindows())
        {
            foreach (var directory in Directory.EnumerateDirectories(root, "*", SearchOption.AllDirectories)
                         .Prepend(root))
                File.SetUnixFileMode(directory, UnixFileMode.UserRead | UnixFileMode.UserWrite |
                    UnixFileMode.UserExecute);
            foreach (var file in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories))
                File.SetUnixFileMode(file, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            return;
        }
        ProtectWindowsTree(root);
    }

    [SupportedOSPlatform("windows")]
    private static void ProtectWindowsTree(string root)
    {
        var current = WindowsIdentity.GetCurrent().User!;
        var system = new SecurityIdentifier("S-1-5-18");
        var administrators = new SecurityIdentifier("S-1-5-32-544");
        foreach (var directory in Directory.EnumerateDirectories(root, "*", SearchOption.AllDirectories)
                     .Prepend(root))
        {
            var security = new DirectorySecurity();
            security.SetOwner(current);
            security.SetAccessRuleProtection(true, false);
            foreach (var identity in new[] { current, system, administrators })
                security.AddAccessRule(new FileSystemAccessRule(identity, FileSystemRights.FullControl,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                    PropagationFlags.None, AccessControlType.Allow));
            new DirectoryInfo(directory).SetAccessControl(security);
        }
        foreach (var file in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories))
        {
            var security = new FileSecurity();
            security.SetOwner(current);
            security.SetAccessRuleProtection(true, false);
            foreach (var identity in new[] { current, system, administrators })
                security.AddAccessRule(new FileSystemAccessRule(identity, FileSystemRights.FullControl,
                    AccessControlType.Allow));
            new FileInfo(file).SetAccessControl(security);
        }
    }

    private static void Exact(JsonElement value, string[] expected, string label)
    {
        var names = value.EnumerateObject().Select(property => property.Name).ToArray();
        Require(names.Length == expected.Length && names.ToHashSet(StringComparer.Ordinal).SetEquals(expected),
            $"{label} contains missing, duplicate, or unknown properties.");
    }

    private static void Require(bool value, string message)
    {
        if (!value) throw new InvalidDataException(message);
    }
}
