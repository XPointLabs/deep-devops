using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;

internal sealed record ClientAckLossState(
    int SchemaVersion,
    string Ack,
    string AckSha256,
    string EmptyRetrieve,
    string EmptyRetrieveSha256,
    string? Mar1,
    string? Mar1Sha256);

internal static class PrivateCrossProcessState
{
    internal const string AckLossFileName = "client-ack-loss.json";
    private const int MaximumStateBytes = 2 * 1024 * 1024;
    private static readonly string[] ExactProperties =
    [
        "SchemaVersion", "Ack", "AckSha256", "EmptyRetrieve",
        "EmptyRetrieveSha256", "Mar1", "Mar1Sha256"
    ];

    internal static ClientAckLossState Create(byte[] ack, byte[] emptyRetrieve) => new(
        1,
        Convert.ToBase64String(ack),
        LowerSha256(ack),
        Convert.ToBase64String(emptyRetrieve),
        LowerSha256(emptyRetrieve),
        null,
        null);

    internal static ClientAckLossState WithMar1(ClientAckLossState state, byte[] mar1) =>
        state with { Mar1 = Convert.ToBase64String(mar1), Mar1Sha256 = LowerSha256(mar1) };

    internal static void WriteAckLossState(string directory, ClientAckLossState state)
    {
        AssertPrivateDirectory(directory);
        Validate(state);
        var path = Path.Combine(directory, AckLossFileName);
        var temporary = Path.Combine(directory, $".{AckLossFileName}.{Guid.NewGuid():N}.tmp");
        var bytes = JsonSerializer.SerializeToUtf8Bytes(state);
        Require(bytes.Length is > 0 and <= MaximumStateBytes, "Private ACK state exceeds its byte bound.");
        try
        {
            if (File.Exists(path))
                AssertPrivateFile(path);
            using (var stream = new FileStream(
                       temporary,
                       FileMode.CreateNew,
                       FileAccess.Write,
                       FileShare.None,
                       bufferSize: 4096,
                       FileOptions.WriteThrough))
            {
                stream.Write(bytes);
                stream.Flush(flushToDisk: true);
            }
            ProtectPrivateFile(temporary);
            AssertPrivateFile(temporary);
            if (OperatingSystem.IsWindows() && File.Exists(path))
                File.SetAttributes(path, File.GetAttributes(path) & ~FileAttributes.ReadOnly);
            File.Move(temporary, path, overwrite: true);
            AssertPrivateFile(path);
            var reread = ReadStable(path);
            Require(CryptographicOperations.FixedTimeEquals(
                    SHA256.HashData(bytes), SHA256.HashData(reread)),
                "Atomic private ACK state reread hash mismatch.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
            if (OperatingSystem.IsWindows() && File.Exists(path)
                && (File.GetAttributes(path) & FileAttributes.ReparsePoint) == 0)
                File.SetAttributes(path, File.GetAttributes(path) | FileAttributes.ReadOnly);
            if (File.Exists(temporary))
            {
                if (OperatingSystem.IsWindows())
                    File.SetAttributes(temporary, File.GetAttributes(temporary) & ~FileAttributes.ReadOnly);
                File.Delete(temporary);
            }
        }
    }

    internal static ClientAckLossState ReadAckLossState(string directory)
    {
        AssertPrivateDirectory(directory);
        var path = Path.Combine(directory, AckLossFileName);
        AssertPrivateFile(path);
        var bytes = ReadStable(path);
        try
        {
            using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 8
            });
            var root = document.RootElement;
            Require(root.ValueKind == JsonValueKind.Object, "Private ACK state must be one JSON object.");
            var names = root.EnumerateObject().Select(property => property.Name).ToArray();
            Require(names.Length == ExactProperties.Length
                    && names.ToHashSet(StringComparer.Ordinal).SetEquals(ExactProperties),
                "Private ACK state contains missing, duplicate, or unknown properties.");
            var state = JsonSerializer.Deserialize<ClientAckLossState>(bytes)
                ?? throw new InvalidDataException("Private ACK state is invalid.");
            Validate(state);
            return state;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    internal static void AssertPrivateDirectory(string directory)
    {
        var full = Path.GetFullPath(directory);
        Require(Directory.Exists(full) && !File.Exists(full), "Private ACK state directory is missing.");
        AssertNoReparseTraversal(full);
        if (OperatingSystem.IsWindows()) AssertWindowsAcl(full, isDirectory: true);
        else Require(File.GetUnixFileMode(full) ==
                (UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute),
            "Private ACK state directory must have exact Unix mode 0700.");
    }

    private static void AssertPrivateFile(string path)
    {
        var full = Path.GetFullPath(path);
        Require(File.Exists(full) && !Directory.Exists(full), "Private ACK state file is missing.");
        AssertNoReparseTraversal(full);
        var attributes = File.GetAttributes(full);
        Require((attributes & FileAttributes.ReparsePoint) == 0,
            "Private ACK state file cannot be a reparse point.");
        if (OperatingSystem.IsWindows())
        {
            Require((attributes & FileAttributes.ReadOnly) != 0,
                "Private ACK state file must be read-only between processes.");
            AssertWindowsAcl(full, isDirectory: false);
        }
        else
        {
            Require(File.GetUnixFileMode(full) ==
                    (UnixFileMode.UserRead | UnixFileMode.UserWrite),
                "Private ACK state file must have exact Unix mode 0600.");
        }
    }

    private static byte[] ReadStable(string path)
    {
        static byte[] ReadOnce(string value)
        {
            using var stream = new FileStream(
                value, FileMode.Open, FileAccess.Read, FileShare.Read,
                bufferSize: 4096, FileOptions.SequentialScan);
            Require(stream.Length is > 0 and <= MaximumStateBytes,
                "Private ACK state has an invalid byte length.");
            var bytes = new byte[checked((int)stream.Length)];
            stream.ReadExactly(bytes);
            Require(stream.Position == stream.Length, "Private ACK state read was incomplete.");
            return bytes;
        }
        AssertPrivateFile(path);
        var first = ReadOnce(path);
        try
        {
            AssertPrivateFile(path);
            var second = ReadOnce(path);
            try
            {
                Require(CryptographicOperations.FixedTimeEquals(
                        SHA256.HashData(first), SHA256.HashData(second)),
                    "Private ACK state changed during verified reread.");
                return first.ToArray();
            }
            finally { CryptographicOperations.ZeroMemory(second); }
        }
        finally { CryptographicOperations.ZeroMemory(first); }
    }

    private static void Validate(ClientAckLossState state)
    {
        Require(state.SchemaVersion == 1, "Private ACK state schema is unsupported.");
        ValidateFrame(state.Ack, state.AckSha256, "ACK");
        ValidateFrame(state.EmptyRetrieve, state.EmptyRetrieveSha256, "Retrieve");
        Require((state.Mar1 is null) == (state.Mar1Sha256 is null),
            "Private ACK state MAR1 fields must be both absent or both present.");
        if (state.Mar1 is not null) ValidateFrame(state.Mar1, state.Mar1Sha256!, "MAR1");
    }

    private static void ValidateFrame(string encoded, string expectedSha256, string label)
    {
        Require(encoded.Length is > 0 and <= MaximumStateBytes * 2,
            $"Private ACK state {label} is outside its text bound.");
        byte[] decoded;
        try { decoded = Convert.FromBase64String(encoded); }
        catch (FormatException error) { throw new InvalidDataException($"Private ACK state {label} is not base64.", error); }
        try
        {
            Require(decoded.Length is > 0 and <= MaximumStateBytes
                    && Convert.ToBase64String(decoded) == encoded,
                $"Private ACK state {label} is not canonical base64.");
            Require(expectedSha256.Length == 64
                    && expectedSha256.All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f')
                    && CryptographicOperations.FixedTimeEquals(
                        Convert.FromHexString(expectedSha256), SHA256.HashData(decoded)),
                $"Private ACK state {label} hash mismatch.");
        }
        finally { CryptographicOperations.ZeroMemory(decoded); }
    }

    private static string LowerSha256(byte[] value) => Convert.ToHexString(SHA256.HashData(value)).ToLowerInvariant();

    private static void ProtectPrivateFile(string path)
    {
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            return;
        }
        ProtectWindowsFile(path);
        File.SetAttributes(path, File.GetAttributes(path) | FileAttributes.ReadOnly);
    }

    [SupportedOSPlatform("windows")]
    private static void ProtectWindowsFile(string path)
    {
        var current = WindowsIdentity.GetCurrent().User
            ?? throw new InvalidDataException("Current Windows SID is unavailable.");
        var existing = new FileInfo(path).GetAccessControl(AccessControlSections.Owner);
        var owner = existing.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
        Require(owner is not null && owner.Equals(current),
            "Private ACK state file owner must be the current Windows identity.");
        var security = new FileSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        foreach (var identity in new[]
                 {
                     current,
                     new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
                     new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null)
                 })
            security.AddAccessRule(new FileSystemAccessRule(
                identity, FileSystemRights.FullControl, AccessControlType.Allow));
        new FileInfo(path).SetAccessControl(security);
    }

    [SupportedOSPlatform("windows")]
    private static void AssertWindowsAcl(string path, bool isDirectory)
    {
        var current = WindowsIdentity.GetCurrent().User
            ?? throw new InvalidDataException("Current Windows SID is unavailable.");
        var security = isDirectory
            ? (FileSystemSecurity)new DirectoryInfo(path).GetAccessControl(
                AccessControlSections.Access | AccessControlSections.Owner)
            : new FileInfo(path).GetAccessControl(
                AccessControlSections.Access | AccessControlSections.Owner);
        var owner = security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
        Require(owner is not null && owner.Equals(current)
                && security.AreAccessRulesProtected && security.AreAccessRulesCanonical,
            "Private ACK state owner/DACL is not exact and protected.");
        var allowed = new HashSet<string>(StringComparer.Ordinal)
        {
            current.Value,
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null).Value,
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null).Value
        };
        var rules = security.GetAccessRules(true, true, typeof(SecurityIdentifier))
            .Cast<FileSystemAccessRule>().ToArray();
        var expectedInheritance = isDirectory
            ? InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit
            : InheritanceFlags.None;
        Require(rules.Length == 3 && rules.All(rule =>
                !rule.IsInherited && rule.AccessControlType == AccessControlType.Allow
                && allowed.Contains(((SecurityIdentifier)rule.IdentityReference).Value)
                && rule.InheritanceFlags == expectedInheritance
                && rule.PropagationFlags == PropagationFlags.None
                && (rule.FileSystemRights & FileSystemRights.FullControl) == FileSystemRights.FullControl),
            "Private ACK state DACL contains a non-exact identity or right.");
    }

    private static void AssertNoReparseTraversal(string path)
    {
        var full = Path.GetFullPath(path);
        if ((File.Exists(full) || Directory.Exists(full))
            && (File.GetAttributes(full) & FileAttributes.ReparsePoint) != 0)
            throw new InvalidDataException("Private ACK state cannot be a reparse point.");
        for (var directory = new DirectoryInfo(Path.GetDirectoryName(full) ?? full);
             directory is not null;
             directory = directory.Parent)
            if (directory.Exists && (directory.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new InvalidDataException("Private ACK state path traverses a reparse point.");
    }

    private static void Require(bool condition, string message)
    {
        if (!condition) throw new InvalidDataException(message);
    }
}
