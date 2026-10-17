using System.Reflection;
using System.Runtime.Loader;
using System.Security.Cryptography;

// Native Linux filesystem contracts against the ACTUAL built publisher DLL.
// Only a read-only public fixture is mounted; all writes are disposable tmpfs.
if (!OperatingSystem.IsLinux() || args.Length != 0) return 2;
const string source = "/run/deep-public";
const string target = "/run/deep-public-native";
var passed = 0;
try
{
    AssemblyLoadContext.Default.Resolving += (_, name) =>
    {
        var file = Path.Combine("/app", name.Name + ".dll");
        return File.Exists(file) ? AssemblyLoadContext.Default.LoadFromAssemblyPath(file) : null;
    };
    var component = AssemblyLoadContext.Default.LoadFromAssemblyPath("/app/Deep.Dev.dll");
    var type = component.GetType("DevPublicArtifactMirror", throwOnError: true)!;
    var method = type.GetMethod("Synchronize", BindingFlags.Static | BindingFlags.NonPublic)!;
    foreach (var name in new[] { "genesis.adh1", "observer.did2", "dev-ca.crt", "network.ncp2", "dev-ca.crl" })
    {
        var input = Path.Combine("/fixture/public", name);
        if (File.Exists(input)) File.WriteAllBytes(Path.Combine(source, name), File.ReadAllBytes(input));
    }
    var bundle = File.ReadAllBytes(Path.Combine(source, "network.ncp2"));
    void Sync(byte[]? bytes = null)
    {
        try { method.Invoke(null, [source, bytes ?? bundle]); }
        catch (TargetInvocationException error) { System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(error.InnerException!).Throw(); }
    }
    void Require(bool condition) { if (!condition) throw new InvalidOperationException("Public-output contract failed."); }
    void Reject<T>(Action action) where T : Exception
    { try { action(); } catch (T) { passed++; return; } throw new InvalidOperationException("Expected public-output refusal."); }
    string Digest() => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(Path.Combine(target, "network.ncp2"))));

    // An unknown file must never be enumerated/read/copied by the exporter.
    File.WriteAllText(Path.Combine(source, "private-key-canary.seed"), "NONSECRET-TEST-CANARY");
    Sync();
    Require(File.ReadAllBytes(Path.Combine(target, "network.ncp2")).AsSpan().SequenceEqual(bundle)); passed++;
    Require(!File.Exists(Path.Combine(target, "private-key-canary.seed"))); passed++;
    var stamp = File.GetLastWriteTimeUtc(Path.Combine(target, "network.ncp2"));
    var digest = Digest();
    Sync(); Require(stamp == File.GetLastWriteTimeUtc(Path.Combine(target, "network.ncp2"))); passed++;
    File.WriteAllBytes(Path.Combine(target, "network.ncp2"), [1, 2, 3]);
    Sync(); Require(Digest() == digest); passed++; // Rebuildable public cache, not private state repair.
    Reject<Exception>(() => Sync([1, 2, 3])); Require(Digest() == digest);

    var observer = Path.Combine(source, "observer.did2");
    var originalObserver = File.ReadAllBytes(observer);
    const string canary = "/tmp/deep-public-link-canary";
    File.WriteAllText(canary, "NONSECRET-LINK-CANARY");
    File.Delete(observer); File.CreateSymbolicLink(observer, canary);
    Reject<IOException>(() => Sync()); Require(Digest() == digest);
    File.Delete(observer); File.WriteAllBytes(observer, originalObserver);
    var destination = Path.Combine(target, "observer.did2");
    File.Delete(destination); File.CreateSymbolicLink(destination, canary);
    Reject<IOException>(() => Sync()); Require(File.ReadAllText(canary) == "NONSECRET-LINK-CANARY");
    File.Delete(destination); Sync();
    var certificate = Path.Combine(source, "dev-ca.crt");
    File.WriteAllText(certificate, "-----BEGIN PRIVATE KEY-----\nNONSECRET-TEST-CANARY");
    Reject<CryptographicException>(() => Sync()); Require(Digest() == digest);
    Console.WriteLine(System.Text.Json.JsonSerializer.Serialize(new { passed, failed = 0, protectedDataTouched = false }));
    return passed == 8 ? 0 : 1;
}
catch
{
    // No raw exception, public payload, private path or source content.
    Console.WriteLine(System.Text.Json.JsonSerializer.Serialize(new { passed, failed = 1, protectedDataTouched = false }));
    return 1;
}
