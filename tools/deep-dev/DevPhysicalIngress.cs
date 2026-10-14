using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.XPointNetworkV1;
using static DevOfflineAuthorityRenewal;

// Current-dev maintenance candidate only. Offline CA/private config stay on the
// host; only the independently sealed online intent/result mount may go online.
internal static class DevPhysicalIngress
{
    internal sealed record Intent(string Schema, string PriorBundleHash, string Address);
    internal sealed record Plan(string Schema, byte[] Ca, Intent Intent, DevPki.Replacement[] Files);
    internal sealed record Result(string IntentHash, DevPublisher.Journal Journal);
    private static readonly JsonSerializerOptions Json = new() { UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow };
    internal const string CandidateRelative = "offline-root/physical-ingress";
    internal static string FailureCategory(Exception error) => error.Message switch
    {
        "Physical candidate seal differs." => "seal",
        "Retained physical CA changed." => "ca",
        "Physical staged image changed." => "staged-image",
        "Physical CRL predecessor differs." => "crl-predecessor",
        "Physical leaf identity or validity changed." => "leaf-identity",
        "Physical leaf extension binding differs." => "leaf-extensions",
        "Retained SAN contains unsupported or noncanonical names." => "san-grammar",
        "Physical peer configuration differs." => "peer-config",
        "Online intent differs from the sealed private plan." => "online-intent",
        "Physical publication result differs." => "publication-result",
        "Installed physical publication is not in the retained prefix." => "publication-prefix",
        _ => "unclassified"
    };
    internal static IPAddress RequireAddress(string text)
    {
        if (!IPAddress.TryParse(text, out var address) || address.AddressFamily != AddressFamily.InterNetwork ||
            address.ToString() != text) throw new ArgumentException("Physical dev ingress requires canonical private LAN IPv4.");
        var bytes = address.GetAddressBytes();
        if (!(bytes[0] == 10 || bytes[0] == 172 && bytes[1] is >= 16 and <= 31 || bytes[0] == 192 && bytes[1] == 168) ||
            bytes[0] == 172 && bytes[1] == 31 && bytes[2] is 240 or 241)
            throw new ArgumentException("Physical ingress must be an explicit private LAN address, not a Docker bridge.");
        return address;
    }
    internal static Uri CrlUri(IPAddress address) => new($"http://{address}:28297/deep-dev-ca.crl");
    internal static string NodeOrigin(IPAddress address, int number) => number is >= 1 and <= 3
        ? $"https://{address}:{28293 + number}/" : throw new ArgumentOutOfRangeException(nameof(number));
    internal static XPointNetworkOperationalOriginRelocation Relocation(IPAddress address, int number) =>
        new(SHA256.HashData(Encoding.UTF8.GetBytes($"Deep/Development/v1/origin-node-{number}")), address,
            checked((ushort)(28293 + number)));

    internal static X509Extension San(X509Certificate2 before, IPAddress address)
    {
        var original = before.Extensions["2.5.29.17"] ?? throw new CryptographicException("Retained SAN missing.");
        var names = new X509SubjectAlternativeNameExtension(original.RawData, original.Critical);
        var builder = new SubjectAlternativeNameBuilder();
        foreach (var dns in names.EnumerateDnsNames()) builder.AddDnsName(dns);
        var ips = names.EnumerateIPAddresses().ToArray();
        foreach (var ip in ips) builder.AddIpAddress(ip);
        if (!builder.Build(original.Critical).RawData.AsSpan().SequenceEqual(original.RawData))
            throw new CryptographicException("Retained SAN contains unsupported or noncanonical names.");
        if (!ips.Contains(address)) builder.AddIpAddress(address);
        return builder.Build(original.Critical);
    }
    internal static X509Certificate2 AuthorLeaf(X509Certificate2 ca, RSA key, X509Certificate2 before, IPAddress address)
    {
        _ = RequireAddress(address.ToString());
        DevPki.VerifySigned(before.RawData, ca);
        if (!before.IssuerName.RawData.AsSpan().SequenceEqual(ca.SubjectName.RawData) ||
            !before.PublicKey.ExportSubjectPublicKeyInfo().AsSpan().SequenceEqual(key.ExportSubjectPublicKeyInfo()))
            throw new CryptographicException("Physical leaf custody differs.");
        var request = new CertificateRequest(before.SubjectName, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        foreach (var extension in before.Extensions)
            if (extension.Oid?.Value is not ("2.5.29.17" or "2.5.29.31"))
                request.CertificateExtensions.Add(new X509Extension(extension.Oid!, extension.RawData, extension.Critical));
        request.CertificateExtensions.Add(San(before, address));
        request.CertificateExtensions.Add(CertificateRevocationListBuilder.BuildCrlDistributionPointExtension([CrlUri(address).AbsoluteUri]));
        return request.Create(ca, new DateTimeOffset(before.NotBefore.ToUniversalTime()),
            new DateTimeOffset(before.NotAfter.ToUniversalTime()), RandomNumberGenerator.GetBytes(16));
    }
    internal static void ValidateLeaf(X509Certificate2 ca, X509Certificate2 before, X509Certificate2 after, IPAddress address)
    {
        DevPki.VerifySigned(before.RawData, ca); DevPki.VerifySigned(after.RawData, ca);
        if (!after.IssuerName.RawData.AsSpan().SequenceEqual(ca.SubjectName.RawData) ||
            before.NotBefore != after.NotBefore || before.NotAfter != after.NotAfter ||
            !before.SubjectName.RawData.AsSpan().SequenceEqual(after.SubjectName.RawData) ||
            !before.PublicKey.ExportSubjectPublicKeyInfo().AsSpan().SequenceEqual(after.PublicKey.ExportSubjectPublicKeyInfo()))
            throw new CryptographicException("Physical leaf identity or validity changed.");
        var expected = before.Extensions.Cast<X509Extension>().Where(e => e.Oid?.Value is not ("2.5.29.17" or "2.5.29.31"))
            .Concat([San(before, address), CertificateRevocationListBuilder.BuildCrlDistributionPointExtension([CrlUri(address).AbsoluteUri])]).ToArray();
        if (after.Extensions.Count != expected.Length || expected.Any(e => after.Extensions[e.Oid!.Value!] is not { } actual ||
            actual.Critical != e.Critical || !actual.RawData.AsSpan().SequenceEqual(e.RawData)))
            throw new CryptographicException("Physical leaf extension binding differs.");
    }
    internal static async Task PrepareAsync(string root, string text, string executable,
        Func<string, AccountDirectoryDts1Source[], Task<ulong>> observe)
    {
        root = RequireRoot(root); var address = RequireAddress(text); var candidate = Path.Combine(root, CandidateRelative);
        RequireNoLinks(candidate); if (Directory.Exists(candidate)) throw new IOException("Inspect or resume the existing physical candidate; no re-authoring.");
        _ = await DevNodeMailboxProvisioning.PolicyAsync(Path.Combine(root, "public"), executable, observe);
        var bundle = Read(Path.Combine(root, "public/network.ncp2"), XPointNetworkClosureWireCodec.MaximumResponseLength);
        var caBytes = Read(Path.Combine(root, "public/dev-ca.crt"), 16_384);
        using var caPublic = X509Certificate2.CreateFromPem(Encoding.ASCII.GetString(caBytes)); using var caKey = RSA.Create();
        var secret = Read(Path.Combine(root, "offline-root/dev-ca.key"), 16_384);
        try { caKey.ImportFromPem(Encoding.ASCII.GetString(secret)); } finally { CryptographicOperations.ZeroMemory(secret); }
        using var ca = caPublic.CopyWithPrivateKey(caKey);
        var priorCrl = Read(Path.Combine(root, "public/dev-ca.crl"), 65_536); DevPki.ValidateCrl(priorCrl, caPublic);
        var builder = CertificateRevocationListBuilder.Load(priorCrl, out var number);
        var closure = XPointNetworkClosureWireCodec.DecodeResponse(bundle);
        var seconds = await observe(executable, AccountDirectoryDts1Codec.Decode(closure.ExactTimePolicyChain[^1].Span).Sources.ToArray());
        var now = DateTimeOffset.FromUnixTimeSeconds(checked((long)seconds));
        if (now < ca.NotBefore.ToUniversalTime() || now >= ca.NotAfter.ToUniversalTime()) throw new CryptographicException("Existing CA is not current.");
        var crl = builder.Build(ca, number + 1, new DateTimeOffset(ca.NotAfter.ToUniversalTime()), HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1, now.AddSeconds(-30));
        var files = new List<DevPki.Replacement> { new("public/dev-ca.crl", priorCrl, crl) };
        foreach (var service in DevPki.Services)
        {
            var path = $"{service}/secrets/server.crt"; var beforeBytes = Read(Path.Combine(root, path), 16_384);
            using var before = X509Certificate2.CreateFromPem(Encoding.ASCII.GetString(beforeBytes)); using var leafKey = RSA.Create();
            secret = Read(Path.Combine(root, service, "secrets/server.key"), 16_384);
            try { leafKey.ImportFromPem(Encoding.ASCII.GetString(secret)); } finally { CryptographicOperations.ZeroMemory(secret); }
            using var after = AuthorLeaf(ca, leafKey, before, address); ValidateLeaf(ca, before, after, address);
            files.Add(new(path, beforeBytes, Encoding.ASCII.GetBytes(after.ExportCertificatePem())));
        }
        for (var node = 1; node <= 3; node++)
        {
            var path = $"node-{node}/appsettings.Development.json"; var before = Read(Path.Combine(root, path), 65_536);
            files.Add(new(path, before, ConfigureNode(before, address, node)));
        }
        if (!Read(Path.Combine(root, "public/network.ncp2"), XPointNetworkClosureWireCodec.MaximumResponseLength).AsSpan().SequenceEqual(bundle))
            throw new IOException("Publisher changed during preparation; leave the retained publisher stopped.");
        var intent = new Intent("deep-dev-physical-intent.v1", Convert.ToHexStringLower(SHA256.HashData(bundle)), address.ToString());
        var plan = new Plan("deep-dev-physical-plan.v1", caBytes, intent, files.ToArray()); var key = Read(Path.Combine(root, "operator/renewal-integrity.key"), 32);
        try
        {
            Directory.CreateDirectory(candidate);
            foreach (var file in files)
            {
                WriteNew(Path.Combine(candidate, "after", file.Path), file.After);
                WriteNew(Path.Combine(candidate, "before", file.Path), file.Before!);
            }
            WriteNew(Path.Combine(candidate, "plan.bin"), Seal(plan, key));
            WriteNew(Path.Combine(candidate, "online/intent.bin"), Seal(intent, key));
        }
        finally { CryptographicOperations.ZeroMemory(key); }
        Console.WriteLine("Sealed physical ingress candidate prepared; no runtime/identity/floor changed.");
    }
    internal static byte[] ConfigureNode(byte[] before, IPAddress address, int number)
    {
        var config = JsonNode.Parse(before)!.AsObject(); var privacy = config["PrivacyRouting"]!.AsObject();
        privacy["PublicPeerBaseUrl"] = NodeOrigin(address, number);
        var peers = privacy["Peers"]!.AsArray(); if (peers.Count != 2) throw new InvalidDataException("Wrong current peer count.");
        var expected = Enumerable.Range(1, 3).Where(n => n != number).ToArray();
        for (var i = 0; i < peers.Count; i++)
        {
            var original = peers[i]!["BaseUrl"]!.GetValue<string>();
            // Match the owned predecessor's exact configured origin, not enumeration order.
            var target = expected.SingleOrDefault(n => original == $"https://172.31.241.{10 + n}/");
            if (target == 0) throw new InvalidDataException("Peer is not the exact owned current-dev predecessor.");
            peers[i]!["BaseUrl"] = NodeOrigin(address, target);
        }
        if (peers.Select(peer => peer!["BaseUrl"]!.GetValue<string>()).Distinct(StringComparer.Ordinal).Count() != 2)
            throw new InvalidDataException("Physical peer targets are duplicated.");
        return JsonSerializer.SerializeToUtf8Bytes(config);
    }
    internal static Plan Validate(string root)
    {
        root = RequireRoot(root); var candidate = Path.Combine(root, CandidateRelative);
        var key = Read(Path.Combine(root, "operator/renewal-integrity.key"), 32);
        Plan plan;
        try { plan = Open<Plan>(Read(Path.Combine(candidate, "plan.bin"), 1024 * 1024), key); }
        finally { CryptographicOperations.ZeroMemory(key); }
        if (plan.Schema != "deep-dev-physical-plan.v1" || plan.Intent.Schema != "deep-dev-physical-intent.v1" ||
            plan.Intent.PriorBundleHash.Length != 64 || plan.Intent.PriorBundleHash.Any(c => !char.IsAsciiHexDigitLower(c)))
            throw new InvalidDataException("Physical candidate scope differs.");
        var address = RequireAddress(plan.Intent.Address);
        if (!Read(Path.Combine(root, "public/dev-ca.crt"), 16_384).AsSpan().SequenceEqual(plan.Ca))
            throw new CryptographicException("Retained physical CA changed.");
        using var ca = X509Certificate2.CreateFromPem(Encoding.ASCII.GetString(plan.Ca));
        var allowed = new[] { "public/dev-ca.crl" }.Concat(DevPki.Services.Select(s => $"{s}/secrets/server.crt"))
            .Concat(Enumerable.Range(1, 3).Select(n => $"node-{n}/appsettings.Development.json")).Order().ToArray();
        if (plan.Files is null || plan.Files.Length != allowed.Length || !plan.Files.Select(f => f.Path).Order().SequenceEqual(allowed))
            throw new InvalidDataException("Physical candidate file whitelist differs.");
        var installed = File.Exists(Path.Combine(root, "mailbox/physical-ingress.json"));
        foreach (var file in plan.Files)
        {
            if (file.Before is null || file.Before.Length is < 1 or > 65_536 || file.After.Length is < 1 or > 65_536)
                throw new InvalidDataException("Physical candidate file bounds differ.");
            var current = Read(Path.Combine(root, file.Path), 65_536);
            RequireCurrentImage(current, file.Before, file.After, installed);
            foreach (var (side, bytes) in new[] { ("before", file.Before), ("after", file.After) })
                if (!Read(Path.Combine(candidate, side, file.Path), 65_536).AsSpan().SequenceEqual(bytes))
                    throw new CryptographicException("Physical staged image changed.");
            if (file.Path == "public/dev-ca.crl")
            {
                DevPki.ValidateCrl(file.Before, ca); DevPki.ValidateCrl(file.After, ca);
                _ = CertificateRevocationListBuilder.Load(file.Before, out var previous);
                _ = CertificateRevocationListBuilder.Load(file.After, out var next);
                if (next != previous + 1) throw new CryptographicException("Physical CRL predecessor differs.");
            }
            else if (file.Path.EndsWith(".crt", StringComparison.Ordinal))
            {
                using var before = X509Certificate2.CreateFromPem(Encoding.ASCII.GetString(file.Before));
                using var after = X509Certificate2.CreateFromPem(Encoding.ASCII.GetString(file.After));
                ValidateLeaf(ca, before, after, address);
                var service = file.Path.Split('/')[0];
                using var installedKey = X509Certificate2.CreateFromPemFile(Path.Combine(candidate, "after", file.Path),
                    Path.Combine(root, service, "secrets/server.key"));
            }
            else
            {
                var number = int.Parse(file.Path.AsSpan(5, 1), System.Globalization.CultureInfo.InvariantCulture);
                if (!ConfigureNode(file.Before, address, number).AsSpan().SequenceEqual(file.After))
                    throw new CryptographicException("Physical peer configuration differs.");
            }
        }
        key = Read(Path.Combine(root, "operator/renewal-integrity.key"), 32);
        try
        {
            var intent = Open<Intent>(Read(Path.Combine(candidate, "online/intent.bin"), 4096), key);
            if (intent != plan.Intent) throw new CryptographicException("Online intent differs from the sealed private plan.");
            var currentBytes = Read(Path.Combine(root, "public/network.ncp2"), XPointNetworkClosureWireCodec.MaximumResponseLength);
            if (Convert.ToHexStringLower(SHA256.HashData(currentBytes)) != intent.PriorBundleHash)
            {
                var result = ReadResult(Path.Combine(candidate, "online"), intent, key)
                    ?? throw new IOException("Physical predecessor changed without its sealed result.");
                if (!currentBytes.AsSpan().SequenceEqual(result.Journal.Bundle))
                {
                    if (!File.Exists(Path.Combine(root, "mailbox/physical-ingress.json")))
                        throw new IOException("Unfinished physical publication changed; no overwrite.");
                    var committed = XPointNetworkClosureWireCodec.DecodeResponse(result.Journal.Bundle);
                    var current = XPointNetworkClosureWireCodec.DecodeResponse(currentBytes);
                    if (!current.NetworkId.Span.SequenceEqual(committed.NetworkId.Span) || current.ExactViewChain.Count < committed.ExactViewChain.Count ||
                        committed.ExactViewChain.Where((bytes, index) => !bytes.Span.SequenceEqual(current.ExactViewChain[index].Span)).Any())
                        throw new CryptographicException("Installed physical publication is not in the retained prefix.");
                    // Distribution metadata only. Runtime still verifies actual
                    // current signatures/time, endpoint and independent floors.
                }
            }
        }
        finally { CryptographicOperations.ZeroMemory(key); }
        return plan;
    }
    internal static void RequireCurrentImage(byte[] current, byte[] before, byte[] after, bool installed)
    {
        // Before/after is resumable only during the stopped maintenance phase.
        // A completed installation must not silently restart with an old image.
        if (!current.AsSpan().SequenceEqual(after) && (installed || !current.AsSpan().SequenceEqual(before)))
            throw new IOException("Physical target changed; no overwrite.");
    }
    internal static void InstallFiles(string root)
    {
        root = RequireRoot(root); var plan = Validate(root);
        foreach (var file in plan.Files)
        {
            var path = Path.Combine(root, file.Path); RequireNoLinks(path);
            var stage = path + ".physical-stage"; RequireNoLinks(stage);
            if (File.Exists(stage))
            {
                if (!Read(stage, 65_536).AsSpan().SequenceEqual(file.After)) throw new IOException("Interrupted physical stage differs.");
            }
            else WriteNew(stage, file.After);
            File.Move(stage, path, true);
        }
        Console.WriteLine("Whitelisted physical TLS/peer files installed; signed publication/readiness still required.");
    }
    internal static void MarkInstalled(string root)
    {
        root = RequireRoot(root); var plan = Validate(root);
        var key = Read(Path.Combine(root, "operator/renewal-integrity.key"), 32);
        try
        {
            var result = ReadResult(Path.Combine(root, CandidateRelative, "online"), plan.Intent, key)
                ?? throw new IOException("Physical publication result missing.");
            if (!Read(Path.Combine(root, "public/network.ncp2"), XPointNetworkClosureWireCodec.MaximumResponseLength)
                .AsSpan().SequenceEqual(result.Journal.Bundle) || plan.Files.Any(file =>
                    !Read(Path.Combine(root, file.Path), 65_536).AsSpan().SequenceEqual(file.After)))
                throw new IOException("Physical publication/installation readback differs.");
            var path = Path.Combine(root, "mailbox/physical-ingress.json"); RequireNoLinks(path);
            var bytes = JsonSerializer.SerializeToUtf8Bytes(new { schema = "deep-dev-physical-config.v1", address = plan.Intent.Address });
            if (File.Exists(path))
            {
                if (!Read(path, 4096).AsSpan().SequenceEqual(bytes)) throw new IOException("Physical runtime configuration changed.");
            }
            else WriteNew(path, bytes);
        }
        finally { CryptographicOperations.ZeroMemory(key); }
        Console.WriteLine("Physical runtime configuration committed; no readiness/device claim.");
    }
    internal static Intent ReadOnlineIntent(string path, byte[] key)
    {
        if (path != "/run/deep-physical") throw new ArgumentException("Wrong physical online mount.");
        RequireNoLinks(path);
        var intent = Open<Intent>(Read(Path.Combine(path, "intent.bin"), 4096), key);
        if (intent.Schema != "deep-dev-physical-intent.v1" || intent.PriorBundleHash.Length != 64 ||
            intent.PriorBundleHash.Any(c => !char.IsAsciiHexDigitLower(c))) throw new InvalidDataException("Physical intent scope differs.");
        _ = RequireAddress(intent.Address); return intent;
    }
    internal static string IntentHash(Intent intent) => Convert.ToHexStringLower(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(intent, Json)));
    internal static Result? ReadResult(string path, Intent intent, byte[] key)
    {
        var file = Path.Combine(path, "result.bin"); RequireNoLinks(file);
        var pending = file + ".pending"; RequireNoLinks(pending);
        var selected = File.Exists(file) ? file : File.Exists(pending) ? pending : null;
        if (selected is null) return null;
        var result = Open<Result>(Read(selected, 2 * XPointNetworkClosureWireCodec.MaximumResponseLength), key);
        if (result.IntentHash != IntentHash(intent) || result.Journal.Schema != "deep-dev-renewal.v1" ||
            result.Journal.PriorPublicHash != intent.PriorBundleHash) throw new CryptographicException("Physical publication result differs.");
        if (selected == pending) File.Move(pending, file); // Only a complete authenticated exact result can finish its rename.
        return result;
    }
    internal static void WriteResult(string path, Intent intent, DevPublisher.Journal journal, byte[] key)
    {
        if (ReadResult(path, intent, key) is not null) throw new IOException("Physical result already authored; resume exact bytes.");
        var final = Path.Combine(path, "result.bin"); var pending = final + ".pending";
        RequireNoLinks(pending); if (File.Exists(pending)) throw new IOException("Uncertain physical result stage; preserve for inspection.");
        WriteNew(pending, Seal(new Result(IntentHash(intent), journal), key)); File.Move(pending, final);
    }
    internal static byte[] Seal<T>(T value, byte[] key)
    {
        if (key.Length != 32 || key.AsSpan().IndexOfAnyExcept((byte)0) < 0) throw new CryptographicException("Physical seal key differs.");
        var payload = JsonSerializer.SerializeToUtf8Bytes(value, Json); return [.. HMACSHA256.HashData(key, payload), .. payload];
    }
    internal static T Open<T>(byte[] bytes, byte[] key)
    {
        if (key.Length != 32 || key.AsSpan().IndexOfAnyExcept((byte)0) < 0 || bytes.Length < 33 || !CryptographicOperations.FixedTimeEquals(bytes.AsSpan(0, 32), HMACSHA256.HashData(key, bytes.AsSpan(32))))
            throw new CryptographicException("Physical candidate seal differs.");
        return JsonSerializer.Deserialize<T>(bytes.AsSpan(32), Json) ?? throw new InvalidDataException("Missing physical candidate.");
    }
    internal static string RequireRoot(string root)
    {
        root = Path.GetFullPath(root);
        if (!OperatingSystem.IsWindows() || !string.Equals(root, Path.GetFullPath("C:/Work/DeepSession/secrets/dev/deep-dev-current"), StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("Physical provisioning accepts only the exact retained current-dev scope.");
        RequireNoLinks(root); return root;
    }
    private static void WriteNew(string path, byte[] bytes)
    {
        RequireNoLinks(path); Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        using var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough);
        stream.Write(bytes); stream.Flush(true);
    }
}
