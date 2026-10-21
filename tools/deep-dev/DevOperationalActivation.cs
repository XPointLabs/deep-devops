using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.XPointNetworkV1;
using Sodium;
using static DevOfflineAuthorityRenewal;

// Local deployment custody, not a protocol reader or a current-authority token.
// The wrapper keeps all six owners stopped during installation and journal import.
internal static class DevOperationalActivation
{
    private static readonly JsonSerializerOptions Json = new() { UnmappedMemberHandling = System.Text.Json.Serialization.JsonUnmappedMemberHandling.Disallow };
    internal sealed record Replacement(string RelativePath, byte[]? Before, byte[] After);
    internal sealed record Plan(string PriorHash, string CandidateHash, Replacement[] Files);
    internal static string[] CandidateFiles => ["public/network.ncp2", "public/dev-ca.crt", "operator/renewal.state", "operator/renewal-nodes.json",
        "online/registry/mailbox-deposit.seed", "online/registry/mailbox-retrieve.seed",
        .. new[] { "registry", "floor", "node-1", "node-2", "node-3", "node-1-next", "node-2-next", "node-3-next" }
            .SelectMany(s => new[] { $"online/{s}/server.crt", $"online/{s}/server.key" }),
        .. Enumerable.Range(1, 3).SelectMany(i => new[] { $"online/node-{i}/key_x25519", $"online/node-{i}/key_x25519_next" })];

    internal static void Seal(string candidate, byte[] integrity)
    {
        var hashes = CandidateFiles.ToDictionary(p => p, p => Convert.ToHexStringLower(SHA256.HashData(Read(Path.Combine(candidate, p), Bound(p)))));
        WriteNew(Path.Combine(candidate, "activation-seal.json"), Protect(JsonSerializer.SerializeToUtf8Bytes(hashes, Json), integrity));
    }

    internal static void Execute(string custodyRoot, string candidatePath, bool install)
    {
        var root = Path.GetFullPath(custodyRoot); var candidate = Path.GetFullPath(candidatePath);
        if (!OperatingSystem.IsWindows() || !root.StartsWith(Path.GetFullPath("C:/Work/DeepSession/secrets/dev") + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) ||
            Path.GetDirectoryName(candidate) != Path.Combine(root, "offline-root", "renewals") ||
            !Regex.IsMatch(Path.GetFileName(candidate), "^operational-[0-9a-f]{32}$", RegexOptions.CultureInvariant))
            throw new ArgumentException("Activation requires exact complete local dev candidate custody.");
        RequireNoLinks(root); RequireNoLinks(candidate);
        var leasePath = Path.Combine(root, "offline-root/authority-renewal.lease"); RequireNoLinks(leasePath);
        using var lease = new FileStream(leasePath, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        var integrity = Read(Path.Combine(root, "operator/renewal-integrity.key"), 32);
        try {
            if (integrity.Length != 32) throw new InvalidDataException("Missing retained integrity custody.");
            var hashes = JsonSerializer.Deserialize<Dictionary<string, string>>(Unprotect(Read(Path.Combine(candidate, "activation-seal.json"), 16_384), integrity), Json)!;
            if (hashes.Count != CandidateFiles.Length || CandidateFiles.Any(p => !hashes.TryGetValue(p, out var hash) ||
                hash != Convert.ToHexStringLower(SHA256.HashData(Read(Path.Combine(candidate, p), Bound(p))))))
                throw new CryptographicException("Offline installation custody changed.");
            using var manifest = JsonDocument.Parse(Read(Path.Combine(root, "public/deep-dev.json"), 16_384));
            var m = manifest.RootElement; var topology = DevTopology.ForProject(m.GetProperty("projectName").GetString()!);
            if (m.GetProperty("schema").GetString() != "deep-dev.v1" || m.GetProperty("nodeCount").GetInt32() != 3 ||
                m.GetProperty("containerIpv4Prefix").GetString() != topology.Ipv4Prefix) throw new InvalidDataException("Wrong development topology.");
            var network = Convert.FromHexString(m.GetProperty("networkIdHex").GetString()!);
            var pin = new XPointNetworkGenesisPin(network, Convert.FromHexString(m.GetProperty("genesisAuthorityCoreHashHex").GetString()!));
            var journal = DevPublisher.ReadJournal(Path.Combine(candidate, "operator/renewal.state"), integrity, network);
            var bundle = Read(Path.Combine(candidate, "public/network.ncp2"), XPointNetworkClosureWireCodec.MaximumResponseLength);
            if (!bundle.AsSpan().SequenceEqual(journal.Bundle)) throw new CryptographicException("Candidate public/journal differs.");
            var current = Read(Path.Combine(root, "public/network.ncp2"), XPointNetworkClosureWireCodec.MaximumResponseLength);
            var digest = Convert.ToHexStringLower(SHA256.HashData(current)); var afterHash = Convert.ToHexStringLower(SHA256.HashData(bundle));
            if (digest != journal.PriorPublicHash && digest != afterHash) throw new CryptographicException("Stale installation candidate.");
            if (digest != afterHash) DevPublisher.ValidatePreparedImport(pin,
                new("deep-dev-renewal.v1", journal.Network, journal.Generation - 1, 1, "", current), journal);
            var closure = XPointNetworkClosureWireCodec.DecodeResponse(bundle);
            if (!Read(Path.Combine(root, "public/genesis.xna1"), 65_535).AsSpan().SequenceEqual(closure.ExactAuthorityChain[0].Span) ||
                !Read(Path.Combine(root, "public/genesis.dts1"), 65_535).AsSpan().SequenceEqual(closure.ExactTimePolicyChain[0].Span))
                throw new CryptographicException("Retained original genesis files differ.");
            var authority = XPointNetworkAuthorityVerifier.Verify(pin, closure.ExactAuthorityChain, closure.ExactTimePolicyChain);
            var pma = MailboxAuthorityV2Verifier.Verify(authority, closure.ExactMailboxAuthorityChain[^1].Span, journal.Observed, checked(journal.Observed + 1));
            foreach (var (name, domain) in new[] { ("deposit", MailboxCapabilityDomain.Deposit), ("retrieve", MailboxCapabilityDomain.Retrieve) }) {
                using var signer = Signer.Load(Path.Combine(candidate, $"online/registry/mailbox-{name}.seed"));
                if (!signer.Ed25519PublicKey.Span.SequenceEqual(pma.ResolveIssuer(domain).PublicKey.Span)) throw new CryptographicException("Staged issuer differs from signed PMA.");
            }
            var keys = JsonSerializer.Deserialize<DevPublisher.NodeKeys[]>(Read(Path.Combine(candidate, "operator/renewal-nodes.json"), 16_384), Json)!;
            if (keys.Length != 3) throw new InvalidDataException("Wrong staged node count.");
            using var ca = X509Certificate2.CreateFromPem(System.Text.Encoding.ASCII.GetString(Read(Path.Combine(candidate, "public/dev-ca.crt"), 16_384)));
            using var oldCa = X509Certificate2.CreateFromPem(System.Text.Encoding.ASCII.GetString(Read(Path.Combine(root, "public/dev-ca.crt"), 16_384)));
            if (!ca.PublicKey.ExportSubjectPublicKeyInfo().AsSpan().SequenceEqual(oldCa.PublicKey.ExportSubjectPublicKeyInfo())) throw new CryptographicException("CA identity changed.");
            foreach (var service in new[] { "registry", "floor", "node-1", "node-2", "node-3", "node-1-next", "node-2-next", "node-3-next" }) {
                using var cert = X509Certificate2.CreateFromPemFile(Path.Combine(candidate, $"online/{service}/server.crt"), Path.Combine(candidate, $"online/{service}/server.key"));
                var dns = service.EndsWith("-next", StringComparison.Ordinal) ? service[..^5] : service;
                using var chain = new X509Chain(); chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                chain.ChainPolicy.CustomTrustStore.Add(ca); chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                chain.ChainPolicy.DisableCertificateDownloads = true; chain.ChainPolicy.VerificationTime = DateTimeOffset.FromUnixTimeSeconds(checked((long)journal.Observed)).UtcDateTime;
                if (!cert.HasPrivateKey || !cert.MatchesHostname(dns) || !cert.MatchesHostname("localhost") || !chain.Build(cert)) throw new CryptographicException("Invalid staged TLS custody.");
                if (service.StartsWith("node-", StringComparison.Ordinal)) {
                    var i = int.Parse(service.Substring(5, 1), System.Globalization.CultureInfo.InvariantCulture) - 1;
                    if (!cert.MatchesHostname($"{topology.Ipv4Prefix}.{11 + i}") || Convert.ToHexStringLower(SHA256.HashData(cert.PublicKey.ExportSubjectPublicKeyInfo())) !=
                        (service.EndsWith("-next", StringComparison.Ordinal) ? keys[i].NextPin : keys[i].CurrentPin)) throw new CryptographicException("Staged TLS metadata differs.");
                }
            }
            for (var i = 0; i < 3; i++) foreach (var next in new[] { false, true }) {
                var seed = Convert.FromHexString(System.Text.Encoding.ASCII.GetString(Read(Path.Combine(candidate, $"online/node-{i + 1}/key_x25519{(next ? "_next" : "")}"), 64)));
                try { if (seed.Length != 32 || Convert.ToHexStringLower(ScalarMult.Base(seed)) != (next ? keys[i].NextKey : keys[i].CurrentKey)) throw new CryptographicException("Staged traffic metadata differs."); }
                finally { CryptographicOperations.ZeroMemory(seed); }
            }
            var planFile = Path.Combine(candidate, "installation.state"); RequireNoLinks(planFile);
            Plan plan;
            if (File.Exists(planFile)) plan = JsonSerializer.Deserialize<Plan>(Unprotect(Read(planFile, 4 * 1024 * 1024), integrity), Json)!;
            else {
                if (digest != journal.PriorPublicHash) throw new CryptographicException("Missing installation custody after journal commit.");
                System.Net.IPAddress? physicalAddress = null;
                var physicalMarker = Path.Combine(root, "mailbox/physical-ingress.json");
                if (File.Exists(physicalMarker))
                {
                    if (File.Exists(Path.Combine(root, "mailbox/operational-candidate.txt"))) DevTimeSourceRollover.ValidateInstalled(root);
                    else _ = DevPhysicalIngress.Validate(root);
                    using var physical = JsonDocument.Parse(Read(physicalMarker, 4096));
                    if (physical.RootElement.GetProperty("schema").GetString() != "deep-dev-physical-config.v1") throw new CryptographicException("Physical configuration scope differs.");
                    physicalAddress = DevPhysicalIngress.RequireAddress(physical.RootElement.GetProperty("address").GetString()!);
                }
                var replacements = new List<Replacement>();
                foreach (var p in CandidateFiles.Where(p => p.StartsWith("online/", StringComparison.Ordinal))) {
                    var parts = p.Split('/'); Add($"{parts[1]}/secrets/{parts[2]}", Read(Path.Combine(candidate, p), Bound(p)));
                }
                Add("public/dev-ca.crt", Read(Path.Combine(candidate, "public/dev-ca.crt"), 16_384));
                Add("operator/renewal-nodes.json", Read(Path.Combine(candidate, "operator/renewal-nodes.json"), 16_384));
                var xna = Export("xna1", closure.ExactAuthorityChain); var dts = Export("dts1", closure.ExactTimePolicyChain);
                foreach (var service in new[] { "registry", "node-1", "node-2", "node-3" }) {
                    var path = $"{service}/appsettings.Development.json";
                    var config = JsonNode.Parse(Read(Path.Combine(root, path), 262_144))!.AsObject();
                    var section = config[service == "registry" ? "DeepIdV2DirectoryAuthority" : "DeepIdV2DirectoryProof"]!.AsObject();
                    if (!string.Equals(section["NetworkIdHex"]!.GetValue<string>(), Convert.ToHexString(network), StringComparison.OrdinalIgnoreCase) ||
                        !string.Equals(section["GenesisAuthorityCoreHashHex"]!.GetValue<string>(), m.GetProperty("genesisAuthorityCoreHashHex").GetString(), StringComparison.OrdinalIgnoreCase))
                        throw new CryptographicException("Configuration identity differs.");
                    section["ExactAuthorityPaths"] = JsonSerializer.SerializeToNode(xna); section["ExactTimePolicyPaths"] = JsonSerializer.SerializeToNode(dts);
                    if (service != "registry") foreach (var peer in config["PrivacyRouting"]!["Peers"]!.AsArray()) {
                        var matches = Enumerable.Range(1, 3).Where(i => peer!["BaseUrl"]!.GetValue<string>() ==
                            (physicalAddress is null ? $"https://{topology.Ipv4Prefix}.{10 + i}/" : DevPhysicalIngress.NodeOrigin(physicalAddress, i))).ToArray();
                        if (matches.Length != 1) throw new InvalidDataException("Unknown retained peer.");
                        using var signer = Signer.Load(Path.Combine(root, $"operator/node-{matches[0]}.seed"), true);
                        if (!string.Equals(peer!["RouterId"]!.GetValue<string>(), Convert.ToHexString(signer.Ed25519PublicKey.Span), StringComparison.OrdinalIgnoreCase)) throw new CryptographicException("Peer identity differs.");
                        peer["CurrentSpkiSha256"] = keys[matches[0] - 1].CurrentPin; peer["NextSpkiSha256"] = keys[matches[0] - 1].NextPin;
                    }
                    Add(path, JsonSerializer.SerializeToUtf8Bytes(config, new JsonSerializerOptions { WriteIndented = true }));
                }
                plan = new(journal.PriorPublicHash, afterHash, replacements.ToArray());
                WriteNew(planFile, Protect(JsonSerializer.SerializeToUtf8Bytes(plan, Json), integrity));
                void Add(string p, byte[] b) { var target = Path.Combine(root, p); RequireNoLinks(target); replacements.Add(new(p, File.Exists(target) ? Read(target, 262_144) : null, b)); }
                string[] Export(string role, IReadOnlyList<ReadOnlyMemory<byte>> chain) => chain.Select((b, i) => {
                    if (i == 0) return $"/run/deep-public/genesis.{role}";
                    var p = $"public/{role}.{i:D4}.bin"; var target = Path.Combine(root, p);
                    if (File.Exists(target) && !Read(target, 65_535).AsSpan().SequenceEqual(b.Span)) throw new CryptographicException("Immutable authority file differs.");
                    Add(p, b.ToArray()); return $"/run/deep-public/{role}.{i:D4}.bin";
                }).ToArray();
            }
            if (plan.PriorHash != journal.PriorPublicHash || plan.CandidateHash != afterHash || plan.Files.Select(f => f.RelativePath).Distinct().Count() != plan.Files.Length)
                throw new CryptographicException("Installation plan differs.");
            var allowedPaths = CandidateFiles.Where(p => p.StartsWith("online/", StringComparison.Ordinal)).Select(p => {
                var parts = p.Split('/'); return $"{parts[1]}/secrets/{parts[2]}";
            }).Concat(new[] { "public/dev-ca.crt", "operator/renewal-nodes.json", "registry/appsettings.Development.json",
                "node-1/appsettings.Development.json", "node-2/appsettings.Development.json", "node-3/appsettings.Development.json" })
                .Concat(Enumerable.Range(1, closure.ExactAuthorityChain.Count - 1).Select(i => $"public/xna1.{i:D4}.bin"))
                .Concat(Enumerable.Range(1, closure.ExactTimePolicyChain.Count - 1).Select(i => $"public/dts1.{i:D4}.bin")).ToHashSet(StringComparer.Ordinal);
            if (!allowedPaths.SetEquals(plan.Files.Select(f => f.RelativePath))) throw new CryptographicException("Installation plan is outside the exact whitelist.");
            foreach (var f in plan.Files) {
                var target = Path.GetFullPath(Path.Combine(root, f.RelativePath));
                if (!target.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) throw new IOException("Installation scope escaped.");
                RequireNoLinks(target);
                var bytes = File.Exists(target) ? Read(target, 262_144) : null;
                if (!(bytes is null && f.Before is null) && !(bytes is not null && (bytes.AsSpan().SequenceEqual(f.After) || f.Before is not null && bytes.AsSpan().SequenceEqual(f.Before))))
                    throw new IOException("Retained installation target changed; no overwrite authorized.");
            }
            // Only whitelisted volume before-images are exposed to the copy helper.
            // The whole candidate/offline-root must never become an online mount.
            foreach (var f in plan.Files.Where(f => f.RelativePath.Contains("/secrets/", StringComparison.Ordinal))) {
                var parts = f.RelativePath.Split('/');
                if (parts[0].EndsWith("-next", StringComparison.Ordinal)) continue;
                var before = Path.Combine(candidate, "volume-before", parts[0], parts[2] + (f.Before is null ? ".absent" : ""));
                RequireNoLinks(before); Directory.CreateDirectory(Path.GetDirectoryName(before)!);
                var bytes = f.Before ?? "absent"u8.ToArray();
                if (File.Exists(before)) { if (!Read(before, 262_144).AsSpan().SequenceEqual(bytes)) throw new IOException("Volume before-image changed."); }
                else WriteNew(before, bytes);
            }
            if (install) foreach (var f in plan.Files) { var path = Path.Combine(root, f.RelativePath); Directory.CreateDirectory(Path.GetDirectoryName(path)!); Atomic(path, f.After); }
            Console.WriteLine(install ? "Whitelisted local successor custody installed; journal import and independent readiness remain required." : "Exact offline successor and recoverable installation plan validated; runtime unchanged.");
        } finally { CryptographicOperations.ZeroMemory(integrity); }
    }

    private static int Bound(string p) => p.EndsWith("network.ncp2", StringComparison.Ordinal) ? XPointNetworkClosureWireCodec.MaximumResponseLength : p.EndsWith("renewal.state", StringComparison.Ordinal) ? 100 * 1024 * 1024 : 16_384;
    private static byte[] Protect(byte[] b, byte[] key) { var result = new byte[b.Length + 32]; HMACSHA256.HashData(key, b).CopyTo(result, 0); b.CopyTo(result, 32); return result; }
    private static byte[] Unprotect(byte[] b, byte[] key) { if (b.Length <= 32 || !CryptographicOperations.FixedTimeEquals(b.AsSpan(0, 32), HMACSHA256.HashData(key, b.AsSpan(32)))) throw new CryptographicException("Installation custody integrity rejected."); return b[32..]; }
    private static void WriteNew(string p, byte[] b) { RequireNoLinks(p); using var f = new FileStream(p, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough); f.Write(b); f.Flush(true); }
    private static void Atomic(string p, byte[] b) { var stage = p + ".stage-" + Guid.NewGuid().ToString("N"); WriteNew(stage, b); File.Move(stage, p, true); }
}
