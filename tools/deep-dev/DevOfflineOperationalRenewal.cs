using System.Buffers.Binary;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.XPointNetworkV1;
using Sodium;
using static DevOfflineAuthorityRenewal;

// Explicit Windows offline producer. The private candidate never becomes an
// online root mount or a readiness bypass. Activation is a separate owner step.
internal static class DevOfflineOperationalRenewal
{
    internal static async Task<string> PrepareAsync(string custodyRoot, string executable,
        Func<string, AccountDirectoryDts1Source[], Task<ulong>> observe)
    {
        var root = Path.GetFullPath(custodyRoot);
        if (!OperatingSystem.IsWindows() || !root.StartsWith(Path.GetFullPath("C:/Work/DeepSession/secrets/dev") + Path.DirectorySeparatorChar,
            StringComparison.OrdinalIgnoreCase)) throw new ArgumentException("Operational preparation requires local dev custody.");
        RequireNoLinks(root);
        var offline = Path.Combine(root, "offline-root");
        var leasePath = Path.Combine(offline, "authority-renewal.lease"); RequireNoLinks(leasePath);
        using var lease = new FileStream(leasePath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
        var publicRoot = Path.Combine(root, "public");
        var manifestBytes = Read(Path.Combine(publicRoot, "deep-dev.json"), 16_384);
        using var manifest = JsonDocument.Parse(manifestBytes);
        var topology = DevTopology.ForProject(manifest.RootElement.GetProperty("projectName").GetString()!);
        if (manifest.RootElement.GetProperty("schema").GetString() != "deep-dev.v1" ||
            manifest.RootElement.GetProperty("nodeCount").GetInt32() != 3 ||
            manifest.RootElement.GetProperty("containerIpv4Prefix").GetString() != topology.Ipv4Prefix)
            throw new InvalidDataException("Wrong current development topology.");
        var network = Convert.FromHexString(manifest.RootElement.GetProperty("networkIdHex").GetString()!);
        var pin = new XPointNetworkGenesisPin(network, Convert.FromHexString(manifest.RootElement.GetProperty("genesisAuthorityCoreHashHex").GetString()!));
        var priorBytes = Read(Path.Combine(publicRoot, "network.ncp2"), XPointNetworkClosureWireCodec.MaximumResponseLength);
        var prior = XPointNetworkClosureWireCodec.DecodeResponse(priorBytes);
        if (!prior.NetworkId.Span.SequenceEqual(network) || prior.ExactViewChain.Count >= XPointNetworkClosureWireCodec.MaximumChainCount)
            throw new InvalidDataException("Development history scope exhausted or different.");
        var priorAuthority = XPointNetworkAuthorityVerifier.Verify(pin, prior.ExactAuthorityChain, prior.ExactTimePolicyChain);
        var observed = await observe(executable, AccountDirectoryDts1Codec.Decode(prior.ExactTimePolicyChain[^1].Span).Sources.ToArray());
        Unchanged();
        using var rootSigner = Signer.LoadRoot(Checked(Path.Combine(offline, "root.seed")));
        var pair = await AuthorPairAsync(pin, prior.ExactAuthorityChain, prior.ExactTimePolicyChain, observed, rootSigner,
            Convert.ToHexStringLower(SHA256.HashData(priorBytes)));
        var xna = pair.ExactAuthorityChain.Select(b => (ReadOnlyMemory<byte>)b).ToArray();
        var dts = pair.ExactTimePolicyChain.Select(b => (ReadOnlyMemory<byte>)b).ToArray();
        var authority = XPointNetworkAuthorityVerifier.Verify(pin, xna, dts);
        var directory = Path.Combine(offline, "renewals"); RequireNoLinks(directory); Directory.CreateDirectory(directory);
        var staging = Path.Combine(directory, "operational-" + Guid.NewGuid().ToString("N") + ".pending"); Directory.CreateDirectory(staging);
        var loaded = new List<Signer>();
        var integrity = Read(Path.Combine(root, "operator/renewal-integrity.key"), 32);
        try
        {
            if (integrity.Length != 32 || integrity.AsSpan().IndexOfAnyExcept((byte)0) < 0) throw new InvalidDataException("Missing retained publisher integrity custody.");
            var witnesses = Enumerable.Range(1, 3).Select(i => Load($"operator/witness-{i}.seed", false)).ToArray();
            var nodes = Enumerable.Range(1, 3).Select(i => Load($"operator/node-{i}.seed", true)).ToArray();
            using var deposit = Signer.Create(Path.Combine(Dir("online/registry"), "mailbox-deposit.seed"));
            using var retrieve = Signer.Create(Path.Combine(Dir("online/registry"), "mailbox-retrieve.seed"));
            using var caKey = RSA.Create();
            caKey.ImportFromPem(Encoding.ASCII.GetString(Read(Path.Combine(offline, "dev-ca.key"), 16_384)));
            using var oldCa = X509Certificate2.CreateFromPem(Encoding.ASCII.GetString(Read(Path.Combine(publicRoot, "dev-ca.crt"), 16_384)));
            if (!oldCa.PublicKey.ExportSubjectPublicKeyInfo().AsSpan().SequenceEqual(caKey.ExportSubjectPublicKeyInfo()))
                throw new CryptographicException("Retained CA private/public key differs.");
            var caRequest = new CertificateRequest(oldCa.SubjectName, caKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            caRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            caRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
            var policyUntil = Math.Min(authority.Dts1ExpiresAt, checked(observed + 7 * 86_400UL));
            using var ca = caRequest.CreateSelfSigned(Time(observed - 86_400), Time(policyUntil + 86_400));
            Write("public/dev-ca.crt", Encoding.ASCII.GetBytes(ca.ExportCertificatePem()));
            _ = Certificate("registry", "registry", IPAddress.Loopback);
            _ = Certificate("floor", "floor", IPAddress.Loopback);
            var keys = new DevPublisher.NodeKeys[3];
            var rollovers = nodes.Select((node, index) => {
                var name = $"node-{index + 1}";
                var current = RandomNumberGenerator.GetBytes(32); var next = RandomNumberGenerator.GetBytes(32);
                try {
                    Write($"online/{name}/key_x25519", Encoding.ASCII.GetBytes(Convert.ToHexStringLower(current)));
                    Write($"online/{name}/key_x25519_next", Encoding.ASCII.GetBytes(Convert.ToHexStringLower(next)));
                    var address = IPAddress.Parse($"{topology.Ipv4Prefix}.{11 + index}");
                    var currentPin = Certificate(name, name, address);
                    var nextPin = Certificate(name + "-next", name, address);
                    var currentPub = ScalarMult.Base(current); var nextPub = ScalarMult.Base(next);
                    keys[index] = new(Convert.ToHexStringLower(currentPin), Convert.ToHexStringLower(nextPin),
                        Convert.ToHexStringLower(currentPub), Convert.ToHexStringLower(nextPub));
                    return new XPointNetworkOperationalNodeRollover(node, currentPin, nextPin, currentPub, nextPub);
                } finally { CryptographicOperations.ZeroMemory(current); CryptographicOperations.ZeroMemory(next); }
            }).ToArray();
            var nextMinimum = XPointNetworkOperationalSuccessorAuthor.ComputeNextMailboxGrantFloor(priorAuthority, prior.ExactMailboxAuthorityChain[^1].Span);
            var adh = Read(Path.Combine(publicRoot, "genesis.adh1"), 65_535);
            var adhRef = new byte[38]; "ADH1"u8.CopyTo(adhRef); adhRef[5] = 1;
            XPointNetworkOperationalSuccessorAuthor.ComputeAdh1CoreHash(adh).CopyTo(adhRef, 6);
            var authored = await XPointNetworkOperationalSuccessorAuthor.AuthorAsync(new(
                RandomNumberGenerator.GetBytes(32), authority, [rootSigner], witnesses, rollovers,
                prior.ExactNetworkPolicyChain[^1], prior.ExactActiveNodeDescriptors, prior.ExactViewChain, prior.ExactHeadChain[^1],
                prior.ExactMailboxAuthorityChain[^1], prior.ExactPlacementTopologyChain[^1],
                XPointNetworkOperationalSuccessorAuthor.ComputeXnh1CoreHash(prior.ExactHeadChain[^1].Span),
                SHA256.HashData(prior.ExactPlacementTopologyChain[^1].Span), adhRef, observed, observed, checked(observed + 3_600), policyUntil,
                new(deposit.Ed25519PublicKey.Span, retrieve.Ed25519PublicKey.Span, nextMinimum)));
            var bundle = XPointNetworkClosureWireCodec.EncodeResponse(network, xna, dts,
                [.. prior.ExactNetworkPolicyChain, authored.ExactXvp1], [.. prior.ExactViewChain, authored.ExactXnv1],
                [.. prior.ExactHeadChain, authored.ExactXnh1], authored.ExactXnd1,
                [.. prior.ExactPlacementTopologyChain, authored.ExactPmt2], [.. prior.ExactMailboxAuthorityChain, authored.ExactPma2]);
            Unchanged();
            Write("public/network.ncp2", bundle);
            Write("public/authority-pair.json", JsonSerializer.SerializeToUtf8Bytes(pair));
            Write("operator/renewal-nodes.json", JsonSerializer.SerializeToUtf8Bytes(keys));
            var journal = new DevPublisher.Journal("deep-dev-renewal.v1", Convert.ToHexStringLower(network),
                checked((ulong)prior.ExactViewChain.Count), observed, pair.PriorBundleSha256, bundle);
            var payload = JsonSerializer.SerializeToUtf8Bytes(journal);
            var encoded = new byte[payload.Length + 32]; HMACSHA256.HashData(integrity, payload).CopyTo(encoded, 0); payload.CopyTo(encoded, 32);
            Write("operator/renewal.state", encoded);
            DevOperationalActivation.Seal(staging, integrity);
            var complete = staging[..^8]; Directory.Move(staging, complete); return complete;

            byte[] Certificate(string service, string dns, IPAddress address)
            {
                using var key = RSA.Create(2048);
                var request = new CertificateRequest("CN=" + dns, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
                request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));
                request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new("1.3.6.1.5.5.7.3.1") }, true));
                var san = new SubjectAlternativeNameBuilder(); san.AddDnsName(dns); san.AddDnsName("localhost"); san.AddIpAddress(address); san.AddIpAddress(IPAddress.Loopback);
                request.CertificateExtensions.Add(san.Build());
                using var certificate = request.Create(ca, Time(observed - 30), Time(policyUntil + 3_600), RandomNumberGenerator.GetBytes(16));
                Write($"online/{service}/server.crt", Encoding.ASCII.GetBytes(certificate.ExportCertificatePem()));
                Write($"online/{service}/server.key", Encoding.ASCII.GetBytes(key.ExportPkcs8PrivateKeyPem()));
                return SHA256.HashData(key.ExportSubjectPublicKeyInfo());
            }
        }
        finally { foreach (var signer in loaded) signer.Dispose(); CryptographicOperations.ZeroMemory(integrity); }

        void Unchanged() {
            if (!Read(Path.Combine(publicRoot, "network.ncp2"), XPointNetworkClosureWireCodec.MaximumResponseLength).AsSpan().SequenceEqual(priorBytes) ||
                !Read(Path.Combine(publicRoot, "deep-dev.json"), 16_384).AsSpan().SequenceEqual(manifestBytes))
                throw new IOException("Development source changed; no activation is authorized.");
        }
        string Dir(string relative) { var path = Path.Combine(staging, relative); Directory.CreateDirectory(path); return path; }
        Signer Load(string relative, bool node) { var signer = Signer.Load(Checked(Path.Combine(root, relative)), node); loaded.Add(signer); return signer; }
        void Write(string relative, byte[] bytes) {
            var path = Path.Combine(staging, relative); Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            using var file = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough); file.Write(bytes); file.Flush(true);
        }
    }

    private static string Checked(string path) { RequireNoLinks(path); return path; }
    private static DateTimeOffset Time(ulong value) => DateTimeOffset.FromUnixTimeSeconds(checked((long)value));
}
