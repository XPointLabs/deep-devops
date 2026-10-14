using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.Identity;
using Deep.Protocol.ContactV1;
using Deep.Protocol.XPointNetworkV1;

internal static partial class OfflineAuthoringTests
{
    private static async Task TestOperationalFileCompletionAsync(string directory, string custody,
        CustodyManifest manifest, string prepared, FileSigner[] witnesses, XPointNetworkOperationalNode[] nodes,
        AuthoredXPointNetworkOperationalGenesis genesis, ParsedDid2 requestedDid2, XPointNetworkGenesisPin pin)
    {
        var privateRoot = Path.Combine(custody, "private");
        var roles = manifest.Roles.ToList();
        for (var index = 0; index < witnesses.Length; index++)
        {
            var name = $"registry-dtt-signer-{index + 1}";
            roles.Add(new(name, Convert.ToHexString(witnesses[index].SignerId.Span), witnesses[index].KeyGeneration,
                Convert.ToHexString(witnesses[index].Ed25519PublicKey.Span),
                Convert.ToHexString(witnesses[index].FailureDomainHash.Span)));
            File.WriteAllBytes(Path.Combine(privateRoot, name + ".ed25519.seed"), B(32, (byte)(0x40 + index)));
        }
        File.WriteAllBytes(Path.Combine(custody, "public", "custody-manifest.v1.json"),
            JsonSerializer.SerializeToUtf8Bytes(manifest with { Roles = roles }));
        var rollover = Path.Combine(directory, "cli-rollover");
        var roots = new List<string>();
        var retained = new Dictionary<string, byte[]>();
        for (var index = 0; index < nodes.Length; index++)
        {
            var node = Path.Combine(directory, $"cli-seed{index + 1}");
            Directory.CreateDirectory(Path.Combine(node, "secrets"));
            File.WriteAllText(Path.Combine(node, ".env.node.prod"),
                "DEEP_NODE_ED25519_PUBLIC_KEY=" + Convert.ToHexString(nodes[index].IdentitySigner.Ed25519PublicKey.Span) +
                $"\nDEEP_NODE_PUBLIC_IP=192.0.2.{index + 1}\nDEEP_NODE_PUBLIC_HOST=node{index + 1}.invalid\n");
            var identity = Path.Combine(node, "secrets", "key_ed25519");
            File.WriteAllBytes(identity, B(32, (byte)(0x70 + index)));
            retained.Add(identity, File.ReadAllBytes(identity)); roots.Add(node);
            var keys = Path.Combine(rollover, $"seed{index + 1}"); Directory.CreateDirectory(keys);
            foreach (var name in new[] { "current", "next" })
            {
                var seed = SHA256.HashData(System.Text.Encoding.ASCII.GetBytes($"cli-onion-{name}-{index}"));
                try { File.WriteAllBytes(Path.Combine(keys, name + ".x25519.seed"), seed); }
                finally { CryptographicOperations.ZeroMemory(seed); }
                using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
                var request = new CertificateRequest($"CN=node{index + 1}.invalid", key, HashAlgorithmName.SHA256);
                var san = new SubjectAlternativeNameBuilder(); san.AddIpAddress(IPAddress.Parse($"192.0.2.{index + 1}"));
                san.AddDnsName($"node{index + 1}.invalid"); request.CertificateExtensions.Add(san.Build());
                using var certificate = request.CreateSelfSigned(DateTimeOffset.FromUnixTimeSeconds(8_000),
                    DateTimeOffset.FromUnixTimeSeconds(150_000));
                File.WriteAllText(Path.Combine(keys, name + "-origin.cer"), certificate.ExportCertificatePem());
                File.WriteAllText(Path.Combine(keys, name + "-origin.key"), key.ExportPkcs8PrivateKeyPem());
            }
            foreach (var path in Directory.EnumerateFiles(keys)) retained.Add(path, File.ReadAllBytes(path));
        }
        var credential = Path.Combine(directory, "cli-requested.did2");
        File.WriteAllBytes(credential, requestedDid2.CanonicalBytes.ToArray());
        var head = Path.Combine(directory, "cli-current.adh1"); File.WriteAllBytes(head, genesis.ExactAdh1.ToArray());
        var output = Path.Combine(directory, "cli-operational-complete");
        var args = new[] { "--successor-from", prepared, "--authority-root", custody,
            "--seed1-root", roots[0], "--seed2-root", roots[1], "--seed3-root", roots[2], "--output", output,
            "--observed-unix", "8600", "--rollover-root", rollover,
            "--protected-head-core-hash", Convert.ToHexString(XPointNetworkOperationalSuccessorAuthor.ComputeXnh1CoreHash(genesis.ExactXnh1.Span)),
            "--protected-pmt-artifact-hash", Convert.ToHexString(ContactCodec.Decode("PMT2", genesis.ExactPmt2.Span).ArtifactHash.Span),
            "--current-adh1-path", head, "--current-adh1-core-hash", Convert.ToHexString(XPointNetworkOperationalSuccessorAuthor.ComputeAdh1CoreHash(genesis.ExactAdh1.Span)),
            "--requested-did2-path", credential };
        try
        {
            var cli = await RunBootstrapCliAsync(args);
            if (cli.ExitCode != 0 || cli.Error.Length != 0 || !cli.Output.Contains("monotonic operational successor", StringComparison.Ordinal))
            {
                var category = System.Text.RegularExpressions.Regex.Match(cli.Error, @"Unhandled exception\. ([A-Za-z0-9_.]+)").Groups[1].Value;
                var reason = System.Text.RegularExpressions.Regex.Match(cli.Error,
                    @"(?:CryptographicException|ArgumentException): ([A-Za-z0-9 .,'()-]+)\r?\n").Groups[1].Value;
                var owner = System.Text.RegularExpressions.Regex.Match(cli.Error, @"at ([A-Za-z0-9_.]+)\(").Groups[1].Value;
                throw new Exception($"Actual file-custody operational CLI failed: exit={cli.ExitCode}; category={category}; reason={reason}; owner={owner}.");
            }
            var bundle = Path.Combine(directory, "cli-operational.ncp2");
            NetworkClosureExport.Run(Arguments.Parse([
                "--extend-network-closure", Path.Combine(directory, "network-initial.ncp2"),
                "--network-successor-source", output, "--network-id-hex", manifest.NetworkIdHex,
                "--genesis-core-hash", Convert.ToHexString(pin.AuthorityCoreHash.Span), "--output", bundle]));
            var decoded = XPointNetworkClosureWireCodec.DecodeResponse(File.ReadAllBytes(bundle));
            var authority = XPointNetworkAuthorityVerifier.Verify(pin, decoded.ExactAuthorityChain, decoded.ExactTimePolicyChain);
            if (authority.AuthorityGeneration != 1 || decoded.ExactViewChain.Count != 2 ||
                decoded.ExactActiveNodeDescriptors.Count != 3 || decoded.ExactHeadChain.Count != 2)
                throw new Exception("Completed CLI lost its authority history or three-node operational prefix.");
            var rejected = args.ToArray(); rejected[11] = Path.Combine(directory, "cli-operational-rejected");
            using var otherPhrase = DeepRecoveryV1.Generate(); var other = DeepIdV2Root.DeriveDid2(otherPhrase);
            var wrongCredential = Path.Combine(directory, "cli-wrong.did2"); File.WriteAllBytes(wrongCredential, other.CanonicalBytes.ToArray());
            rejected[^1] = wrongCredential;
            await RejectAsync<CryptographicException>(() => SuccessorCeremony.RunAsync(Arguments.Parse(rejected)));
            var refused = await RunBootstrapCliAsync(rejected);
            if (refused.ExitCode != 1 || !refused.Error.Contains("(CryptographicException)", StringComparison.Ordinal) ||
                refused.Error.Contains(directory, StringComparison.OrdinalIgnoreCase))
                throw new Exception("The actual successor CLI did not reject with sanitized diagnostics.");
            rejected[^1] = credential;
            var nodeEnv = Path.Combine(roots[0], ".env.node.prod");
            var oldEnv = File.ReadAllText(nodeEnv);
            File.WriteAllText(nodeEnv, oldEnv.Replace("node1.invalid", "foreign.invalid", StringComparison.Ordinal));
            try { await RejectAsync<CryptographicException>(() => SuccessorCeremony.RunAsync(Arguments.Parse(rejected))); }
            finally { File.WriteAllText(nodeEnv, oldEnv); }
            if (Directory.Exists(rejected[11])) throw new Exception("Rejected credential/origin published an operational output.");
            foreach (var (path, bytes) in retained)
                if (!File.ReadAllBytes(path).AsSpan().SequenceEqual(bytes))
                    throw new Exception("Operational completion changed existing identity or installed traffic/TLS custody.");
            Console.WriteLine("PASS operational file CLI: prepared authority, DID2 leaf, three retained identities, exact certificate origins and public closure");
        }
        finally { foreach (var bytes in retained.Values) CryptographicOperations.ZeroMemory(bytes); }

        static async Task RejectAsync<T>(Func<Task> action) where T : Exception
        {
            try { await action(); } catch (T) { return; }
            throw new Exception($"Expected {typeof(T).Name} operational file rejection.");
        }
    }
}
