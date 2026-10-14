using System.Security.Cryptography;
using System.Diagnostics;
using System.Text.Json;
using Deep.Protocol.XPointNetworkV1;
using Deep.Protocol.ApplicationCore;

internal static partial class OfflineAuthoringTests
{
    private static async Task TestOfflineAuthorityRenewalCommandAsync(string directory,
        VerifiedXPointNetworkBootstrap bootstrap, FileSigner signer, FileSigner[] witnesses,
        XPointNetworkOperationalNode[] nodes, AuthoredXPointNetworkOperationalGenesis genesis, ParsedDid2 requestedDid2)
    {
        var source = Path.Combine(directory, "network-initial");
        var custody = Path.Combine(directory, "offline-renewal-custody");
        Directory.CreateDirectory(Path.Combine(custody, "public"));
        Directory.CreateDirectory(Path.Combine(custody, "private"));
        var role = new CustodyRole("offline-root-1", Convert.ToHexString(signer.RootKeyId.Span),
            signer.KeyGeneration, Convert.ToHexString(signer.Ed25519PublicKey.Span),
            Convert.ToHexString(signer.CustodyDomainHash.Span));
        var manifest = new CustodyManifest("deep-production-authority-custody.v1", "prod", "Mr. X",
            Convert.ToHexString(bootstrap.GenesisPin.NetworkId.Span), [role]);
        File.WriteAllBytes(Path.Combine(custody, "public", "custody-manifest.v1.json"),
            JsonSerializer.SerializeToUtf8Bytes(manifest));
        var privatePath = Path.Combine(custody, "private", "offline-root-1.ed25519.seed");
        File.WriteAllBytes(privatePath, B(32, 0x21)); // The same synthetic seed as this fixture's root.
        var sourceManifest = File.ReadAllBytes(Path.Combine(source, "public-manifest.v1.json"));
        var originalSeed = File.ReadAllBytes(privatePath);
        try
        {
            var output1 = Path.Combine(directory, "offline-prepared-1");
            var args = Args(source, output1, bootstrap.Authority, 8_500, 300_000, 200_000);
            var actualCli = await RunBootstrapCliAsync(args);
            if (actualCli.ExitCode != 0 || actualCli.Error.Length != 0 ||
                !actualCli.Output.Contains("Offline same-key authority renewal prepared", StringComparison.Ordinal))
                throw new Exception("The actual offline CLI entry point failed its owned prepared command.");
            var prepared1 = SuccessorCeremony.ReadSource(output1);
            var authority1 = prepared1.VerifyAuthority(bootstrap.GenesisPin);
            if (prepared1.Manifest.Schema != SuccessorCeremony.PreparedAuthoritySchema ||
                authority1.AuthorityGeneration != 1 || authority1.Dts1PolicyGeneration != 1 ||
                !authority1.RootKeys[0].Ed25519PublicKey.Span.SequenceEqual(signer.Ed25519PublicKey.Span))
                throw new Exception("Offline command did not preserve the original root in a verified prepared successor.");
            RequirePreservedSource(source, output1);
            await TestOperationalFileCompletionAsync(directory, custody, manifest, output1, witnesses,
                nodes, genesis, requestedDid2, bootstrap.GenesisPin);
            await RejectAsync<IOException>(() => AuthorityRenewalCeremony.RunAsync(Arguments.Parse(args)));
            var output2 = Path.Combine(directory, "offline-prepared-2");
            await AuthorityRenewalCeremony.RunAsync(Arguments.Parse(Args(output1, output2,
                authority1, 19_000, 400_000, 350_000)));
            var prepared2 = SuccessorCeremony.ReadSource(output2);
            if (prepared2.VerifyAuthority(bootstrap.GenesisPin).AuthorityGeneration != 2)
                throw new Exception("A second offline renewal did not retain its paired predecessor chain.");
            RequirePreservedSource(output1, output2);

            // A prepared pair is not a coherent operational successor and may
            // not be emitted directly as current/public NCP2 distribution.
            var rejectedBundle = Path.Combine(directory, "offline-prepared-rejected.ncp2");
            await RejectAsync<CryptographicException>(() =>
            {
                NetworkClosureExport.Run(Arguments.Parse([
                    "--extend-network-closure", Path.Combine(directory, "network-initial.ncp2"),
                    "--network-successor-source", output1,
                    "--network-id-hex", manifest.NetworkIdHex,
                    "--genesis-core-hash", Convert.ToHexString(bootstrap.GenesisPin.AuthorityCoreHash.Span),
                    "--output", rejectedBundle]));
                return Task.CompletedTask;
            });
            if (File.Exists(rejectedBundle)) throw new Exception("An incomplete authority preparation was distributed.");

            var invalidOutput = Path.Combine(directory, "offline-renewal-rejected");
            var wrongAuthority = Args(source, invalidOutput, bootstrap.Authority, 8_500, 30_000, 20_000);
            wrongAuthority[9] = new string('f', 64);
            var wrongPolicy = Args(source, invalidOutput, bootstrap.Authority, 8_500, 30_000, 20_000);
            wrongPolicy[11] = new string('f', 64);
            // Remove only the owned synthetic seed. These public-input failures
            // must still reject cryptographically before trying to open custody.
            File.Move(privatePath, privatePath + ".retained");
            try
            {
                await RejectAsync<CryptographicException>(() => AuthorityRenewalCeremony.RunAsync(Arguments.Parse(wrongAuthority)));
                await RejectAsync<CryptographicException>(() => AuthorityRenewalCeremony.RunAsync(Arguments.Parse(wrongPolicy)));
                var refusedCli = await RunBootstrapCliAsync(wrongPolicy);
                if (refusedCli.ExitCode != 1 || !refusedCli.Error.Contains("(CryptographicException)", StringComparison.Ordinal) ||
                    refusedCli.Error.Contains(directory, StringComparison.OrdinalIgnoreCase) ||
                    refusedCli.Error.Contains(".seed", StringComparison.OrdinalIgnoreCase))
                    throw new Exception("The CLI did not fail with sanitized diagnostics before opening missing private custody.");
            }
            finally { File.Move(privatePath + ".retained", privatePath); }
            var afterExpiryOutput = Path.Combine(directory, "offline-after-expiry");
            await AuthorityRenewalCeremony.RunAsync(Arguments.Parse(
                Args(source, afterExpiryOutput, bootstrap.Authority, 10_001, 30_000, 20_000)));
            var afterExpiry = SuccessorCeremony.ReadSource(afterExpiryOutput).VerifyAuthority(bootstrap.GenesisPin);
            if (afterExpiry.IssuedAt != 10_001 || afterExpiry.NotBefore != 10_001 ||
                afterExpiry.AuthorityGeneration != 1 ||
                !SuccessorCeremony.ReadSource(afterExpiryOutput).Many("xna1")[0].AsSpan().SequenceEqual(bootstrap.ExactXna1.Span))
                throw new Exception("Offline root continuity backdated time or revived its expired predecessor.");
            RequirePreservedSource(source, afterExpiryOutput);
            await RejectAsync<ArgumentException>(() => AuthorityRenewalCeremony.RunAsync(Arguments.Parse(
                Args(source, invalidOutput, bootstrap.Authority, bootstrap.Authority.NotBefore - 1, 30_000, 20_000))));
            await RejectAsync<ArgumentException>(() => AuthorityRenewalCeremony.RunAsync(Arguments.Parse(
                Args(source, invalidOutput, bootstrap.Authority, 8_500, 30_000, 8_999))));
            if (Directory.Exists(invalidOutput)) throw new Exception("Rejected offline renewal published an output.");
            if (!File.ReadAllBytes(Path.Combine(source, "public-manifest.v1.json")).AsSpan().SequenceEqual(sourceManifest) ||
                !File.ReadAllBytes(privatePath).AsSpan().SequenceEqual(originalSeed))
                throw new Exception("Offline renewal changed source or private root custody.");
            Console.WriteLine("PASS offline authority command: paired same-key renewals, independent predecessor guards, prepared-only export and retained custody");
        }
        finally { CryptographicOperations.ZeroMemory(originalSeed); }

        string[] Args(string input, string output, VerifiedXPointNetworkAuthority prior,
            ulong observed, ulong authorityExpires, ulong policyExpires) =>
            ["--renew-authority-from", input, "--authority-root", custody,
             "--network-id-hex", manifest.NetworkIdHex,
             "--genesis-core-hash", Convert.ToHexString(bootstrap.GenesisPin.AuthorityCoreHash.Span),
             "--protected-authority-core-hash", Convert.ToHexString(prior.AuthorityCoreHash.Span),
             "--protected-dts1-policy-hash", Convert.ToHexString(prior.TimeSourcePolicyHash.Span),
             "--observed-unix", observed.ToString(System.Globalization.CultureInfo.InvariantCulture),
             "--authority-expires-unix", authorityExpires.ToString(System.Globalization.CultureInfo.InvariantCulture),
             "--time-policy-expires-unix", policyExpires.ToString(System.Globalization.CultureInfo.InvariantCulture), "--output", output];

        static void RequirePreservedSource(string previousPath, string currentPath)
        {
            var previous = SuccessorCeremony.ReadSource(previousPath);
            var current = SuccessorCeremony.ReadSource(currentPath);
            foreach (var roleName in previous.Manifest.Artifacts.Select(entry => entry.Role).Distinct(StringComparer.Ordinal))
            {
                var old = previous.Many(roleName); var next = current.Many(roleName);
                var expected = old.Count + (roleName is "xna1" or "dts1" ? 1 : 0);
                if (next.Count != expected || old.Where((bytes, index) => !bytes.AsSpan().SequenceEqual(next[index])).Any())
                    throw new Exception("Prepared renewal changed existing exact source records.");
            }
        }
        static async Task RejectAsync<T>(Func<Task> action) where T : Exception
        {
            try { await action(); }
            catch (T) { return; }
            throw new Exception($"Expected {typeof(T).Name} offline command rejection.");
        }
    }

    private static async Task<(int ExitCode, string Output, string Error)> RunBootstrapCliAsync(string[] arguments)
    {
        var start = new ProcessStartInfo("dotnet")
        {
            UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardOutput = true, RedirectStandardError = true
        };
        start.ArgumentList.Add(typeof(AuthorityRenewalCeremony).Assembly.Location);
        foreach (var value in arguments) start.ArgumentList.Add(value);
        using var process = Process.Start(start) ?? throw new Exception("The owned operator CLI did not start.");
        var output = process.StandardOutput.ReadToEndAsync();
        var error = process.StandardError.ReadToEndAsync();
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        try { await process.WaitForExitAsync(deadline.Token); }
        catch (OperationCanceledException)
        {
            process.Kill(entireProcessTree: true);
            await process.WaitForExitAsync(CancellationToken.None);
            throw new TimeoutException("The owned synthetic operator CLI exceeded its test budget.");
        }
        return (process.ExitCode, await output, await error);
    }
}
