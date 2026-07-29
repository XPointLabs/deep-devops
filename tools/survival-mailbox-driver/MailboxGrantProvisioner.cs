using System.Security.Cryptography;
using System.Text.Json;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

/// <summary>
/// Host-only development credential issuer.  This intentionally accepts public
/// holder keys only: SessionIdentityProvider retains every holder private key.
/// </summary>
static class MailboxGrantProvisioner
{
    private const string Android = "android";
    private const string Windows = "windows";
    private const string PhysicalCoordinator = "192.168.1.44";
    private const int CoordinatorPort = 41801;
    private static readonly string[] ExpectedReplicaIds =
    [
        "4cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29",
        "7422b9887598068e32c4448a949adb290d0f4e35b9e01b0ee5f1a1e600fe2674"
    ];

    public static ProvisionedBundles Provision(Arguments arguments)
    {
        Require(arguments.DevelopmentOnly, "Provisioning requires --development-only.");
        var android = PublicKey(arguments.AndroidHolderPublicKey, "android holder");
        var windows = PublicKey(arguments.WindowsHolderPublicKey, "windows holder");
        Require(!CryptographicOperations.FixedTimeEquals(android, windows),
            "Exactly two distinct holder public keys are required.");
        Require(!string.IsNullOrWhiteSpace(arguments.IssuerSeedPath)
            && File.Exists(arguments.IssuerSeedPath), "An existing --issuer-seed-path is required.");
        Require(!string.IsNullOrWhiteSpace(arguments.OutputDirectory), "--output-directory is required.");
        Require(!string.IsNullOrWhiteSpace(arguments.MailboxSecretDirectory),
            "--mailbox-secret-directory is required (it is host-only and must not be an output directory).");
        AssertNoReparseTraversal(arguments.IssuerSeedPath!);
        AssertNoReparseTraversal(arguments.AuthorityPublicPath);

        var issuerSeed = ReadSeed(arguments.IssuerSeedPath!);
        try
        {
            var authority = LoadAuthority(arguments);
            var crypto = new SodiumMailboxCapabilityCrypto();
            Require(CryptographicOperations.FixedTimeEquals(
                crypto.GetPublicKey(issuerSeed), Hex(authority.IssuerPublicKey, 32, "issuer public key")),
                "Issuer seed does not match the authority issuer public key.");

            var outputDirectory = Path.GetFullPath(arguments.OutputDirectory!);
            var secretDirectory = Path.GetFullPath(arguments.MailboxSecretDirectory!);
            Require(!PathsOverlap(outputDirectory, secretDirectory),
                "Mailbox secrets must not be written in, above, or below the public output directory.");
            Directory.CreateDirectory(outputDirectory);
            Directory.CreateDirectory(secretDirectory);
            AssertNoReparseTraversal(outputDirectory);
            AssertNoReparseTraversal(secretDirectory);
            AssertWindowsSecretAcl(secretDirectory);

            var authorityHash = Sha256(File.ReadAllBytes(arguments.AuthorityPublicPath));
            var androidSecret = ReadOrCreateMailboxSecret(secretDirectory, Android);
            var windowsSecret = ReadOrCreateMailboxSecret(secretDirectory, Windows);
            var androidMailbox = Hmac(androidSecret, "deep.mailbox.blinded-mailbox-id.v1|android");
            var windowsMailbox = Hmac(windowsSecret, "deep.mailbox.blinded-mailbox-id.v1|windows");
            var androidBundle = BuildBundle(Android, android, windows, androidMailbox, windowsMailbox,
                issuerSeed, authority, authorityHash, androidSecret);
            var windowsBundle = BuildBundle(Windows, windows, android, windowsMailbox, androidMailbox,
                issuerSeed, authority, authorityHash, windowsSecret);
            try
            {
                var androidPath = Path.Combine(outputDirectory, "android.mailbox-credentials.v1.json");
                var windowsPath = Path.Combine(outputDirectory, "windows.mailbox-credentials.v1.json");
                WriteSanitized(androidPath, androidBundle, issuerSeed);
                WriteSanitized(windowsPath, windowsBundle, issuerSeed);
                return new ProvisionedBundles(
                    [Path.GetFileName(androidPath), Path.GetFileName(windowsPath)],
                    new Dictionary<string, string>(StringComparer.Ordinal)
                    {
                        [Path.GetFileName(androidPath)] = Sha256(File.ReadAllBytes(androidPath)),
                        [Path.GetFileName(windowsPath)] = Sha256(File.ReadAllBytes(windowsPath))
                    });
            }
            finally
            {
                CryptographicOperations.ZeroMemory(androidBundle.MailboxSecret);
                CryptographicOperations.ZeroMemory(windowsBundle.MailboxSecret);
                CryptographicOperations.ZeroMemory(androidMailbox);
                CryptographicOperations.ZeroMemory(windowsMailbox);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(issuerSeed);
        }
    }

    public static void Verify(Arguments arguments)
    {
        Require(!string.IsNullOrWhiteSpace(arguments.AndroidBundle) && File.Exists(arguments.AndroidBundle),
            "An existing --android-bundle is required.");
        Require(!string.IsNullOrWhiteSpace(arguments.WindowsBundle) && File.Exists(arguments.WindowsBundle),
            "An existing --windows-bundle is required.");
        var androidText = File.ReadAllText(arguments.AndroidBundle!);
        var windowsText = File.ReadAllText(arguments.WindowsBundle!);
        RejectPrivateMaterial(androidText, []);
        RejectPrivateMaterial(windowsText, []);
        using var android = JsonDocument.Parse(androidText);
        using var windows = JsonDocument.Parse(windowsText);
        VerifyBundle(android.RootElement, Android, windows.RootElement, Windows);
        VerifyBundle(windows.RootElement, Windows, android.RootElement, Android);
    }

    private static void VerifyBundle(JsonElement bundle, string identity, JsonElement peer, string peerIdentity)
    {
        Require(bundle.GetProperty("schemaVersion").GetInt32() == 1
            && bundle.GetProperty("developmentOnly").GetBoolean()
            && bundle.GetProperty("identity").GetString() == identity,
            "Bundle schema is invalid.");
        var ownMailbox = bundle.GetProperty("ownMailbox").GetProperty("blindedMailboxId").GetString()!;
        var peerMailbox = bundle.GetProperty("peerMailboxRoute").GetProperty("blindedMailboxId").GetString()!;
        Require(peerMailbox == peer.GetProperty("ownMailbox").GetProperty("blindedMailboxId").GetString()
            && peerMailbox != ownMailbox && bundle.GetProperty("peerMailboxRoute").GetProperty("holderPublicKey").GetString()
                == peer.GetProperty("holderPublicKey").GetString(),
            "Peer route must reference only the counterpart public mailbox.");
        var holder = Hex(bundle.GetProperty("holderPublicKey").GetString(), 32, "holder public key");
        Require(bundle.GetProperty("authorityHashSha256").GetString() == peer.GetProperty("authorityHashSha256").GetString()
            && bundle.GetProperty("networkId").GetString() == peer.GetProperty("networkId").GetString()
            && bundle.GetProperty("issuerPublicKey").GetString() == peer.GetProperty("issuerPublicKey").GetString()
            && bundle.GetProperty("coordinatorLanUrl").GetString() == peer.GetProperty("coordinatorLanUrl").GetString()
            && bundle.GetProperty("currentEpoch").GetRawText() == peer.GetProperty("currentEpoch").GetRawText()
            && bundle.GetProperty("nextEpoch").GetRawText() == peer.GetProperty("nextEpoch").GetRawText()
            && bundle.GetProperty("replicas").GetRawText() == peer.GetProperty("replicas").GetRawText(),
            "Both bundles must bind the exact same authority material.");
        var issuer = Hex(bundle.GetProperty("issuerPublicKey").GetString(), 32, "issuer public key");
        var network = Hex(bundle.GetProperty("networkId").GetString(), 16, "network id");
        var current = ReadBundleEpoch(bundle.GetProperty("currentEpoch"), 1);
        var next = ReadBundleEpoch(bundle.GetProperty("nextEpoch"), 2);
        Require(current.NotBefore < next.NotBefore && next.NotBefore <= current.ExpiresAt
            && current.ExpiresAt < next.ExpiresAt, "Bundle epoch windows are not canonical E/E+1 overlap.");
        var own = bundle.GetProperty("ownMailbox").GetProperty("retrieveAndAcknowledgeGrants");
        var deposit = bundle.GetProperty("peerMailboxRoute").GetProperty("depositGrants");
        VerifyGrantSet(own, MailboxCapabilityDomain.Retrieve, holder, issuer, network, current, next, "retrieve grant");
        VerifyGrantSet(deposit, MailboxCapabilityDomain.Deposit, holder, issuer, network, current, next, "deposit grant");
        CryptographicOperations.ZeroMemory(holder);
        CryptographicOperations.ZeroMemory(issuer);
        CryptographicOperations.ZeroMemory(network);
        Require(peer.GetProperty("identity").GetString() == peerIdentity, "Counterpart identity is invalid.");
    }

    private static void VerifyGrantSet(JsonElement grants, MailboxCapabilityDomain domain, byte[] holder, byte[] issuer,
        byte[] network, BundleEpoch current, BundleEpoch next, string label)
    {
        Require(grants.ValueKind == JsonValueKind.Array && grants.GetArrayLength() == 2, $"{label} set must contain E and E+1.");
        ulong expectedEpoch = 1;
        foreach (var item in grants.EnumerateArray())
        {
            var encoded = Convert.FromBase64String(item.GetProperty("canonicalGrant").GetString()!);
            var grant = MailboxAuthenticatedCapabilityCodec.DecodeGrant(encoded);
            var expected = expectedEpoch == 1 ? current : next;
            Require(item.GetProperty("epoch").GetUInt64() == expectedEpoch
                && grant.Epoch == expectedEpoch && grant.Generation == expectedEpoch
                && grant.Domain == domain && grant.Lifecycle == MailboxCapabilityLifecycle.Active
                && grant.NotBeforeUnixSeconds == expected.NotBefore && grant.ExpiresAtUnixSeconds == expected.ExpiresAt
                && grant.OverlapUntilUnixSeconds == 0 && grant.Serial.Span.IndexOfAnyExcept((byte)0) >= 0
                && CryptographicOperations.FixedTimeEquals(grant.HolderPublicKey.Span, holder)
                && CryptographicOperations.FixedTimeEquals(grant.IssuerPublicKey.Span, issuer)
                && CryptographicOperations.FixedTimeEquals(grant.NetworkId.Span, network)
                && CryptographicOperations.FixedTimeEquals(grant.PlacementCommitment.Span, expected.PlacementCommitment)
                && CryptographicOperations.FixedTimeEquals(grant.MembershipCommitment.Span, expected.MembershipCommitment)
                && new SodiumMailboxCapabilityCrypto().VerifyIssuer(issuer,
                    MailboxAuthenticatedCapabilityCodec.GetGrantSigningBytes(grant), grant.IssuerSignature.Span)
                && CryptographicOperations.FixedTimeEquals(encoded,
                    MailboxAuthenticatedCapabilityCodec.EncodeGrant(grant)),
                $"{label} is not bound to its holder, domain, or epoch.");
            Require(item.GetProperty("sha256").GetString() == Sha256(encoded), $"{label} hash is invalid.");
            expectedEpoch++;
        }
    }

    private static BundleEpoch ReadBundleEpoch(JsonElement value, ulong expectedEpoch)
    {
        Require(value.GetProperty("epoch").GetUInt64() == expectedEpoch, "Bundle epoch is invalid.");
        var notBefore = value.GetProperty("notBeforeUnixSeconds").GetUInt64();
        var expiresAt = value.GetProperty("expiresAtUnixSeconds").GetUInt64();
        Require(notBefore < expiresAt, "Bundle epoch window is invalid.");
        return new BundleEpoch(notBefore, expiresAt,
            Hex(value.GetProperty("placementCommitment").GetString(), 32, "placement commitment"),
            Hex(value.GetProperty("membershipCommitment").GetString(), 32, "membership commitment"));
    }

    private static ProvisioningAuthority LoadAuthority(Arguments arguments)
    {
        Require(!string.IsNullOrWhiteSpace(arguments.AuthorityPublicPath)
            && File.Exists(arguments.AuthorityPublicPath), "An existing --authority-public path is required.");
        var authority = JsonSerializer.Deserialize<PublicAuthority>(File.ReadAllText(arguments.AuthorityPublicPath),
            new JsonSerializerOptions { PropertyNameCaseInsensitive = true })
            ?? throw new InvalidDataException("Authority JSON is invalid.");
        Require(authority.SchemaVersion == 2 && authority.Protocol == "P10E/MCP2/MAU2/MIP1/RIP1/PRQ2",
            "Only the signed driver authority schema v2 is accepted.");
        Require(authority.MinimumGeneration == 1 && authority.MaximumGeneration == 2
            && authority.Epochs.Count == 2 && authority.Epochs[0].Epoch == 1 && authority.Epochs[1].Epoch == 2,
            "Authority must contain E and E+1 only.");
        Require(authority.ReplicaIds.Count == 2 && authority.ReplicaSigningPublicKeys.Count == 2,
            "Authority must contain exactly two client replicas.");
        Require(Hex(authority.NetworkId, 16, "network id").Length == 16, "Network id is invalid.");
        _ = Hex(authority.IssuerPublicKey, 32, "issuer public key");
        var coordinator = ValidateCoordinator(arguments, authority.CoordinatorUrl);

        var current = ParseEpoch(authority.Epochs[0], 1);
        var next = ParseEpoch(authority.Epochs[1], 2);
        Require(authority.IssuerValidFromUnixSeconds == current.NotBefore
            && authority.IssuerValidUntilUnixSeconds == next.ExpiresAt
            && current.NotBefore < next.NotBefore && next.NotBefore <= current.ExpiresAt
            && current.ExpiresAt < next.ExpiresAt
            && current.ExpiresAt - current.NotBefore <= 7200
            && next.ExpiresAt - next.NotBefore <= 10800,
            "Epoch windows must be bounded and overlap.");
        var replicas = authority.ReplicaIds.Select((id, i) => new Replica(
            id, authority.ReplicaSigningPublicKeys[i])).ToArray();
        Require(replicas.DistinctBy(item => item.Id, StringComparer.Ordinal).Count() == 2
            && replicas.DistinctBy(item => item.SigningPublicKey, StringComparer.Ordinal).Count() == 2,
            "The two replicas must be distinct.");
        Require(replicas.Select(item => item.Id).SequenceEqual(ExpectedReplicaIds, StringComparer.Ordinal),
            "The authority must use the exact xnode-1/xnode-2 replica ids.");
        for (var i = 0; i < 2; i++)
        {
            Require(replicas[i].Id == current.Replicas[i].Id && replicas[i].Id == next.Replicas[i].Id
                && replicas[i].SigningPublicKey == current.Replicas[i].SigningPublicKey
                && replicas[i].SigningPublicKey == next.Replicas[i].SigningPublicKey,
                "Replica public material does not bind both epochs.");
        }
        return new ProvisioningAuthority(authority.NetworkId, authority.IssuerPublicKey, coordinator,
            current, next, replicas);
    }

    private static Uri ValidateCoordinator(Arguments arguments, string value)
    {
        Require(Uri.TryCreate(value, UriKind.Absolute, out var authorityUrl)
            && Uri.TryCreate(arguments.CoordinatorUrl, UriKind.Absolute, out var commandUrl)
            && authorityUrl == commandUrl && string.IsNullOrEmpty(authorityUrl.UserInfo)
            && authorityUrl.AbsolutePath == "/" && string.IsNullOrEmpty(authorityUrl.Query)
            && string.IsNullOrEmpty(authorityUrl.Fragment) && authorityUrl.Port == CoordinatorPort
            && System.Net.IPAddress.TryParse(authorityUrl.Host, out var address)
            && !System.Net.IPAddress.IsLoopback(address),
            "Coordinator must be the exact non-loopback IPv4 authority URL on port 41801.");
        Require(authorityUrl!.Scheme == Uri.UriSchemeHttps || (authorityUrl.Scheme == Uri.UriSchemeHttp
            && arguments.AllowHttp), "HTTP requires --allow-http with --development-only.");
        if (arguments.PhysicalDev)
        {
            Require(authorityUrl.Scheme == Uri.UriSchemeHttp && authorityUrl.Host == PhysicalCoordinator,
                "--physical-dev requires http://192.168.1.44:41801.");
        }
        return authorityUrl;
    }

    private static Epoch ParseEpoch(PublicEpochAuthority source, ulong epoch)
    {
        Require(source.Epoch == epoch && source.Replicas.Count == 6
            && source.NotBeforeUnixSeconds < source.ExpiresAtUnixSeconds,
            "Authority epoch is invalid.");
        var placementId = Hex(source.PlacementId, 32, "placement id");
        var placementCommitment = Hex(source.PlacementCommitment, 32, "placement commitment");
        Require(CryptographicOperations.FixedTimeEquals(
            MailboxPlacementCommitment.Compute(new BlindedPlacementId(placementId)), placementCommitment),
            "Placement commitment is invalid.");
        _ = Hex(source.MembershipCommitment, 32, "membership commitment");
        var replicas = source.Replicas.Select((item, index) =>
        {
            Require(item.Node == index + 1 && item.RouterId.Length == 64, "Replica id is invalid.");
            _ = Hex(item.RouterId, 32, "replica id");
            _ = Hex(item.SigningPublicKey, 32, "replica signing public key");
            return new Replica(item.RouterId, item.SigningPublicKey);
        }).ToArray();
        return new Epoch(source.Epoch, source.NotBeforeUnixSeconds, source.ExpiresAtUnixSeconds,
            source.MembershipCommitment, source.PlacementId, source.PlacementCommitment, replicas);
    }

    private static Bundle BuildBundle(string identity, byte[] holder, byte[] peerHolder, byte[] mailbox,
        byte[] peerMailbox, byte[] issuerSeed, ProvisioningAuthority authority, string authorityHash,
        byte[] mailboxSecret)
    {
        var own = Grants(identity, "retrieve", holder, mailbox, issuerSeed, authority);
        var deposit = Grants(identity, "deposit-peer", holder, peerMailbox, issuerSeed, authority);
        return new Bundle(identity, holder, peerHolder, mailbox, peerMailbox, authority, authorityHash, own, deposit, mailboxSecret);
    }

    private static GrantSet Grants(string identity, string role, byte[] holder, byte[] mailbox,
        byte[] issuerSeed, ProvisioningAuthority authority)
    {
        var crypto = new SodiumMailboxCapabilityCrypto();
        Grant Grant(Epoch epoch, MailboxCapabilityDomain domain)
        {
            var serial = Hmac(mailbox, $"deep.mailbox.v1|{identity}|{role}|{epoch.Value}|serial")[..16];
            try
            {
                var signed = crypto.SignGrant(new MailboxAuthenticatedGrant
                {
                    Domain = domain,
                    Lifecycle = MailboxCapabilityLifecycle.Active,
                    NetworkId = Hex(authority.NetworkId, 16, "network id"),
                    Epoch = epoch.Value,
                    Generation = epoch.Value,
                    Serial = serial,
                    NotBeforeUnixSeconds = epoch.NotBefore,
                    ExpiresAtUnixSeconds = epoch.ExpiresAt,
                    OverlapUntilUnixSeconds = 0,
                    PlacementCommitment = Hex(epoch.PlacementCommitment, 32, "placement commitment"),
                    MembershipCommitment = Hex(epoch.MembershipCommitment, 32, "membership commitment"),
                    IssuerPublicKey = Hex(authority.IssuerPublicKey, 32, "issuer public key"),
                    HolderPublicKey = holder.ToArray(),
                    IssuerSignature = new byte[MailboxAuthenticatedCapabilityLimits.SignatureLength]
                }, issuerSeed);
                var encoded = MailboxAuthenticatedCapabilityCodec.EncodeGrant(signed);
                return new Grant(epoch.Value, Convert.ToBase64String(encoded), Sha256(encoded));
            }
            finally { CryptographicOperations.ZeroMemory(serial); }
        }
        var domain = role == "retrieve" ? MailboxCapabilityDomain.Retrieve : MailboxCapabilityDomain.Deposit;
        return new GrantSet(Grant(authority.Current, domain), Grant(authority.Next, domain));
    }

    private static void WriteSanitized(string path, Bundle bundle, byte[] issuerSeed)
    {
        var document = new
        {
            schemaVersion = 1,
            developmentOnly = true,
            identity = bundle.Identity,
            authorityHashSha256 = bundle.AuthorityHash,
            networkId = bundle.Authority.NetworkId,
            issuerPublicKey = bundle.Authority.IssuerPublicKey,
            coordinatorLanUrl = bundle.Authority.Coordinator.ToString().TrimEnd('/'),
            holderPublicKey = Lower(bundle.Holder),
            currentEpoch = EpochJson(bundle.Authority.Current),
            nextEpoch = EpochJson(bundle.Authority.Next),
            replicas = bundle.Authority.Replicas.Select(item => new { id = item.Id, signingPublicKey = item.SigningPublicKey }),
            ownMailbox = new
            {
                blindedMailboxId = Lower(bundle.Mailbox),
                retrieveAndAcknowledgeGrants = GrantJson(bundle.Own)
            },
            peerMailboxRoute = new
            {
                holderPublicKey = Lower(bundle.PeerHolder),
                blindedMailboxId = Lower(bundle.PeerMailbox),
                depositGrants = GrantJson(bundle.Deposit)
            },
            hashes = new { mailboxRouteSha256 = Sha256(bundle.Mailbox) }
        };
        var json = JsonSerializer.Serialize(document, new JsonSerializerOptions { WriteIndented = false }) + "\n";
        RejectPrivateMaterial(json, issuerSeed);
        var temporary = path + ".tmp-" + Guid.NewGuid().ToString("N");
        AssertNoReparseTraversal(temporary);
        File.WriteAllText(temporary, json, new System.Text.UTF8Encoding(false));
        RejectPrivateMaterial(File.ReadAllText(temporary), issuerSeed);
        File.Move(temporary, path, true);
    }

    private static object EpochJson(Epoch epoch) => new
    {
        epoch = epoch.Value,
        notBeforeUnixSeconds = epoch.NotBefore,
        expiresAtUnixSeconds = epoch.ExpiresAt,
        membershipCommitment = epoch.MembershipCommitment,
        placementId = epoch.PlacementId,
        placementCommitment = epoch.PlacementCommitment
    };

    private static object GrantJson(GrantSet set) => new[]
    {
        new { epoch = set.Current.Epoch, canonicalGrant = set.Current.CanonicalGrant, sha256 = set.Current.Hash },
        new { epoch = set.Next.Epoch, canonicalGrant = set.Next.CanonicalGrant, sha256 = set.Next.Hash }
    };

    private static byte[] ReadOrCreateMailboxSecret(string directory, string identity)
    {
        var path = Path.Combine(directory, identity + ".mailbox-secret");
        AssertNoReparseTraversal(path);
        var secret = File.Exists(path) ? Convert.FromHexString(File.ReadAllText(path).Trim()) : RandomNumberGenerator.GetBytes(32);
        Require(secret.Length == 32 && secret.AsSpan().IndexOfAnyExcept((byte)0) >= 0,
            "Host-only mailbox secret is invalid.");
        if (!File.Exists(path))
        {
            File.WriteAllText(path, Lower(secret) + "\n", new System.Text.UTF8Encoding(false));
            if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
        AssertNoReparseTraversal(path);
        if (OperatingSystem.IsWindows()) AssertWindowsSecretAcl(path);
        return secret;
    }

    private static byte[] ReadSeed(string path)
    {
        var seed = Convert.FromHexString(File.ReadAllText(path).Trim());
        Require(seed.Length == 32 && seed.AsSpan().IndexOfAnyExcept((byte)0) >= 0, "Issuer seed is invalid.");
        return seed;
    }

    private static void RejectPrivateMaterial(string output, byte[] issuerSeed)
    {
        Require(issuerSeed.Length == 0 || !output.Contains(Lower(issuerSeed), StringComparison.OrdinalIgnoreCase),
            "Refusing to write output containing issuer seed material.");
        foreach (var forbidden in new[] { "issuerSeed", "privateKey", "privateSeed", "sessionId", "mailboxSecret" })
            Require(!output.Contains(forbidden, StringComparison.OrdinalIgnoreCase), "Refusing private material in output.");
    }

    private static byte[] PublicKey(string? value, string label) => Hex(value, 32, label);
    private static byte[] Hex(string? value, int size, string label)
    {
        Require(value is not null && value.Length == size * 2 && value.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f'),
            $"{label} must be lowercase hexadecimal.");
        var bytes = Convert.FromHexString(value!);
        Require(bytes.AsSpan().IndexOfAnyExcept((byte)0) >= 0, $"{label} must be nonzero.");
        return bytes;
    }
    private static byte[] Hmac(byte[] key, string value) => HMACSHA256.HashData(key, System.Text.Encoding.UTF8.GetBytes(value));
    private static string Sha256(byte[] value) => Lower(SHA256.HashData(value));
    private static string Lower(byte[] value) => Convert.ToHexString(value).ToLowerInvariant();
    private static bool PathsOverlap(string first, string second)
    {
        var normalizedFirst = first.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) + Path.DirectorySeparatorChar;
        var normalizedSecond = second.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) + Path.DirectorySeparatorChar;
        return normalizedFirst.StartsWith(normalizedSecond, StringComparison.OrdinalIgnoreCase)
            || normalizedSecond.StartsWith(normalizedFirst, StringComparison.OrdinalIgnoreCase);
    }
    private static void AssertNoReparseTraversal(string path)
    {
        var full = Path.GetFullPath(path);
        if ((File.Exists(full) || Directory.Exists(full))
            && (File.GetAttributes(full) & FileAttributes.ReparsePoint) != 0)
            throw new InvalidDataException("Reparse-point files and directories are not accepted for mailbox provisioning.");
        for (var directory = new DirectoryInfo(Path.GetDirectoryName(full) ?? full);
             directory is not null;
             directory = directory.Parent)
        {
            if (directory.Exists && (directory.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new InvalidDataException("Reparse-point path traversal is not accepted for mailbox provisioning.");
        }
    }
    private static void AssertWindowsSecretAcl(string path)
    {
        if (!OperatingSystem.IsWindows()) return;
        using var process = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
        {
            FileName = "icacls",
            Arguments = "\"" + path.Replace("\"", "\"\"") + "\"",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        }) ?? throw new InvalidDataException("Unable to inspect the Windows secret ACL.");
        var acl = process.StandardOutput.ReadToEnd();
        process.WaitForExit();
        Require(process.ExitCode == 0
            && !System.Text.RegularExpressions.Regex.IsMatch(acl,
                @"(?im)^(?=.*(?:Everyone|BUILTIN\\Users|Authenticated Users))(?=.*\((?:F|M|W|WD)\)).*$"),
            "Mailbox secret root/file ACL permits broad write access.");
    }
    private static void Require(bool condition, string message) { if (!condition) throw new InvalidDataException(message); }

    private sealed record Replica(string Id, string SigningPublicKey);
    private sealed record Epoch(ulong Value, ulong NotBefore, ulong ExpiresAt, string MembershipCommitment,
        string PlacementId, string PlacementCommitment, Replica[] Replicas);
    private sealed record ProvisioningAuthority(string NetworkId, string IssuerPublicKey, Uri Coordinator,
        Epoch Current, Epoch Next, Replica[] Replicas);
    private sealed record Grant(ulong Epoch, string CanonicalGrant, string Hash);
    private sealed record GrantSet(Grant Current, Grant Next);
    private sealed record BundleEpoch(ulong NotBefore, ulong ExpiresAt, byte[] PlacementCommitment, byte[] MembershipCommitment);
    private sealed record Bundle(string Identity, byte[] Holder, byte[] PeerHolder, byte[] Mailbox, byte[] PeerMailbox,
        ProvisioningAuthority Authority, string AuthorityHash, GrantSet Own, GrantSet Deposit, byte[] MailboxSecret);
}

sealed record ProvisionedBundles(IReadOnlyList<string> BundleNames, IReadOnlyDictionary<string, string> OutputHashes);
