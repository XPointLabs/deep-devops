using System.ComponentModel;
using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Microsoft.Win32.SafeHandles;
using XNode.Core;

/// <summary>
/// Host-only development credential issuer. Holder private keys remain in the
/// device SessionIdentityProvider and are never accepted by this process.
/// </summary>
static class MailboxGrantProvisioner
{
    private const string Android = "android";
    private const string Windows = "windows";
    private const string PhysicalCoordinator = "http://192.168.1.44:41801";
    private static readonly string[] ExpectedReplicaIds =
    [
        "4cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29",
        "7422b9887598068e32c4448a949adb290d0f4e35b9e01b0ee5f1a1e600fe2674"
    ];

    public static ProvisionedBundles Provision(Arguments arguments)
    {
        Require(arguments.DevelopmentOnly, "Provisioning requires --development-only.");
        var androidHolder = PublicKey(arguments.AndroidHolderPublicKey, "android holder");
        var windowsHolder = PublicKey(arguments.WindowsHolderPublicKey, "windows holder");
        Require(!CryptographicOperations.FixedTimeEquals(androidHolder, windowsHolder),
            "Exactly two distinct holder public keys are required.");
        RequireFile(arguments.IssuerSeedPath, "issuer seed");
        AssertSecretFilePermissions(arguments.IssuerSeedPath!);
        var outputRoot = RequireProtectedRoot(arguments.OutputDirectory, "output");
        var secretRoot = RequireProtectedRoot(arguments.MailboxSecretDirectory, "mailbox secret");
        Require(!PathsOverlap(outputRoot, secretRoot),
            "Mailbox secrets must not be written in, above, or below the output root.");

        var issuerSeed = ReadSecretFile(arguments.IssuerSeedPath!);
        try
        {
            var issuerPublicKey = Lower(new SodiumMailboxCapabilityCrypto().GetPublicKey(issuerSeed));
            Require(arguments.ExpectedIssuerPublicKey == issuerPublicKey,
                "The protected expected issuer public key does not match the issuer seed.");
            var authority = LoadStrictAuthority(arguments);

            var androidSecret = ReadOrCreateMailboxSecret(secretRoot, Android);
            var windowsSecret = ReadOrCreateMailboxSecret(secretRoot, Windows);
            var androidMailbox = Hmac(androidSecret, "deep.mailbox.blinded-mailbox-id.v1|android");
            var windowsMailbox = Hmac(windowsSecret, "deep.mailbox.blinded-mailbox-id.v1|windows");
            try
            {
                var android = BuildBundle(
                    Android, androidHolder, windowsHolder,
                    androidMailbox, windowsMailbox,
                    androidSecret, windowsSecret,
                    issuerSeed, authority);
                var windows = BuildBundle(
                    Windows, windowsHolder, androidHolder,
                    windowsMailbox, androidMailbox,
                    windowsSecret, androidSecret,
                    issuerSeed, authority);
                var androidBytes = SerializeBundle(android, issuerSeed);
                var windowsBytes = SerializeBundle(windows, issuerSeed);
                return PublishPair(outputRoot, authority, androidHolder, windowsHolder,
                    androidBytes, windowsBytes, arguments);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(androidSecret);
                CryptographicOperations.ZeroMemory(windowsSecret);
                CryptographicOperations.ZeroMemory(androidMailbox);
                CryptographicOperations.ZeroMemory(windowsMailbox);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(issuerSeed);
            CryptographicOperations.ZeroMemory(androidHolder);
            CryptographicOperations.ZeroMemory(windowsHolder);
        }
    }

    public static void Verify(Arguments arguments)
    {
        Require(arguments.DevelopmentOnly, "Verification requires --development-only.");
        var pairRoot = RequireProtectedRoot(arguments.PairDirectory, "pair");
        var authority = LoadStrictAuthority(arguments);
        var expectedAndroid = PublicKey(arguments.AndroidHolderPublicKey, "expected android holder");
        var expectedWindows = PublicKey(arguments.WindowsHolderPublicKey, "expected windows holder");
        try
        {
            var pointerBytes = ReadStableFile(Path.Combine(pairRoot, "current-generation.json"));
            using var pointer = JsonDocument.Parse(pointerBytes);
            Require(pointer.RootElement.GetProperty("schemaVersion").GetInt32() == 1
                && pointer.RootElement.GetProperty("developmentOnly").GetBoolean(),
                "Current generation pointer schema is invalid.");
            var generation = LowerHex(pointer.RootElement.GetProperty("generation").GetString(), 32, "generation");
            var expectedManifestHash = LowerHex(
                pointer.RootElement.GetProperty("pairManifestSha256").GetString(), 32, "pair manifest hash");
            var generationDirectory = Path.Combine(pairRoot, "generations", generation);
            Require(Directory.Exists(generationDirectory), "The current generation directory is missing.");
            AssertNoReparseTraversal(generationDirectory);

            var manifestBytes = ReadStableFile(Path.Combine(generationDirectory, "pair-manifest.v1.json"));
            Require(Sha256(manifestBytes) == expectedManifestHash, "Pair manifest hash does not match the pointer.");
            using var manifest = JsonDocument.Parse(manifestBytes);
            var manifestRoot = manifest.RootElement;
            Require(manifestRoot.GetProperty("schemaVersion").GetInt32() == 1
                && manifestRoot.GetProperty("developmentOnly").GetBoolean()
                && manifestRoot.GetProperty("generation").GetString() == generation
                && manifestRoot.GetProperty("authoritySha256").GetString() == authority.Hash
                && manifestRoot.GetProperty("issuerPublicKey").GetString() == authority.IssuerPublicKey
                && manifestRoot.GetProperty("androidHolderPublicKey").GetString() == Lower(expectedAndroid)
                && manifestRoot.GetProperty("windowsHolderPublicKey").GetString() == Lower(expectedWindows),
                "Pair manifest is not bound to the trusted authority and expected holders.");

            var androidPath = Path.Combine(generationDirectory, "android.mailbox-credentials.v1.json");
            var windowsPath = Path.Combine(generationDirectory, "windows.mailbox-credentials.v1.json");
            var androidBytes = ReadStableFile(androidPath);
            var windowsBytes = ReadStableFile(windowsPath);
            Require(manifestRoot.GetProperty("files").GetProperty("android").GetString() == Sha256(androidBytes)
                && manifestRoot.GetProperty("files").GetProperty("windows").GetString() == Sha256(windowsBytes),
                "A bundle does not match the atomic pair manifest.");
            RejectPrivateMaterial(Encoding.UTF8.GetString(androidBytes), []);
            RejectPrivateMaterial(Encoding.UTF8.GetString(windowsBytes), []);
            using var android = JsonDocument.Parse(androidBytes);
            using var windows = JsonDocument.Parse(windowsBytes);
            VerifyBundle(android.RootElement, Android, windows.RootElement, Windows,
                expectedAndroid, authority);
            VerifyBundle(windows.RootElement, Windows, android.RootElement, Android,
                expectedWindows, authority);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(expectedAndroid);
            CryptographicOperations.ZeroMemory(expectedWindows);
        }
    }

    private static StrictAuthority LoadStrictAuthority(Arguments arguments)
    {
        RequireFile(arguments.AuthorityPublicPath, "trusted authority");
        var authorityBytes = ReadStableFile(arguments.AuthorityPublicPath);
        var actualHash = Sha256(authorityBytes);
        var expectedHash = LowerHex(arguments.ExpectedAuthoritySha256, 32, "expected authority sha256");
        Require(actualHash == expectedHash, "Trusted authority SHA-256 mismatch.");
        var expectedIssuer = LowerHex(arguments.ExpectedIssuerPublicKey, 32, "expected issuer public key");
        var source = JsonSerializer.Deserialize<PublicAuthority>(authorityBytes,
            new JsonSerializerOptions { PropertyNameCaseInsensitive = true })
            ?? throw new InvalidDataException("Authority JSON is invalid.");
        Require(source.SchemaVersion == 2
            && source.Scope == "DEV-LOCAL-ONLY"
            && source.Protocol == "P10E/MCP2/MAU2/MIP1/RIP1/PRQ2"
            && source.MinimumGeneration == ProtocolFixture.Epoch
            && source.MaximumGeneration == ProtocolFixture.NextEpoch
            && source.Epochs.Count == 2
            && source.Selections.Count == 30
            && source.ReplicaIds.Count == 2
            && source.ReplicaSigningPublicKeys.Count == 2
            && source.IssuerPublicKey == expectedIssuer,
            "Only the exact trusted authority schema is accepted.");

        var runtimeAuthorityHash = actualHash;
        if (arguments.RuntimeAuthorityPublicPath is not null ||
            arguments.ExpectedRuntimeAuthoritySha256 is not null)
        {
            Require(arguments.RuntimeAuthorityPublicPath is not null &&
                    arguments.ExpectedRuntimeAuthoritySha256 is not null,
                "Runtime authority path and hash must be supplied together.");
            RequireFile(arguments.RuntimeAuthorityPublicPath!, "runtime authority");
            var runtimeAuthorityBytes = ReadStableFile(arguments.RuntimeAuthorityPublicPath!);
            var expectedRuntimeBytes = Fixture.SerializeClientAuthority(source);
            var expectedRuntimeHash = LowerHex(
                arguments.ExpectedRuntimeAuthoritySha256, 32,
                "expected runtime authority sha256");
            runtimeAuthorityHash = Sha256(runtimeAuthorityBytes);
            Require(runtimeAuthorityHash == expectedRuntimeHash &&
                    runtimeAuthorityBytes.Length == expectedRuntimeBytes.Length &&
                    CryptographicOperations.FixedTimeEquals(
                        runtimeAuthorityBytes, expectedRuntimeBytes),
                "Runtime authority is not the exact minimized projection of the trusted source authority.");
        }

        var expectedNetwork = Lower(SHA256.HashData(
            Encoding.UTF8.GetBytes("deep-survival-dev-p10e-network-v1"))[..16]);
        Require(source.NetworkId == expectedNetwork, "Authority network id is not the exact development network.");
        var coordinator = ValidateCoordinator(arguments, source.CoordinatorUrl);
        var currentSource = source.Epochs[0];
        var nextSource = source.Epochs[1];
        var now = checked((ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        Require(source.IssuerValidFromUnixSeconds == currentSource.NotBeforeUnixSeconds
            && source.IssuerValidUntilUnixSeconds == nextSource.ExpiresAtUnixSeconds
            && currentSource.NotBeforeUnixSeconds < nextSource.NotBeforeUnixSeconds
            && nextSource.NotBeforeUnixSeconds <= currentSource.ExpiresAtUnixSeconds
            && currentSource.ExpiresAtUnixSeconds < nextSource.ExpiresAtUnixSeconds
            && currentSource.ExpiresAtUnixSeconds - currentSource.NotBeforeUnixSeconds == 29100
            && nextSource.ExpiresAtUnixSeconds - nextSource.NotBeforeUnixSeconds == 43260
            && now >= nextSource.NotBeforeUnixSeconds
            && now + 1800 <= currentSource.ExpiresAtUnixSeconds,
            "Authority does not contain a live bounded overlapping E/E+1 window.");

        // Reuse the exact authority parser used by the mailbox driver. This
        // validates all six canonical MIP1/RIP1 proofs, descriptors, roots,
        // signing keys, validity, and exact internal xnode-N endpoints.
        var currentParsed = Fixture.ParsePublicEpoch(currentSource, ProtocolFixture.Epoch,
            currentSource.NotBeforeUnixSeconds, currentSource.ExpiresAtUnixSeconds, "current");
        var nextParsed = Fixture.ParsePublicEpoch(nextSource, ProtocolFixture.NextEpoch,
            nextSource.NotBeforeUnixSeconds, nextSource.ExpiresAtUnixSeconds, "next");
        var proofVerifier =
            new Deep.Protocol.DeepExtension.MembershipRoutes.MembershipRoutesMailboxReplicaProofVerifier();
        Require(currentParsed.Proofs.All(proof =>
                proofVerifier.VerifyStorageReplica(proof, now))
            && nextParsed.Proofs.All(proof =>
                proofVerifier.VerifyStorageReplica(proof, now)),
            "Every canonical RIP1 must prove its storage descriptor against the trusted membership root.");
        var currentIds = currentParsed.Descriptors
            .Select(item => RouterId.FromBytes(item.RouterId.Span).Value).ToArray();
        var nextIds = nextParsed.Descriptors
            .Select(item => RouterId.FromBytes(item.RouterId.Span).Value).ToArray();
        Require(currentIds.SequenceEqual(nextIds, StringComparer.Ordinal)
            && source.ReplicaIds.SequenceEqual(currentIds.Take(2), StringComparer.Ordinal)
            && source.ReplicaIds.SequenceEqual(ExpectedReplicaIds, StringComparer.Ordinal)
            && source.ReplicaSigningPublicKeys.SequenceEqual(
                currentParsed.Descriptors.Take(2).Select(item => Lower(item.Ed25519PublicKey.Span)),
                StringComparer.Ordinal)
            && source.ReplicaSigningPublicKeys.SequenceEqual(
                nextParsed.Descriptors.Take(2).Select(item => Lower(item.Ed25519PublicKey.Span)),
                StringComparer.Ordinal),
            "Authority does not bind the exact xnode-1/xnode-2 client replicas across both epochs.");

        var selectionIndex = 0;
        foreach (var epoch in new[]
        {
            (Value: ProtocolFixture.Epoch, Placements: Fixture.BuildPlacements("current")),
            (Value: ProtocolFixture.NextEpoch, Placements: Fixture.BuildPlacements("next"))
        })
        {
            for (var first = 0; first < 6; first++)
            for (var second = first + 1; second < 6; second++)
            {
                var selection = source.Selections[selectionIndex++];
                var placement = epoch.Placements[first, second];
                Require(selection.Epoch == epoch.Value
                    && selection.FirstNode == first + 1
                    && selection.SecondNode == second + 1
                    && selection.PlacementId == Lower(placement.Bytes.Span)
                    && selection.PlacementCommitment == Lower(MailboxPlacementCommitment.Compute(placement)),
                    "Authority placement selection matrix is not the exact canonical 30-item matrix.");
            }
        }

        var replicas = source.ReplicaIds.Select((id, index) =>
            new Replica(id, source.ReplicaSigningPublicKeys[index])).ToArray();
        return new StrictAuthority(runtimeAuthorityHash, source.NetworkId, source.IssuerPublicKey, coordinator,
            FromAuthorityEpoch(currentSource), FromAuthorityEpoch(nextSource), replicas);
    }

    private static Epoch FromAuthorityEpoch(PublicEpochAuthority source) => new(
        source.Epoch, source.NotBeforeUnixSeconds, source.ExpiresAtUnixSeconds,
        source.MembershipCommitment, source.PlacementId, source.PlacementCommitment);

    private static Uri ValidateCoordinator(Arguments arguments, string value)
    {
        Require(Uri.TryCreate(value, UriKind.Absolute, out var authorityUrl)
            && Uri.TryCreate(arguments.CoordinatorUrl, UriKind.Absolute, out var expectedUrl)
            && authorityUrl == expectedUrl
            && string.IsNullOrEmpty(authorityUrl.UserInfo)
            && authorityUrl.AbsolutePath == "/"
            && string.IsNullOrEmpty(authorityUrl.Query)
            && string.IsNullOrEmpty(authorityUrl.Fragment)
            && System.Net.IPAddress.TryParse(authorityUrl.Host, out var address)
            && !System.Net.IPAddress.IsLoopback(address),
            "Authority coordinator must be the exact expected non-loopback IP URL.");
        if (authorityUrl!.Scheme == Uri.UriSchemeHttp)
        {
            Require(arguments.DevelopmentOnly && arguments.AllowHttp && arguments.PhysicalDev
                && authorityUrl.ToString().TrimEnd('/') == PhysicalCoordinator,
                "Any HTTP coordinator requires --physical-dev and exact http://192.168.1.44:41801.");
        }
        else
        {
            Require(authorityUrl.Scheme == Uri.UriSchemeHttps,
                "Only HTTPS is accepted outside the exact physical development HTTP route.");
        }
        return authorityUrl;
    }

    private static Bundle BuildBundle(string identity, byte[] holder, byte[] peerHolder,
        byte[] mailbox, byte[] peerMailbox,
        byte[] mailboxSecret, byte[] peerMailboxSecret,
        byte[] issuerSeed, StrictAuthority authority)
    {
        var ownRetrieve = Grants(identity, "retrieve", MailboxCapabilityDomain.Retrieve,
            holder, mailboxSecret, issuerSeed, authority);
        var ownDeposit = Grants(identity, "deposit-own", MailboxCapabilityDomain.Deposit,
            holder, mailboxSecret, issuerSeed, authority);
        var peerDeposit = Grants(identity, "deposit-peer", MailboxCapabilityDomain.Deposit,
            holder, peerMailboxSecret, issuerSeed, authority);
        return new Bundle(
            identity,
            holder,
            peerHolder,
            mailbox,
            peerMailbox,
            authority,
            ownRetrieve,
            ownDeposit,
            peerDeposit);
    }

    private static GrantSet Grants(
        string identity,
        string role,
        MailboxCapabilityDomain domain,
        byte[] holder,
        byte[] targetMailboxSecret,
        byte[] issuerSeed,
        StrictAuthority authority)
    {
        var crypto = new SodiumMailboxCapabilityCrypto();
        Grant Grant(Epoch epoch, MailboxCapabilityDomain domain)
        {
            var serial = GrantSerial(
                targetMailboxSecret, identity, role, domain, epoch, holder, authority);
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
            finally
            {
                CryptographicOperations.ZeroMemory(serial);
            }
        }
        return new GrantSet(Grant(authority.Current, domain), Grant(authority.Next, domain));
    }

    private static byte[] SerializeBundle(Bundle bundle, byte[] issuerSeed)
    {
        var document = new
        {
            schemaVersion = 1,
            developmentOnly = true,
            authorityHashSha256 = bundle.Authority.Hash,
            identity = bundle.Identity,
            networkId = bundle.Authority.NetworkId,
            issuerPublicKey = bundle.Authority.IssuerPublicKey,
            coordinatorLanUrl = bundle.Authority.Coordinator.ToString().TrimEnd('/'),
            holderPublicKey = Lower(bundle.Holder),
            currentEpoch = EpochJson(bundle.Authority.Current),
            nextEpoch = EpochJson(bundle.Authority.Next),
            replicas = bundle.Authority.Replicas.Select(item =>
                new { id = item.Id, signingPublicKey = item.SigningPublicKey }),
            ownMailbox = new
            {
                blindedMailboxId = Lower(bundle.Mailbox),
                retrieveAndAcknowledgeGrants = GrantJson(bundle.OwnRetrieve),
                depositGrants = GrantJson(bundle.OwnDeposit)
            },
            peerMailboxRoute = new
            {
                holderPublicKey = Lower(bundle.PeerHolder),
                blindedMailboxId = Lower(bundle.PeerMailbox),
                depositGrants = GrantJson(bundle.PeerDeposit)
            },
            hashes = new { mailboxRouteSha256 = Sha256(bundle.Mailbox) }
        };
        var bytes = Encoding.UTF8.GetBytes(
            JsonSerializer.Serialize(document, new JsonSerializerOptions { WriteIndented = false }) + "\n");
        RejectPrivateMaterial(Encoding.UTF8.GetString(bytes), issuerSeed);
        return bytes;
    }

    private static ProvisionedBundles PublishPair(
        string outputRoot,
        StrictAuthority authority,
        byte[] androidHolder,
        byte[] windowsHolder,
        byte[] androidBytes,
        byte[] windowsBytes,
        Arguments arguments)
    {
        var androidHash = Sha256(androidBytes);
        var windowsHash = Sha256(windowsBytes);
        var generation = Sha256(Encoding.UTF8.GetBytes(
            $"deep.mailbox-pair-generation.v1\n{authority.Hash}\n{androidHash}\n{windowsHash}\n"));
        var manifestBytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new
        {
            schemaVersion = 1,
            developmentOnly = true,
            generation,
            authoritySha256 = authority.Hash,
            issuerPublicKey = authority.IssuerPublicKey,
            androidHolderPublicKey = Lower(androidHolder),
            windowsHolderPublicKey = Lower(windowsHolder),
            files = new { android = androidHash, windows = windowsHash }
        }) + "\n");
        var manifestHash = Sha256(manifestBytes);
        var generations = Path.Combine(outputRoot, "generations");
        Directory.CreateDirectory(generations);
        AssertNoReparseTraversal(generations);
        var stage = Path.Combine(generations, ".stage-" + Guid.NewGuid().ToString("N"));
        string? pointerTemp = null;
        Directory.CreateDirectory(stage);
        try
        {
            WriteDurableNewFile(Path.Combine(stage, "android.mailbox-credentials.v1.json"), androidBytes);
            WriteDurableNewFile(Path.Combine(stage, "windows.mailbox-credentials.v1.json"), windowsBytes);
            WriteDurableNewFile(Path.Combine(stage, "pair-manifest.v1.json"), manifestBytes);
            SyncDirectory(stage, "stage", arguments);
            if (arguments.FailAfterStage)
                throw new InjectedProvisionFailure("Injected failure after complete pair staging.");

            var final = Path.Combine(generations, generation);
            if (!Directory.Exists(final))
            {
                Directory.Move(stage, final);
                SyncDirectory(generations, "generation-parent", arguments);
            }
            else
            {
                Require(Sha256(ReadStableFile(Path.Combine(final, "pair-manifest.v1.json"))) == manifestHash
                    && Sha256(ReadStableFile(Path.Combine(final,
                        "android.mailbox-credentials.v1.json"))) == androidHash
                    && Sha256(ReadStableFile(Path.Combine(final,
                        "windows.mailbox-credentials.v1.json"))) == windowsHash,
                    "Existing immutable generation does not match this pair.");
                Directory.Delete(stage, recursive: true);
                SyncDirectory(generations, "generation-parent", arguments);
            }
            if (arguments.FailAfterPromotion)
                throw new InjectedProvisionFailure("Injected failure after pair promotion.");

            var pointerBytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new
            {
                schemaVersion = 1,
                developmentOnly = true,
                generation,
                pairManifestSha256 = manifestHash
            }) + "\n");
            pointerTemp = Path.Combine(
                outputRoot,
                ".current-" + Guid.NewGuid().ToString("N") + ".json");
            WriteDurableNewFile(pointerTemp, pointerBytes);
            SyncDirectory(outputRoot, "pointer-temp-parent", arguments);
            File.Move(pointerTemp, Path.Combine(outputRoot, "current-generation.json"), overwrite: true);
            SyncDirectory(outputRoot, "pointer-parent", arguments);
            return new ProvisionedBundles(
                ["android.mailbox-credentials.v1.json", "windows.mailbox-credentials.v1.json"],
                new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["android.mailbox-credentials.v1.json"] = androidHash,
                    ["windows.mailbox-credentials.v1.json"] = windowsHash,
                    ["pair-manifest.v1.json"] = manifestHash
                },
                generation);
        }
        catch
        {
            if (Directory.Exists(stage))
            {
                AssertNoReparseTraversal(stage);
                Directory.Delete(stage, recursive: true);
            }
            if (pointerTemp is not null && File.Exists(pointerTemp))
            {
                AssertNoReparseTraversal(pointerTemp);
                File.Delete(pointerTemp);
                SyncDirectory(outputRoot, "pointer-cleanup-parent", arguments);
            }
            throw;
        }
    }

    private static void VerifyBundle(JsonElement bundle, string identity, JsonElement peer,
        string peerIdentity, byte[] expectedHolder, StrictAuthority authority)
    {
        Require(bundle.GetProperty("schemaVersion").GetInt32() == 1
            && bundle.GetProperty("developmentOnly").GetBoolean()
            && bundle.GetProperty("identity").GetString() == identity
            && bundle.GetProperty("authorityHashSha256").GetString() == authority.Hash
            && bundle.GetProperty("networkId").GetString() == authority.NetworkId
            && bundle.GetProperty("issuerPublicKey").GetString() == authority.IssuerPublicKey
            && bundle.GetProperty("coordinatorLanUrl").GetString()
                == authority.Coordinator.ToString().TrimEnd('/')
            && bundle.GetProperty("holderPublicKey").GetString() == Lower(expectedHolder),
            "Bundle is not bound to the trusted authority, identity, and expected holder.");
        Require(bundle.GetProperty("currentEpoch").GetRawText() == EpochJsonText(authority.Current)
            && bundle.GetProperty("nextEpoch").GetRawText() == EpochJsonText(authority.Next)
            && bundle.GetProperty("replicas").GetRawText() == ReplicasJsonText(authority.Replicas),
            "Bundle authority fields differ from the trusted public authority.");

        var ownMailbox = LowerHex(
            bundle.GetProperty("ownMailbox").GetProperty("blindedMailboxId").GetString(), 32, "own mailbox");
        var peerMailbox = LowerHex(
            bundle.GetProperty("peerMailboxRoute").GetProperty("blindedMailboxId").GetString(), 32, "peer mailbox");
        Require(peerMailbox == peer.GetProperty("ownMailbox").GetProperty("blindedMailboxId").GetString()
            && peerMailbox != ownMailbox
            && bundle.GetProperty("peerMailboxRoute").GetProperty("holderPublicKey").GetString()
                == peer.GetProperty("holderPublicKey").GetString()
            && peer.GetProperty("identity").GetString() == peerIdentity,
            "Peer route is not the exact counterpart public mailbox.");
        var ownRetrieveSerials = VerifyGrantSet(
            bundle.GetProperty("ownMailbox").GetProperty("retrieveAndAcknowledgeGrants"),
            MailboxCapabilityDomain.Retrieve, expectedHolder, authority, "retrieve grant");
        var ownDepositSerials = VerifyGrantSet(
            bundle.GetProperty("ownMailbox").GetProperty("depositGrants"),
            MailboxCapabilityDomain.Deposit, expectedHolder, authority, "own deposit grant");
        var peerDepositSerials = VerifyGrantSet(
            bundle.GetProperty("peerMailboxRoute").GetProperty("depositGrants"),
            MailboxCapabilityDomain.Deposit, expectedHolder, authority, "deposit grant");
        for (var index = 0; index < 2; index++)
        {
            Require(ownRetrieveSerials[index] != ownDepositSerials[index]
                && ownRetrieveSerials[index] != peerDepositSerials[index]
                && ownDepositSerials[index] != peerDepositSerials[index],
                "Retrieve, own-copy deposit, and peer deposit grants must use distinct serials.");
        }
    }

    private static string[] VerifyGrantSet(JsonElement grants, MailboxCapabilityDomain domain,
        byte[] holder, StrictAuthority authority, string label)
    {
        Require(grants.ValueKind == JsonValueKind.Array && grants.GetArrayLength() == 2,
            $"{label} set must contain E and E+1.");
        var issuer = Hex(authority.IssuerPublicKey, 32, "issuer public key");
        var network = Hex(authority.NetworkId, 16, "network id");
        try
        {
            var serials = new List<string>(2);
            var index = 0;
            foreach (var item in grants.EnumerateArray())
            {
                var expected = index++ == 0 ? authority.Current : authority.Next;
                var encoded = Convert.FromBase64String(item.GetProperty("canonicalGrant").GetString()!);
                var grant = MailboxAuthenticatedCapabilityCodec.DecodeGrant(encoded);
                Require(item.GetProperty("epoch").GetUInt64() == expected.Value
                    && grant.Epoch == expected.Value
                    && grant.Generation == expected.Value
                    && grant.Domain == domain
                    && grant.Lifecycle == MailboxCapabilityLifecycle.Active
                    && grant.NotBeforeUnixSeconds == expected.NotBefore
                    && grant.ExpiresAtUnixSeconds == expected.ExpiresAt
                    && grant.OverlapUntilUnixSeconds == 0
                    && grant.Serial.Span.IndexOfAnyExcept((byte)0) >= 0
                    && CryptographicOperations.FixedTimeEquals(grant.HolderPublicKey.Span, holder)
                    && CryptographicOperations.FixedTimeEquals(grant.IssuerPublicKey.Span, issuer)
                    && CryptographicOperations.FixedTimeEquals(grant.NetworkId.Span, network)
                    && CryptographicOperations.FixedTimeEquals(grant.PlacementCommitment.Span,
                        Hex(expected.PlacementCommitment, 32, "placement commitment"))
                    && CryptographicOperations.FixedTimeEquals(grant.MembershipCommitment.Span,
                        Hex(expected.MembershipCommitment, 32, "membership commitment"))
                    && new SodiumMailboxCapabilityCrypto().VerifyIssuer(issuer,
                        MailboxAuthenticatedCapabilityCodec.GetGrantSigningBytes(grant),
                        grant.IssuerSignature.Span)
                    && CryptographicOperations.FixedTimeEquals(
                        encoded, MailboxAuthenticatedCapabilityCodec.EncodeGrant(grant)),
                    $"{label} is not cryptographically bound to its trusted holder, domain, or epoch.");
                Require(item.GetProperty("sha256").GetString() == Sha256(encoded),
                    $"{label} hash is invalid.");
                serials.Add(Lower(grant.Serial.Span));
            }
            return serials.ToArray();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(issuer);
            CryptographicOperations.ZeroMemory(network);
        }
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

    private static string EpochJsonText(Epoch epoch) => JsonSerializer.Serialize(EpochJson(epoch));
    private static string ReplicasJsonText(Replica[] replicas) => JsonSerializer.Serialize(
        replicas.Select(item => new { id = item.Id, signingPublicKey = item.SigningPublicKey }));
    private static object GrantJson(GrantSet set) => new[]
    {
        new { epoch = set.Current.Epoch, canonicalGrant = set.Current.CanonicalGrant, sha256 = set.Current.Hash },
        new { epoch = set.Next.Epoch, canonicalGrant = set.Next.CanonicalGrant, sha256 = set.Next.Hash }
    };

    private static byte[] ReadOrCreateMailboxSecret(string root, string identity)
    {
        var path = Path.Combine(root, identity + ".mailbox-secret");
        AssertNoReparseTraversal(path);
        if (!File.Exists(path))
        {
            var generated = RandomNumberGenerator.GetBytes(32);
            try
            {
                WriteDurableNewFile(path, Encoding.ASCII.GetBytes(Lower(generated) + "\n"));
                RestrictSecretFile(path);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(generated);
            }
        }
        AssertSecretFilePermissions(path);
        return ReadSecretFile(path);
    }

    private static byte[] ReadSecretFile(string path)
    {
        var bytes = ReadStableFile(path);
        var text = Encoding.ASCII.GetString(bytes).Trim();
        var secret = Hex(text, 32, "secret");
        CryptographicOperations.ZeroMemory(bytes);
        return secret;
    }

    private static byte[] ReadStableFile(string path)
    {
        AssertNoReparseTraversal(path);
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read,
            4096, FileOptions.SequentialScan);
        Require(stream.Length <= 4 * 1024 * 1024, "Provisioning input exceeds its exact size bound.");
        var bytes = new byte[checked((int)stream.Length)];
        stream.ReadExactly(bytes);
        AssertNoReparseTraversal(path);
        return bytes;
    }

    private static void WriteDurableNewFile(string path, byte[] bytes)
    {
        AssertNoReparseTraversal(path);
        using (var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None,
            4096, FileOptions.WriteThrough))
        {
            stream.Write(bytes);
            stream.Flush(flushToDisk: true);
        }
        AssertNoReparseTraversal(path);
    }

    private static void SyncDirectory(string path, string barrier, Arguments arguments)
    {
        if (OperatingSystem.IsWindows())
        {
            using var handle = NativeMethods.CreateFile(
                path,
                NativeMethods.GenericWrite,
                FileShare.ReadWrite | FileShare.Delete,
                IntPtr.Zero,
                FileMode.Open,
                NativeMethods.FileFlagBackupSemantics,
                IntPtr.Zero);
            if (handle.IsInvalid)
            {
                throw new InvalidDataException(
                    "Required Windows directory durability handle is unavailable.",
                    new Win32Exception(Marshal.GetLastWin32Error()));
            }
            if (!NativeMethods.FlushFileBuffers(handle))
            {
                throw new InvalidDataException(
                    "Required Windows directory durability barrier failed.",
                    new Win32Exception(Marshal.GetLastWin32Error()));
            }
        }
        else
        {
            try
            {
                using var handle = File.OpenHandle(
                    path,
                    FileMode.Open,
                    FileAccess.Read,
                    FileShare.ReadWrite | FileShare.Delete);
                RandomAccess.FlushToDisk(handle);
            }
            catch (UnauthorizedAccessException exception)
            {
                throw new InvalidDataException(
                    "Directory fsync is required but unavailable.",
                    exception);
            }
        }

        if (string.Equals(
                arguments.FailAfterDurabilityBarrier,
                barrier,
                StringComparison.Ordinal))
            throw new InjectedProvisionFailure(
                $"Injected failure after durability barrier {barrier}.");
    }

    private static string RequireProtectedRoot(string? value, string label)
    {
        Require(!string.IsNullOrWhiteSpace(value), $"--{label}-directory is required.");
        var path = Path.GetFullPath(value!);
        Require(Directory.Exists(path), $"{label} root must be pre-created by the operator.");
        AssertNoReparseTraversal(path);
        if (OperatingSystem.IsWindows())
            AssertWindowsAcl(path);
        else
            AssertUnixMode(path, isDirectory: true);
        return path;
    }

    private static void RequireFile(string? value, string label)
    {
        Require(!string.IsNullOrWhiteSpace(value) && File.Exists(value),
            $"An existing {label} file is required.");
        AssertNoReparseTraversal(value!);
    }

    private static void RestrictSecretFile(string path)
    {
        if (OperatingSystem.IsWindows())
            SetExclusiveWindowsAcl(path, isDirectory: false);
        else
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
    }

    private static void AssertSecretFilePermissions(string path)
    {
        AssertNoReparseTraversal(path);
        if (OperatingSystem.IsWindows())
            AssertWindowsAcl(path);
        else
            AssertUnixMode(path, isDirectory: false);
    }

    [System.Runtime.Versioning.UnsupportedOSPlatform("windows")]
    private static void AssertUnixMode(string path, bool isDirectory)
    {
        var mode = File.GetUnixFileMode(path);
        var forbidden = UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute
            | UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute;
        var required = UnixFileMode.UserRead | UnixFileMode.UserWrite
            | (isDirectory ? UnixFileMode.UserExecute : 0);
        Require((mode & forbidden) == 0 && (mode & required) == required,
            "Operator root/secret permissions must be directory 0700 and file 0600.");
    }

    [SupportedOSPlatform("windows")]
    private static void AssertWindowsAcl(string path)
    {
        var current = WindowsIdentity.GetCurrent().User
            ?? throw new InvalidDataException("The current Windows identity has no SID.");
        var isDirectory = Directory.Exists(path);
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var administrators = new SecurityIdentifier(
            WellKnownSidType.BuiltinAdministratorsSid,
            null);
        var security = isDirectory
            ? (FileSystemSecurity)new DirectoryInfo(path).GetAccessControl(
                AccessControlSections.Access | AccessControlSections.Owner)
            : new FileInfo(path).GetAccessControl(
                AccessControlSections.Access | AccessControlSections.Owner);
        var owner = security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier
            ?? throw new InvalidDataException("Operator root/secret owner SID is unavailable.");
        Require(owner.Equals(current),
            "Operator root/secret owner must be the exact current Windows identity SID.");
        Require(security.AreAccessRulesProtected && security.AreAccessRulesCanonical,
            "Operator root/secret DACL must be protected from inheritance and canonical.");

        var allowed = new Dictionary<string, FileSystemRights>(StringComparer.Ordinal)
        {
            [current.Value] = 0,
            [system.Value] = 0,
            [administrators.Value] = 0
        };
        foreach (FileSystemAccessRule rule in security.GetAccessRules(
                     includeExplicit: true,
                     includeInherited: true,
                     targetType: typeof(SecurityIdentifier)))
        {
            var sid = (SecurityIdentifier)rule.IdentityReference;
            var expectedInheritance = isDirectory
                ? InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit
                : InheritanceFlags.None;
            Require(!rule.IsInherited
                && rule.AccessControlType == AccessControlType.Allow
                && allowed.ContainsKey(sid.Value)
                && rule.InheritanceFlags == expectedInheritance
                && rule.PropagationFlags == PropagationFlags.None,
                "Operator root/secret DACL contains an inherited, denied, or non-allowlisted SID.");
            allowed[sid.Value] |= rule.FileSystemRights;
        }
        Require(allowed.Values.All(rights =>
                (rights & FileSystemRights.FullControl) == FileSystemRights.FullControl),
            "Current identity, SYSTEM, and Administrators must have exact protected control.");
    }

    [SupportedOSPlatform("windows")]
    private static void SetExclusiveWindowsAcl(string path, bool isDirectory)
    {
        var current = WindowsIdentity.GetCurrent().User
            ?? throw new InvalidDataException("The current Windows identity has no SID.");
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var administrators = new SecurityIdentifier(
            WellKnownSidType.BuiltinAdministratorsSid,
            null);
        FileSystemSecurity security = isDirectory
            ? new DirectorySecurity()
            : new FileSecurity();
        var existing = isDirectory
            ? (FileSystemSecurity)new DirectoryInfo(path).GetAccessControl(AccessControlSections.Owner)
            : new FileInfo(path).GetAccessControl(AccessControlSections.Owner);
        var owner = existing.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
        Require(owner is not null && owner.Equals(current),
            "Provisioned path owner must be the exact current Windows identity.");
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        foreach (var sid in new[] { current, system, administrators })
        {
            var inheritance = isDirectory
                ? InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit
                : InheritanceFlags.None;
            security.AddAccessRule(new FileSystemAccessRule(
                sid,
                FileSystemRights.FullControl,
                inheritance,
                PropagationFlags.None,
                AccessControlType.Allow));
        }
        if (isDirectory)
            new DirectoryInfo(path).SetAccessControl((DirectorySecurity)security);
        else
            new FileInfo(path).SetAccessControl((FileSecurity)security);
        AssertWindowsAcl(path);
    }

    private static void AssertNoReparseTraversal(string path)
    {
        var full = Path.GetFullPath(path);
        if ((File.Exists(full) || Directory.Exists(full))
            && (File.GetAttributes(full) & FileAttributes.ReparsePoint) != 0)
            throw new InvalidDataException("Reparse-point paths are not accepted.");
        for (var directory = new DirectoryInfo(Path.GetDirectoryName(full) ?? full);
             directory is not null;
             directory = directory.Parent)
        {
            if (directory.Exists && (directory.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new InvalidDataException("Reparse-point path traversal is not accepted.");
        }
    }

    private static void RejectPrivateMaterial(string output, byte[] issuerSeed)
    {
        Require(issuerSeed.Length == 0
            || !output.Contains(Lower(issuerSeed), StringComparison.OrdinalIgnoreCase),
            "Refusing output containing issuer seed material.");
        foreach (var forbidden in new[]
            { "issuerSeed", "privateKey", "privateSeed", "sessionId", "mailboxSecret" })
            Require(!output.Contains(forbidden, StringComparison.OrdinalIgnoreCase),
                "Refusing private material in output.");
    }

    private static byte[] PublicKey(string? value, string label) => Hex(value, 32, label);
    private static byte[] Hex(string? value, int size, string label)
    {
        var canonical = LowerHex(value, size, label);
        var bytes = Convert.FromHexString(canonical);
        Require(bytes.AsSpan().IndexOfAnyExcept((byte)0) >= 0, $"{label} must be nonzero.");
        return bytes;
    }

    private static string LowerHex(string? value, int size, string label)
    {
        Require(value is not null && value.Length == size * 2
            && value.All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f'),
            $"{label} must be lowercase hexadecimal.");
        return value!;
    }

    private static byte[] Hmac(byte[] key, string value) =>
        HMACSHA256.HashData(key, Encoding.UTF8.GetBytes(value));
    private static byte[] GrantSerial(
        byte[] targetMailboxSecret,
        string platform,
        string role,
        MailboxCapabilityDomain domain,
        Epoch epoch,
        byte[] holder,
        StrictAuthority authority)
    {
        var authorityHash = Hex(authority.Hash, 32, "authority hash");
        var network = Hex(authority.NetworkId, 16, "network id");
        var issuer = Hex(authority.IssuerPublicKey, 32, "issuer public key");
        var membership = Hex(
            epoch.MembershipCommitment, 32, "membership commitment");
        var placement = Hex(
            epoch.PlacementCommitment, 32, "placement commitment");
        var selectors = new byte[]
        {
            platform switch
            {
                Android => 1,
                Windows => 2,
                _ => throw new InvalidDataException("Grant platform is invalid.")
            },
            role switch
            {
                "retrieve" => 1,
                "deposit-own" => 2,
                "deposit-peer" => 3,
                _ => throw new InvalidDataException("Grant role is invalid.")
            },
            (byte)domain
        };
        var epochAndGeneration = new byte[16];
        BinaryPrimitives.WriteUInt64BigEndian(
            epochAndGeneration.AsSpan(0, 8), epoch.Value);
        BinaryPrimitives.WriteUInt64BigEndian(
            epochAndGeneration.AsSpan(8, 8), epoch.Value);
        var context = new byte[
            "deep.mailbox.grant-serial.v2"u8.Length + authorityHash.Length +
            network.Length + issuer.Length + selectors.Length +
            epochAndGeneration.Length + holder.Length + membership.Length +
            placement.Length];
        var offset = 0;
        Append("deep.mailbox.grant-serial.v2"u8, context, ref offset);
        Append(authorityHash, context, ref offset);
        Append(network, context, ref offset);
        Append(issuer, context, ref offset);
        Append(selectors, context, ref offset);
        Append(epochAndGeneration, context, ref offset);
        Append(holder, context, ref offset);
        Append(membership, context, ref offset);
        Append(placement, context, ref offset);
        Require(offset == context.Length, "Grant serial context length is invalid.");
        var digest = HMACSHA256.HashData(targetMailboxSecret, context);
        try
        {
            return digest[..16];
        }
        finally
        {
            CryptographicOperations.ZeroMemory(authorityHash);
            CryptographicOperations.ZeroMemory(network);
            CryptographicOperations.ZeroMemory(issuer);
            CryptographicOperations.ZeroMemory(membership);
            CryptographicOperations.ZeroMemory(placement);
            CryptographicOperations.ZeroMemory(selectors);
            CryptographicOperations.ZeroMemory(epochAndGeneration);
            CryptographicOperations.ZeroMemory(context);
            CryptographicOperations.ZeroMemory(digest);
        }
    }
    private static void Append(
        ReadOnlySpan<byte> source,
        Span<byte> destination,
        ref int offset)
    {
        source.CopyTo(destination[offset..]);
        offset = checked(offset + source.Length);
    }
    private static string Sha256(byte[] value) => Lower(SHA256.HashData(value));
    private static string Lower(byte[] value) => Convert.ToHexString(value).ToLowerInvariant();
    private static string Lower(ReadOnlySpan<byte> value) =>
        Convert.ToHexString(value).ToLowerInvariant();
    private static bool PathsOverlap(string first, string second)
    {
        var left = first.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
            + Path.DirectorySeparatorChar;
        var right = second.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
            + Path.DirectorySeparatorChar;
        return left.StartsWith(right, StringComparison.OrdinalIgnoreCase)
            || right.StartsWith(left, StringComparison.OrdinalIgnoreCase);
    }
    private static void Require(bool condition, string message)
    {
        if (!condition)
            throw new InvalidDataException(message);
    }

    private sealed record Replica(string Id, string SigningPublicKey);
    private sealed record Epoch(ulong Value, ulong NotBefore, ulong ExpiresAt,
        string MembershipCommitment, string PlacementId, string PlacementCommitment);
    private sealed record StrictAuthority(string Hash, string NetworkId, string IssuerPublicKey,
        Uri Coordinator, Epoch Current, Epoch Next, Replica[] Replicas);
    private sealed record Grant(ulong Epoch, string CanonicalGrant, string Hash);
    private sealed record GrantSet(Grant Current, Grant Next);
    private sealed record Bundle(
        string Identity,
        byte[] Holder,
        byte[] PeerHolder,
        byte[] Mailbox,
        byte[] PeerMailbox,
        StrictAuthority Authority,
        GrantSet OwnRetrieve,
        GrantSet OwnDeposit,
        GrantSet PeerDeposit);

    private static class NativeMethods
    {
        internal const uint GenericWrite = 0x40000000;
        internal const uint FileFlagBackupSemantics = 0x02000000;

        [DllImport(
            "kernel32.dll",
            EntryPoint = "CreateFileW",
            CharSet = CharSet.Unicode,
            SetLastError = true)]
        internal static extern SafeFileHandle CreateFile(
            string fileName,
            uint desiredAccess,
            FileShare shareMode,
            IntPtr securityAttributes,
            FileMode creationDisposition,
            uint flagsAndAttributes,
            IntPtr templateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool FlushFileBuffers(SafeFileHandle handle);
    }
}

sealed class InjectedProvisionFailure(string message) : Exception(message);

sealed record ProvisionedBundles(
    IReadOnlyList<string> BundleNames,
    IReadOnlyDictionary<string, string> OutputHashes,
    string Generation);
