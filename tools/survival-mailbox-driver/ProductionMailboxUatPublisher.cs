using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Deep.Protocol.DeepExtension.MailboxAuthority;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.MailboxTopology;
using Deep.Protocol.DeepExtension.MembershipRoutes;
using Sodium;
using XNode.Core;
using XNode.Core.Mailbox;

internal static class ProductionMailboxUatPublisher
{
    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true };

    public static void Publish(string[] args)
    {
        var input = Input.Parse(args);
        RequireDirectory(input.SecretDirectory, "secret directory");
        RequireDirectory(input.PrivateDirectory, "private directory");
        Directory.CreateDirectory(input.OutputDirectory);

        var issuerSeed = ReadSecret(Path.Combine(input.PrivateDirectory, "issuer.seed"));
        var mrXSeed = ReadSecret(Path.Combine(input.PrivateDirectory, "mrx.seed"));
        var closureSeed = ReadSecret(Path.Combine(input.PrivateDirectory, "closure-publisher.seed"));
        try
        {
            var xnodeSeeds = Enumerable.Range(1, 6)
                .Select(index => ReadHexSecret(Path.Combine(
                    input.SecretDirectory, $"xnode-{index}-ed25519.seed")))
                .ToArray();
            var window = AuthorityWindow.Load(input.AuthorityStatePath);
            var fixture = Fixture.CreateAuthority(
                xnodeSeeds, Convert.ToHexString(issuerSeed), window);
            var issuer = PublicKeyAuth.GenerateKeyPair(issuerSeed);
            var mrX = PublicKeyAuth.GenerateKeyPair(mrXSeed);
            var closure = PublicKeyAuth.GenerateKeyPair(closureSeed);
            try
            {
                Write(input, fixture, issuer, mrX, closure);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(issuer.PrivateKey);
                CryptographicOperations.ZeroMemory(mrX.PrivateKey);
                CryptographicOperations.ZeroMemory(closure.PrivateKey);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(issuerSeed);
            CryptographicOperations.ZeroMemory(mrXSeed);
            CryptographicOperations.ZeroMemory(closureSeed);
        }
    }

    public static void PublishRoutes(string[] args)
    {
        var input = RouteInput.Parse(args);
        RequireDirectory(input.SecretDirectory, "secret directory");
        RequireDirectory(input.PrivateDirectory, "private directory");
        Directory.CreateDirectory(input.OutputDirectory);
        if (Directory.EnumerateFileSystemEntries(input.OutputDirectory).Any())
            throw new InvalidOperationException(
                "UAT privacy-route output directory must be empty.");

        var mrXSeed = ReadSecret(Path.Combine(input.PrivateDirectory, "mrx.seed"));
        var xnodeSeeds = Enumerable.Range(1, 6)
            .Select(index => ReadHexSecret(Path.Combine(
                input.SecretDirectory, $"xnode-{index}-ed25519.seed")))
            .ToArray();
        var x25519PublicKeys = new byte[6][];
        KeyPair? mrX = null;
        try
        {
            var fixture = Fixture.CreateAuthority(xnodeSeeds,
                Convert.ToHexString(mrXSeed), AuthorityWindow.Load(input.AuthorityStatePath));
            mrX = PublicKeyAuth.GenerateKeyPair(mrXSeed);
            var networkId = DomainHash(
                "Deep/survival-uat/production-mailbox/network/v1", mrX.PublicKey)[..16];
            for (var index = 0; index < x25519PublicKeys.Length; index++)
            {
                var privateKey = ReadHexSecret(Path.Combine(
                    input.SecretDirectory, $"xnode-{index + 1}-x25519.private"));
                var privateKeyBytes = Convert.FromHexString(privateKey);
                try { x25519PublicKeys[index] = ScalarMult.Base(privateKeyBytes); }
                finally { CryptographicOperations.ZeroMemory(privateKeyBytes); }
            }
            if (x25519PublicKeys.Any(key => key.Length != 32 ||
                    key.AsSpan().IndexOfAnyExcept((byte)0) < 0) ||
                x25519PublicKeys.Select(static key => Convert.ToHexStringLower(key))
                    .Distinct(StringComparer.Ordinal).Count() != 6)
                throw new InvalidDataException("UAT privacy X25519 public keys are invalid.");

            object Route(int port, int[] indices) => new
            {
                entryOrigin = $"https://{input.PublicHost}:{port}/",
                hops = indices.Select(index => new
                {
                    routerId = Lower(fixture.Descriptors[index].RouterId.Span),
                    x25519PublicKey = Lower(x25519PublicKeys[index])
                }).ToArray()
            };
            var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            var expires = checked((long)Math.Min(
                fixture.CurrentExpiresAt, fixture.NextExpiresAt));
            if (expires <= now + 1800)
                throw new InvalidDataException("UAT privacy-route window is not live.");
            var json = JsonSerializer.SerializeToUtf8Bytes(new
            {
                schemaVersion = 1,
                developmentOnly = false,
                networkId = Lower(networkId),
                notBeforeUnixSeconds = Math.Max(0, now - 60),
                expiresUnixSeconds = expires,
                primary = Route(41803, [2, 3, 0]),
                fallback = Route(41805, [4, 5, 1])
            });
            var signature = PublicKeyAuth.SignDetached(json, mrX.PrivateKey);
            if (!PublicKeyAuth.VerifyDetached(signature, json, mrX.PublicKey))
                throw new CryptographicException("UAT privacy-route signature failed verification.");
            WriteAtomic(Path.Combine(input.OutputDirectory,
                "production-mailbox-privacy-routes.v1.json"), json);
            WriteAtomic(Path.Combine(input.OutputDirectory,
                "production-mailbox-privacy-routes.v1.sig"), signature);
            WriteAtomic(Path.Combine(input.OutputDirectory,
                "production-mailbox-privacy-routes.v1.pub"), mrX.PublicKey);
            CryptographicOperations.ZeroMemory(json);
            CryptographicOperations.ZeroMemory(signature);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(mrXSeed);
            foreach (var key in x25519PublicKeys)
                if (key is not null) CryptographicOperations.ZeroMemory(key);
            if (mrX is not null)
            {
                CryptographicOperations.ZeroMemory(mrX.PrivateKey);
                CryptographicOperations.ZeroMemory(mrX.PublicKey);
            }
        }
        Console.WriteLine("UAT privacy-route public artifacts published.");
    }

    private static void Write(
        Input input,
        Fixture fixture,
        KeyPair issuer,
        KeyPair mrX,
        KeyPair closure)
    {
        var now = checked((ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        if (fixture.CurrentNotBefore > now || fixture.CurrentExpiresAt <= now + 1800
            || fixture.NextNotBefore > now || fixture.NextExpiresAt <= now + 1800)
            throw new InvalidDataException("UAT authority window is not live for both epochs.");

        var networkId = DomainHash("Deep/survival-uat/production-mailbox/network/v1",
            mrX.PublicKey)[..16];
        var currentSpki = Spki(input.CurrentCertificatePath);
        var nextSpki = Spki(input.NextCertificatePath);
        if (CryptographicOperations.FixedTimeEquals(currentSpki, nextSpki))
            throw new InvalidDataException("Current and next UAT TLS SPKI pins must differ.");

        var predecessor = input.PreviousTrustFloorPath is null
            ? null
            : LoadPredecessor(input, mrX.PublicKey, networkId);
        var previousAuthorityHash = predecessor?.AuthorityHash ?? DomainHash(
            "Deep/survival-uat/production-mailbox/previous-authority/v1", networkId);
        var previousRevocationHead = predecessor?.RevocationHeadHash ?? DomainHash(
            "Deep/survival-uat/production-mailbox/previous-revocation-head/v1", networkId);
        var previousRevocationSnapshot = predecessor?.RevocationSnapshotHash ?? DomainHash(
            "Deep/survival-uat/production-mailbox/previous-revocation-snapshot/v1", networkId);
        var previousTopologyHash = predecessor?.TopologyHash ?? DomainHash(
            "Deep/survival-uat/production-mailbox/previous-topology/v1", networkId);
        var currentPlacement = DomainHash(
            "Deep/survival-uat/production-mailbox/current-placement/v1", networkId);
        var nextPlacement = DomainHash(
            "Deep/survival-uat/production-mailbox/next-placement/v1", networkId);
        var authorityGeneration = predecessor is null
            ? checked(fixture.CurrentEpoch + 1)
            : checked(predecessor.AuthorityGeneration + 1);
        var revocationGeneration = predecessor is null
            ? authorityGeneration
            : checked(predecessor.RevocationGeneration + 1);
        var topologyGeneration = predecessor is null
            ? authorityGeneration
            : checked(predecessor.TopologyGeneration + 1);
        var revocationGenerationBytes = new byte[sizeof(ulong)];
        BinaryPrimitives.WriteUInt64BigEndian(revocationGenerationBytes, revocationGeneration);
        var revocationHead = DomainHash(
            "Deep/survival-uat/production-mailbox/revocation-head/v2",
            networkId, previousRevocationHead, revocationGenerationBytes);
        var rolloutUntil = Math.Min(fixture.CurrentExpiresAt, fixture.NextExpiresAt);
        var revocationUntil = Math.Min(rolloutUntil, checked(now +
            ProductionMailboxAuthorityConstants.MaximumRevocationSnapshotLifetimeSeconds));

        var draft = new ProductionMailboxAuthority
        {
            DevelopmentOnly = false,
            Environment = ProductionMailboxAuthorityEnvironment.Production,
            Transport = ProductionMailboxAuthorityTransport.AuthenticatedMau2,
            Ownership = ProductionMailboxAuthorityOwnership.OfficialManaged,
            EndpointPolicy = ProductionMailboxAuthorityEndpointPolicy.PublicHttpsOnly,
            NetworkId = networkId,
            AuthorityGeneration = authorityGeneration,
            PreviousAuthorityHash = previousAuthorityHash,
            MailboxIssuerEd25519PublicKey = issuer.PublicKey,
            MrXApprovalEd25519PublicKey = mrX.PublicKey,
            Coordinator = Endpoint($"https://{input.PublicHost}:41810/", currentSpki, nextSpki),
            NodeIngress = Endpoint($"https://{input.PublicHost}:41801/", currentSpki, nextSpki),
            CurrentEpoch = Epoch(fixture.CurrentEpoch, fixture.CurrentEpoch,
                fixture.Root, currentPlacement, fixture.CurrentNotBefore,
                fixture.CurrentExpiresAt),
            NextEpoch = Epoch(fixture.NextEpoch, fixture.NextEpoch,
                fixture.NextRoot, nextPlacement, fixture.NextNotBefore,
                fixture.NextExpiresAt),
            Revocation = new ProductionMailboxAuthorityRevocation
            {
                SnapshotHash = previousRevocationSnapshot,
                HeadHash = revocationHead,
                PreviousHeadHash = previousRevocationHead,
                Generation = revocationGeneration,
                IssuedAtUnixSeconds = now,
                ExpiresAtUnixSeconds = revocationUntil
            },
            MrXApproval = new ProductionMailboxAuthorityApproval
            {
                AuthorityPayloadHash = DomainHash(
                    "Deep/survival-uat/production-mailbox/approval-placeholder/v1",
                    networkId),
                AllowedAndroidSigningCertificateSha256 = [input.AndroidSigningCertificateSha256],
                AllowedWindowsSigningCertificateSha256 =
                    input.WindowsSigningCertificateSha256 is { } windowsSigner
                        ? [(ReadOnlyMemory<byte>)windowsSigner]
                        : predecessor?.WindowsSigningCertificateSha256 ??
                            throw new InvalidOperationException(),
                AndroidReleaseBuildArtifactSha256 = [input.AndroidBuildArtifactSha256],
                WindowsReleaseBuildArtifactSha256 =
                    input.WindowsBuildArtifactSha256 is { } windowsArtifact
                        ? [(ReadOnlyMemory<byte>)windowsArtifact]
                        : predecessor?.WindowsBuildArtifactSha256 ??
                            throw new InvalidOperationException(),
                RolloutNotBeforeUnixSeconds = now,
                RolloutNotAfterUnixSeconds = rolloutUntil
            },
            Signature = new byte[64]
        };
        var unsignedRevocations = new ProductionMailboxRevocationSnapshot
        {
            NetworkId = networkId,
            AuthorityGeneration = authorityGeneration,
            AuthorityBindingHash = ProductionMailboxRevocationSnapshotCodec
                .ComputeAuthorityBindingHash(draft),
            RevocationGeneration = revocationGeneration,
            RevocationHeadHash = revocationHead,
            PreviousRevocationHeadHash = previousRevocationHead,
            IssuedAtUnixSeconds = now,
            ExpiresAtUnixSeconds = revocationUntil,
            RevokedGrantSerials = [],
            IssuerSignature = new byte[64]
        };
        var revocations = unsignedRevocations with
        {
            IssuerSignature = PublicKeyAuth.SignDetached(
                ProductionMailboxRevocationSnapshotCodec.GetSigningBytes(unsignedRevocations),
                issuer.PrivateKey)
        };
        var revocationBytes = ProductionMailboxRevocationSnapshotCodec.Encode(revocations);
        var authority = SignAuthority(draft with
        {
            Revocation = draft.Revocation with
            {
                SnapshotHash = SHA256.HashData(revocationBytes)
            }
        }, mrX.PrivateKey);
        var authorityBytes = ProductionMailboxAuthorityCodec.Encode(authority);
        var authorityHash = SHA256.HashData(authorityBytes);

        var topology = SignTopology(new ProductionMailboxTopologySnapshot
        {
            NetworkId = networkId,
            AuthorityGeneration = authorityGeneration,
            CanonicalAuthorityHash = authorityHash,
            TopologyGeneration = topologyGeneration,
            PreviousTopologyHash = previousTopologyHash,
            IssuedAtUnixSeconds = now,
            ExpiresAtUnixSeconds = rolloutUntil,
            CurrentEpoch = TopologyEpoch(authority.CurrentEpoch,
                fixture.Descriptors, input.PublicHost, currentSpki, nextSpki),
            NextEpoch = TopologyEpoch(authority.NextEpoch,
                fixture.NextDescriptors, input.PublicHost, currentSpki, nextSpki),
            IssuerSignature = new byte[64]
        }, issuer.PrivateKey);
        var topologyBytes = ProductionMailboxTopologyCodec.Encode(topology);
        var topologyHash = SHA256.HashData(topologyBytes);

        var verifiedAuthority = ProductionMailboxAuthorityVerifier.Verify(
            authority,
            new ProductionMailboxAuthorityVerificationContext
            {
                PinnedMrXPublicKeySha256 = SHA256.HashData(mrX.PublicKey),
                ExpectedNetworkId = networkId,
                LastCommittedGeneration = authorityGeneration - 1,
                LastCommittedAuthorityHash = previousAuthorityHash,
                LastCommittedRevocationGeneration = revocationGeneration - 1,
                LastCommittedRevocationHeadHash = previousRevocationHead,
                LastCommittedRevocationSnapshotHash = previousRevocationSnapshot,
                NowUnixSeconds = now,
                ClockSkewSeconds = 60
            },
            new SodiumProductionMailboxAuthoritySignatureVerifier());
        var verifiedTopology = ProductionMailboxTopologyVerifier.Verify(
            topologyBytes,
            verifiedAuthority,
            new ProductionMailboxTopologyVerificationContext
            {
                LastCommittedTopologyGeneration = topologyGeneration - 1,
                LastCommittedTopologyHash = previousTopologyHash,
                NowUnixSeconds = now,
                ClockSkewSeconds = 60
            },
            new SodiumProductionMailboxTopologySignatureVerifier());

        var proofRoot = Path.Combine(input.OutputDirectory, "proofs");
        var selectionRoot = Path.Combine(input.OutputDirectory, "selections");
        Directory.CreateDirectory(proofRoot);
        Directory.CreateDirectory(selectionRoot);
        RemovePublishedArtifacts(proofRoot, "*.mip1");
        RemovePublishedArtifacts(selectionRoot, "*.pms1");
        WriteProofs(proofRoot, fixture.Descriptors, fixture.Proofs);
        WriteProofs(proofRoot, fixture.NextDescriptors, fixture.NextProofs);

        var readinessPlacement = new BlindedPlacementId(DomainHash(
            "Deep/survival-uat/production-mailbox/readiness-placement/v1", networkId));
        var readinessSelectionInput = ProductionMailboxReplicaSelection
            .ComputeSelectionInputCommitment(readinessPlacement);
        var readiness = SignSelection(topology, verifiedTopology, fixture.Descriptors,
            fixture.Proofs, readinessPlacement, issuer.PrivateKey, now);
        WriteAtomic(Path.Combine(selectionRoot,
            $"{Lower(readinessSelectionInput)}.pms1"),
            ProductionMailboxTopologyCodec.EncodeSelection(readiness));

        WriteAtomic(Path.Combine(input.OutputDirectory, "authority.pma1"), authorityBytes);
        WriteAtomic(Path.Combine(input.OutputDirectory, "revocations.pmr1"), revocationBytes);
        WriteAtomic(Path.Combine(input.OutputDirectory, "topology.pmt1"), topologyBytes);
        WriteAtomic(Path.Combine(input.OutputDirectory, "baseline.pml3"), EncodeLkg(
            predecessor?.AuthorityGeneration ?? authorityGeneration - 1, previousAuthorityHash,
            predecessor?.RevocationGeneration ?? revocationGeneration - 1, previousRevocationHead,
            previousRevocationSnapshot, topologyGeneration - 1,
            previousTopologyHash));

        var trustFloor = new
        {
            schemaVersion = 1,
            trustFloor = new
            {
                mrXPublicKeySha256 = Lower(SHA256.HashData(mrX.PublicKey)),
                networkId = Lower(networkId),
                authorityGeneration = authorityGeneration.ToString(),
                authorityHash = Lower(authorityHash),
                revocationGeneration = revocationGeneration.ToString(),
                revocationHeadHash = Lower(revocationHead),
                revocationSnapshotHash = Lower(SHA256.HashData(revocationBytes)),
                topologyGeneration = topologyGeneration.ToString(),
                topologyHash = Lower(topologyHash)
            },
            android = new
            {
                buildIdSha256 = Lower(input.AndroidBuildArtifactSha256),
                applicationId = input.AndroidApplicationId,
                versionCode = input.AndroidVersionCode.ToString(),
                playAppSigningLineageSha256 = input.AndroidSignerLineageSha256
                    .Select(hash => Lower(hash)).ToArray()
            }
        };
        WriteJson(Path.Combine(input.OutputDirectory, "trust-floor.json"), trustFloor);
        WriteJson(Path.Combine(input.OutputDirectory, "runtime-public.json"), new
        {
            schemaVersion = 1,
            scope = "DEVELOPMENT-UAT-ONLY",
            coordinatorUrl = $"https://{input.PublicHost}:41810/",
            mrXPublicKeySha256 = Lower(SHA256.HashData(mrX.PublicKey)),
            networkId = Lower(networkId),
            authorityGeneration,
            authorityHash = Lower(authorityHash),
            revocationGeneration,
            revocationHeadHash = Lower(revocationHead),
            revocationSnapshotHash = Lower(SHA256.HashData(revocationBytes)),
            topologyGeneration,
            topologyHash = Lower(topologyHash),
            closurePublisherEd25519PublicKey = Lower(closure.PublicKey),
            readinessBlindedPlacementId = Lower(readinessPlacement.Bytes.Span),
            readinessSelectionInputCommitment = Lower(readinessSelectionInput),
            previousAuthorityGeneration = authorityGeneration - 1,
            previousAuthorityHash = Lower(previousAuthorityHash),
            previousRevocationGeneration = revocationGeneration - 1,
            previousRevocationHeadHash = Lower(previousRevocationHead),
            previousRevocationSnapshotHash = Lower(previousRevocationSnapshot),
            previousTopologyGeneration = topologyGeneration - 1,
            previousTopologyHash = Lower(previousTopologyHash),
            currentEpoch = fixture.CurrentEpoch,
            currentEpochGeneration = fixture.CurrentEpoch,
            currentMembershipCommitment = Lower(fixture.Root),
            currentNotBeforeUnixSeconds = fixture.CurrentNotBefore,
            currentExpiresAtUnixSeconds = fixture.CurrentExpiresAt,
            nextEpoch = fixture.NextEpoch,
            nextEpochGeneration = fixture.NextEpoch,
            nextMembershipCommitment = Lower(fixture.NextRoot),
            nextNotBeforeUnixSeconds = fixture.NextNotBefore,
            nextExpiresAtUnixSeconds = fixture.NextExpiresAt
        });
        WritePrivacyPeerEnvironments(input.OutputDirectory, input.PublicHost,
            fixture.Descriptors, currentSpki, nextSpki);
        Console.WriteLine(JsonSerializer.Serialize(new
        {
            schemaVersion = 1,
            command = "publish-production-uat",
            published = true,
            developmentUatOnly = true,
            privateMaterialIncluded = false
        }));
    }

    private static ProductionMailboxAuthority SignAuthority(
        ProductionMailboxAuthority value, byte[] privateKey)
    {
        var bound = value with
        {
            MrXApproval = value.MrXApproval with
            {
                AuthorityPayloadHash = ProductionMailboxAuthorityCodec.ComputePayloadHash(value)
            },
            Signature = new byte[64]
        };
        return bound with
        {
            Signature = PublicKeyAuth.SignDetached(
                ProductionMailboxAuthorityCodec.GetSigningBytes(bound), privateKey)
        };
    }

    private static ProductionMailboxTopologySnapshot SignTopology(
        ProductionMailboxTopologySnapshot value, byte[] privateKey)
    {
        var unsigned = value with { IssuerSignature = new byte[64] };
        return unsigned with
        {
            IssuerSignature = PublicKeyAuth.SignDetached(
                ProductionMailboxTopologyCodec.GetSigningBytes(unsigned), privateKey)
        };
    }

    private static ProductionMailboxSelectionProof SignSelection(
        ProductionMailboxTopologySnapshot topology,
        VerifiedProductionMailboxTopology verified,
        MembershipRouteDescriptor[] descriptors,
        MailboxReplicaMembershipProof[] proofs,
        BlindedPlacementId placement,
        byte[] privateKey,
        ulong now)
    {
        var selectionInput = ProductionMailboxReplicaSelection
            .ComputeSelectionInputCommitment(placement);
        var selected = ProductionMailboxReplicaSelection.Select(
            topology.NetworkId.Span, topology.CurrentEpoch, selectionInput);
        var replicas = selected.Select(id =>
        {
            var index = Array.FindIndex(descriptors,
                descriptor => descriptor.RouterId.Span.SequenceEqual(id.Span));
            if (index < 0) throw new InvalidDataException("Selected UAT replica is absent.");
            return new ProductionMailboxSelectionReplica
            {
                ReplicaId = id,
                CanonicalMIP1Proof = MailboxPeerReplicationCodec
                    .EncodeMembershipProof(proofs[index])
            };
        }).ToArray();
        var unsigned = new ProductionMailboxSelectionProof
        {
            Algorithm = ProductionMailboxSelectionAlgorithm.RendezvousSha256V2,
            NetworkId = topology.NetworkId,
            AuthorityGeneration = topology.AuthorityGeneration,
            CanonicalAuthorityHash = topology.CanonicalAuthorityHash,
            TopologyGeneration = topology.TopologyGeneration,
            CanonicalTopologyHash = verified.CanonicalTopologyHash,
            Epoch = topology.CurrentEpoch.Epoch,
            Generation = topology.CurrentEpoch.Generation,
            MembershipCommitment = topology.CurrentEpoch.MembershipCommitment,
            TopologyPlacementCommitment = topology.CurrentEpoch.TopologyPlacementCommitment,
            MailboxPlacementCommitment = MailboxPlacementCommitment.Compute(placement),
            SelectionInputCommitment = selectionInput,
            IssuedAtUnixSeconds = now,
            ExpiresAtUnixSeconds = Math.Min(topology.CurrentEpoch.NotAfterUnixSeconds,
                checked(now + 900)),
            Replicas = replicas,
            IssuerSignature = new byte[64]
        };
        return unsigned with
        {
            IssuerSignature = PublicKeyAuth.SignDetached(
                ProductionMailboxTopologyCodec.GetSelectionSigningBytes(unsigned), privateKey)
        };
    }

    private static ProductionMailboxAuthorityEndpoint Endpoint(
        string uri, byte[] currentSpki, byte[] nextSpki) => new()
    {
        Uri = uri,
        CurrentSpkiSha256 = currentSpki,
        NextSpkiSha256 = nextSpki
    };

    private static ProductionMailboxAuthorityEpoch Epoch(
        ulong epoch, ulong generation, byte[] membership, byte[] placement,
        ulong from, ulong until) => new()
    {
        Epoch = epoch,
        Generation = generation,
        MembershipCommitment = membership,
        TopologyPlacementCommitment = placement,
        NotBeforeUnixSeconds = from,
        NotAfterUnixSeconds = until
    };

    private static ProductionMailboxTopologyEpoch TopologyEpoch(
        ProductionMailboxAuthorityEpoch epoch,
        MembershipRouteDescriptor[] descriptors,
        string host,
        byte[] currentSpki,
        byte[] nextSpki) => new()
    {
        Epoch = epoch.Epoch,
        Generation = epoch.Generation,
        MembershipCommitment = epoch.MembershipCommitment,
        TopologyPlacementCommitment = epoch.TopologyPlacementCommitment,
        NotBeforeUnixSeconds = epoch.NotBeforeUnixSeconds,
        NotAfterUnixSeconds = epoch.NotAfterUnixSeconds,
        Nodes = descriptors.Select((descriptor, index) => new ProductionMailboxTopologyNode
        {
            NodeId = descriptor.RouterId,
            HttpsEndpoint = $"https://{host}:{41801 + index}/",
            CurrentSpkiSha256 = currentSpki,
            NextSpkiSha256 = nextSpki
        }).OrderBy(node => Lower(node.NodeId.Span), StringComparer.Ordinal).ToArray()
    };

    private static void WriteProofs(
        string root,
        MembershipRouteDescriptor[] descriptors,
        MailboxReplicaMembershipProof[] proofs)
    {
        if (descriptors.Length != proofs.Length)
            throw new InvalidDataException("UAT membership proof count mismatch.");
        for (var index = 0; index < descriptors.Length; index++)
        {
            var descriptor = descriptors[index];
            WriteAtomic(Path.Combine(root,
                $"{descriptor.Epoch}-{Lower(descriptor.RouterId.Span)}.mip1"),
                MailboxPeerReplicationCodec.EncodeMembershipProof(proofs[index]));
        }
    }

    private static void WritePrivacyPeerEnvironments(
        string outputRoot,
        string host,
        MembershipRouteDescriptor[] descriptors,
        byte[] currentSpki,
        byte[] nextSpki)
    {
        if (descriptors.Length != 6)
            throw new InvalidDataException("UAT privacy topology must contain six nodes.");
        for (var local = 0; local < descriptors.Length; local++)
        {
            var lines = new List<string>();
            var peer = 0;
            for (var remote = 0; remote < descriptors.Length; remote++)
            {
                if (remote == local) continue;
                lines.Add($"PrivacyRouting__Peers__{peer}__RouterId=" +
                    Lower(descriptors[remote].RouterId.Span));
                lines.Add($"PrivacyRouting__Peers__{peer}__BaseUrl=" +
                    $"https://{host}:{41801 + remote}/");
                lines.Add($"PrivacyRouting__Peers__{peer}__CurrentSpkiSha256=" +
                    Lower(currentSpki));
                lines.Add($"PrivacyRouting__Peers__{peer}__NextSpkiSha256=" +
                    Lower(nextSpki));
                peer++;
            }
            WriteAtomic(Path.Combine(outputRoot,
                    $"privacy-routing-xnode-{local + 1}.env"),
                Encoding.UTF8.GetBytes(string.Join('\n', lines) + "\n"));
        }
    }

    private static void RemovePublishedArtifacts(string root, string pattern)
    {
        foreach (var path in Directory.EnumerateFiles(
                     root, pattern, SearchOption.TopDirectoryOnly))
            File.Delete(path);
    }

    private static byte[] EncodeLkg(
        ulong authorityGeneration,
        byte[] authorityHash,
        ulong revocationGeneration,
        byte[] revocationHead,
        byte[] revocationSnapshot,
        ulong topologyGeneration,
        byte[] topologyHash)
    {
        const int commitLength = 152;
        const int authorityFlagOffset = 8 + commitLength;
        const int authorityAnchorOffset = authorityFlagOffset + 1;
        const int topologyFlagOffset = authorityAnchorOffset + commitLength;
        const int topologyAnchorOffset = topologyFlagOffset + 1;
        const int payloadLength = topologyAnchorOffset + 40;
        var bytes = new byte[payloadLength + 32];
        "PML3"u8.CopyTo(bytes);
        bytes[4] = 1;
        var commit = bytes.AsSpan(8, commitLength);
        BinaryPrimitives.WriteUInt64BigEndian(commit[..8], authorityGeneration);
        authorityHash.CopyTo(commit.Slice(8, 32));
        BinaryPrimitives.WriteUInt64BigEndian(commit.Slice(40, 8), revocationGeneration);
        revocationHead.CopyTo(commit.Slice(48, 32));
        revocationSnapshot.CopyTo(commit.Slice(80, 32));
        BinaryPrimitives.WriteUInt64BigEndian(commit.Slice(112, 8), topologyGeneration);
        topologyHash.CopyTo(commit.Slice(120, 32));
        SHA256.HashData(bytes.AsSpan(0, payloadLength))
            .CopyTo(bytes.AsSpan(payloadLength, 32));
        return bytes;
    }

    private static byte[] Spki(string path)
    {
        using var certificate = X509CertificateLoader.LoadCertificateFromFile(path);
        return SHA256.HashData(certificate.PublicKey.ExportSubjectPublicKeyInfo());
    }

    private static byte[] ReadSecret(string path)
    {
        var bytes = File.ReadAllBytes(Path.GetFullPath(path));
        if (bytes.Length != 32 || bytes.AsSpan().IndexOfAnyExcept((byte)0) < 0)
            throw new InvalidDataException("A UAT private seed is invalid.");
        return bytes;
    }

    private static string ReadHexSecret(string path)
    {
        var text = File.ReadAllText(Path.GetFullPath(path)).Trim();
        if (text.Length != 64 || text.Any(static value => value is not
                (>= '0' and <= '9') and not (>= 'a' and <= 'f')))
            throw new InvalidDataException("An XNode seed is invalid.");
        return text;
    }

    private static void RequireDirectory(string path, string name)
    {
        if (!Directory.Exists(Path.GetFullPath(path)))
            throw new InvalidDataException($"UAT {name} is missing.");
    }

    private static byte[] DomainHash(string domain, params byte[][] values)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(Encoding.UTF8.GetBytes(domain));
        foreach (var value in values) hash.AppendData(value);
        return hash.GetHashAndReset();
    }

    private static string Lower(ReadOnlySpan<byte> value) =>
        Convert.ToHexStringLower(value);

    private static void WriteJson(string path, object value) => WriteAtomic(
        path, Encoding.UTF8.GetBytes(JsonSerializer.Serialize(value, Json) + "\n"));

    private static void WriteAtomic(string path, byte[] bytes)
    {
        var full = Path.GetFullPath(path);
        Directory.CreateDirectory(Path.GetDirectoryName(full)!);
        var temporary = full + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            File.WriteAllBytes(temporary, bytes);
            File.Move(temporary, full, true);
        }
        finally
        {
            if (File.Exists(temporary)) File.Delete(temporary);
        }
    }

    private static Predecessor LoadPredecessor(
        Input input,
        byte[] expectedMrXPublicKey,
        byte[] expectedNetworkId)
    {
        var trustPath = input.PreviousTrustFloorPath ?? throw new InvalidOperationException();
        var authorityPath = input.PreviousAuthorityPath ?? throw new InvalidOperationException();
        using var trust = JsonDocument.Parse(File.ReadAllBytes(trustPath), new JsonDocumentOptions
        {
            AllowTrailingCommas = false,
            CommentHandling = JsonCommentHandling.Disallow,
            MaxDepth = 4
        });
        var root = trust.RootElement;
        var floor = root.GetProperty("trustFloor");
        static byte[] Hash(JsonElement value, string name, int bytes)
        {
            var text = value.GetProperty(name).GetString();
            if (text is null || text.Length != bytes * 2 || text.Any(character => character is not
                    (>= '0' and <= '9') and not (>= 'a' and <= 'f')))
                throw new InvalidDataException($"Previous UAT trust floor {name} is invalid.");
            var decoded = Convert.FromHexString(text);
            if (decoded.AsSpan().IndexOfAnyExcept((byte)0) < 0)
                throw new InvalidDataException($"Previous UAT trust floor {name} is invalid.");
            return decoded;
        }
        static ulong Generation(JsonElement value, string name)
        {
            var text = value.GetProperty(name).GetString();
            if (text is null || text.Length == 0 || text[0] == '0' ||
                !ulong.TryParse(text, out var parsed) || parsed == 0)
                throw new InvalidDataException($"Previous UAT trust floor {name} is invalid.");
            return parsed;
        }
        var mrXHash = Hash(floor, "mrXPublicKeySha256", 32);
        var network = Hash(floor, "networkId", 16);
        var authorityHash = Hash(floor, "authorityHash", 32);
        var authorityBytes = File.ReadAllBytes(authorityPath);
        try
        {
            var authority = ProductionMailboxAuthorityCodec.Decode(authorityBytes);
            if (!CryptographicOperations.FixedTimeEquals(
                    SHA256.HashData(expectedMrXPublicKey), mrXHash) ||
                !CryptographicOperations.FixedTimeEquals(expectedNetworkId, network) ||
                !CryptographicOperations.FixedTimeEquals(SHA256.HashData(authorityBytes), authorityHash) ||
                !CryptographicOperations.FixedTimeEquals(authority.NetworkId.Span, network) ||
                !CryptographicOperations.FixedTimeEquals(
                    authority.MrXApprovalEd25519PublicKey.Span, expectedMrXPublicKey) ||
                !PublicKeyAuth.VerifyDetached(authority.Signature.ToArray(),
                    ProductionMailboxAuthorityCodec.GetSigningBytes(authority),
                    expectedMrXPublicKey))
                throw new InvalidDataException(
                    "Previous UAT authority does not match its trust floor or Mr. X root.");
            var authorityGeneration = Generation(floor, "authorityGeneration");
            var revocationGeneration = Generation(floor, "revocationGeneration");
            var topologyGeneration = Generation(floor, "topologyGeneration");
            if (authority.AuthorityGeneration != authorityGeneration ||
                authority.Revocation.Generation != revocationGeneration)
                throw new InvalidDataException(
                    "Previous UAT authority generations do not match its trust floor.");
            return new Predecessor(
                authorityGeneration,
                authorityHash,
                revocationGeneration,
                Hash(floor, "revocationHeadHash", 32),
                Hash(floor, "revocationSnapshotHash", 32),
                topologyGeneration,
                Hash(floor, "topologyHash", 32),
                authority.MrXApproval.AllowedWindowsSigningCertificateSha256
                    .Select(static hash => (ReadOnlyMemory<byte>)hash.ToArray()).ToArray(),
                authority.MrXApproval.WindowsReleaseBuildArtifactSha256
                    .Select(static hash => (ReadOnlyMemory<byte>)hash.ToArray()).ToArray());
        }
        finally
        {
            CryptographicOperations.ZeroMemory(mrXHash);
            CryptographicOperations.ZeroMemory(network);
            CryptographicOperations.ZeroMemory(authorityBytes);
        }
    }

    private sealed record Predecessor(
        ulong AuthorityGeneration,
        byte[] AuthorityHash,
        ulong RevocationGeneration,
        byte[] RevocationHeadHash,
        byte[] RevocationSnapshotHash,
        ulong TopologyGeneration,
        byte[] TopologyHash,
        ReadOnlyMemory<byte>[] WindowsSigningCertificateSha256,
        ReadOnlyMemory<byte>[] WindowsBuildArtifactSha256);

    private sealed record RouteInput(
        string SecretDirectory,
        string PrivateDirectory,
        string OutputDirectory,
        string AuthorityStatePath,
        string PublicHost)
    {
        public static RouteInput Parse(string[] args)
        {
            var names = new[]
            {
                "--secrets-dir", "--private-dir", "--output-dir",
                "--authority-state", "--public-host"
            };
            if (args.Length != 1 + names.Length * 2 ||
                args[0] != "publish-production-uat-routes")
                throw new InvalidOperationException(
                    "publish-production-uat-routes requires the exact documented argument set.");
            var values = new Dictionary<string, string>(StringComparer.Ordinal);
            for (var index = 1; index < args.Length; index += 2)
                if (!names.Contains(args[index], StringComparer.Ordinal) ||
                    string.IsNullOrWhiteSpace(args[index + 1]) ||
                    !values.TryAdd(args[index], args[index + 1]))
                    throw new InvalidOperationException(
                        "publish-production-uat-routes contains an unknown, duplicate, or empty argument.");
            var host = values["--public-host"];
            if (Uri.CheckHostName(host) != UriHostNameType.Dns)
                throw new InvalidOperationException(
                    "--public-host must be a DNS name accepted by PublicHttpsOnly.");
            return new(
                Path.GetFullPath(values["--secrets-dir"]),
                Path.GetFullPath(values["--private-dir"]),
                Path.GetFullPath(values["--output-dir"]),
                Path.GetFullPath(values["--authority-state"]),
                host);
        }
    }

    private sealed record Input(
        string SecretDirectory,
        string PrivateDirectory,
        string OutputDirectory,
        string AuthorityStatePath,
        string LanHost,
        string PublicHost,
        string CurrentCertificatePath,
        string NextCertificatePath,
        byte[] AndroidSigningCertificateSha256,
        byte[] AndroidBuildArtifactSha256,
        string AndroidApplicationId,
        ulong AndroidVersionCode,
        byte[][] AndroidSignerLineageSha256,
        byte[]? WindowsSigningCertificateSha256,
        byte[]? WindowsBuildArtifactSha256,
        string? PreviousTrustFloorPath,
        string? PreviousAuthorityPath)
    {
        public static Input Parse(string[] args)
        {
            var successor = string.Equals(args.FirstOrDefault(),
                "publish-production-uat-successor", StringComparison.Ordinal);
            var allowed = new HashSet<string>(StringComparer.Ordinal)
            {
                "--secrets-dir", "--private-dir", "--output-dir", "--authority-state",
                "--lan-host", "--public-host", "--current-certificate",
                "--next-certificate", "--android-signing-certificate-sha256",
                "--android-build-artifact-sha256", "--android-application-id",
                "--android-version-code", "--android-signer-lineage-sha256"
            };
            if (successor)
            {
                allowed.Add("--previous-trust-floor");
                allowed.Add("--previous-authority");
                allowed.Add("--windows-signing-certificate-sha256");
                allowed.Add("--windows-build-artifact-sha256");
            }
            else
            {
                allowed.Add("--windows-signing-certificate-sha256");
                allowed.Add("--windows-build-artifact-sha256");
            }
            var exactArgumentCount = 1 + allowed.Count * 2;
            var successorWithoutWindowsCount = exactArgumentCount - 4;
            if (args.Length != exactArgumentCount &&
                (!successor || args.Length != successorWithoutWindowsCount)
                || args[0] is not ("publish-production-uat" or
                    "publish-production-uat-successor"))
                throw new InvalidOperationException(
                    "publish-production-uat requires the exact documented argument set.");
            var seen = new HashSet<string>(StringComparer.Ordinal);
            for (var index = 1; index < args.Length; index += 2)
            {
                if (!allowed.Contains(args[index]) || !seen.Add(args[index])
                    || string.IsNullOrWhiteSpace(args[index + 1])
                    || args[index + 1].StartsWith("--", StringComparison.Ordinal))
                    throw new InvalidOperationException(
                        "publish-production-uat contains an unknown, duplicate, or empty argument.");
            }
            string Required(string name)
            {
                var index = Array.IndexOf(args, name);
                if (index < 0 || index + 1 >= args.Length
                    || string.IsNullOrWhiteSpace(args[index + 1]))
                    throw new InvalidOperationException($"{name} is required.");
                return args[index + 1];
            }
            bool Supplied(string name) => Array.IndexOf(args, name) >= 0;
            byte[] Hash(string name)
            {
                var value = Required(name);
                if (value.Length != 64 || value.Any(static item => item is not
                        (>= '0' and <= '9') and not (>= 'a' and <= 'f')))
                    throw new InvalidOperationException($"{name} must be lowercase SHA-256.");
                var bytes = Convert.FromHexString(value);
                if (bytes.AsSpan().IndexOfAnyExcept((byte)0) < 0)
                    throw new InvalidOperationException($"{name} cannot be all-zero.");
                return bytes;
            }
            ulong Version(string name)
            {
                var value = Required(name);
                if (value.Length == 0 || value[0] == '0' ||
                    !ulong.TryParse(value, out var parsed) || parsed == 0)
                    throw new InvalidOperationException($"{name} must be a positive integer.");
                return parsed;
            }
            byte[][] Lineage(string name)
            {
                var values = Required(name).Split('|', StringSplitOptions.None);
                if (values.Length is < 1 or > 32)
                    throw new InvalidOperationException($"{name} count is invalid.");
                var hashes = values.Select(value =>
                {
                    if (value.Length != 64 || value.Any(static item => item is not
                            (>= '0' and <= '9') and not (>= 'a' and <= 'f')))
                        throw new InvalidOperationException($"{name} must contain lowercase SHA-256 values.");
                    var hash = Convert.FromHexString(value);
                    if (hash.AsSpan().IndexOfAnyExcept((byte)0) < 0)
                        throw new InvalidOperationException($"{name} cannot contain all-zero values.");
                    return hash;
                }).ToArray();
                if (hashes.Select(static hash => Convert.ToHexStringLower(hash))
                        .Distinct(StringComparer.Ordinal).Count() != hashes.Length)
                    throw new InvalidOperationException($"{name} contains duplicates.");
                return hashes;
            }
            string ApplicationId(string name)
            {
                var value = Required(name);
                if (!string.Equals(value, "network.xpoint.deep.e2e", StringComparison.Ordinal))
                    throw new InvalidOperationException(
                        $"{name} must be the isolated physical E2E package.");
                return value;
            }
            var host = Required("--lan-host");
            if (!System.Net.IPAddress.TryParse(host, out var address)
                || address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork
                || address.Equals(System.Net.IPAddress.Any))
                throw new InvalidOperationException("--lan-host must be an exact IPv4 address.");
            var publicHost = Required("--public-host");
            if (Uri.CheckHostName(publicHost) != UriHostNameType.Dns)
                throw new InvalidOperationException(
                    "--public-host must be a DNS name accepted by PublicHttpsOnly.");
            return new(
                Path.GetFullPath(Required("--secrets-dir")),
                Path.GetFullPath(Required("--private-dir")),
                Path.GetFullPath(Required("--output-dir")),
                Path.GetFullPath(Required("--authority-state")),
                host,
                publicHost,
                Path.GetFullPath(Required("--current-certificate")),
                Path.GetFullPath(Required("--next-certificate")),
                Hash("--android-signing-certificate-sha256"),
                Hash("--android-build-artifact-sha256"),
                ApplicationId("--android-application-id"),
                Version("--android-version-code"),
                Lineage("--android-signer-lineage-sha256"),
                Supplied("--windows-signing-certificate-sha256")
                    ? Hash("--windows-signing-certificate-sha256") : null,
                Supplied("--windows-build-artifact-sha256")
                    ? Hash("--windows-build-artifact-sha256") : null,
                successor ? Path.GetFullPath(Required("--previous-trust-floor")) : null,
                successor ? Path.GetFullPath(Required("--previous-authority")) : null);
        }
    }
}
