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

        var previousAuthorityHash = DomainHash(
            "Deep/survival-uat/production-mailbox/previous-authority/v1", networkId);
        var previousRevocationHead = DomainHash(
            "Deep/survival-uat/production-mailbox/previous-revocation-head/v1", networkId);
        var previousRevocationSnapshot = DomainHash(
            "Deep/survival-uat/production-mailbox/previous-revocation-snapshot/v1", networkId);
        var previousTopologyHash = DomainHash(
            "Deep/survival-uat/production-mailbox/previous-topology/v1", networkId);
        var revocationHead = DomainHash(
            "Deep/survival-uat/production-mailbox/revocation-head/v1", networkId);
        var currentPlacement = DomainHash(
            "Deep/survival-uat/production-mailbox/current-placement/v1", networkId);
        var nextPlacement = DomainHash(
            "Deep/survival-uat/production-mailbox/next-placement/v1", networkId);
        var authorityGeneration = checked(fixture.CurrentEpoch + 1);
        var revocationGeneration = authorityGeneration;
        var topologyGeneration = authorityGeneration;
        var rolloutUntil = Math.Min(fixture.CurrentExpiresAt, fixture.NextExpiresAt);

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
                ExpiresAtUnixSeconds = rolloutUntil
            },
            MrXApproval = new ProductionMailboxAuthorityApproval
            {
                AuthorityPayloadHash = DomainHash(
                    "Deep/survival-uat/production-mailbox/approval-placeholder/v1",
                    networkId),
                AllowedAndroidSigningCertificateSha256 = [input.AndroidSigningCertificateSha256],
                AllowedWindowsSigningCertificateSha256 = [input.WindowsSigningCertificateSha256],
                AndroidReleaseBuildArtifactSha256 = [input.AndroidBuildArtifactSha256],
                WindowsReleaseBuildArtifactSha256 = [input.WindowsBuildArtifactSha256],
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
            ExpiresAtUnixSeconds = rolloutUntil,
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
            authorityGeneration - 1, previousAuthorityHash,
            revocationGeneration - 1, previousRevocationHead,
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
            android = (object?)null
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
        byte[] WindowsSigningCertificateSha256,
        byte[] WindowsBuildArtifactSha256)
    {
        public static Input Parse(string[] args)
        {
            var allowed = new HashSet<string>(StringComparer.Ordinal)
            {
                "--secrets-dir", "--private-dir", "--output-dir", "--authority-state",
                "--lan-host", "--public-host", "--current-certificate",
                "--next-certificate", "--android-signing-certificate-sha256",
                "--android-build-artifact-sha256", "--windows-signing-certificate-sha256",
                "--windows-build-artifact-sha256"
            };
            if (args.Length != 1 + allowed.Count * 2
                || !string.Equals(args[0], "publish-production-uat", StringComparison.Ordinal))
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
                Hash("--windows-signing-certificate-sha256"),
                Hash("--windows-build-artifact-sha256"));
        }
    }
}
