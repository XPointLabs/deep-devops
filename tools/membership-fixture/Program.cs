using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Deep.Protocol.DeepExtension.Membership;
using Deep.Protocol.DeepExtension.MembershipRoutes;
using Sodium;

const string outputName = "membership-route-catalog.json";
const ushort clientProtocol = 2;
FixtureOptions options;
try
{
    options = ParseOptions(args);
}
catch (ArgumentException exception)
{
    Console.Error.WriteLine(exception.Message);
    return 2;
}
var outputDirectory = options.OutputDirectory;
var advertisedHost = options.AdvertisedHost;
var advertisedScheme = options.AdvertisedScheme;
Directory.CreateDirectory(outputDirectory);
if (!OperatingSystem.IsWindows())
{
    File.SetUnixFileMode(
        outputDirectory,
        UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
}

// DEV-LOCAL-ONLY. These deterministic seeds never leave this one-shot container:
// they are not mounted into XNode, Registry, clients, volumes, logs, or the artifact.
var localOnlyDevSeeds = Enumerable.Range(1, 8).Select(index => SHA256.HashData(Encoding.UTF8.GetBytes($"deep-survival-local-only-{index}"))).ToArray();
// This verifier deliberately has the same framing, length checks, and native
// Ed25519 primitive as SodiumEd25519MembershipSignatureVerifier.  Keeping the
// signing capability in this one-shot, network-isolated DEV fixture is what
// lets the generated catalog exercise the real client verification contract.
var verifier = new SodiumCompatibleEd25519Verifier();
var now = checked((ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds());
var validFrom = now - 300;
var validUntil = now + 30UL * 24 * 60 * 60; // regenerated on every supported dev Up; bounded for persistent work.
var networkId = SHA256.HashData("deep-survival-local-membership-v1"u8)[..MembershipLimits.NetworkIdLength];

var roots = Enumerable.Range(0, 5).Select(index => Signer(MembershipSignerRole.OfflineRoot, localOnlyDevSeeds[index])).OrderBy(Id).ToArray();
var online = Enumerable.Range(5, 3).Select(index => Signer(MembershipSignerRole.Online, localOnlyDevSeeds[index])).OrderBy(Id).ToArray();
var genesis = new NetworkGenesis {
    NetworkId = networkId, GenesisSequence = 1, PolicyVersion = 1, MinimumProtocol = clientProtocol, MaximumProtocol = clientProtocol,
    IssuedAtUnixSeconds = now, Policy = MembershipPolicy.Beta(roots.Select(x => x.Descriptor.SignerId).ToArray()), OfflineRoots = roots.Select(x => x.Descriptor).ToArray()
};
var genesisBytes = MembershipContractCodec.EncodeGenesis(genesis);
var genesisLkg = new MembershipLastKnownGood { NetworkId = networkId, PolicyVersion = 1, Sequence = 1, CanonicalHash = MembershipContractHash.Sha256(genesisBytes) };
var unsignedDelegation = new SignerDelegation {
    NetworkId = networkId, Sequence = 2, PreviousHash = genesisLkg.CanonicalHash, IssuedAtUnixSeconds = validFrom,
    ValidFromUnixSeconds = validFrom, ValidUntilUnixSeconds = validUntil, MinimumProtocol = clientProtocol, MaximumProtocol = clientProtocol,
    PolicyVersion = 1, OnlineSigners = online.Select(x => x.Descriptor).ToArray(), Signatures = []
};
var delegationBytes = MembershipContractCodec.GetDelegationSigningBytes(unsignedDelegation);
var delegation = unsignedDelegation with { Signatures = roots.Take(3).Select(root => Signature(root, MembershipSignatureDomain.OfflineDelegation, delegationBytes)).ToArray() };
var verifiedDelegation = MembershipContractVerifier.VerifyDelegation(delegation, genesis, genesisLkg, now, 900, clientProtocol, verifier);

var routerIds = new[] {
    "4cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29", "7422b9887598068e32c4448a949adb290d0f4e35b9e01b0ee5f1a1e600fe2674",
    "f381626e41e7027ea431bfe3009e94bdd25a746beec468948d6c3c7c5dc9a54b", "fd50b8e3b144ea244fbf7737f550bc8dd0c2650bbc1aada833ca17ff8dbf329b",
    "fde4fba030ad002f7c2f7d4c331f49d13fb0ec747eceebec634f1ff4cbca9def", "b4c92afb3ba57f3ab959ffe6d319c98484a2155a0f4c65b2c37011ffd197b075"
};
var devNodeSeeds = Enumerable.Range(1, routerIds.Length).Select(index =>
{
    var seed = new byte[32];
    seed[^1] = checked((byte)index);
    return seed;
}).ToArray();
var x25519PublicKeys = routerIds.Zip(devNodeSeeds, (routerId, seed) =>
{
    var pair = PublicKeyAuth.GenerateKeyPair(seed);
    try
    {
        if (!Convert.ToHexStringLower(pair.PublicKey).Equals(routerId, StringComparison.Ordinal))
            throw new InvalidOperationException("Development node seed does not match its configured router id.");
        return PublicKeyAuth.ConvertEd25519PublicKeyToCurve25519PublicKey(pair.PublicKey);
    }
    finally
    {
        CryptographicOperations.ZeroMemory(pair.PrivateKey);
    }
}).ToArray();
var descriptors = routerIds.Select((id, index) => new MembershipRouteDescriptor {
    RouterId = Convert.FromHexString(id), Ed25519PublicKey = Convert.FromHexString(id),
    X25519PublicKey = x25519PublicKeys[index],
    RpcEndpoint = $"{advertisedScheme}://{advertisedHost}:{41801 + index}/", Roles = MembershipRouteRole.Ingress | MembershipRouteRole.Core | MembershipRouteRole.Storage,
    Capabilities = MembershipRouteCapability.SessionRpc | MembershipRouteCapability.OnionV1 | MembershipRouteCapability.Storage,
    Epoch = 3, ValidFromUnixSeconds = validFrom, ValidUntilUnixSeconds = validUntil
}).OrderBy(x => Convert.ToHexStringLower(x.RouterId.Span), StringComparer.Ordinal).ToArray();
// The catalog is deliberately capable of exactly two disjoint development routes.
// This is a generator invariant, not a production path-selection policy.
var primaryRoute = descriptors.Take(3).Select(x => Convert.ToHexStringLower(x.RouterId.Span)).ToHashSet(StringComparer.Ordinal);
var fallbackRoute = descriptors.Skip(3).Take(3).Select(x => Convert.ToHexStringLower(x.RouterId.Span)).ToHashSet(StringComparer.Ordinal);
if (primaryRoute.Count != 3 || fallbackRoute.Count != 3 || primaryRoute.Overlaps(fallbackRoute) ||
    descriptors.Any(x => (x.Roles & (MembershipRouteRole.Ingress | MembershipRouteRole.Core | MembershipRouteRole.Storage)) !=
                         (MembershipRouteRole.Ingress | MembershipRouteRole.Core | MembershipRouteRole.Storage)))
    throw new InvalidOperationException("Catalog does not provide two disjoint three-hop development routes.");
var statement = new NodeMembershipCommitment {
    NetworkId = networkId, Sequence = 3, PreviousHash = verifiedDelegation.CanonicalHash, IssuedAtUnixSeconds = validFrom,
    ValidFromUnixSeconds = validFrom, ValidUntilUnixSeconds = validUntil, MinimumProtocol = clientProtocol, MaximumProtocol = clientProtocol, PolicyVersion = 1,
    MemberCount = 6, MerkleRoot = MembershipRouteDescriptorCodec.ComputeRoot(descriptors)
};
var membershipBytes = MembershipContractCodec.GetMembershipSigningBytes(statement);
var signedMembership = new SignedMembershipCommitment { Statement = statement, Signatures = online.Take(2).Select(signer => Signature(signer, MembershipSignatureDomain.Membership, membershipBytes)).ToArray() };
var context = new MembershipVerificationContext {
    Genesis = genesis, ActiveDelegation = delegation, AuthorityLastKnownGood = verifiedDelegation.NextAuthorityLastKnownGood,
    RevokedDelegationHashes = [], LastKnownGood = new MembershipLastKnownGood { NetworkId = networkId, PolicyVersion = 1, Sequence = 2, CanonicalHash = verifiedDelegation.CanonicalHash },
    VerificationTimeUnixSeconds = now, AllowedClockSkewSeconds = 900, ClientProtocol = clientProtocol
};
_ = MembershipContractVerifier.VerifyMembership(signedMembership, context, verifier);
var proofs = MembershipRouteDescriptorCodec.BuildProofs(descriptors);
if (descriptors.Length != 6 || descriptors.Zip(proofs).Any(pair => !MembershipRouteDescriptorCodec.VerifyInclusion(pair.First, pair.Second, statement.MerkleRoot.Span))) throw new InvalidOperationException("MRL1 catalog verification failed.");

var canonicalGenesisSha256 = MembershipContractHash.Sha256(genesisBytes);
var canonicalDelegation = MembershipContractCodec.EncodeSignedDelegation(delegation);
var trustAnchor = new
{
    sequence = verifiedDelegation.NextAuthorityLastKnownGood.Sequence,
    canonicalHash = Convert.ToBase64String(verifiedDelegation.CanonicalHash.Span)
};
var artifact = JsonSerializer.SerializeToUtf8Bytes(new {
    version = "deep-membership-route-catalog-v1",
    trustBootstrap = new
    {
        version = "deep-membership-trust-bootstrap-v1",
        scope = "DEV-LOCAL-ONLY",
        opaqueProfileKey = DevFixtureTrust.OpaqueProfileKeyBase,
        canonicalGenesis = Convert.ToBase64String(genesisBytes),
        expectedNetworkId = Convert.ToBase64String(networkId),
        expectedCanonicalGenesisSha256 = Convert.ToBase64String(canonicalGenesisSha256),
        signedDelegation = Convert.ToBase64String(canonicalDelegation),
        // Content anchors pin the verified authority predecessor. The first
        // bridge/MSM1 sequence 3 artifact is therefore a strict successor.
        bridgeAnchor = trustAnchor,
        membershipAnchor = trustAnchor
    },
    signedMembership = Convert.ToBase64String(MembershipContractCodec.EncodeSignedMembership(signedMembership)),
    members = descriptors.Select((descriptor, index) => new { leaf = Convert.ToBase64String(MembershipRouteDescriptorCodec.Encode(descriptor)), leafIndex = proofs[index].LeafIndex, memberCount = proofs[index].MemberCount, siblingHashes = proofs[index].SiblingHashes.Select(x => Convert.ToBase64String(x.Span)).ToArray() }).ToArray()
}, new JsonSerializerOptions(JsonSerializerDefaults.Web));
var target = Path.Combine(outputDirectory, outputName);
var temporary = Path.Combine(outputDirectory, $".{outputName}.{Guid.NewGuid():N}.tmp");
File.WriteAllBytes(temporary, artifact);
File.Move(temporary, target, true); // same-volume replace is the publication boundary.
VerifyPublishedArtifact(target, genesis, genesisLkg, delegation, context, verifier, descriptors, advertisedHost, advertisedScheme);
var publishedArtifactSha256 = Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(target)));
DevFixtureTrust.ValidateDerivedProfileKey(publishedArtifactSha256);
foreach (var signer in roots.Concat(online))
    CryptographicOperations.ZeroMemory(signer.PrivateKey);
foreach (var seed in localOnlyDevSeeds)
    CryptographicOperations.ZeroMemory(seed);
foreach (var seed in devNodeSeeds)
    CryptographicOperations.ZeroMemory(seed);
Console.WriteLine($"PublishedArtifactSha256={publishedArtifactSha256}");
Console.WriteLine("Generated and Sodium-verified one DEV-LOCAL-ONLY 3-of-5 / 2-of-3 membership route catalog (no private material published).");
return 0;

static DevSigner Signer(MembershipSignerRole role, byte[] seed)
{
    var pair = PublicKeyAuth.GenerateKeyPair(seed);
    return new DevSigner(
        new MembershipSignerDescriptor
        {
            SignerId = SHA256.HashData(ByteUtil.Combine("id"u8, pair.PublicKey))[..MembershipLimits.SignerIdLength],
            Role = role,
            PublicKey = pair.PublicKey
        },
        pair.PrivateKey);
}

static string Id(DevSigner signer) => Convert.ToHexStringLower(signer.Descriptor.SignerId.Span);

static MembershipSignature Signature(DevSigner signer, MembershipSignatureDomain domain, ReadOnlySpan<byte> canonicalStatement)
{
    var framed = MembershipSigningDomains.Frame(domain, canonicalStatement);
    var signature = PublicKeyAuth.SignDetached(framed, signer.PrivateKey);
    if (signature.Length != 64)
        throw new InvalidOperationException("libsodium did not produce an Ed25519 detached signature.");
    return new MembershipSignature
    {
        SignerId = signer.Descriptor.SignerId.ToArray(),
        Domain = domain,
        Signature = signature
    };
}

static void VerifyPublishedArtifact(
    string target,
    NetworkGenesis genesis,
    MembershipLastKnownGood genesisLkg,
    SignerDelegation delegation,
    MembershipVerificationContext context,
    IMembershipSignatureVerifier verifier,
    IReadOnlyList<MembershipRouteDescriptor> expectedDescriptors,
    string advertisedHost,
    string advertisedScheme)
{
    // This is deliberately a read-after-publication integration check.  It
    // validates the exact bytes mounted by the consumers, rather than merely
    // the pre-serialization objects used by the generator.
    using var document = JsonDocument.Parse(File.ReadAllBytes(target));
    var root = document.RootElement;
    if (root.GetProperty("version").GetString() != "deep-membership-route-catalog-v1")
        throw new InvalidOperationException("Published membership artifact version is invalid.");

    var trust = root.GetProperty("trustBootstrap");
    var expectedTrustProperties = new[]
    {
        "version", "scope", "opaqueProfileKey", "canonicalGenesis",
        "expectedNetworkId", "expectedCanonicalGenesisSha256",
        "signedDelegation", "bridgeAnchor", "membershipAnchor"
    };
    var actualTrustProperties = trust.EnumerateObject()
        .Select(property => property.Name)
        .OrderBy(name => name, StringComparer.Ordinal)
        .ToArray();
    if (!actualTrustProperties.SequenceEqual(expectedTrustProperties.OrderBy(name => name, StringComparer.Ordinal)) ||
        trust.GetProperty("version").GetString() != "deep-membership-trust-bootstrap-v1" ||
        trust.GetProperty("scope").GetString() != "DEV-LOCAL-ONLY" ||
        trust.GetProperty("opaqueProfileKey").GetString() != DevFixtureTrust.OpaqueProfileKeyBase)
        throw new InvalidOperationException("Published development trust bootstrap framing is invalid.");

    var publishedGenesis = Convert.FromBase64String(trust.GetProperty("canonicalGenesis").GetString()
        ?? throw new InvalidOperationException("Published canonical genesis is missing."));
    var publishedNetworkId = Convert.FromBase64String(trust.GetProperty("expectedNetworkId").GetString()
        ?? throw new InvalidOperationException("Published expected network ID is missing."));
    var publishedGenesisSha256 = Convert.FromBase64String(trust.GetProperty("expectedCanonicalGenesisSha256").GetString()
        ?? throw new InvalidOperationException("Published canonical genesis pin is missing."));
    var publishedDelegation = Convert.FromBase64String(trust.GetProperty("signedDelegation").GetString()
        ?? throw new InvalidOperationException("Published signed delegation is missing."));
    if (!publishedGenesis.AsSpan().SequenceEqual(MembershipContractCodec.EncodeGenesis(genesis)) ||
        !publishedNetworkId.AsSpan().SequenceEqual(genesis.NetworkId.Span) ||
        !publishedGenesisSha256.AsSpan().SequenceEqual(MembershipContractHash.Sha256(publishedGenesis)))
        throw new InvalidOperationException("Published development genesis pins are inconsistent.");

    var decodedPublishedDelegation = MembershipContractCodec.DecodeSignedDelegation(publishedDelegation);
    if (!MembershipContractCodec.EncodeSignedDelegation(decodedPublishedDelegation).AsSpan().SequenceEqual(publishedDelegation))
        throw new InvalidOperationException("Published development delegation is not canonical.");
    var publishedVerifiedDelegation = MembershipContractVerifier.VerifyDelegation(
        decodedPublishedDelegation, genesis, genesisLkg, context.VerificationTimeUnixSeconds,
        context.AllowedClockSkewSeconds, context.ClientProtocol, verifier);
    foreach (var anchorName in new[] { "bridgeAnchor", "membershipAnchor" })
    {
        var anchor = trust.GetProperty(anchorName);
        var anchorProperties = anchor.EnumerateObject()
            .Select(property => property.Name)
            .OrderBy(name => name, StringComparer.Ordinal)
            .ToArray();
        var expectedAnchorProperties = new[] { "canonicalHash", "sequence" };
        if (!anchorProperties.SequenceEqual(expectedAnchorProperties) ||
            anchor.GetProperty("sequence").GetUInt64() != publishedVerifiedDelegation.NextAuthorityLastKnownGood.Sequence ||
            !Convert.FromBase64String(anchor.GetProperty("canonicalHash").GetString()
                    ?? throw new InvalidOperationException($"Published {anchorName} hash is missing."))
                .AsSpan().SequenceEqual(publishedVerifiedDelegation.CanonicalHash.Span))
            throw new InvalidOperationException($"Published {anchorName} is not bound to the verified delegation LKG.");
    }

    var signedBytes = Convert.FromBase64String(root.GetProperty("signedMembership").GetString()
        ?? throw new InvalidOperationException("Published membership statement is missing."));
    var signed = MembershipContractCodec.DecodeSignedMembership(signedBytes);
    if (!MembershipContractCodec.EncodeSignedMembership(signed).AsSpan().SequenceEqual(signedBytes) ||
        signed.Signatures.Count != 2 || signed.Signatures.Any(signature => signature.Signature.Length != 64))
        throw new InvalidOperationException("Published membership statement is not canonical 2-of-3 Ed25519.");

    var canonicalDelegation = MembershipContractCodec.EncodeSignedDelegation(delegation);
    var decodedDelegation = MembershipContractCodec.DecodeSignedDelegation(canonicalDelegation);
    if (!MembershipContractCodec.EncodeSignedDelegation(decodedDelegation).AsSpan().SequenceEqual(canonicalDelegation) ||
        decodedDelegation.Signatures.Count != 3 || decodedDelegation.Signatures.Any(signature => signature.Signature.Length != 64))
        throw new InvalidOperationException("Development delegation is not canonical 3-of-5 Ed25519.");
    var verifiedDelegation = MembershipContractVerifier.VerifyDelegation(
        decodedDelegation, genesis, genesisLkg, context.VerificationTimeUnixSeconds,
        context.AllowedClockSkewSeconds, context.ClientProtocol, verifier);
    if (verifiedDelegation.NextAuthorityLastKnownGood.Sequence != 2 ||
        !verifiedDelegation.NextAuthorityLastKnownGood.CanonicalHash.Span.SequenceEqual(verifiedDelegation.CanonicalHash.Span))
        throw new InvalidOperationException("Development delegation LKG chain is invalid.");

    var verifiedMembership = MembershipContractVerifier.VerifyMembership(
        signed,
        context with
        {
            ActiveDelegation = decodedDelegation,
            AuthorityLastKnownGood = verifiedDelegation.NextAuthorityLastKnownGood,
            LastKnownGood = new MembershipLastKnownGood
            {
                NetworkId = genesis.NetworkId.ToArray(), PolicyVersion = genesis.PolicyVersion,
                Sequence = 2, CanonicalHash = verifiedDelegation.CanonicalHash
            }
        },
        verifier);
    if (verifiedMembership.NextLastKnownGood.Sequence != 3 ||
        !verifiedMembership.NextLastKnownGood.CanonicalHash.Span.SequenceEqual(verifiedMembership.CanonicalHash.Span))
        throw new InvalidOperationException("Published membership LKG chain is invalid.");

    var members = root.GetProperty("members");
    if (members.GetArrayLength() != 6)
        throw new InvalidOperationException("Published route catalog does not contain six members.");
    var seenRouterIds = new HashSet<string>(StringComparer.Ordinal);
    var seenEndpoints = new HashSet<string>(StringComparer.Ordinal);
    var expectedEndpoints = expectedDescriptors.ToDictionary(
        descriptor => Convert.ToHexString(descriptor.RouterId.Span),
        descriptor => descriptor.RpcEndpoint,
        StringComparer.Ordinal);
    foreach (var member in members.EnumerateArray())
    {
        var descriptor = MembershipRouteDescriptorCodec.Decode(Convert.FromBase64String(
            member.GetProperty("leaf").GetString() ?? throw new InvalidOperationException("Route leaf is missing.")));
        var proof = new MembershipRouteInclusionProof
        {
            LeafIndex = member.GetProperty("leafIndex").GetUInt32(),
            MemberCount = member.GetProperty("memberCount").GetUInt32(),
            SiblingHashes = member.GetProperty("siblingHashes").EnumerateArray()
                .Select(value => (ReadOnlyMemory<byte>)Convert.FromBase64String(value.GetString()
                    ?? throw new InvalidOperationException("Route proof sibling is missing.")))
                .ToArray()
        };
        var routerId = Convert.ToHexString(descriptor.RouterId.Span);
        if (!seenRouterIds.Add(routerId) ||
            !expectedEndpoints.TryGetValue(routerId, out var expectedEndpoint) ||
            !string.Equals(descriptor.RpcEndpoint, expectedEndpoint, StringComparison.Ordinal) ||
            !seenEndpoints.Add(descriptor.RpcEndpoint) ||
            !MembershipRouteDescriptorCodec.VerifyInclusion(descriptor, proof, signed.Statement.MerkleRoot.Span))
            throw new InvalidOperationException("Published MRL1 proof verification failed.");
    }
    var requiredEndpoints = Enumerable.Range(41801, 6)
        .Select(port => $"{advertisedScheme}://{advertisedHost}:{port}/")
        .ToHashSet(StringComparer.Ordinal);
    if (!seenEndpoints.SetEquals(requiredEndpoints))
        throw new InvalidOperationException("Published MRL1 endpoints do not match the exact advertised development ports.");
}

static FixtureOptions ParseOptions(string[] arguments)
{
    string? advertisedHost = null;
    var advertisedScheme = "http";
    var outputDirectory = "/out";
    var seen = new HashSet<string>(StringComparer.Ordinal);
    if (arguments.Length == 0 || arguments.Length % 2 != 0)
        throw Usage();
    for (var index = 0; index < arguments.Length; index += 2)
    {
        var name = arguments[index];
        var value = arguments[index + 1];
        if (!seen.Add(name) || string.IsNullOrWhiteSpace(value))
            throw Usage();
        switch (name)
        {
            case "--advertised-host":
                advertisedHost = CanonicalDevLocalIpv4(value);
                break;
            case "--advertised-scheme":
                if (++index >= arguments.Length)
                    throw new ArgumentException("--advertised-scheme requires a value.");
                advertisedScheme = arguments[index] switch
                {
                    "http" => "http",
                    "https" => "https",
                    _ => throw new ArgumentException("--advertised-scheme must be exactly http or https.")
                };
                break;
            case "--output":
                outputDirectory = value;
                break;
            default:
                throw Usage();
        }
    }
    if (advertisedHost is null)
        throw Usage();
    return new FixtureOptions(outputDirectory, advertisedHost, advertisedScheme);
}

static string CanonicalDevLocalIpv4(string value)
{
    var parts = value.Split('.', StringSplitOptions.None);
    if (parts.Length != 4)
        throw new ArgumentException("Advertised host must be a canonical DEV-LOCAL-ONLY IPv4 address.");
    var octets = new byte[4];
    for (var index = 0; index < parts.Length; index++)
    {
        var part = parts[index];
        if (part.Length is < 1 or > 3 ||
            part.Any(character => character is < '0' or > '9') ||
            !byte.TryParse(part, out octets[index]) ||
            !string.Equals(octets[index].ToString(), part, StringComparison.Ordinal))
            throw new ArgumentException("Advertised host must be a canonical DEV-LOCAL-ONLY IPv4 address.");
    }
    var allowed =
        octets[0] == 10 ||
        octets[0] == 127 ||
        octets[0] == 169 && octets[1] == 254 ||
        octets[0] == 172 && octets[1] is >= 16 and <= 31 ||
        octets[0] == 192 && octets[1] == 168;
    if (!allowed)
        throw new ArgumentException("Advertised host must be loopback, RFC1918, or IPv4 link-local.");
    return string.Join('.', octets);
}

static ArgumentException Usage() =>
    new("Usage: MembershipFixture --advertised-host IPv4 [--output DIRECTORY]");

sealed record DevSigner(MembershipSignerDescriptor Descriptor, byte[] PrivateKey);
sealed record FixtureOptions(string OutputDirectory, string AdvertisedHost, string AdvertisedScheme);

static class DevFixtureTrust
{
    public const string OpaqueProfileKeyBase = "install:deep-survival-dev-v2";
    private const int Sha256HexLength = 64;
    private const int MaximumProfileKeyLength = 128;

    public static void ValidateDerivedProfileKey(string artifactSha256)
    {
        var derived = $"{OpaqueProfileKeyBase}:{artifactSha256}";
        if (artifactSha256.Length != Sha256HexLength ||
            artifactSha256.Any(character =>
                character is not (>= '0' and <= '9') and
                not (>= 'a' and <= 'f')) ||
            derived.Length != OpaqueProfileKeyBase.Length + 1 + Sha256HexLength ||
            derived.Length > MaximumProfileKeyLength)
        {
            throw new InvalidOperationException(
                "Derived development membership profile key is invalid.");
        }
    }
}

static class ByteUtil {
    public static byte[] Combine(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) { var result = new byte[left.Length + right.Length]; left.CopyTo(result); right.CopyTo(result.AsSpan(left.Length)); return result; }
}

sealed class SodiumCompatibleEd25519Verifier : IMembershipSignatureVerifier {
    public bool Verify(ReadOnlySpan<byte> signerId, ReadOnlySpan<byte> publicKey, MembershipSignatureDomain domain, ReadOnlySpan<byte> signingBytes, ReadOnlySpan<byte> signature)
    {
        if (signerId.Length != MembershipLimits.SignerIdLength || publicKey.Length != 32 ||
            signature.Length != 64 || signingBytes.Length < MembershipSigningDomains.FixedTagLength)
            return false;
        try
        {
            if (!signingBytes[..MembershipSigningDomains.FixedTagLength]
                    .SequenceEqual(MembershipSigningDomains.GetFixedTag(domain).Span))
                return false;
            return PublicKeyAuth.VerifyDetached(signature.ToArray(), signingBytes.ToArray(), publicKey.ToArray());
        }
        catch (Exception exception) when (exception is not OutOfMemoryException)
        {
            return false;
        }
    }
}
