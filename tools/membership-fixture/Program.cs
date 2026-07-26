using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Deep.Protocol.DeepExtension.Membership;
using Deep.Protocol.DeepExtension.MembershipRoutes;

const string outputName = "membership-route-catalog.json";
var outputDirectory = args.Length == 2 && args[0] == "--output" ? args[1] : "/out";
if (args.Length is not (0 or 2)) throw new ArgumentException("Usage: MembershipFixture [--output DIRECTORY]");
Directory.CreateDirectory(outputDirectory);

// DEV-LOCAL-ONLY. These deterministic seeds never leave this one-shot container:
// they are not mounted into XNode, Registry, clients, volumes, logs, or the artifact.
var localOnlyDevSeeds = Enumerable.Range(1, 8).Select(index => SHA256.HashData(Encoding.UTF8.GetBytes($"deep-survival-local-only-{index}"))).ToArray();
var verifier = new LocalOnlyDeterministicVerifier();
var now = checked((ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds());
var validFrom = now - 300;
var validUntil = now + 30UL * 24 * 60 * 60; // regenerated on every supported dev Up; bounded for persistent work.
var networkId = SHA256.HashData("deep-survival-local-membership-v1"u8)[..MembershipLimits.NetworkIdLength];

var roots = Enumerable.Range(0, 5).Select(index => Signer(MembershipSignerRole.OfflineRoot, localOnlyDevSeeds[index])).OrderBy(Id).ToArray();
var online = Enumerable.Range(5, 3).Select(index => Signer(MembershipSignerRole.Online, localOnlyDevSeeds[index])).OrderBy(Id).ToArray();
var genesis = new NetworkGenesis {
    NetworkId = networkId, GenesisSequence = 1, PolicyVersion = 1, MinimumProtocol = 1, MaximumProtocol = 1,
    IssuedAtUnixSeconds = now, Policy = MembershipPolicy.Beta(roots.Select(x => x.SignerId).ToArray()), OfflineRoots = roots
};
var genesisBytes = MembershipContractCodec.EncodeGenesis(genesis);
var genesisLkg = new MembershipLastKnownGood { NetworkId = networkId, PolicyVersion = 1, Sequence = 1, CanonicalHash = MembershipContractHash.Sha256(genesisBytes) };
var unsignedDelegation = new SignerDelegation {
    NetworkId = networkId, Sequence = 2, PreviousHash = genesisLkg.CanonicalHash, IssuedAtUnixSeconds = validFrom,
    ValidFromUnixSeconds = validFrom, ValidUntilUnixSeconds = validUntil, MinimumProtocol = 1, MaximumProtocol = 1,
    PolicyVersion = 1, OnlineSigners = online, Signatures = []
};
var delegationBytes = MembershipContractCodec.GetDelegationSigningBytes(unsignedDelegation);
var delegation = unsignedDelegation with { Signatures = roots.Take(3).Select(root => Signature(root, MembershipSignatureDomain.OfflineDelegation, delegationBytes, verifier)).ToArray() };
var verifiedDelegation = MembershipContractVerifier.VerifyDelegation(delegation, genesis, genesisLkg, now, 900, 1, verifier);

var routerIds = new[] {
    "4cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29", "7422b9887598068e32c4448a949adb290d0f4e35b9e01b0ee5f1a1e600fe2674",
    "f381626e41e7027ea431bfe3009e94bdd25a746beec468948d6c3c7c5dc9a54b", "fd50b8e3b144ea244fbf7737f550bc8dd0c2650bbc1aada833ca17ff8dbf329b",
    "fde4fba030ad002f7c2f7d4c331f49d13fb0ec747eceebec634f1ff4cbca9def", "b4c92afb3ba57f3ab959ffe6d319c98484a2155a0f4c65b2c37011ffd197b075"
};
var descriptors = routerIds.Select((id, index) => new MembershipRouteDescriptor {
    RouterId = Convert.FromHexString(id), Ed25519PublicKey = Convert.FromHexString(id),
    X25519PublicKey = SHA256.HashData(ByteUtil.Combine("x25519-local-only"u8, Convert.FromHexString(id))),
    RpcEndpoint = $"http://xnode-{index + 1}:8080/", Roles = MembershipRouteRole.Ingress | MembershipRouteRole.Core | MembershipRouteRole.Storage,
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
    ValidFromUnixSeconds = validFrom, ValidUntilUnixSeconds = validUntil, MinimumProtocol = 1, MaximumProtocol = 1, PolicyVersion = 1,
    MemberCount = 6, MerkleRoot = MembershipRouteDescriptorCodec.ComputeRoot(descriptors)
};
var membershipBytes = MembershipContractCodec.GetMembershipSigningBytes(statement);
var signedMembership = new SignedMembershipCommitment { Statement = statement, Signatures = online.Take(2).Select(signer => Signature(signer, MembershipSignatureDomain.Membership, membershipBytes, verifier)).ToArray() };
var context = new MembershipVerificationContext {
    Genesis = genesis, ActiveDelegation = delegation, AuthorityLastKnownGood = verifiedDelegation.NextAuthorityLastKnownGood,
    RevokedDelegationHashes = [], LastKnownGood = new MembershipLastKnownGood { NetworkId = networkId, PolicyVersion = 1, Sequence = 2, CanonicalHash = verifiedDelegation.CanonicalHash },
    VerificationTimeUnixSeconds = now, AllowedClockSkewSeconds = 900, ClientProtocol = 1
};
_ = MembershipContractVerifier.VerifyMembership(signedMembership, context, verifier);
var proofs = MembershipRouteDescriptorCodec.BuildProofs(descriptors);
if (descriptors.Length != 6 || descriptors.Zip(proofs).Any(pair => !MembershipRouteDescriptorCodec.VerifyInclusion(pair.First, pair.Second, statement.MerkleRoot.Span))) throw new InvalidOperationException("MRL1 catalog verification failed.");

var artifact = JsonSerializer.SerializeToUtf8Bytes(new {
    version = "deep-membership-route-catalog-v1",
    signedMembership = Convert.ToBase64String(MembershipContractCodec.EncodeSignedMembership(signedMembership)),
    members = descriptors.Select((descriptor, index) => new { leaf = Convert.ToBase64String(MembershipRouteDescriptorCodec.Encode(descriptor)), leafIndex = proofs[index].LeafIndex, memberCount = proofs[index].MemberCount, siblingHashes = proofs[index].SiblingHashes.Select(x => Convert.ToBase64String(x.Span)).ToArray() }).ToArray()
}, new JsonSerializerOptions(JsonSerializerDefaults.Web));
var target = Path.Combine(outputDirectory, outputName);
var temporary = Path.Combine(outputDirectory, $".{outputName}.{Guid.NewGuid():N}.tmp");
File.WriteAllBytes(temporary, artifact);
File.Move(temporary, target, true); // same-volume replace is the publication boundary.
Console.WriteLine("Generated and locally verified one DEV-LOCAL-ONLY 3-of-5 / 2-of-3 membership route catalog (no private material published).");

static MembershipSignerDescriptor Signer(MembershipSignerRole role, byte[] seed) => new() { SignerId = SHA256.HashData(ByteUtil.Combine("id"u8, seed))[..MembershipLimits.SignerIdLength], Role = role, PublicKey = SHA256.HashData(ByteUtil.Combine("public"u8, seed)) };
static string Id(MembershipSignerDescriptor signer) => Convert.ToHexStringLower(signer.SignerId.Span);
static MembershipSignature Signature(MembershipSignerDescriptor signer, MembershipSignatureDomain domain, byte[] bytes, LocalOnlyDeterministicVerifier verifier) => new() { SignerId = signer.SignerId.ToArray(), Domain = domain, Signature = verifier.Sign(signer.SignerId.Span, signer.PublicKey.Span, domain, bytes) };

static class ByteUtil {
    public static byte[] Combine(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) { var result = new byte[left.Length + right.Length]; left.CopyTo(result); right.CopyTo(result.AsSpan(left.Length)); return result; }
}

sealed class LocalOnlyDeterministicVerifier : IMembershipSignatureVerifier {
    public bool Verify(ReadOnlySpan<byte> signerId, ReadOnlySpan<byte> publicKey, MembershipSignatureDomain domain, ReadOnlySpan<byte> signingBytes, ReadOnlySpan<byte> signature) => signature.SequenceEqual(SignFramed(signerId, publicKey, signingBytes));
    public byte[] Sign(ReadOnlySpan<byte> signerId, ReadOnlySpan<byte> publicKey, MembershipSignatureDomain domain, ReadOnlySpan<byte> canonicalStatement) => SignFramed(signerId, publicKey, MembershipSigningDomains.Frame(domain, canonicalStatement));
    private static byte[] SignFramed(ReadOnlySpan<byte> signerId, ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> bytes) => SHA256.HashData(ByteUtil.Combine(ByteUtil.Combine(signerId, publicKey), bytes));
}
