using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text.Json;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.MembershipRoutes;
using XNode.Core;
using XNode.Core.Mailbox;
using XNode.Core.Mailbox.Client;

if (args.Length > 0 && args[0] == "publish-runtime")
{
    MailboxRuntimePublisher.Publish(args);
    return;
}

var arguments = Arguments.Parse(args);
if (arguments.Command == "provision")
{
    var provisioned = MailboxGrantProvisioner.Provision(arguments);
    Result("provision", new
    {
        schemaVersion = 1,
        developmentOnly = true,
        generation = provisioned.Generation,
        bundles = provisioned.BundleNames,
        outputHashes = provisioned.OutputHashes
    });
    return;
}
if (arguments.Command == "verify-provision")
{
    MailboxGrantProvisioner.Verify(arguments);
    Result("verify-provision", new { schemaVersion = 1, verified = true });
    return;
}
var fixture = arguments.Command == "authority"
    ? Fixture.CreateAuthority(Enumerable.Range(1, 6)
        .Select(index => File.ReadAllText(
            Path.Combine(arguments.SecretsDirectory, $"xnode-{index}-ed25519.seed")).Trim())
        .ToArray(),
        File.ReadAllText(
            Path.Combine(arguments.SecretsDirectory, "mailbox-client-issuer.seed")).Trim(),
        arguments.AuthorityStatePath is null
            ? AuthorityWindow.CreateDefault()
            : AuthorityWindow.Load(arguments.AuthorityStatePath))
    : Fixture.LoadPublic(
        File.ReadAllText(Path.Combine(arguments.SecretsDirectory, "xnode-1-ed25519.seed")).Trim(),
        File.ReadAllText(Path.Combine(arguments.SecretsDirectory, "mailbox-client-issuer.seed")).Trim(),
        arguments.AuthorityPublicPath,
        arguments.CoordinatorUrl,
        arguments.RequireNonLoopbackCoordinator);

switch (arguments.Command)
{
    case "authority":
        fixture.WriteAuthority(
            arguments.OutputEnvironment!,
            arguments.OutputClientEnvironment!,
            arguments.OutputPublic!,
            arguments.CoordinatorUrl,
            arguments.OutputClientPublic);
        Result("authority", new
        {
            membershipProofs = 12,
            placementSelections = 30,
            publicClientFixture = true,
            realMip1Rip1 = true,
            boundedEpochWindows = true,
            currentWindowSeconds =
                fixture.CurrentExpiresAt - fixture.CurrentNotBefore,
            nextWindowSeconds =
                fixture.NextExpiresAt - fixture.NextNotBefore
        });
        break;
    case "reset":
        if (Directory.Exists(arguments.StateDirectory))
        {
            Directory.Delete(arguments.StateDirectory, recursive: true);
        }
        Directory.CreateDirectory(arguments.StateDirectory);
        Result("reset", new { boundedDriverState = true });
        break;
    case "store":
        await RunNewAsync(fixture, arguments, "primary", 0, 1, expectDurable: true);
        break;
    case "replay":
        await RunReplayAsync(fixture, arguments, "primary", expectDurable: true);
        break;
    case "loss":
        await RunNewAsync(fixture, arguments, "loss", 0, 2, expectDurable: false);
        break;
    case "retry-loss":
        await RunReplayAsync(fixture, arguments, "loss", expectDurable: true);
        break;
    case "tombstone":
        await RunTombstoneAsync(fixture, arguments);
        break;
    case "client-lifecycle":
        await RunClientLifecycleAsync(fixture, arguments);
        break;
    case "client-loss":
        await RunClientLossAsync(fixture, arguments);
        break;
    case "client-retry-loss":
        await RunClientRetryLossAsync(arguments);
        break;
    case "client-uncertain-resend":
        await RunClientUncertainResendAsync(fixture, arguments);
        break;
    case "retention-gc":
        RunRetentionGc(fixture, arguments);
        break;
    default:
        throw new InvalidOperationException("Unknown mailbox rehearsal command.");
}

static async Task RunNewAsync(
    Fixture fixture,
    Arguments arguments,
    string name,
    int senderIndex,
    int recipientIndex,
    bool expectDurable)
{
    if (string.IsNullOrWhiteSpace(arguments.RunId))
    {
        throw new InvalidOperationException("A run id is required.");
    }

    var now = checked((ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds());
    var scenario = fixture.NewScenario(arguments.RunId, name, senderIndex, recipientIndex, now);
    Directory.CreateDirectory(arguments.StateDirectory);
    await File.WriteAllTextAsync(
        Path.Combine(arguments.StateDirectory, $"{name}.json"),
        JsonSerializer.Serialize(scenario));
    var result = await ExecuteCoordinatorAsync(fixture, arguments, scenario);
    AssertOutcome(result, expectDurable);
    ReadOnlyMemory<byte>? remote = null;
    if (expectDurable)
    {
        remote = await new ExactHttpPeerClient().SendAsync(
            fixture.Peer(recipientIndex, scenario.Operation),
            scenario.Operation,
            Convert.FromBase64String(scenario.Prq2),
            CancellationToken.None);
        if (remote is null || !HasMagic(remote.Value.Span, "MRR2"))
        {
            throw new InvalidOperationException("The selected live peer did not replay a native MRR2.");
        }
    }
    scenario = scenario with
    {
        Mrr2 = remote is null ? "" : Convert.ToBase64String(remote.Value.Span),
        Mqr3 = Convert.ToBase64String(result.CanonicalMqr3.Span)
    };
    await File.WriteAllTextAsync(
        Path.Combine(arguments.StateDirectory, $"{name}.json"),
        JsonSerializer.Serialize(scenario));
    Result(name == "loss" ? "selected-peer-loss" : "store", new
    {
        status = result.Status.ToString(),
        durableReplicaCount = result.DurableReplicaCount,
        mrr2 = remote is not null,
        mqr3 = HasMagic(result.CanonicalMqr3.Span, "MQR3"),
        prq2Bytes = Convert.FromBase64String(scenario.Prq2).Length,
        mrr2Bytes = remote?.Length ?? 0,
        mqr3Bytes = result.CanonicalMqr3.Length
    });
}

static async Task RunReplayAsync(
    Fixture fixture,
    Arguments arguments,
    string name,
    bool expectDurable)
{
    var scenario = await LoadAsync(arguments.StateDirectory, name);
    var request = Convert.FromBase64String(scenario.Prq2);
    var peer = fixture.Peer(scenario.RecipientIndex, scenario.Operation);
    var direct = await new ExactHttpPeerClient().SendAsync(
        peer,
        scenario.Operation,
        request,
        CancellationToken.None);
    if (direct is null || !HasMagic(direct.Value.Span, "MRR2"))
    {
        throw new InvalidOperationException("The selected live peer did not return a native MRR2.");
    }
    var hadPriorMrr2 = !string.IsNullOrEmpty(scenario.Mrr2);
    var exactMrr2 = !hadPriorMrr2
        || CryptographicOperations.FixedTimeEquals(
            Convert.FromBase64String(scenario.Mrr2),
            direct.Value.Span);
    if (!exactMrr2)
    {
        throw new InvalidOperationException("Exact replay did not return the persisted native MRR2.");
    }

    var result = await ExecuteCoordinatorAsync(fixture, arguments, scenario);
    AssertOutcome(result, expectDurable);
    var hadPriorMqr3 = !string.IsNullOrEmpty(scenario.Mqr3);
    var exactMqr3 = !hadPriorMqr3
        || CryptographicOperations.FixedTimeEquals(
            Convert.FromBase64String(scenario.Mqr3),
            result.CanonicalMqr3.Span);
    if (!exactMqr3)
    {
        throw new InvalidOperationException("Exact replay did not return the persisted native MQR3.");
    }
    if (string.IsNullOrEmpty(scenario.Mqr3))
    {
        scenario = scenario with
        {
            Mrr2 = Convert.ToBase64String(direct.Value.Span),
            Mqr3 = Convert.ToBase64String(result.CanonicalMqr3.Span)
        };
        await File.WriteAllTextAsync(
            Path.Combine(arguments.StateDirectory, $"{name}.json"),
            JsonSerializer.Serialize(scenario));
    }
    Result(name == "loss" ? "selected-peer-retry" : "replay", new
    {
        status = result.Status.ToString(),
        durableReplicaCount = result.DurableReplicaCount,
        nativeMrr2 = true,
        nativeMqr3 = HasMagic(result.CanonicalMqr3.Span, "MQR3"),
        exactMrr2 = hadPriorMrr2 ? exactMrr2 : (bool?)null,
        exactMqr3 = hadPriorMqr3 ? exactMqr3 : (bool?)null,
        mrr2Bytes = direct.Value.Length,
        mqr3Bytes = result.CanonicalMqr3.Length
    });
}

static async Task RunTombstoneAsync(Fixture fixture, Arguments arguments)
{
    var stored = await LoadAsync(arguments.StateDirectory, "primary");
    var decoded = MailboxPeerWireV2Codec.Decode(Convert.FromBase64String(stored.Prq2));
    var nonceMaterial = SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(
        $"{stored.RunId}|tombstone"));
    var payload = Convert.FromBase64String(stored.DeduplicationDigest);
    var unsigned = decoded with
    {
        Operation = MailboxPeerReplicationOperation.Tombstone,
        OperationId = nonceMaterial.AsSpan(0, 16).ToArray(),
        ReplayNonce = SHA256.HashData(nonceMaterial),
        Payload = payload,
        PayloadDigest = SHA256.HashData(payload),
        Signature = ReadOnlyMemory<byte>.Empty
    };
    var signed = fixture.Crypto.SignRequest(
        unsigned,
        fixture.SenderPrivateSeed(stored.SenderIndex));
    var scenario = stored with
    {
        Name = "tombstone",
        Operation = MailboxPeerReplicationOperation.Tombstone,
        Prq2 = Convert.ToBase64String(MailboxPeerWireV2Codec.Encode(signed)),
        Mrr2 = "",
        Mqr3 = ""
    };
    var result = await ExecuteCoordinatorAsync(fixture, arguments, scenario);
    AssertOutcome(result, expectDurable: true);
    var tombstoneRequest = Convert.FromBase64String(scenario.Prq2);
    var peer = fixture.Peer(scenario.RecipientIndex, scenario.Operation);
    var firstMrr2 = await new ExactHttpPeerClient().SendAsync(
        peer,
        scenario.Operation,
        tombstoneRequest,
        CancellationToken.None);
    var secondMrr2 = await new ExactHttpPeerClient().SendAsync(
        peer,
        scenario.Operation,
        tombstoneRequest,
        CancellationToken.None);
    if (firstMrr2 is null
        || secondMrr2 is null
        || !HasMagic(firstMrr2.Value.Span, "MRR2")
        || !CryptographicOperations.FixedTimeEquals(firstMrr2.Value.Span, secondMrr2.Value.Span))
    {
        throw new InvalidOperationException("Exact Tombstone replay did not return the persisted native MRR2.");
    }
    scenario = scenario with
    {
        Mrr2 = Convert.ToBase64String(firstMrr2.Value.Span),
        Mqr3 = Convert.ToBase64String(result.CanonicalMqr3.Span)
    };
    await File.WriteAllTextAsync(
        Path.Combine(arguments.StateDirectory, "tombstone.json"),
        JsonSerializer.Serialize(scenario));
    var replay = await ExecuteCoordinatorAsync(fixture, arguments, scenario);
    AssertOutcome(replay, expectDurable: true);
    if (!CryptographicOperations.FixedTimeEquals(result.CanonicalMqr3.Span, replay.CanonicalMqr3.Span))
    {
        throw new InvalidOperationException("Exact Tombstone replay changed the native MQR3.");
    }
    Result("tombstone", new
    {
        status = result.Status.ToString(),
        durableReplicaCount = result.DurableReplicaCount,
        mrr2 = true,
        mqr3 = HasMagic(result.CanonicalMqr3.Span, "MQR3"),
        exactReplay = true,
        mrr2Bytes = firstMrr2.Value.Length,
        mqr3Bytes = result.CanonicalMqr3.Length
    });
}

static async Task RunClientLifecycleAsync(Fixture fixture, Arguments arguments)
{
    if (string.IsNullOrWhiteSpace(arguments.RunId))
    {
        throw new InvalidOperationException("A run id is required.");
    }
    var now = checked((ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds());
    var store = fixture.NewClientStore(arguments.RunId, "client-primary", now);
    var client = new ExactHttpClient(arguments.ClientUrl);
    var firstStore = await client.SendSuccessAsync(
        MailboxWireHttpContract.Store,
        store.CanonicalRequest);
    var replayStore = await client.SendSuccessAsync(
        MailboxWireHttpContract.Store,
        store.CanonicalRequest);
    _ = MailboxReceiptV3Codec.DecodeDurableQuorum(firstStore);
    if (!CryptographicOperations.FixedTimeEquals(firstStore, replayStore))
    {
        throw new InvalidOperationException(
            "Exact public Store replay changed the native MQR3.");
    }

    var retrieve = fixture.NewClientRetrieve(
        arguments.RunId,
        "client-retrieve",
        store.Envelope,
        now,
        replayCounter: 2);
    var pageBytes = await client.SendSuccessAsync(
        MailboxWireHttpContract.Retrieve,
        retrieve);
    var page = MailboxClientCodec.DecodeRetrievePage(
        pageBytes,
        fixture.ClientDecodePolicy(now));
    if (page.Items.Count != 1
        || !page.Items[0].Envelope.OperationId.Span.SequenceEqual(
            store.Envelope.OperationId.Span)
        || !page.Items[0].Envelope.DeduplicationDigest.Span.SequenceEqual(
            store.Envelope.DeduplicationDigest.Span))
    {
        throw new InvalidOperationException(
            "Public Retrieve did not return the exact stored envelope.");
    }

    var ack = fixture.NewClientAck(
        arguments.RunId,
        "client-ack",
        store.Envelope,
        [page.Items[0].ToAcknowledgement()],
        now,
        replayCounter: 3);
    var ackBytes = await client.SendSuccessAsync(
        MailboxWireHttpContract.Acknowledge,
        ack);
    var aggregate = MailboxAggregateAckCodec.DecodeMqr3(ackBytes);
    if (aggregate.TombstoneQuorums.Count != 1)
    {
        throw new InvalidOperationException(
            "Public ACK did not return one native tombstone MQR3.");
    }

    var emptyRetrieve = fixture.NewClientRetrieve(
        arguments.RunId,
        "client-retrieve-empty",
        store.Envelope,
        now,
        replayCounter: 4);
    var emptyPageBytes = await client.SendSuccessAsync(
        MailboxWireHttpContract.Retrieve,
        emptyRetrieve);
    var emptyPage = MailboxClientCodec.DecodeRetrievePage(
        emptyPageBytes,
        fixture.ClientDecodePolicy(now));
    if (emptyPage.Items.Count != 0)
    {
        throw new InvalidOperationException(
            "Public ACK did not make the acknowledged envelope disappear.");
    }
    Result("client-lifecycle", new
    {
        store = "durable",
        retrieveItems = page.Items.Count,
        ackTombstoneQuorums = aggregate.TombstoneQuorums.Count,
        retrieveAfterAckItems = emptyPage.Items.Count,
        exactStoreReplay = true,
        mau2StoreBytes = store.CanonicalRequest.Length,
        mqr3Bytes = firstStore.Length,
        mau2RetrieveBytes = retrieve.Length,
        mrp1Bytes = pageBytes.Length,
        mau2AckBytes = ack.Length,
        mar1Bytes = ackBytes.Length
    });
}

static async Task RunClientLossAsync(Fixture fixture, Arguments arguments)
{
    if (string.IsNullOrWhiteSpace(arguments.RunId))
    {
        throw new InvalidOperationException("A run id is required.");
    }
    var now = checked((ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds());
    var store = fixture.NewClientStore(arguments.RunId, "client-loss", now);
    Directory.CreateDirectory(arguments.StateDirectory);
    await File.WriteAllBytesAsync(
        Path.Combine(arguments.StateDirectory, "client-loss.mau2"),
        store.CanonicalRequest);
    await new ExactHttpClient(arguments.ClientUrl).SendFailureAsync(
        MailboxWireHttpContract.Store,
        store.CanonicalRequest,
        MailboxHttpFailure.DependencyUnavailable);
    Result("client-selected-peer-loss", new
    {
        status = "dependency-unavailable",
        exactRetryPersisted = true,
        mau2StoreBytes = store.CanonicalRequest.Length
    });
}

static async Task RunClientRetryLossAsync(Arguments arguments)
{
    var canonical = await File.ReadAllBytesAsync(
        Path.Combine(arguments.StateDirectory, "client-loss.mau2"));
    var response = await new ExactHttpClient(arguments.ClientUrl).SendSuccessAsync(
        MailboxWireHttpContract.Store,
        canonical);
    _ = MailboxReceiptV3Codec.DecodeDurableQuorum(response);
    var replay = await new ExactHttpClient(arguments.ClientUrl).SendSuccessAsync(
        MailboxWireHttpContract.Store,
        canonical);
    if (!CryptographicOperations.FixedTimeEquals(response, replay))
    {
        throw new InvalidOperationException(
            "Recovered public Store exact replay changed the native MQR3.");
    }
    Result("client-selected-peer-retry", new
    {
        status = "durable",
        nativeMqr3 = true,
        exactReplay = true,
        mau2StoreBytes = canonical.Length,
        mqr3Bytes = response.Length
    });
}

static async Task RunClientUncertainResendAsync(Fixture fixture, Arguments arguments)
{
    if (string.IsNullOrWhiteSpace(arguments.RunId))
    {
        throw new InvalidOperationException("A run id is required.");
    }
    var now = checked((ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds());
    var store = fixture.NewClientStore(arguments.RunId, "client-uncertain-resend", now);
    var client = new ExactHttpClient(arguments.ClientUrl);
    await client.SendTransportFailureAsync(
        MailboxWireHttpContract.Store,
        store.CanonicalRequest);
    var retry = await client.SendSuccessAsync(
        MailboxWireHttpContract.Store,
        store.CanonicalRequest);
    var replay = await client.SendSuccessAsync(
        MailboxWireHttpContract.Store,
        store.CanonicalRequest);
    _ = MailboxReceiptV3Codec.DecodeDurableQuorum(retry);
    if (!CryptographicOperations.FixedTimeEquals(retry, replay))
    {
        throw new InvalidOperationException(
            "Exact uncertain Store retry changed the durable MQR3 outcome.");
    }

    var retrieve = fixture.NewClientRetrieve(
        arguments.RunId,
        "client-uncertain-resend-retrieve",
        store.Envelope,
        now,
        replayCounter: 2);
    var pageBytes = await client.SendSuccessAsync(
        MailboxWireHttpContract.Retrieve,
        retrieve);
    var page = MailboxClientCodec.DecodeRetrievePage(
        pageBytes,
        fixture.ClientDecodePolicy(now));
    if (page.Items.Count != 1
        || !page.Items[0].Envelope.OperationId.Span.SequenceEqual(
            store.Envelope.OperationId.Span))
    {
        throw new InvalidOperationException(
            "Uncertain Store retry produced anything other than one exact server item.");
    }
    Result("client-uncertain-resend", new
    {
        firstOutcome = "transport-unknown-after-dispatch",
        retry = "durable",
        exactReplay = true,
        serverItemCount = page.Items.Count,
        duplicateServerItemCreated = false,
        nativeMqr3 = true
    });
}

static void RunRetentionGc(Fixture fixture, Arguments arguments)
{
    var directory = Path.Combine(arguments.StateDirectory, "retention-gc");
    if (Directory.Exists(directory))
    {
        Directory.Delete(directory, recursive: true);
    }
    Directory.CreateDirectory(directory);
    var retention = TimeSpan.FromDays(7);
    using var journal = new DurableMailboxCapabilityReplayJournal(
        directory,
        new DurableMailboxCapabilityReplayJournalOptions
        {
            DirectoryName = "bounded-p10e-replay",
            MaximumScopes = 1,
            RetentionAfterValidity = retention
        });
    using var outcomes = new MailboxClientCanonicalOutcomeStore(
        directory,
        new MailboxClientCanonicalOutcomeStoreOptions
        {
            DirectoryName = "bounded-p10e-outcomes",
            MaximumEntries = 1,
            MaximumBytes = 4096
        });
    var runtime = new MailboxAuthenticatedCapabilityRuntime(
        fixture.CreateRuntimeAuthority(),
        fixture.CreateRuntimeRevocations(),
        journal,
        outcomes);
    var now = checked((ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds());
    var canonicalMau2 = fixture.NewRuntimeStore("retention-gc", "current", now);
    var reservation = runtime.Verify(canonicalMau2);
    if (!runtime.TryAcquireExecution(reservation))
    {
        throw new InvalidOperationException("Retention rehearsal did not own its real MAU2 execution.");
    }
    runtime.ReserveOutcomeCapacity(reservation, 64);
    runtime.PersistTerminal(
        reservation,
        MailboxClientTerminalOutcome.DurableStateRejected);
    var retainUntil = reservation.RetainUntilUnixSeconds;
    var retentionSeconds = checked((ulong)retention.TotalSeconds);
    if (retainUntil != fixture.CurrentExpiresAt + retentionSeconds)
    {
        throw new InvalidOperationException(
            "Replay retention is not bound to authority epoch expiry plus fixed retention.");
    }
    var beforeReplay = journal.Diagnostics;
    var beforeOutcomes = outcomes.Diagnostics;
    var atBoundary = runtime.CollectExpired(retainUntil, 1);
    var afterBoundaryReplay = journal.Diagnostics;
    var afterBoundaryOutcomes = outcomes.Diagnostics;
    var collected = runtime.CollectExpired(retainUntil + 1, 1);
    var afterReplay = journal.Diagnostics;
    var afterOutcomes = outcomes.Diagnostics;
    if (beforeReplay.ScopeCount != 1
        || beforeReplay.CompletedCount != 1
        || beforeOutcomes.EntryCount != 1
        || atBoundary != 0
        || afterBoundaryReplay.ScopeCount != 1
        || afterBoundaryOutcomes.EntryCount != 1
        || collected != 1
        || afterReplay.ScopeCount != 0
        || afterOutcomes.EntryCount != 0
        || afterReplay.CapacityRemaining != 1
        || afterOutcomes.EntryCapacityRemaining != 1)
    {
        throw new InvalidOperationException(
            "Coordinated replay/outcome retirement did not retain through its bound then recover capacity.");
    }
    Result("retention-gc", new
    {
        authorityBound = "epoch-expiry-plus-fixed-retention",
        retentionSeconds,
        retainedAtBoundary = true,
        collectedAfterBoundary = collected,
        replayOutcomeCoordinated = true,
        capacityRecovered = true
    });
}

static async Task<MailboxPeerQuorumResult> ExecuteCoordinatorAsync(
    Fixture fixture,
    Arguments arguments,
    Scenario scenario)
{
    var root = Path.Combine(
        arguments.StateDirectory,
        scenario.Name == "tombstone" ? "primary" : scenario.Name);
    Directory.CreateDirectory(root);
    var options = Options();
    var store = new ReplicatedMailboxStore(root, options);
    await store.InitializeAsync();
    using var mutations = new MailboxPeerMutationStore(root, options, store);
    await mutations.InitializeAsync();
    using var journal = new DurableMailboxPeerReplayJournal(root, options);
    var request = Convert.FromBase64String(scenario.Prq2);
    var decoded = MailboxPeerWireV2Codec.Decode(request);
    var policy = new MailboxPeerWireVerificationPolicyV2
    {
        ExpectedOperation = scenario.Operation,
        Epoch = decoded.Epoch,
        OperationId = decoded.OperationId.ToArray(),
        SenderRouterId = decoded.SenderRouterId.ToArray(),
        RecipientRouterId = decoded.RecipientRouterId.ToArray(),
        MembershipCommitment = decoded.MembershipCommitment.ToArray(),
        PlacementCommitment = decoded.PlacementCommitment.ToArray(),
        PlacementId = new BlindedPlacementId(Convert.FromBase64String(scenario.PlacementId)),
        NowUnixSeconds = checked((ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds()),
        EpochExpiresAtUnixSeconds = fixture.CurrentExpiresAt
    };
    var coordinator = new MailboxReplicationCoordinator(
        fixture.RouterIds[scenario.SenderIndex],
        Convert.ToHexString(fixture.SenderPrivateSeed(scenario.SenderIndex)),
        options,
        mutations,
        new ExactHttpPeerClient(),
        new MembershipRoutesMailboxReplicaProofVerifier(),
        journal);
    return await coordinator.ReplicateAsync(
        fixture.Peer(scenario.RecipientIndex, scenario.Operation),
        request,
        policy);
}

static ReplicatedMailboxOptions Options() => new()
{
    Enabled = true,
    MinimumTtl = TimeSpan.FromMinutes(1),
    MaximumTtl = TimeSpan.FromDays(7),
    PeerTimeout = TimeSpan.FromSeconds(5),
    MaxStoredBlobs = 128,
    MaxRecoveryScanFiles = 256,
    MaxPeerReplayRecords = 128,
    MaxPeerReplayRecordsPerRouterPairEpoch = 64,
    MaxPeerMutationRecords = 128
};

static void AssertOutcome(MailboxPeerQuorumResult result, bool expectDurable)
{
    var expected = expectDurable
        ? MailboxPeerQuorumStatus.Durable
        : MailboxPeerQuorumStatus.PartialFailure;
    var replicas = expectDurable ? 2 : 1;
    if (result.Status != expected
        || result.DurableReplicaCount != replicas
        || expectDurable != HasMagic(result.CanonicalMqr3.Span, "MQR3"))
    {
        throw new InvalidOperationException($"Unexpected quorum result: {result.Status}/{result.DurableReplicaCount}.");
    }
}

static async Task<Scenario> LoadAsync(string directory, string name)
{
    var value = JsonSerializer.Deserialize<Scenario>(
        await File.ReadAllTextAsync(Path.Combine(directory, $"{name}.json")));
    return value ?? throw new InvalidDataException("Stored rehearsal scenario is invalid.");
}

static bool HasMagic(ReadOnlySpan<byte> bytes, string magic) =>
    bytes.Length >= 4 && bytes[..4].SequenceEqual(System.Text.Encoding.ASCII.GetBytes(magic));

static void Result(string phase, object details) =>
    Console.WriteLine(JsonSerializer.Serialize(new { schemaVersion = 1, phase, passed = true, details }));

sealed record Scenario(
    string RunId,
    string Name,
    int SenderIndex,
    int RecipientIndex,
    MailboxPeerReplicationOperation Operation,
    string PlacementId,
    string DeduplicationDigest,
    string Prq2,
    string Mrr2,
    string Mqr3);

sealed record ClientStoreFixture(
    byte[] CanonicalRequest,
    MailboxEncryptedEnvelope Envelope);

sealed record AuthorityWindow(
    ulong CurrentEpoch,
    ulong CurrentNotBeforeUnixSeconds,
    ulong CurrentExpiresAtUnixSeconds,
    ulong NextEpoch,
    ulong NextNotBeforeUnixSeconds,
    ulong NextExpiresAtUnixSeconds)
{
    public static AuthorityWindow CreateDefault()
    {
        var anchor = checked((ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 60 * 60);
        return new(1, anchor - 300, anchor + 28800, 2, anchor - 60, anchor + 43200);
    }

    public static AuthorityWindow Load(string path)
    {
        var fullPath = Path.GetFullPath(path);
        var bytes = File.ReadAllBytes(fullPath);
        if (bytes.Length is 0 or > 4096)
            throw new InvalidDataException("Mailbox authority state has an invalid size.");
        using var document = JsonDocument.Parse(bytes);
        var root = document.RootElement;
        var expected = new HashSet<string>(StringComparer.Ordinal)
        {
            "schemaVersion", "currentEpoch", "currentNotBeforeUnixSeconds",
            "currentExpiresAtUnixSeconds", "nextEpoch", "nextNotBeforeUnixSeconds",
            "nextExpiresAtUnixSeconds"
        };
        if (root.ValueKind != JsonValueKind.Object
            || root.EnumerateObject().Count() != expected.Count
            || root.EnumerateObject().Any(property => !expected.Contains(property.Name))
            || root.GetProperty("schemaVersion").GetInt32() != 1)
        {
            throw new InvalidDataException("Mailbox authority state schema is invalid.");
        }
        var result = new AuthorityWindow(
            root.GetProperty("currentEpoch").GetUInt64(),
            root.GetProperty("currentNotBeforeUnixSeconds").GetUInt64(),
            root.GetProperty("currentExpiresAtUnixSeconds").GetUInt64(),
            root.GetProperty("nextEpoch").GetUInt64(),
            root.GetProperty("nextNotBeforeUnixSeconds").GetUInt64(),
            root.GetProperty("nextExpiresAtUnixSeconds").GetUInt64());
        result.Validate();
        return result;
    }

    public void Validate()
    {
        if (CurrentEpoch == 0
            || NextEpoch != checked(CurrentEpoch + 1)
            || CurrentNotBeforeUnixSeconds >= NextNotBeforeUnixSeconds
            || NextNotBeforeUnixSeconds > CurrentExpiresAtUnixSeconds
            || CurrentExpiresAtUnixSeconds >= NextExpiresAtUnixSeconds
            || CurrentExpiresAtUnixSeconds - CurrentNotBeforeUnixSeconds > 43260
            || NextExpiresAtUnixSeconds - NextNotBeforeUnixSeconds != 43260)
        {
            throw new InvalidDataException("Mailbox authority state window is invalid.");
        }
    }
}

sealed class Fixture
{
    private byte[] SenderSeed { get; init; } = [];
    private byte[] IssuerSeed { get; init; } = [];
    public required RouterId[] RouterIds { get; init; }
    public required MembershipRouteDescriptor[] Descriptors { get; init; }
    public required MailboxReplicaMembershipProof[] Proofs { get; init; }
    public required byte[] Root { get; init; }
    public required BlindedPlacementId[,] Placements { get; init; }
    public required MembershipRouteDescriptor[] NextDescriptors { get; init; }
    public required MailboxReplicaMembershipProof[] NextProofs { get; init; }
    public required byte[] NextRoot { get; init; }
    public required BlindedPlacementId[,] NextPlacements { get; init; }
    public required ulong CurrentEpoch { get; init; }
    public required ulong NextEpoch { get; init; }
    public required ulong CurrentNotBefore { get; init; }
    public required ulong NextNotBefore { get; init; }
    public required ulong CurrentExpiresAt { get; init; }
    public required ulong NextExpiresAt { get; init; }
    public SodiumMailboxPeerReplicationCrypto Crypto { get; } = new();

    public static Fixture CreateAuthority(
        string[] seeds,
        string issuerSeedHex,
        AuthorityWindow window)
    {
        var crypto = new SodiumMailboxPeerReplicationCrypto();
        window.Validate();
        var currentEpoch = window.CurrentEpoch;
        var nextEpoch = window.NextEpoch;
        var currentNotBefore = window.CurrentNotBeforeUnixSeconds;
        var nextNotBefore = window.NextNotBeforeUnixSeconds;
        var currentExpiresAt = window.CurrentExpiresAtUnixSeconds;
        var nextExpiresAt = window.NextExpiresAtUnixSeconds;
        var ids = seeds.Select(RelayContactSigner.DeriveRouterId).ToArray();
        var expectedIds = new[]
        {
            "4cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29",
            "7422b9887598068e32c4448a949adb290d0f4e35b9e01b0ee5f1a1e600fe2674",
            "f381626e41e7027ea431bfe3009e94bdd25a746beec468948d6c3c7c5dc9a54b",
            "fd50b8e3b144ea244fbf7737f550bc8dd0c2650bbc1aada833ca17ff8dbf329b",
            "fde4fba030ad002f7c2f7d4c331f49d13fb0ec747eceebec634f1ff4cbca9def",
            "b4c92afb3ba57f3ab959ffe6d319c98484a2155a0f4c65b2c37011ffd197b075"
        };
        if (!ids.Select(id => id.Value).SequenceEqual(expectedIds, StringComparer.Ordinal))
        {
            throw new InvalidOperationException("DEV-LOCAL-ONLY seeds do not derive the exact six configured XNode identities.");
        }
        var descriptors = ids.Select((id, index) =>
        {
            var signingKey = crypto.GetPublicKey(Convert.FromHexString(seeds[index]));
            return new MembershipRouteDescriptor
            {
                RouterId = id.ToBytes(),
                Ed25519PublicKey = signingKey,
                X25519PublicKey = SHA256.HashData(signingKey),
                RpcEndpoint = PrivatePeerOrigin(index),
                Roles = MembershipRouteRole.Storage,
                Capabilities = MembershipRouteCapability.Storage,
                Epoch = currentEpoch,
                ValidFromUnixSeconds = currentNotBefore,
                ValidUntilUnixSeconds = currentExpiresAt
            };
        }).ToArray();
        var root = MembershipRouteDescriptorCodec.ComputeRoot(descriptors);
        var paths = MembershipRouteDescriptorCodec.BuildProofs(descriptors);
        var proofs = descriptors.Select((descriptor, index) => new MailboxReplicaMembershipProof
        {
            ReplicaId = descriptor.RouterId,
            SigningPublicKey = descriptor.Ed25519PublicKey,
            Epoch = currentEpoch,
            MembershipCommitment = root,
            CanonicalInclusionProof = MailboxReplicaRouteProofCodec.Encode(descriptor, paths[index])
        }).ToArray();
        var nextDescriptors = ids.Select((id, index) =>
        {
            var signingKey = crypto.GetPublicKey(Convert.FromHexString(seeds[index]));
            return new MembershipRouteDescriptor
            {
                RouterId = id.ToBytes(),
                Ed25519PublicKey = signingKey,
                X25519PublicKey = SHA256.HashData(signingKey),
                RpcEndpoint = PrivatePeerOrigin(index),
                Roles = MembershipRouteRole.Storage,
                Capabilities = MembershipRouteCapability.Storage,
                Epoch = nextEpoch,
                ValidFromUnixSeconds = nextNotBefore,
                ValidUntilUnixSeconds = nextExpiresAt
            };
        }).ToArray();
        var nextRoot = MembershipRouteDescriptorCodec.ComputeRoot(nextDescriptors);
        var nextPaths = MembershipRouteDescriptorCodec.BuildProofs(nextDescriptors);
        var nextProofs = nextDescriptors.Select((descriptor, index) =>
            new MailboxReplicaMembershipProof
            {
                ReplicaId = descriptor.RouterId,
                SigningPublicKey = descriptor.Ed25519PublicKey,
                Epoch = nextEpoch,
                MembershipCommitment = nextRoot,
                CanonicalInclusionProof =
                    MailboxReplicaRouteProofCodec.Encode(descriptor, nextPaths[index])
            }).ToArray();
        return new Fixture
        {
            SenderSeed = Convert.FromHexString(seeds[0]),
            IssuerSeed = Convert.FromHexString(issuerSeedHex),
            RouterIds = ids,
            Descriptors = descriptors,
            Proofs = proofs,
            Root = root,
            Placements = BuildPlacements(PlacementDomain(currentEpoch)),
            NextDescriptors = nextDescriptors,
            NextProofs = nextProofs,
            NextRoot = nextRoot,
            NextPlacements = BuildPlacements(PlacementDomain(nextEpoch)),
            CurrentEpoch = currentEpoch,
            NextEpoch = nextEpoch,
            CurrentNotBefore = currentNotBefore,
            NextNotBefore = nextNotBefore,
            CurrentExpiresAt = currentExpiresAt,
            NextExpiresAt = nextExpiresAt
        };
    }

    internal static string PlacementDomain(ulong epoch) => epoch switch
    {
        1 => "current",
        2 => "next",
        _ => $"epoch-{epoch}"
    };

    public static Fixture LoadPublic(
        string senderSeedHex,
        string issuerSeedHex,
        string publicPath,
        string expectedCoordinatorUrl,
        bool requireNonLoopbackCoordinator)
    {
        var authority = JsonSerializer.Deserialize<PublicAuthority>(
            File.ReadAllText(publicPath),
            new JsonSerializerOptions { PropertyNameCaseInsensitive = true })
            ?? throw new InvalidDataException("The public mailbox authority fixture is invalid.");
        var issuerSeed = Convert.FromHexString(issuerSeedHex);
        var crypto = new SodiumMailboxPeerReplicationCrypto();
        var capabilityCrypto = new SodiumMailboxCapabilityCrypto();
        var now = checked((ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        var coordinatorValid =
            Uri.TryCreate(authority.CoordinatorUrl, UriKind.Absolute, out var coordinator)
            && Uri.TryCreate(expectedCoordinatorUrl, UriKind.Absolute, out var expectedCoordinator)
            && coordinator == expectedCoordinator
            && coordinator.Scheme == Uri.UriSchemeHttp
            && string.IsNullOrEmpty(coordinator.UserInfo)
            && coordinator.AbsolutePath == "/"
            && string.IsNullOrEmpty(coordinator.Query)
            && string.IsNullOrEmpty(coordinator.Fragment)
            && (!requireNonLoopbackCoordinator
                || !IsLoopbackCoordinator(coordinator));
        if (authority.SchemaVersion != 2
            || authority.Protocol != "P10E/MCP2/MAU2/MIP1/RIP1/PRQ2"
            || authority.MinimumGeneration == 0
            || authority.MaximumGeneration != checked(authority.MinimumGeneration + 1)
            || authority.Epochs.Count != 2
            || authority.Selections.Count != 30
            || authority.ReplicaIds.Count != 2
            || authority.ReplicaSigningPublicKeys.Count != 2
            || !coordinatorValid
            || !TryLowerHex(authority.NetworkId, 16, out _)
            || !TryLowerHex(authority.IssuerPublicKey, 32, out var issuerPublicKey)
            || !CryptographicOperations.FixedTimeEquals(
                capabilityCrypto.GetPublicKey(issuerSeed),
                issuerPublicKey))
        {
            throw new InvalidDataException(
                "The public mailbox authority fixture is not the exact supported schema.");
        }
        var currentAuthority = authority.Epochs[0];
        var nextAuthority = authority.Epochs[1];
        if (authority.IssuerValidFromUnixSeconds
                != currentAuthority.NotBeforeUnixSeconds
            || authority.IssuerValidUntilUnixSeconds
                != nextAuthority.ExpiresAtUnixSeconds
            || currentAuthority.NotBeforeUnixSeconds
                >= nextAuthority.NotBeforeUnixSeconds
            || nextAuthority.NotBeforeUnixSeconds
                > currentAuthority.ExpiresAtUnixSeconds
            || currentAuthority.ExpiresAtUnixSeconds
                >= nextAuthority.ExpiresAtUnixSeconds
            || currentAuthority.ExpiresAtUnixSeconds
                - currentAuthority.NotBeforeUnixSeconds > 43260
            || nextAuthority.ExpiresAtUnixSeconds
                - nextAuthority.NotBeforeUnixSeconds != 43260
            || now < nextAuthority.NotBeforeUnixSeconds
            || now + 1800 > currentAuthority.ExpiresAtUnixSeconds)
        {
            throw new InvalidDataException(
                "The public mailbox authority does not contain a live bounded E/E+1 window.");
        }

        var current = ParsePublicEpoch(
            currentAuthority,
            authority.MinimumGeneration,
            currentAuthority.NotBeforeUnixSeconds,
            currentAuthority.ExpiresAtUnixSeconds,
            PlacementDomain(authority.MinimumGeneration));
        var next = ParsePublicEpoch(
            nextAuthority,
            authority.MaximumGeneration,
            nextAuthority.NotBeforeUnixSeconds,
            nextAuthority.ExpiresAtUnixSeconds,
            PlacementDomain(authority.MaximumGeneration));
        var ids = current.Descriptors
            .Select(descriptor => RouterId.FromBytes(descriptor.RouterId.Span))
            .ToArray();
        if (!ids.Select(id => id.Value).SequenceEqual(
                next.Descriptors
                    .Select(descriptor => RouterId.FromBytes(descriptor.RouterId.Span).Value),
                StringComparer.Ordinal))
        {
            throw new InvalidDataException(
                "The current and next mailbox authority identities differ.");
        }
        if (!authority.ReplicaIds.SequenceEqual(
                ids.Take(2).Select(id => id.Value),
                StringComparer.Ordinal)
            || !authority.ReplicaSigningPublicKeys.SequenceEqual(
                current.Descriptors.Take(2)
                    .Select(descriptor => Lower(descriptor.Ed25519PublicKey.Span)),
                StringComparer.Ordinal))
        {
            throw new InvalidDataException(
                "The public mailbox client replica pair is invalid.");
        }
        var placements = BuildPlacements(PlacementDomain(authority.MinimumGeneration));
        var nextPlacements = BuildPlacements(PlacementDomain(authority.MaximumGeneration));
        var selection = 0;
        foreach (var epoch in new[]
            {
                (Value: authority.MinimumGeneration, Placements: placements),
                (Value: authority.MaximumGeneration, Placements: nextPlacements)
            })
        {
            for (var first = 0; first < 6; first++)
            for (var second = first + 1; second < 6; second++)
            {
                var item = authority.Selections[selection++];
                var placement = epoch.Placements[first, second];
                var expected = MailboxPlacementCommitment.Compute(placement);
                if (item.Epoch != epoch.Value
                    || item.FirstNode != first + 1
                    || item.SecondNode != second + 1
                    || !TryLowerHex(item.PlacementId, 32, out var placementId)
                    || !CryptographicOperations.FixedTimeEquals(placement.Bytes.Span, placementId)
                    || !TryLowerHex(item.PlacementCommitment, 32, out var actual)
                    || !CryptographicOperations.FixedTimeEquals(expected, actual))
                {
                    throw new InvalidDataException(
                        "The public mailbox authority placement binding is invalid.");
                }
            }
        }

        var senderSeed = Convert.FromHexString(senderSeedHex);
        if (!CryptographicOperations.FixedTimeEquals(
                crypto.GetPublicKey(senderSeed),
                current.Descriptors[0].Ed25519PublicKey.Span))
        {
            throw new InvalidDataException(
                "The only mounted sender seed does not match xnode-1.");
        }
        return new Fixture
        {
            SenderSeed = senderSeed,
            IssuerSeed = issuerSeed,
            RouterIds = ids,
            Descriptors = current.Descriptors,
            Proofs = current.Proofs,
            Root = current.Root,
            Placements = placements,
            NextDescriptors = next.Descriptors,
            NextProofs = next.Proofs,
            NextRoot = next.Root,
            NextPlacements = nextPlacements,
            CurrentEpoch = authority.MinimumGeneration,
            NextEpoch = authority.MaximumGeneration,
            CurrentNotBefore = currentAuthority.NotBeforeUnixSeconds,
            NextNotBefore = nextAuthority.NotBeforeUnixSeconds,
            CurrentExpiresAt = currentAuthority.ExpiresAtUnixSeconds,
            NextExpiresAt = nextAuthority.ExpiresAtUnixSeconds
        };
    }

    public void WriteAuthority(
        string environmentPath,
        string clientEnvironmentPath,
        string publicPath,
        string coordinatorUrl,
        string? clientPublicPath)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(environmentPath))!);
        var lines = new List<string>
        {
            "MailboxClient__Enabled=false",
            "MailboxClientAdapter__Enabled=false",
            $"MailboxPeerAuthority__CurrentEpoch={CurrentEpoch}",
            $"MailboxPeerAuthority__CurrentMembershipCommitment={Convert.ToHexString(Root).ToLowerInvariant()}",
            $"MailboxPeerAuthority__CurrentEpochExpiresAtUnixSeconds={CurrentExpiresAt}",
            $"MailboxPeerAuthority__NextEpoch={NextEpoch}",
            $"MailboxPeerAuthority__NextMembershipCommitment={Convert.ToHexString(NextRoot).ToLowerInvariant()}",
            $"MailboxPeerAuthority__NextEpochExpiresAtUnixSeconds={NextExpiresAt}"
        };
        var selections = new List<object>();
        var selection = 0;
        foreach (var epoch in new[]
            {
                (Value: CurrentEpoch, Placements),
                (Value: NextEpoch, Placements: NextPlacements)
            })
        {
            for (var first = 0; first < 6; first++)
            for (var second = first + 1; second < 6; second++)
            {
                var placementId = epoch.Placements[first, second];
                var commitment = MailboxPlacementCommitment.Compute(placementId);
                var prefix = $"MailboxPeerAuthority__PlacementSelections__{selection}";
                lines.Add($"{prefix}__Epoch={epoch.Value}");
                lines.Add($"{prefix}__PlacementCommitment={Lower(commitment)}");
                lines.Add($"{prefix}__FirstRouterId={RouterIds[first].Value}");
                lines.Add($"{prefix}__SecondRouterId={RouterIds[second].Value}");
                selections.Add(new
                {
                    epoch = epoch.Value,
                    firstNode = first + 1,
                    secondNode = second + 1,
                    placementId = Lower(placementId.Bytes.Span),
                    placementCommitment = Lower(commitment)
                });
                selection++;
            }
        }
        File.WriteAllText(environmentPath, string.Join('\n', lines) + "\n");
        var networkId = NetworkId();
        var issuerPublicKey =
            new SodiumMailboxCapabilityCrypto().GetPublicKey(IssuerSeed);
        var currentPlacement = Placements[0, 1];
        var nextPlacement = NextPlacements[0, 1];
        var currentMip = Proofs.Take(2)
            .Select(MailboxPeerReplicationCodec.EncodeMembershipProof)
            .Select(Convert.ToBase64String)
            .ToArray();
        var nextMip = NextProofs.Take(2)
            .Select(MailboxPeerReplicationCodec.EncodeMembershipProof)
            .Select(Convert.ToBase64String)
            .ToArray();
        var clientLines = new[]
        {
            "MailboxClient__Enabled=true",
            "MailboxClient__DevelopmentFixture__Enabled=true",
            $"MailboxClient__DevelopmentFixture__NetworkId={Lower(networkId)}",
            $"MailboxClient__DevelopmentFixture__IssuerPublicKey={Lower(issuerPublicKey)}",
            $"MailboxClient__DevelopmentFixture__MinimumGeneration={CurrentEpoch}",
            $"MailboxClient__DevelopmentFixture__MaximumGeneration={NextEpoch}",
            $"MailboxClient__DevelopmentFixture__IssuerValidFromUnixSeconds={CurrentNotBefore}",
            $"MailboxClient__DevelopmentFixture__IssuerValidUntilUnixSeconds={NextExpiresAt}",
            $"MailboxClient__DevelopmentFixture__CoordinatorUrl={coordinatorUrl}",
            $"MailboxClient__DevelopmentFixture__CurrentPlacementId={Lower(currentPlacement.Bytes.Span)}",
            $"MailboxClient__DevelopmentFixture__CurrentPlacementCommitment={Lower(MailboxPlacementCommitment.Compute(currentPlacement))}",
            $"MailboxClient__DevelopmentFixture__NextPlacementId={Lower(nextPlacement.Bytes.Span)}",
            $"MailboxClient__DevelopmentFixture__NextPlacementCommitment={Lower(MailboxPlacementCommitment.Compute(nextPlacement))}",
            $"MailboxClient__DevelopmentFixture__ReplicaIds__0={RouterIds[0].Value}",
            $"MailboxClient__DevelopmentFixture__ReplicaIds__1={RouterIds[1].Value}",
            $"MailboxClient__DevelopmentFixture__ReplicaSigningPublicKeys__0={Lower(Descriptors[0].Ed25519PublicKey.Span)}",
            $"MailboxClient__DevelopmentFixture__ReplicaSigningPublicKeys__1={Lower(Descriptors[1].Ed25519PublicKey.Span)}",
            $"MailboxClient__DevelopmentFixture__CurrentLocalMembershipProof={currentMip[0]}",
            $"MailboxClient__DevelopmentFixture__CurrentRemoteMembershipProof={currentMip[1]}",
            $"MailboxClient__DevelopmentFixture__NextLocalMembershipProof={nextMip[0]}",
            $"MailboxClient__DevelopmentFixture__NextRemoteMembershipProof={nextMip[1]}",
            "MailboxClientAdapter__Enabled=true",
            $"MailboxClientAdapter__CurrentMembershipCommitment={Lower(Root)}",
            $"MailboxClientAdapter__NextMembershipCommitment={Lower(NextRoot)}",
            $"MailboxClientAdapter__CurrentEpoch={CurrentEpoch}",
            $"MailboxClientAdapter__NextEpoch={NextEpoch}",
            $"MailboxClientAdapter__CurrentNotBeforeUnixSeconds={CurrentNotBefore}",
            $"MailboxClientAdapter__NextNotBeforeUnixSeconds={NextNotBefore}",
            $"MailboxClientAdapter__CurrentExpiresAtUnixSeconds={CurrentExpiresAt}",
            $"MailboxClientAdapter__NextExpiresAtUnixSeconds={NextExpiresAt}"
        };
        File.WriteAllText(clientEnvironmentPath, string.Join('\n', clientLines) + "\n");
        File.WriteAllText(publicPath, JsonSerializer.Serialize(new
        {
            schemaVersion = 2,
            scope = "DEV-LOCAL-ONLY",
            protocol = "P10E/MCP2/MAU2/MIP1/RIP1/PRQ2",
            networkId = Lower(networkId),
            issuerPublicKey = Lower(issuerPublicKey),
            minimumGeneration = CurrentEpoch,
            maximumGeneration = NextEpoch,
            issuerValidFromUnixSeconds = CurrentNotBefore,
            issuerValidUntilUnixSeconds = NextExpiresAt,
            coordinatorUrl,
            replicaIds = RouterIds.Take(2).Select(id => id.Value),
            replicaSigningPublicKeys = Descriptors.Take(2)
                .Select(descriptor => Lower(descriptor.Ed25519PublicKey.Span)),
            epochs = new[]
            {
                PublicEpoch(
                    CurrentEpoch,
                    CurrentNotBefore,
                    CurrentExpiresAt,
                    Root,
                    currentPlacement,
                    Descriptors,
                    Proofs),
                PublicEpoch(
                    NextEpoch,
                    NextNotBefore,
                    NextExpiresAt,
                    NextRoot,
                    nextPlacement,
                    NextDescriptors,
                    NextProofs)
            },
            selections
        }, new JsonSerializerOptions { WriteIndented = true }) + "\n");
        if (!string.IsNullOrWhiteSpace(clientPublicPath))
        {
            var source = JsonSerializer.Deserialize<PublicAuthority>(
                File.ReadAllText(publicPath),
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true })
                ?? throw new InvalidDataException("Generated mailbox authority is invalid.");
            Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(clientPublicPath))!);
            File.WriteAllBytes(clientPublicPath, SerializeClientAuthority(source));
        }
    }

    internal static byte[] SerializeClientAuthority(PublicAuthority source)
    {
        var json = JsonSerializer.Serialize(new
        {
            schemaVersion = source.SchemaVersion,
            scope = source.Scope,
            protocol = source.Protocol,
            networkId = source.NetworkId,
            issuerPublicKey = source.IssuerPublicKey,
            minimumGeneration = source.MinimumGeneration,
            maximumGeneration = source.MaximumGeneration,
            issuerValidFromUnixSeconds = source.IssuerValidFromUnixSeconds,
            issuerValidUntilUnixSeconds = source.IssuerValidUntilUnixSeconds,
            coordinatorUrl = source.CoordinatorUrl,
            replicaIds = source.ReplicaIds,
            replicaSigningPublicKeys = source.ReplicaSigningPublicKeys,
            epochs = source.Epochs.Select(epoch => new
            {
                epoch = epoch.Epoch,
                notBeforeUnixSeconds = epoch.NotBeforeUnixSeconds,
                expiresAtUnixSeconds = epoch.ExpiresAtUnixSeconds,
                membershipCommitment = epoch.MembershipCommitment,
                placementId = epoch.PlacementId,
                placementCommitment = epoch.PlacementCommitment,
                replicas = Array.Empty<object>()
            }),
            selections = Array.Empty<object>()
        }, new JsonSerializerOptions { WriteIndented = true });
        return System.Text.Encoding.UTF8.GetBytes(json + "\n");
    }

    public Scenario NewScenario(
        string runId,
        string name,
        int senderIndex,
        int recipientIndex,
        ulong now)
    {
        var material = SHA256.HashData(System.Text.Encoding.UTF8.GetBytes($"{runId}|{name}"));
        var placement = Placements[senderIndex, recipientIndex];
        var envelope = new MailboxEncryptedEnvelope
        {
            Epoch = CurrentEpoch,
            MailboxId = new BlindedMailboxId(SHA256.HashData(material.Concat("mailbox"u8.ToArray()).ToArray())),
            PlacementId = placement,
            OperationId = material.AsSpan(0, 16).ToArray(),
            DeduplicationDigest = SHA256.HashData(material.Concat("dedup"u8.ToArray()).ToArray()),
            CreatedAtUnixSeconds = now,
            ExpiresAtUnixSeconds = Math.Min(now + 1800, CurrentExpiresAt),
            Ciphertext = SHA256.HashData(material.Concat("ciphertext"u8.ToArray()).ToArray())
        };
        var payload = MailboxClientCodec.EncodeEncryptedEnvelope(envelope);
        var unsigned = new MailboxPeerWireRequestV2
        {
            Operation = MailboxPeerReplicationOperation.Store,
            Epoch = CurrentEpoch,
            OperationId = envelope.OperationId,
            SenderRouterId = RouterIds[senderIndex].ToBytes(),
            RecipientRouterId = RouterIds[recipientIndex].ToBytes(),
            MembershipCommitment = Root,
            PlacementCommitment = MailboxPlacementCommitment.Compute(placement),
            BlindedMailboxId = envelope.MailboxId.Bytes,
            Cursor = now,
            CreatedAtUnixSeconds = now,
            ExpiresAtUnixSeconds = envelope.ExpiresAtUnixSeconds,
            ReplayNonce = SHA256.HashData(material.Concat("replay"u8.ToArray()).ToArray()),
            PayloadDigest = SHA256.HashData(payload),
            Payload = payload,
            SenderMembershipProof = Proofs[senderIndex],
            RecipientMembershipProof = Proofs[recipientIndex],
            Signature = ReadOnlyMemory<byte>.Empty
        };
        var signed = Crypto.SignRequest(unsigned, SenderPrivateSeed(senderIndex));
        return new(
            runId,
            name,
            senderIndex,
            recipientIndex,
            MailboxPeerReplicationOperation.Store,
            Convert.ToBase64String(placement.Bytes.Span),
            Convert.ToBase64String(envelope.DeduplicationDigest.Span),
            Convert.ToBase64String(MailboxPeerWireV2Codec.Encode(signed)),
            "",
            "");
    }

    public byte[] NewRuntimeStore(
        string runId,
        string name,
        ulong now,
        ulong epoch = 0)
    {
        if (epoch == 0) epoch = CurrentEpoch;
        var next = epoch == NextEpoch;
        if (epoch != CurrentEpoch && epoch != NextEpoch)
        {
            throw new ArgumentOutOfRangeException(nameof(epoch));
        }
        var material = Material(runId, name);
        var envelope = new MailboxEncryptedEnvelope
        {
            Epoch = epoch,
            MailboxId = new BlindedMailboxId(material),
            PlacementId = (next ? NextPlacements : Placements)[0, 1],
            OperationId = material[..16],
            DeduplicationDigest = SHA256.HashData(material.Concat("runtime-gc-dedup"u8.ToArray()).ToArray()),
            CreatedAtUnixSeconds = now,
            ExpiresAtUnixSeconds = Math.Min(now + 1800, next ? NextExpiresAt : CurrentExpiresAt),
            Ciphertext = SHA256.HashData(material.Concat("runtime-gc-ciphertext"u8.ToArray()).ToArray())
        };
        var binding = MailboxAuthenticatedRequestTranscript.ForStore(envelope);
        var crypto = new SodiumMailboxCapabilityCrypto();
        var holderSeed = Material(runId, "client-holder");
        var notBefore = Math.Max(now - Math.Min(now, 60), next ? NextNotBefore : CurrentNotBefore);
        var grant = crypto.SignGrant(
            new MailboxAuthenticatedGrant
            {
                Domain = MailboxCapabilityDomain.Deposit,
                Lifecycle = MailboxCapabilityLifecycle.Active,
                NetworkId = NetworkId(),
                Epoch = epoch,
                Generation = epoch,
                Serial = Material(runId, $"{name}-grant")[..16],
                NotBeforeUnixSeconds = notBefore,
                ExpiresAtUnixSeconds = next ? NextExpiresAt : CurrentExpiresAt,
                OverlapUntilUnixSeconds = 0,
                PlacementCommitment = MailboxPlacementCommitment.Compute(envelope.PlacementId),
                MembershipCommitment = next ? NextRoot : Root,
                IssuerPublicKey = crypto.GetPublicKey(IssuerSeed),
                HolderPublicKey = crypto.GetPublicKey(holderSeed),
                IssuerSignature = new byte[MailboxAuthenticatedCapabilityLimits.SignatureLength]
            },
            IssuerSeed);
        var presentation = crypto.SignPresentation(grant, binding, 1, holderSeed);
        return MailboxAuthenticatedClientRequestCodec.Encode(
            new MailboxAuthenticatedClientRequest
            {
                Binding = binding,
                Presentation = presentation
            });
    }

    public IMailboxCapabilityAuthoritySource CreateRuntimeAuthority() =>
        new RuntimeAuthority(this);

    public IMailboxCapabilityRevocationPolicy CreateRuntimeRevocations() =>
        new RuntimeRevocations();

    public ClientStoreFixture NewClientStore(
        string runId,
        string name,
        ulong now)
    {
        var material = Material(runId, name);
        var envelope = new MailboxEncryptedEnvelope
        {
            Epoch = CurrentEpoch,
            MailboxId = new BlindedMailboxId(
                SHA256.HashData(material.Concat("client-mailbox"u8.ToArray()).ToArray())),
            PlacementId = Placements[0, 1],
            OperationId = SHA256.HashData(
                material.Concat("client-store-operation"u8.ToArray()).ToArray())[..16],
            DeduplicationDigest = SHA256.HashData(
                material.Concat("client-store-dedup"u8.ToArray()).ToArray()),
            CreatedAtUnixSeconds = now,
            ExpiresAtUnixSeconds = Math.Min(now + 1800, CurrentExpiresAt),
            Ciphertext = SHA256.HashData(
                material.Concat("client-store-ciphertext"u8.ToArray()).ToArray())
        };
        var binding = MailboxAuthenticatedRequestTranscript.ForStore(envelope);
        var canonicalMau2 = AuthenticatedRequest(
            runId,
            name,
            MailboxCapabilityDomain.Deposit,
            binding,
            now,
            replayCounter: 1);
        return new ClientStoreFixture(
            canonicalMau2,
            envelope);
    }

    public byte[] NewClientRetrieve(
        string runId,
        string name,
        MailboxEncryptedEnvelope envelope,
        ulong now,
        ulong replayCounter)
    {
        var operationId = Material(runId, name)[..16];
        var binding = MailboxAuthenticatedRequestTranscript.ForRetrieve(
            CurrentEpoch,
            operationId,
            envelope.MailboxId,
            envelope.PlacementId,
            afterCursor: 0,
            maximumItems: 10,
            continuationToken: []);
        return AuthenticatedRequest(
            runId,
            name,
            MailboxCapabilityDomain.Retrieve,
            binding,
            now,
            replayCounter);
    }

    public byte[] NewClientAck(
        string runId,
        string name,
        MailboxEncryptedEnvelope envelope,
        IReadOnlyList<MailboxAcknowledgement> acknowledgements,
        ulong now,
        ulong replayCounter)
    {
        var operationId = Material(runId, name)[..16];
        var binding = MailboxAuthenticatedRequestTranscript.ForAck(
            CurrentEpoch,
            operationId,
            envelope.MailboxId,
            envelope.PlacementId,
            isFinalPage: true,
            continuationToken: [],
            acknowledgements);
        return AuthenticatedRequest(
            runId,
            name,
            MailboxCapabilityDomain.Retrieve,
            binding,
            now,
            replayCounter);
    }

    public MailboxClientDecodePolicy ClientDecodePolicy(ulong now) => new()
    {
        NowUnixSeconds = now,
        EpochWindow = new MailboxEpochWindow
        {
            CurrentEpoch = this.CurrentEpoch,
            NextEpoch = this.NextEpoch,
            CurrentNotBeforeUnixSeconds = CurrentNotBefore,
            NextNotBeforeUnixSeconds = NextNotBefore,
            CurrentExpiresAtUnixSeconds = CurrentExpiresAt,
            NextExpiresAtUnixSeconds = NextExpiresAt
        },
        CapabilityPolicy = new MailboxCapabilityDecodePolicy
        {
            CurrentBucket = checked((uint)now),
            MinimumGeneration = CurrentEpoch,
            AllowLegacyMirrorOverlap = false,
            AllowRevoked = false,
            AllowRecovery = false
        },
        AllowLegacyMirrorOverlap = false
    };

    public MailboxReplicaPeer Peer(int recipientIndex, MailboxPeerReplicationOperation operation)
    {
        var route = operation == MailboxPeerReplicationOperation.Store
            ? MailboxWireHttpContract.PeerStore.Route
            : MailboxWireHttpContract.PeerTombstone.Route;
        return new MailboxReplicaPeer(
            RouterIds[recipientIndex],
            $"{PrivatePeerOrigin(recipientIndex)}{route}");
    }

    public byte[] SenderPrivateSeed(int senderIndex)
    {
        if (senderIndex != 0)
        {
            throw new InvalidOperationException(
                "The rehearsal driver is restricted to the xnode-1 sender identity.");
        }
        return SenderSeed.ToArray();
    }

    private byte[] AuthenticatedRequest(
        string runId,
        string name,
        MailboxCapabilityDomain domain,
        MailboxAuthenticatedRequestBinding binding,
        ulong now,
        ulong replayCounter)
    {
        var crypto = new SodiumMailboxCapabilityCrypto();
        var holderSeed = Material(runId, "client-holder");
        var serial = Material(runId, $"{name}-grant")[..16];
        var expiresAt = Math.Min(now + 1800, CurrentExpiresAt);
        var notBefore = Math.Max(
            now - Math.Min(now, 60),
            CurrentNotBefore);
        var grant = crypto.SignGrant(
            new MailboxAuthenticatedGrant
            {
                Domain = domain,
                Lifecycle = MailboxCapabilityLifecycle.Active,
                NetworkId = NetworkId(),
                Epoch = CurrentEpoch,
                Generation = CurrentEpoch,
                Serial = serial,
                NotBeforeUnixSeconds = notBefore,
                ExpiresAtUnixSeconds = expiresAt,
                OverlapUntilUnixSeconds = 0,
                PlacementCommitment =
                    MailboxPlacementCommitment.Compute(Placements[0, 1]),
                MembershipCommitment = Root,
                IssuerPublicKey = crypto.GetPublicKey(IssuerSeed),
                HolderPublicKey = crypto.GetPublicKey(holderSeed),
                IssuerSignature =
                    new byte[MailboxAuthenticatedCapabilityLimits.SignatureLength]
            },
            IssuerSeed);
        var presentation = crypto.SignPresentation(
            grant,
            binding,
            replayCounter,
            holderSeed);
        return MailboxAuthenticatedClientRequestCodec.Encode(
            new MailboxAuthenticatedClientRequest
            {
                Binding = binding,
                Presentation = presentation
            });
    }

    private static byte[] Material(string runId, string name) =>
        SHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes($"{runId}|{name}"));

    private static string PrivatePeerOrigin(int zeroBasedNodeIndex)
    {
        if (zeroBasedNodeIndex is < 0 or > 5)
        {
            throw new ArgumentOutOfRangeException(nameof(zeroBasedNodeIndex));
        }
        return $"http://172.30.82.{zeroBasedNodeIndex + 11}:8081";
    }

    private static byte[] NetworkId() =>
        SHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes(
                 "deep-survival-dev-p10e-network-v1"))[..16];

    private sealed class RuntimeAuthority(Fixture fixture)
        : IMailboxCapabilityAuthoritySource
    {
        private readonly byte[] _network = NetworkId();
        private readonly byte[] _issuer = new SodiumMailboxCapabilityCrypto().GetPublicKey(fixture.IssuerSeed);

        public bool IsConfigured => true;

        public ulong ReplayValidityEndsAt(
            MailboxCapabilityAuthorityQuery query,
            MailboxAuthenticatedGrant grant) =>
            query.Epoch == fixture.NextEpoch
                ? fixture.NextExpiresAt
                : fixture.CurrentExpiresAt;

        public bool TryResolve(
            MailboxCapabilityAuthorityQuery query,
            out MailboxAuthenticatedVerificationPolicy? policy)
        {
            var next = query.Epoch == fixture.NextEpoch;
            var placement = next ? fixture.NextPlacements[0, 1] : fixture.Placements[0, 1];
            var membership = next ? fixture.NextRoot : fixture.Root;
            if (query.Operation != MailboxAuthenticatedOperation.Store
                || query.Domain != MailboxCapabilityDomain.Deposit
                || query.Lifecycle != MailboxCapabilityLifecycle.Active
                || query.Generation != query.Epoch
                || (query.Epoch != fixture.CurrentEpoch && query.Epoch != fixture.NextEpoch)
                || !CryptographicOperations.FixedTimeEquals(query.NetworkId.Span, _network)
                || !CryptographicOperations.FixedTimeEquals(query.IssuerPublicKey.Span, _issuer)
                || !CryptographicOperations.FixedTimeEquals(
                    query.PlacementCommitment.Span,
                    MailboxPlacementCommitment.Compute(placement))
                || !CryptographicOperations.FixedTimeEquals(query.MembershipCommitment.Span, membership))
            {
                policy = null;
                return false;
            }
            policy = new MailboxAuthenticatedVerificationPolicy
            {
                NetworkId = _network.ToArray(),
                Epoch = query.Epoch,
                PlacementCommitment = query.PlacementCommitment.ToArray(),
                MembershipCommitment = query.MembershipCommitment.ToArray(),
                NowUnixSeconds = 0,
                MinimumGeneration = fixture.CurrentEpoch,
                TrustedIssuers =
                [
                    new MailboxCapabilityIssuerAuthority
                    {
                        PublicKey = _issuer.ToArray(),
                        Domain = MailboxCapabilityDomain.Deposit,
                        AllowedLifecycle = MailboxCapabilityLifecycle.Active,
                        MinimumGeneration = fixture.CurrentEpoch,
                        MaximumGeneration = fixture.NextEpoch,
                        ValidFromUnixSeconds = fixture.CurrentNotBefore,
                        ValidUntilUnixSeconds = fixture.NextExpiresAt
                    }
                ]
            };
            return true;
        }
    }

    private sealed class RuntimeRevocations : IMailboxCapabilityRevocationPolicy
    {
        public bool IsConfigured => true;
        public bool IsRevoked(MailboxCapabilityRevocationQuery query) => false;
    }

    internal static BlindedPlacementId[,] BuildPlacements(string generation)
    {
        var placements = new BlindedPlacementId[6, 6];
        for (var first = 0; first < 6; first++)
        for (var second = first + 1; second < 6; second++)
        {
            var bytes = SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(
                $"deep-survival-dev-p10e-{generation}-placement-id-v1|{first + 1}|{second + 1}"));
            placements[first, second] = new BlindedPlacementId(bytes);
            placements[second, first] = placements[first, second];
        }
        return placements;
    }

    private static object PublicEpoch(
        ulong epoch,
        ulong notBefore,
        ulong expiresAt,
        byte[] root,
        BlindedPlacementId placementId,
        MembershipRouteDescriptor[] descriptors,
        MailboxReplicaMembershipProof[] proofs) => new
    {
        epoch,
        notBeforeUnixSeconds = notBefore,
        expiresAtUnixSeconds = expiresAt,
        membershipCommitment = Lower(root),
        placementId = Lower(placementId.Bytes.Span),
        placementCommitment = Lower(MailboxPlacementCommitment.Compute(placementId)),
        replicas = descriptors.Select((descriptor, index) => new
        {
            node = index + 1,
            routerId = Lower(descriptor.RouterId.Span),
            signingPublicKey = Lower(descriptor.Ed25519PublicKey.Span),
            rpcEndpoint = descriptor.RpcEndpoint,
            canonicalMip1 = Convert.ToBase64String(
                MailboxPeerReplicationCodec.EncodeMembershipProof(proofs[index])),
            canonicalRip1 = Convert.ToBase64String(
                proofs[index].CanonicalInclusionProof.Span)
        })
    };

    private static string Lower(ReadOnlySpan<byte> value) =>
        Convert.ToHexString(value).ToLowerInvariant();

    internal static ParsedPublicEpoch ParsePublicEpoch(
        PublicEpochAuthority authority,
        ulong expectedEpoch,
        ulong expectedNotBefore,
        ulong expectedExpiresAt,
        string placementGeneration)
    {
        if (authority.Epoch != expectedEpoch
            || authority.NotBeforeUnixSeconds != expectedNotBefore
            || authority.ExpiresAtUnixSeconds != expectedExpiresAt
            || authority.Replicas.Count != 6
            || !TryLowerHex(authority.MembershipCommitment, 32, out var root))
        {
            throw new InvalidDataException(
                "The public mailbox authority epoch is invalid.");
        }
        var expectedPlacement = BuildPlacements(placementGeneration)[0, 1];
        if (!TryLowerHex(authority.PlacementId, 32, out var placementId)
            || !CryptographicOperations.FixedTimeEquals(
                expectedPlacement.Bytes.Span,
                placementId)
            || !TryLowerHex(authority.PlacementCommitment, 32, out var placementCommitment)
            || !CryptographicOperations.FixedTimeEquals(
                MailboxPlacementCommitment.Compute(expectedPlacement),
                placementCommitment))
        {
            throw new InvalidDataException(
                "The public mailbox client placement is invalid.");
        }
        var descriptors = new MembershipRouteDescriptor[6];
        var proofs = new MailboxReplicaMembershipProof[6];
        for (var index = 0; index < 6; index++)
        {
            var item = authority.Replicas[index];
            var canonicalMip1 = Convert.FromBase64String(item.CanonicalMip1);
            var proof = MailboxPeerReplicationCodec.DecodeMembershipProof(canonicalMip1);
            var canonicalRip1 = Convert.FromBase64String(item.CanonicalRip1);
            var descriptor = MailboxReplicaRouteProofCodec.Decode(canonicalRip1).Descriptor;
            var routerId = RouterId.FromBytes(descriptor.RouterId.Span);
            if (item.Node != index + 1
                || item.RouterId != routerId.Value
                || item.SigningPublicKey != Lower(descriptor.Ed25519PublicKey.Span)
                || item.RpcEndpoint != PrivatePeerOrigin(index)
                || descriptor.Epoch != expectedEpoch
                || descriptor.ValidFromUnixSeconds != expectedNotBefore
                || descriptor.ValidUntilUnixSeconds != expectedExpiresAt
                || descriptor.RpcEndpoint != item.RpcEndpoint
                || !proof.ReplicaId.Span.SequenceEqual(descriptor.RouterId.Span)
                || !proof.SigningPublicKey.Span.SequenceEqual(descriptor.Ed25519PublicKey.Span)
                || proof.Epoch != expectedEpoch
                || !proof.MembershipCommitment.Span.SequenceEqual(root)
                || !proof.CanonicalInclusionProof.Span.SequenceEqual(canonicalRip1))
            {
                throw new InvalidDataException(
                    "The public mailbox authority replica binding is invalid.");
            }
            descriptors[index] = descriptor;
            proofs[index] = proof;
        }
        if (!CryptographicOperations.FixedTimeEquals(
                MembershipRouteDescriptorCodec.ComputeRoot(descriptors),
                root))
        {
            throw new InvalidDataException(
                "The public mailbox authority membership root is invalid.");
        }
        return new ParsedPublicEpoch(descriptors, proofs, root);
    }

    private static bool TryLowerHex(string? value, int bytes, out byte[] decoded)
    {
        decoded = [];
        if (value is null
            || value.Length != bytes * 2
            || value.Any(character =>
                character is not (>= '0' and <= '9' or >= 'a' and <= 'f')))
        {
            return false;
        }
        decoded = Convert.FromHexString(value);
        return decoded.AsSpan().IndexOfAnyExcept((byte)0) >= 0;
    }

    private static bool IsLoopbackCoordinator(Uri coordinator) =>
        string.Equals(coordinator.Host, "localhost", StringComparison.OrdinalIgnoreCase)
        || System.Net.IPAddress.TryParse(coordinator.Host, out var address)
            && System.Net.IPAddress.IsLoopback(address);
}

sealed record PublicAuthority(
    int SchemaVersion,
    string Scope,
    string Protocol,
    string NetworkId,
    string IssuerPublicKey,
    ulong MinimumGeneration,
    ulong MaximumGeneration,
    ulong IssuerValidFromUnixSeconds,
    ulong IssuerValidUntilUnixSeconds,
    string CoordinatorUrl,
    List<string> ReplicaIds,
    List<string> ReplicaSigningPublicKeys,
    List<PublicEpochAuthority> Epochs,
    List<PublicSelection> Selections);

sealed record PublicEpochAuthority(
    ulong Epoch,
    ulong NotBeforeUnixSeconds,
    ulong ExpiresAtUnixSeconds,
    string MembershipCommitment,
    string PlacementId,
    string PlacementCommitment,
    List<PublicReplica> Replicas);

sealed record PublicReplica(
    int Node,
    string RouterId,
    string SigningPublicKey,
    string RpcEndpoint,
    string CanonicalMip1,
    string CanonicalRip1);

sealed record PublicSelection(
    ulong Epoch,
    int FirstNode,
    int SecondNode,
    string PlacementId,
    string PlacementCommitment);

sealed record ParsedPublicEpoch(
    MembershipRouteDescriptor[] Descriptors,
    MailboxReplicaMembershipProof[] Proofs,
    byte[] Root);

sealed class ExactHttpClient(string baseUrl)
{
    private readonly HttpClient _client = new()
    {
        BaseAddress = new Uri(baseUrl.TrimEnd('/') + "/"),
        Timeout = TimeSpan.FromSeconds(20)
    };

    public async Task<byte[]> SendSuccessAsync(
        MailboxHttpEndpointContract contract,
        byte[] canonicalRequest)
    {
        using var response = await SendAsync(contract, canonicalRequest);
        var body = await response.Content.ReadAsByteArrayAsync();
        if ((int)response.StatusCode != contract.SuccessStatusCode
            || response.Content.Headers.ContentLength != body.Length
            || body.Length < contract.MinimumResponseBytes
            || body.Length > contract.MaximumResponseBytes
            || !string.Equals(
                response.Content.Headers.ContentType?.ToString(),
                contract.ResponseContentType,
                StringComparison.Ordinal)
            || response.Content.Headers.ContentEncoding.Count != 0)
        {
            throw new InvalidOperationException(
                $"Public mailbox {contract.RequestFrame} response violated its exact contract: "
                + $"status={(int)response.StatusCode}, "
                + $"declaredLength={response.Content.Headers.ContentLength?.ToString() ?? "missing"}, "
                + $"actualLength={body.Length}, "
                + $"contentType={response.Content.Headers.ContentType?.ToString() ?? "missing"}, "
                + $"contentEncodingCount={response.Content.Headers.ContentEncoding.Count}.");
        }
        return body;
    }

    public async Task SendFailureAsync(
        MailboxHttpEndpointContract contract,
        byte[] canonicalRequest,
        MailboxHttpFailure expected)
    {
        using var response = await SendAsync(contract, canonicalRequest);
        var body = await response.Content.ReadAsByteArrayAsync();
        if ((int)response.StatusCode != MailboxWireHttpContract.StatusCode(expected)
            || body.Length != MailboxWireHttpContract.ErrorResponseBytes
            || response.Content.Headers.ContentEncoding.Count != 0)
        {
            throw new InvalidOperationException(
                $"Public mailbox {contract.RequestFrame} failure violated its exact contract.");
        }
    }

    public async Task SendTransportFailureAsync(
        MailboxHttpEndpointContract contract,
        byte[] canonicalRequest)
    {
        try
        {
            using var response = await SendAsync(contract, canonicalRequest);
            throw new InvalidOperationException(
                $"Public mailbox {contract.RequestFrame} unexpectedly returned "
                + $"HTTP {(int)response.StatusCode} instead of a transport-unknown outcome.");
        }
        catch (HttpRequestException)
        {
            // The development chaos proxy closes the downstream connection only
            // after it has consumed the complete successful upstream response.
        }
    }

    private Task<HttpResponseMessage> SendAsync(
        MailboxHttpEndpointContract contract,
        byte[] canonicalRequest)
    {
        if (canonicalRequest.Length < contract.MinimumRequestBytes
            || canonicalRequest.Length > contract.MaximumRequestBytes)
        {
            throw new InvalidOperationException(
                $"Public mailbox {contract.RequestFrame} request violates its exact byte bound.");
        }
        var content = new ByteArrayContent(canonicalRequest);
        content.Headers.ContentType =
            new MediaTypeHeaderValue(contract.RequestContentType);
        return _client.PostAsync(contract.Route.TrimStart('/'), content);
    }
}

sealed class ExactHttpPeerClient : IMailboxReplicaPeerClient
{
    private readonly HttpClient _client = new() { Timeout = TimeSpan.FromSeconds(6) };

    public async Task<ReadOnlyMemory<byte>?> SendAsync(
        MailboxReplicaPeer peer,
        MailboxPeerReplicationOperation operation,
        ReadOnlyMemory<byte> canonicalPrq2,
        CancellationToken cancellationToken)
    {
        var contract = operation == MailboxPeerReplicationOperation.Store
            ? MailboxWireHttpContract.PeerStore
            : MailboxWireHttpContract.PeerTombstone;
        using var content = new ByteArrayContent(canonicalPrq2.ToArray());
        content.Headers.ContentType = new MediaTypeHeaderValue(contract.RequestContentType);
        using var response = await _client.PostAsync(peer.Endpoint, content, cancellationToken);
        if ((int)response.StatusCode != contract.SuccessStatusCode
            || response.Content.Headers.ContentLength != contract.MaximumResponseBytes
            || !string.Equals(response.Content.Headers.ContentType?.ToString(), contract.ResponseContentType, StringComparison.Ordinal)
            || response.Content.Headers.ContentEncoding.Count != 0)
        {
            return null;
        }
        var body = await response.Content.ReadAsByteArrayAsync(cancellationToken);
        return body.Length == contract.MaximumResponseBytes ? body : null;
    }
}

sealed record Arguments(
    string Command,
    string SecretsDirectory,
    string StateDirectory,
    string AuthorityPublicPath,
    string CoordinatorUrl,
    string ClientUrl,
    bool RequireNonLoopbackCoordinator,
    string? RunId,
    string? OutputEnvironment,
    string? OutputClientEnvironment,
    string? OutputPublic,
    string? OutputClientPublic,
    string? AndroidHolderPublicKey,
    string? WindowsHolderPublicKey,
    string? IssuerSeedPath,
    string? OutputDirectory,
    string? MailboxSecretDirectory,
    bool DevelopmentOnly,
    bool AllowHttp,
    bool PhysicalDev,
    string? ExpectedAuthoritySha256,
    string? RuntimeAuthorityPublicPath,
    string? ExpectedRuntimeAuthoritySha256,
    string? ExpectedIssuerPublicKey,
    string? PairDirectory,
    string? AuthorityStatePath,
    bool FailAfterStage,
    bool FailAfterPromotion,
    string? FailAfterDurabilityBarrier)
{
    public static Arguments Parse(string[] values)
    {
        if (values.Length == 0) throw new InvalidOperationException("A command is required.");
        string Option(string name, string fallback = "")
        {
            var index = Array.IndexOf(values, name);
            return index >= 0 && index + 1 < values.Length ? values[index + 1] : fallback;
        }
        string? Optional(string name)
        {
            var value = Option(name);
            return string.IsNullOrWhiteSpace(value) ? null : value;
        }
        return new(
            values[0],
            Option("--secrets-dir", "/run/secrets"),
            Option("--state-dir", "/state/driver"),
            Option("--authority-public", "/run/survival/mailbox-peer-authority.public.json"),
            Option("--coordinator-url", "http://127.0.0.1:41801"),
            Option("--client-url", "http://xnode-1:8080"),
            values.Contains(
                "--require-non-loopback-coordinator",
                StringComparer.Ordinal),
            Optional("--run-id"),
            Optional("--output-env"),
            Optional("--output-client-env"),
            Optional("--output-public"),
            Optional("--output-client-public"),
            Optional("--android-holder-public-key"),
            Optional("--windows-holder-public-key"),
            Optional("--issuer-seed-path"),
            Optional("--output-directory"),
            Optional("--mailbox-secret-directory"),
            values.Contains("--development-only", StringComparer.Ordinal),
            values.Contains("--allow-http", StringComparer.Ordinal),
            values.Contains("--physical-dev", StringComparer.Ordinal),
            Optional("--expected-authority-sha256"),
            Optional("--runtime-authority-public"),
            Optional("--expected-runtime-authority-sha256"),
            Optional("--expected-issuer-public-key"),
            Optional("--pair-directory"),
            Optional("--authority-state"),
            values.Contains("--fail-after-stage", StringComparer.Ordinal),
            values.Contains("--fail-after-promotion", StringComparer.Ordinal),
            Optional("--fail-after-durability-barrier"));
    }
}
