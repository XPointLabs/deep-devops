using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;
using static DevOfflineAuthorityRenewal;

// One actual disposable client owner. No signer/node/private floor mounts,
// injected transport callbacks, pre-signed grants or fixture clocks.
internal static class DevOwnedMailboxExercise
{
    internal static async Task RunAsync(string publicRoot)
    {
        if(!OperatingSystem.IsLinux() || publicRoot!="/run/deep-public")throw new ArgumentException("Wrong disposable client mount.");
        using var manifest=JsonDocument.Parse(Read(Path.Combine(publicRoot,"deep-dev.json"),16_384));
        var m=manifest.RootElement;
        if(m.GetProperty("schema").GetString()!="deep-dev.v1" || m.GetProperty("projectName").GetString()!="deep-dev-current" ||
            m.GetProperty("containerIpv4Prefix").GetString()!="172.31.241" || m.GetProperty("nodeCount").GetInt32()!=3 || m.GetProperty("deviceEvidence").GetBoolean())
            throw new InvalidDataException("Wrong current development client scope.");
        var pin=new XPointNetworkGenesisPin(Convert.FromHexString(m.GetProperty("networkIdHex").GetString()!),
            Convert.FromHexString(m.GetProperty("genesisAuthorityCoreHashHex").GetString()!));
        var closure=XPointNetworkClosureWireCodec.DecodeResponse(Read(Path.Combine(publicRoot,"network.ncp2"),XPointNetworkClosureWireCodec.MaximumResponseLength));
        if(!closure.NetworkId.Span.SequenceEqual(pin.NetworkId.Span) ||
            !Read(Path.Combine(publicRoot,"genesis.xna1"),65_535).AsSpan().SequenceEqual(closure.ExactAuthorityChain[0].Span) ||
            !Read(Path.Combine(publicRoot,"genesis.dts1"),65_535).AsSpan().SequenceEqual(closure.ExactTimePolicyChain[0].Span))throw new CryptographicException("Original client bootstrap differs.");
        var authority=XPointNetworkAuthorityVerifier.Verify(pin,closure.ExactAuthorityChain,closure.ExactTimePolicyChain);
        var head=Read(Path.Combine(publicRoot,"genesis.adh1"),4096);
        var headPin=Convert.FromHexString(m.GetProperty("genesisHeadCoreHashHex").GetString()!);
        _=DeepIdV2DirectoryBootstrapVerifier.RestoreGenesis(authority,head,headPin);
        const string scratch="/tmp/deep-dev-owned-mailbox-exercise";
        if(Directory.Exists(scratch))throw new IOException("Disposable client scratch already exists; preserve it.");
        Directory.CreateDirectory(scratch);
        using var storage=new InMemoryDeepSecureStorage();
        var accounts=new DeepIdV2AccountService(storage,scratch,pin.NetworkId.Span,1,new SystemClock(),DeepMlDsa65CandidateVerifierFactory.OpenForCurrentProcess);
        using var budget=new CancellationTokenSource(TimeSpan.FromMinutes(5));var ct=budget.Token;
        await StageAsync("AccountCreate",async()=>{_ = await accounts.CreateAsync("Dev owned mailbox fixture",ct);});
        var floor=await accounts.OpenDirectoryLkgStoreAsync(authority,head,headPin,ct);
        var factory=new HttpServiceTransportFactory(HttpServiceEndpointPolicy.Production);
        // Ordinary platform TLS against the explicit dev CA installed by the image.
        using var admissions=factory.CreateDeepIdV2GenesisAdmissionClient("https://registry/");
        using var verifier=DeepMlDsa65CandidateVerifierFactory.OpenForCurrentProcess();
        var clock=new ProcessMonotonicClock();
        using var proofs=factory.CreateDeepIdV2DirectoryProofClient("https://registry/",clock,verifier,floor);
        await StageAsync("AccountAdmission",async()=>{_ = await accounts.AdmitAndVerifyGenesisAsync(admissions,proofs,authority,cancellationToken:ct);});
        using var artifacts=factory.CreateDeepIdV2NetworkClosureArtifactSource("https://registry/");
        var networkFloor=await accounts.OpenNetworkLkgStoreAsync(pin,ct);
        var source=new DeepIdV2ContactPathAuthoritySource(pin,accounts,proofs,artifacts,networkFloor,clock);
        await StageAsync("CurrentNetwork",async()=>{var current=await source.VerifyCurrentNetworkAsync(pin.NetworkId,ct);current.EnsureCurrent();});
        await StageAsync("PreKeyStage",async()=>{_ = await accounts.EnsureOwnInitialPreKeyInventoryAsync(source,ct);});
        var custody=await accounts.OpenOwnOnionClientCustodyAsync(ct);
        await StageAsync("PreKeyPublication",async()=>{_ = await accounts.PublishOwnStagedPreKeyInventoryAsync(source,custody,ct);});
        await StageAsync("ContactPublication",async()=>{_ = await accounts.EnsureOwnPermanentContactPublishedAsync(source,ct);});
        DeepIdV2MailboxSynchronizationResult? result=null;
        await StageAsync("OwnedGrantNodeRead",async()=>{result=await accounts.SynchronizeOwnMailboxAsync(source,ct);});
        if(result is null || result.ProcessedEnvelopes!=0 || result.HasMore || result.DurableTombstones!=0)
            throw new InvalidDataException("A fresh disposable mailbox did not return an authenticated empty page.");
        Console.WriteLine(JsonSerializer.Serialize(new {schema="deep-dev-owned-mailbox-exercise.v1",ownedClientGrantNodeRead=true,
            authenticatedEmptyPage=true,deviceEvidence=false,messageDeliveryEvidence=false,restartEvidence=false}));
    }

    private static async Task StageAsync(string stage,Func<Task> action)
    {
        try{await action();Console.WriteLine("Owned development client stage completed: "+stage+".");}
        catch(Exception error){Console.Error.WriteLine("Owned development client stage failed: "+stage+" ("+error.GetType().Name+").");
            if(error is HttpRequestException http)Console.Error.WriteLine("Owned development HTTP classification: status="+
                (http.StatusCode is {} status?((int)status).ToString(System.Globalization.CultureInfo.InvariantCulture):"transport")+
                "; category="+http.HttpRequestError+"; inner="+(http.InnerException?.GetType().Name??"none")+".");throw;}
    }

    // Real process monotonic elapsed time, not a simulated trusted-time provider.
    // This disposable probe never claims cold process/host recovery evidence.
    private sealed class ProcessMonotonicClock : IOnionMonotonicClock
    {
        private readonly byte[] boot=RandomNumberGenerator.GetBytes(16);
        private readonly long started=Stopwatch.GetTimestamp();
        public ValueTask<OnionMonotonicReading> ReadAsync(CancellationToken ct)
        {ct.ThrowIfCancellationRequested();return ValueTask.FromResult(new OnionMonotonicReading(boot,
            checked(1_000UL+(ulong)Math.Floor(Stopwatch.GetElapsedTime(started).TotalSeconds))));}
    }
}
