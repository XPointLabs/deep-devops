using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;
using static DevOfflineAuthorityRenewal;

// One actual disposable client owner. No signer/node/private floor mounts,
// injected transport callbacks, pre-signed grants or fixture clocks.
internal static class DevOwnedMailboxExercise
{
    internal static async Task RunAsync(string publicRoot, string clientScope = "primary")
    {
        var windows=OperatingSystem.IsWindows();
        var relativeScope = clientScope switch {
            "primary" => "client-probes/windows-current-publication",
            "contact-diagnostic" => "client-probes/windows-contact-diagnostic",
            "contact-replication" => "client-probes/windows-contact-replication",
            "contact-acceptance" => "client-probes/windows-contact-acceptance",
            _ => throw new ArgumentException("Unknown retained test owner.", nameof(clientScope))
        };
        if(clientScope != "primary" && !windows)throw new PlatformNotSupportedException("The retained contact diagnostic owner requires Windows protected storage.");
        var expected=windows?Path.GetFullPath("C:/Work/DeepSession/secrets/dev/deep-dev-current/public"):"/run/deep-public";
        if((!windows && !OperatingSystem.IsLinux()) || !string.Equals(Path.GetFullPath(publicRoot),expected,
            windows?StringComparison.OrdinalIgnoreCase:StringComparison.Ordinal))throw new ArgumentException("Wrong disposable client public root.");
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
        // DR-0121 semantic clean break. Keep the pre-cutover probe untouched as
        // negative evidence; this is one fixed current test owner, not a state
        // migration, a key replacement or a legacy execution path.
        var scratch=windows?Path.Combine(Path.GetDirectoryName(expected)!,relativeScope):"/tmp/deep-dev-owned-mailbox-exercise";
        RequireNoLinks(scratch);
        if(!windows && Directory.Exists(scratch))throw new IOException("Disposable client scratch already exists; preserve it.");
        Directory.CreateDirectory(scratch);
        IDeepSecureStorage secureStorage=windows?new JournaledDeepSecureStorage(Path.Combine(scratch,"secure-state.bin"),
            new DevWindowsSecretProtector(Path.Combine(scratch,"protection"))):new InMemoryDeepSecureStorage();
        using var storageLifetime=(IDisposable)secureStorage;
        var storage=secureStorage;
        var accounts=new DeepIdV2AccountService(storage,scratch,pin.NetworkId.Span,1,new SystemClock(),DeepMlDsa65CandidateVerifierFactory.OpenForCurrentProcess);
        using var budget=new CancellationTokenSource(TimeSpan.FromMinutes(5));var ct=budget.Token;
        await StageAsync("AccountCreateOrRestore",async()=>{if(await accounts.GetCurrentAsync(ct) is null)
            _ = await accounts.CreateAsync("Dev owned mailbox fixture",ct);},ct);
        var floor=await accounts.OpenDirectoryLkgStoreAsync(authority,head,headPin,ct);
        var factory=new HttpServiceTransportFactory(HttpServiceEndpointPolicy.Production);
        // Windows adds only an exact app-scoped dev root, keeping online
        // revocation/name/EKU checks. Linux uses the image's explicit dev CA.
        if(windows){using var ca=X509Certificate2.CreateFromPem(System.Text.Encoding.ASCII.GetString(Read(Path.Combine(publicRoot,"dev-ca.crt"),16_384)));
            factory=factory.WithAppScopedPrivateCertificateAuthority(ca.RawData);}
        var origin=windows?"https://localhost:28543/":"https://registry/";
        using var admissions=factory.CreateDeepIdV2GenesisAdmissionClient(origin);
        using var verifier=DeepMlDsa65CandidateVerifierFactory.OpenForCurrentProcess();
        var clock=new ProcessMonotonicClock();
        using var proofs=factory.CreateDeepIdV2DirectoryProofClient(origin,clock,verifier,floor);
        await StageAsync("AccountAdmission",async()=>{_ = await accounts.AdmitAndVerifyGenesisAsync(admissions,proofs,authority,cancellationToken:ct);},ct);
        using var artifacts=factory.CreateDeepIdV2NetworkClosureArtifactSource(origin);
        var networkFloor=await accounts.OpenNetworkLkgStoreAsync(pin,ct);
        var source=new DeepIdV2ContactPathAuthoritySource(pin,accounts,proofs,artifacts,networkFloor,clock);
        await StageAsync("CurrentNetwork",async()=>{
            var current=await source.VerifyCurrentNetworkAsync(pin.NetworkId,ct);current.EnsureCurrent();
            var checkpoint=current.ProtectedLkg??throw new CryptographicException("Verified network checkpoint is absent.");
            Console.WriteLine("Owned development verified view generation: "+checkpoint.ViewGeneration.ToString(System.Globalization.CultureInfo.InvariantCulture)+".");
        },ct);
        await StageAsync("PreKeyStage",async()=>{_ = await accounts.EnsureOwnInitialPreKeyInventoryAsync(source,ct);},ct);
        if(windows) await StageAsync("SignedEntryTls",async()=>{
            var staged=await accounts.ReadOwnStagedPreKeyPublicationAsync(ct)??throw new InvalidDataException("Protected inventory missing.");
            var publication=DeepIdV2PreKeyPublicationCodec.Decode(staged.ExactXpp1.Span);
            var selected=await source.GetCurrentForPublicationAsync(pin.NetworkId,publication.Manifest.Field(2),ct);
            await VerifyEntryTlsAsync(selected.Network,selected.Placement,publicRoot,ct);
        },ct);
        DeepIdV2OnionClientCustody? custody=null;
        await StageAsync("OnionCustody",async()=>{custody=await accounts.OpenOwnOnionClientCustodyAsync(ct);},ct);
        var priorPair=await accounts.ReadOwnPreKeyCommitPairAsync(ct);
        await StageAsync("PreKeyPublication",async()=>{
            var pair=await accounts.PublishOwnStagedPreKeyInventoryAsync(source,custody!,ct);
            if(priorPair is not null && (!priorPair.ExactFirstXic1.Span.SequenceEqual(pair.ExactFirstXic1.Span)||
                !priorPair.ExactSecondXic1.Span.SequenceEqual(pair.ExactSecondXic1.Span)))
                throw new CryptographicException("Protected prekey receipt pair changed during reopen.");
            if(priorPair is not null)Console.WriteLine("Owned development protected prekey pair reauthenticated byte-identically after reopen.");
        },ct);
        await StageAsync("ContactPublication",async()=>{
            var committed=await accounts.EnsureOwnPermanentContactPublishedAsync(source,ct);
            Console.WriteLine("Owned development verified contact generation: "+committed.Generation.ToString(System.Globalization.CultureInfo.InvariantCulture)+".");
        },ct);
        DeepIdV2MailboxSynchronizationResult? result=null;
        await StageAsync("OwnedGrantNodeRead",async()=>{result=await accounts.SynchronizeOwnMailboxAsync(source,ct);},ct);
        if(result is null || result.ProcessedEnvelopes!=0 || result.HasMore || result.DurableTombstones!=0)
            throw new InvalidDataException("A fresh disposable mailbox did not return an authenticated empty page.");
        Console.WriteLine(JsonSerializer.Serialize(new {schema="deep-dev-owned-mailbox-exercise.v1",ownedClientGrantNodeRead=true,
            authenticatedEmptyPage=true,deviceEvidence=false,messageDeliveryEvidence=false,restartEvidence=false}));
    }

    private static async Task VerifyEntryTlsAsync(VerifiedOnionNetworkContext network,
        VerifiedContactServicePlacement placement,string publicRoot,CancellationToken ct)
    {
        using var ca=X509Certificate2.CreateFromPem(System.Text.Encoding.ASCII.GetString(Read(Path.Combine(publicRoot,"dev-ca.crt"),16_384)));
        var candidates=OnionPathCandidateSnapshotFactory.Create(network).Candidates.Select(x=>x.NodeId).ToArray();
        if(candidates.Length!=3)throw new InvalidDataException("Exact three-node diagnostic required.");
        var matched=0;
        foreach(var ingress in candidates){
            var exit=placement.RankedReplicaNodeIds.First(x=>!x.Span.SequenceEqual(ingress.Span));
            var core=candidates.Single(x=>!x.Span.SequenceEqual(ingress.Span)&&!x.Span.SequenceEqual(exit.Span));
            var entry=OnionEntryTransportFactory.Create(OnionPathContextFactory.CreateContactResolver(network,placement,ingress,core,exit));
            var peer=entry.Peer;
            var address=new IPAddress(peer.AddressFamily==OnionNextHopAddressFamily.IPv4?peer.Address.Span[..4]:peer.Address.Span);
            using var tcp=new TcpClient(address.AddressFamily);
            await tcp.ConnectAsync(address,peer.Port,ct);
            using var tls=new SslStream(tcp.GetStream(),false);
            var policy=new X509ChainPolicy{TrustMode=X509ChainTrustMode.CustomRootTrust,RevocationMode=X509RevocationMode.Online,
                RevocationFlag=X509RevocationFlag.ExcludeRoot,VerificationFlags=X509VerificationFlags.NoFlag};
            policy.CustomTrustStore.Add(ca);policy.ApplicationPolicy.Add(new Oid("1.3.6.1.5.5.7.3.1"));
            await tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions{TargetHost=address.ToString(),
                CertificateChainPolicy=policy,ApplicationProtocols=[SslApplicationProtocol.Http2]},ct);
            entry.EnsureCurrent();
            if(tls.NegotiatedApplicationProtocol!=SslApplicationProtocol.Http2||tls.RemoteCertificate is not X509Certificate2 leaf)
                throw new CryptographicException("Signed entry diagnostic requires strict TLS/H2.");
            var same=CryptographicOperations.FixedTimeEquals(SHA256.HashData(leaf.PublicKey.ExportSubjectPublicKeyInfo()),peer.SpkiSha256.Span);
            if(same)matched++;
            Console.WriteLine("Owned development strict entry TLS: signed pin "+(same?"matched":"DIFFERS")+".");
        }
        if(matched!=3)throw new CryptographicException("Signed entry certificate/placement binding differs.");
    }

    internal static async Task StageAsync(string stage,Func<Task> action,CancellationToken ct)
    {
        try{
            for(var attempt=0;;attempt++){
                ct.ThrowIfCancellationRequested();
                try{await action();break;}
                catch(Deep.Client.Shared.Services.AccountDirectoryV2.DeepIdV2DirectoryProofUnavailableException unavailable)when(attempt<3){
                    var delay=unavailable.RetryAfter??TimeSpan.FromSeconds(10);
                    Console.WriteLine("Owned development proof backoff: "+stage+"; status="+((int)unavailable.StatusCode)+"; attempt="+(attempt+1)+"; delaySeconds="+delay.TotalSeconds.ToString(System.Globalization.CultureInfo.InvariantCulture)+".");
                    await Task.Delay(delay,ct);
                }
                catch(ClientMailboxTransportException unavailable)when(stage=="ContactPublication" && attempt<4 && unavailable.Retryable &&
                    unavailable.Failure==ClientMailboxTransportFailure.DependencyUnavailable){
                    // This contact transport preserves the ingress's explicit
                    // before-forward rejection. Unknown completion uses another
                    // exception and is never caught/replayed here. The account
                    // owner reopens exact journal custody on the next attempt.
                    var delay=TimeSpan.FromMilliseconds(RandomNumberGenerator.GetInt32(500,1500)*(1<<Math.Min(attempt,3)));
                    Console.WriteLine("Owned development before-forward backoff: "+stage+"; attempt="+(attempt+1)+".");
                    await Task.Delay(delay,ct);
                }
            }
            Console.WriteLine("Owned development client stage completed: "+stage+".");
        }
        catch(Exception error){Console.Error.WriteLine("Owned development client stage failed: "+stage+" ("+error.GetType().Name+").");
            if(error is CryptographicException && error.Data["Deep.ContactRoute.Scope"] is string routeScope &&
                routeScope is "pmt-reference" or "device-or-delegation")
                Console.Error.WriteLine("Owned development closed route scope: "+routeScope+".");
            if(error is CryptographicException && error.Data["Deep.ContactPublication.Status"] is ushort publicationStatus &&
                publicationStatus is >=1 and <=9 && error.Data["Deep.ContactPublication.MutationOutcome"] is byte mutationOutcome)
                Console.Error.WriteLine("Owned development closed publication result: status="+publicationStatus+"; mutation="+mutationOutcome+".");
            if(error is CryptographicException && error.Data["Deep.ContactPublication.RequestScope"] is string publicationScope &&
                publicationScope is "request-window" or "request-authority-bound" or "owned-lineage")
                Console.Error.WriteLine("Owned development closed publication request scope: "+publicationScope+".");
            if(error is CryptographicException && error.Message=="The protected DID2 publication differs from current placement.")
                Console.Error.WriteLine("Owned development closed failure classification: prekey-placement-changed.");
            if(error is ClientMailboxDispatchOutcomeUnknownException) {
                var category=error.Message switch {
                    "Privacy ingress returned an invalid response length."=>"response-length",
                    "Privacy ingress success response is not canonical."=>"response-canonicality",
                    "Privacy ingress returned an outcome-unknown error."=>"remote-outcome-unknown",
                    "Privacy ingress outcome is unknown after dispatch began."=>"dispatch-unknown",
                    "Privacy ingress outcome is unknown because dispatch was cancelled."=>"dispatch-cancelled",
                    _=>"unclassified"};
                Console.Error.WriteLine("Owned development closed ingress classification: "+category+".");
                if (error.Data["Deep.ContactResolve.TerminalFailure"] is ushort terminalCode &&
                    Enum.IsDefined(typeof(OnionFailureCode), terminalCode))
                    Console.Error.WriteLine("Owned development authenticated terminal failure: "+(OnionFailureCode)terminalCode+".");
            }
            var frames=new StackTrace(error,false).GetFrames()??[];var emitted=0;
            foreach(var frame in frames){var method=frame.GetMethod();var type=method?.DeclaringType;
                if(type?.Assembly.GetName().Name is not ("Deep.Client.Shared" or "Deep.Protocol"))continue;
                Console.Error.WriteLine("Owned development source classification: "+type.FullName+"."+method!.Name+".");
                if(++emitted==5)break;}
            if(error is Deep.Client.Shared.Services.AccountDirectoryV2.DeepIdV2DirectoryProofUnavailableException unavailable)
                Console.Error.WriteLine("Owned development proof availability: status="+((int)unavailable.StatusCode)+".");
            var depth=0;for(var inner=error.InnerException;inner is not null && depth++<4;inner=inner.InnerException){
                Console.Error.WriteLine("Owned development inner classification: "+inner.GetType().Name+".");
                if(inner.Message is "Privacy ingress rejected the request before forwarding (Unavailable)." or
                    "Privacy ingress rejected the request before forwarding (Saturated)." or
                    "Privacy ingress rejected the request before forwarding (WrongOrigin)." or
                    "Privacy ingress rejected the request before forwarding (MalformedFrame).")
                    Console.Error.WriteLine("Owned development closed before-forward classification: "+
                        (inner.Message.Contains("(Unavailable)",StringComparison.Ordinal)?"unavailable":
                        inner.Message.Contains("(Saturated)",StringComparison.Ordinal)?"saturated":
                        inner.Message.Contains("(WrongOrigin)",StringComparison.Ordinal)?"wrong-origin":"malformed-frame")+".");
                if(inner is HttpRequestException && inner.Data["Deep.ManagedIngress.TlsFailure"] is string tlsCategory &&
                    tlsCategory is "certificate-name" or "certificate-missing" or "certificate-policy" or "certificate-pin" or "certificate-usage-or-time" or "entry-authority")
                    Console.Error.WriteLine("Owned development signed TLS rejection: "+tlsCategory+".");
                if(inner is System.Security.Authentication.AuthenticationException)
                    Console.Error.WriteLine("Owned development closed TLS classification: "+(inner.Message=="The remote certificate was rejected by the provided RemoteCertificateValidationCallback."?"certificate-callback-rejected":"other-authentication")+".");
                if(inner is OnionBoundaryException boundary)Console.Error.WriteLine("Owned development ONION classification: "+boundary.Code+".");
            }
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
