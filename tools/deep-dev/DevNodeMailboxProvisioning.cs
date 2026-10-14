using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.XPointNetworkV1;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.Extensions.DependencyInjection;
using Sodium;
using static DevOfflineAuthorityRenewal;

// Explicit DEV operator inputs only. Node's existing enrollment command remains
// the owner of current proof verification and native floor installation.
internal static class DevNodeMailboxProvisioning
{
    internal const string Application = "XPoint.XNode.Mailbox.Custody.v1";
    internal static void ProvisionKeys(string path)
    {
        if (!OperatingSystem.IsLinux() || path != "/run/mailbox-keys") throw new ArgumentException("Wrong explicit key provisioning mount.");
        RequireNoLinks(path);
        if (!Directory.Exists(path) || Directory.EnumerateFileSystemEntries(path).Any())
            throw new IOException("Key provisioning requires a genuinely empty owned volume; never regenerate existing custody.");
        File.SetUnixFileMode(path,UnixFileMode.UserRead|UnixFileMode.UserWrite|UnixFileMode.UserExecute);
        var services = new ServiceCollection();
        services.AddDataProtection().PersistKeysToFileSystem(new DirectoryInfo(path))
            .SetApplicationName(Application).DisableAutomaticKeyGeneration();
        using(var provider = services.BuildServiceProvider())
            provider.GetRequiredService<IKeyManager>().CreateNewKey(DateTimeOffset.UtcNow.AddMinutes(-1),DateTimeOffset.UtcNow.AddDays(90));
        var files = Directory.GetFiles(path);
        if(files.Length != 1 || !Path.GetFileName(files[0]).StartsWith("key-",StringComparison.Ordinal) || Path.GetExtension(files[0]) != ".xml")
            throw new IOException("Unexpected generated key-ring state; preserve it for inspection.");
        File.SetUnixFileMode(files[0],UnixFileMode.UserRead|UnixFileMode.UserWrite);
        Console.WriteLine("Explicit new mailbox protection key ring provisioned; no node identity or floor was created.");
    }

    private static async Task<VerifiedMailboxAuthorityV2> PolicyAsync(string publicRoot,string executable,
        Func<string,AccountDirectoryDts1Source[],Task<ulong>> observe)
    {
        using var manifest = JsonDocument.Parse(Read(Path.Combine(publicRoot,"deep-dev.json"),16_384));
        var m=manifest.RootElement;
        if(m.GetProperty("schema").GetString()!="deep-dev.v1" || m.GetProperty("projectName").GetString()!="deep-dev-current" ||
            m.GetProperty("nodeCount").GetInt32()!=3 || m.GetProperty("deviceEvidence").GetBoolean()) throw new InvalidDataException("Wrong current dev scope.");
        var network=Convert.FromHexString(m.GetProperty("networkIdHex").GetString()!);
        var closure=XPointNetworkClosureWireCodec.DecodeResponse(Read(Path.Combine(publicRoot,"network.ncp2"),XPointNetworkClosureWireCodec.MaximumResponseLength));
        if(!closure.NetworkId.Span.SequenceEqual(network) ||
            !Read(Path.Combine(publicRoot,"genesis.xna1"),65_535).AsSpan().SequenceEqual(closure.ExactAuthorityChain[0].Span) ||
            !Read(Path.Combine(publicRoot,"genesis.dts1"),65_535).AsSpan().SequenceEqual(closure.ExactTimePolicyChain[0].Span)) throw new CryptographicException("Original genesis differs.");
        var root=XPointNetworkAuthorityVerifier.Verify(new(network,Convert.FromHexString(m.GetProperty("genesisAuthorityCoreHashHex").GetString()!)),
            closure.ExactAuthorityChain,closure.ExactTimePolicyChain);
        var observed=await observe(executable,AccountDirectoryDts1Codec.Decode(closure.ExactTimePolicyChain[^1].Span).Sources.ToArray());
        var policy=MailboxAuthorityV2Verifier.Verify(root,closure.ExactMailboxAuthorityChain[^1].Span,observed,checked(observed+1));
        if(!policy.BindsProjection(closure.ExactPlacementTopologyChain[^1].Span)) throw new CryptographicException("Policy/projection differs.");
        return policy;
    }

    internal static async Task PrepareAsync(string custodyRoot,string executable,
        Func<string,AccountDirectoryDts1Source[],Task<ulong>> observe)
    {
        var root=Path.GetFullPath(custodyRoot);
        if(!OperatingSystem.IsWindows() || !root.StartsWith(Path.GetFullPath("C:/Work/DeepSession/secrets/dev")+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("Node mailbox preparation requires local dev custody.");
        RequireNoLinks(root);
        var policy=await PolicyAsync(Path.Combine(root,"public"),executable,observe);
        var file=Path.Combine(root,"mailbox/node-bindings.json"); RequireNoLinks(file);
        var bytes=JsonSerializer.SerializeToUtf8Bytes(new { NetworkIdHex=Convert.ToHexStringLower(policy.NetworkId.Span),
            MailboxAuthorityCoreHashHex=Convert.ToHexStringLower(policy.CoreHash.Span) });
        if(File.Exists(file)) { if(!Read(file,4096).AsSpan().SequenceEqual(bytes)) throw new IOException("Existing node mailbox scope differs; no overwrite."); }
        else { using var stream=new FileStream(file,FileMode.CreateNew,FileAccess.Write,FileShare.None,4096,FileOptions.WriteThrough); stream.Write(bytes);stream.Flush(true); }
        Console.WriteLine("Signed current node mailbox bindings prepared; not native floor authority.");
    }

    internal static async Task FetchControlAsync(string publicRoot,string destination,string executable,
        Func<string,AccountDirectoryDts1Source[],Task<ulong>> observe)
    {
        if(!OperatingSystem.IsLinux() || publicRoot!="/run/deep-public" || destination!="/run/node-control") throw new ArgumentException("Wrong public control mount.");
        RequireNoLinks(destination);
        var policy=await PolicyAsync(publicRoot,executable,observe);
        using var handler=new SocketsHttpHandler { AllowAutoRedirect=false,UseCookies=false,AutomaticDecompression=DecompressionMethods.None };
        using var client=new HttpClient(handler){Timeout=TimeSpan.FromSeconds(30)};
        using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(30));
        foreach(var (name,role) in new[]{("deposit",MailboxCapabilityDomain.Deposit),("retrieve",MailboxCapabilityDomain.Retrieve)}) {
            var path=$"https://registry/api/v1/node-control/mailbox-revocations/{Convert.ToHexStringLower(policy.NetworkId.Span)}/{Convert.ToHexStringLower(policy.CoreHash.Span)}/{(byte)role}/latest";
            using var request=new HttpRequestMessage(HttpMethod.Get,path);
            request.Headers.Accept.Add(new("application/vnd.deep.mailbox-grant-revocation.v1+octet-stream"));
            request.Headers.CacheControl = new() { NoStore = true };
            using var response=await client.SendAsync(request,HttpCompletionOption.ResponseHeadersRead,deadline.Token);
            if(response.RequestMessage?.RequestUri is not {} actual || actual.AbsoluteUri != path)
                throw new InvalidDataException("Signed control endpoint changed.");
            var length = ValidateControlFraming(response);
            var exact=new byte[checked((int)length)];await using var body=await response.Content.ReadAsStreamAsync(deadline.Token);
            await body.ReadExactlyAsync(exact,deadline.Token);
            if(await body.ReadAsync(new byte[1],deadline.Token)!=0)throw new InvalidDataException("Trailing control bytes.");
            ValidateControl(policy,role,exact);
            var target=Path.Combine(destination,name+".mgr1");RequireNoLinks(target);
            var stage=target+".stage-"+Guid.NewGuid().ToString("N");
            await using(var output=new FileStream(stage,FileMode.CreateNew,FileAccess.Write,FileShare.None,4096,FileOptions.WriteThrough)) {
                await output.WriteAsync(exact,deadline.Token);output.Flush(true);
            }
            File.Move(stage,target,true);
        }
        Console.WriteLine("Two exact issuer-signed control records captured through TLS; node currentness/enrollment still required.");
    }

    internal static long ValidateControlFraming(HttpResponseMessage response)
    {
        if(response.StatusCode is HttpStatusCode.TooManyRequests or HttpStatusCode.ServiceUnavailable)
            throw new IOException("Signed control transport unavailable.");
        var media=response.Content.Headers.ContentType;
        if(response.StatusCode!=HttpStatusCode.OK || media?.MediaType!="application/vnd.deep.mailbox-grant-revocation.v1+octet-stream" ||
            media.Parameters.Count!=0 || response.Content.Headers.ContentEncoding.Count!=0 || response.Headers.CacheControl?.NoStore!=true ||
            !response.Headers.TryGetValues("X-Content-Type-Options",out var sniff) || !sniff.SequenceEqual(["nosniff"]) ||
            response.Content.Headers.ContentLength is not {} length || length<MailboxGrantRevocationV1Codec.MinimumBytes || length>MailboxGrantRevocationV1Codec.MaximumBytes)
            throw new InvalidDataException("Signed control framing differs.");
        return length;
    }

    internal static void ValidateControl(VerifiedMailboxAuthorityV2 policy,MailboxCapabilityDomain role,ReadOnlySpan<byte> exact)
    {
        var parsed=MailboxGrantRevocationV1Codec.Decode(exact);
        byte[] reference=[.. "PMA2"u8,0,1,..policy.CoreHash.Span];
        if(parsed.Domain!=role || !parsed.Field(1).Span.SequenceEqual(policy.NetworkId.Span) || !parsed.Field(2).Span.SequenceEqual(reference) ||
            !parsed.Field(4).Span.SequenceEqual(policy.ResolveIssuer(role).PublicKey.Span) ||
            !PublicKeyAuth.VerifyDetached(parsed.Field(12).ToArray(),parsed.SignatureInput.ToArray(),policy.ResolveIssuer(role).PublicKey.ToArray()))
            throw new CryptographicException("Signed control scope/signature differs.");
        // Parsed signature/scope is not an admission capability. Node's closed
        // current-host verifier checks full protected time and actual native state.
    }
}
