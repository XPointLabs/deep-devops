using System.Formats.Asn1;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Deep.Protocol.AccountDirectoryV1;
using static DevOfflineAuthorityRenewal;

// Explicit local TLS ceremony only; no protocol root, identity or floor writes.
internal static class DevPki
{
    internal const string DistributionUri="http://publisher:8080/deep-dev-ca.crl";
    internal static readonly string[] Services=["registry","floor","node-1","node-2","node-3","node-1-next","node-2-next","node-3-next"];
    internal sealed record Replacement(string Path,byte[]? Before,byte[] After);
    internal sealed record Plan(byte[] Ca,Replacement[] Files);
    private static readonly JsonSerializerOptions Json=new(){UnmappedMemberHandling=System.Text.Json.Serialization.JsonUnmappedMemberHandling.Disallow};

    internal static async Task PrepareAsync(string custodyRoot,string executable,Func<string,AccountDirectoryDts1Source[],Task<ulong>> observe)
    {
        var root=RequireRoot(custodyRoot);var candidate=Path.Combine(root,"offline-root/dev-pki");RequireNoLinks(candidate);
        if(Directory.Exists(candidate))throw new IOException("Existing PKI candidate must be inspected or resumed; no re-authoring.");
        _=await DevNodeMailboxProvisioning.PolicyAsync(Path.Combine(root,"public"),executable,observe);
        var closure=Deep.Protocol.XPointNetworkV1.XPointNetworkClosureWireCodec.DecodeResponse(Read(Path.Combine(root,"public/network.ncp2"),
            Deep.Protocol.XPointNetworkV1.XPointNetworkClosureWireCodec.MaximumResponseLength));
        var sources=AccountDirectoryDts1Codec.Decode(closure.ExactTimePolicyChain[^1].Span).Sources.ToArray();
        var seconds=await observe(executable,sources);var now=DateTimeOffset.FromUnixTimeSeconds(checked((long)seconds));
        var caBytes=Read(Path.Combine(root,"public/dev-ca.crt"),16_384);
        var secret=Read(Path.Combine(root,"offline-root/dev-ca.key"),16_384);
        using var caPublic=X509Certificate2.CreateFromPem(Encoding.ASCII.GetString(caBytes));using var caKey=RSA.Create();
        try{caKey.ImportFromPem(Encoding.ASCII.GetString(secret));}finally{CryptographicOperations.ZeroMemory(secret);}
        using var ca=caPublic.CopyWithPrivateKey(caKey);
        if(now<ca.NotBefore.ToUniversalTime() || now>=ca.NotAfter.ToUniversalTime())throw new CryptographicException("Existing dev CA is not current; no root replacement.");
        var crlPath=Path.Combine(root,"public/dev-ca.crl");RequireNoLinks(crlPath);
        var prior=File.Exists(crlPath)?Read(crlPath,65_536):null;
        var number=BigInteger.Zero;var builder=new CertificateRevocationListBuilder();
        if(prior is not null){ValidateCrl(prior,caPublic);builder=CertificateRevocationListBuilder.Load(prior,out number);}
        var crl=builder.Build(ca,number+1,new DateTimeOffset(ca.NotAfter.ToUniversalTime()),HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1,now.AddSeconds(-30));
        ValidateCrl(crl,caPublic);
        var files=new List<Replacement>{new("public/dev-ca.crl",prior,crl)};
        foreach(var service in Services){
            var path=$"{service}/secrets/server.crt";var before=Read(Path.Combine(root,path),16_384);
            using var old=X509Certificate2.CreateFromPem(Encoding.ASCII.GetString(before));using var key=RSA.Create();
            secret=Read(Path.Combine(root,$"{service}/secrets/server.key"),16_384);
            try{key.ImportFromPem(Encoding.ASCII.GetString(secret));}finally{CryptographicOperations.ZeroMemory(secret);}
            using var after=AuthorLeaf(ca,key,old);
            files.Add(new(path,before,Encoding.ASCII.GetBytes(after.ExportCertificatePem())));
        }
        var plan=new Plan(caBytes,files.ToArray());var integrity=Read(Path.Combine(root,"operator/renewal-integrity.key"),32);
        try{
            if(integrity.Length!=32)throw new CryptographicException("PKI integrity key length differs.");
            Directory.CreateDirectory(candidate);
            foreach(var file in plan.Files){
                var target=Path.Combine(candidate,file.Path);Directory.CreateDirectory(Path.GetDirectoryName(target)!);WriteNew(target,file.After);
                if(file.Path.Contains("/secrets/",StringComparison.Ordinal) && file.Before is not null){
                    var before=Path.Combine(candidate,"volume-before",file.Path);Directory.CreateDirectory(Path.GetDirectoryName(before)!);WriteNew(before,file.Before);
                }
            }
            var payload=JsonSerializer.SerializeToUtf8Bytes(plan,Json);WriteNew(Path.Combine(candidate,"plan.bin"),[..HMACSHA256.HashData(integrity,payload),..payload]);
        }finally{CryptographicOperations.ZeroMemory(integrity);}
        Console.WriteLine("Signed dev CRL and same-key certificate candidate prepared; not installed, no protocol authority changed.");
    }

    internal static X509Certificate2 AuthorLeaf(X509Certificate2 ca,RSA key,X509Certificate2 old)
    {
        VerifySigned(old.RawData,ca);
        if(!old.IssuerName.RawData.AsSpan().SequenceEqual(ca.SubjectName.RawData) ||
            !old.PublicKey.ExportSubjectPublicKeyInfo().AsSpan().SequenceEqual(key.ExportSubjectPublicKeyInfo()))throw new CryptographicException("Retained leaf/CA/key binding differs.");
        var request=new CertificateRequest(old.SubjectName,key,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);
        foreach(var extension in old.Extensions)if(extension.Oid?.Value!="2.5.29.31")request.CertificateExtensions.Add(new X509Extension(extension.Oid!,extension.RawData,extension.Critical));
        request.CertificateExtensions.Add(CertificateRevocationListBuilder.BuildCrlDistributionPointExtension([DistributionUri]));
        return request.Create(ca,new DateTimeOffset(old.NotBefore.ToUniversalTime()),new DateTimeOffset(old.NotAfter.ToUniversalTime()),RandomNumberGenerator.GetBytes(16));
    }

    internal static Plan Validate(string custodyRoot)
    {
        var root=RequireRoot(custodyRoot);var candidate=Path.Combine(root,"offline-root/dev-pki");
        var exact=Read(Path.Combine(candidate,"plan.bin"),512*1024);var key=Read(Path.Combine(root,"operator/renewal-integrity.key"),32);
        try{if(key.Length!=32 || exact.Length<33 || !CryptographicOperations.FixedTimeEquals(exact.AsSpan(0,32),HMACSHA256.HashData(key,exact.AsSpan(32))))throw new CryptographicException("PKI candidate seal differs.");}
        finally{CryptographicOperations.ZeroMemory(key);}
        var plan=JsonSerializer.Deserialize<Plan>(exact.AsSpan(32),Json)??throw new InvalidDataException("Missing PKI plan.");
        if(!Read(Path.Combine(root,"public/dev-ca.crt"),16_384).AsSpan().SequenceEqual(plan.Ca))throw new CryptographicException("PKI CA changed.");
        var allowed=new[]{"public/dev-ca.crl"}.Concat(Services.Select(s=>$"{s}/secrets/server.crt")).ToArray();
        if(plan.Files.Length!=allowed.Length || !plan.Files.Select(f=>f.Path).Order().SequenceEqual(allowed.Order()))throw new InvalidDataException("PKI whitelist differs.");
        using var ca=X509Certificate2.CreateFromPem(Encoding.ASCII.GetString(plan.Ca));
        foreach(var file in plan.Files){
            var target=Path.Combine(root,file.Path);RequireNoLinks(target);
            var current=File.Exists(target)?Read(target,65_536):null;
            if(!(current is null && file.Before is null) && !(current is not null && (current.AsSpan().SequenceEqual(file.After) || file.Before is not null && current.AsSpan().SequenceEqual(file.Before))))
                throw new IOException("Retained PKI target changed; no overwrite.");
            if(!Read(Path.Combine(candidate,file.Path),65_536).AsSpan().SequenceEqual(file.After))throw new CryptographicException("PKI staged file differs.");
            if(file.Path=="public/dev-ca.crl"){
                ValidateCrl(file.After,ca);_=CertificateRevocationListBuilder.Load(file.After,out var number);var priorNumber=BigInteger.Zero;
                if(file.Before is not null){ValidateCrl(file.Before,ca);_=CertificateRevocationListBuilder.Load(file.Before,out priorNumber);}
                if(number!=priorNumber+1)throw new CryptographicException("CRL sequence differs from its retained predecessor.");continue;
            }
            if(file.Before is null)throw new InvalidDataException("Missing retained certificate.");
            using var before=X509Certificate2.CreateFromPem(Encoding.ASCII.GetString(file.Before));using var after=X509Certificate2.CreateFromPem(Encoding.ASCII.GetString(file.After));
            VerifySigned(after.RawData,ca);
            var service=file.Path.Split('/')[0];var dns=service.EndsWith("-next",StringComparison.Ordinal)?service[..^5]:service;
            if(!before.PublicKey.ExportSubjectPublicKeyInfo().AsSpan().SequenceEqual(after.PublicKey.ExportSubjectPublicKeyInfo()) || !after.MatchesHostname(dns) ||
                before.NotBefore!=after.NotBefore || before.NotAfter!=after.NotAfter || !before.SubjectName.RawData.AsSpan().SequenceEqual(after.SubjectName.RawData))
                throw new CryptographicException("PKI candidate changed its key, host or validity.");
            var expected=CertificateRevocationListBuilder.BuildCrlDistributionPointExtension([DistributionUri]);
            if(after.Extensions["2.5.29.31"] is not {} cdp || !cdp.RawData.AsSpan().SequenceEqual(expected.RawData))throw new CryptographicException("PKI distribution binding differs.");
            var extensions=before.Extensions.Cast<X509Extension>().Where(e=>e.Oid?.Value!="2.5.29.31").ToArray();
            if(after.Extensions.Count!=extensions.Length+1 || extensions.Any(e=>after.Extensions[e.Oid!.Value!] is not {} matching ||
                matching.Critical!=e.Critical || !matching.RawData.AsSpan().SequenceEqual(e.RawData)))throw new CryptographicException("Retained certificate extensions changed.");
            if(!Read(Path.Combine(candidate,"volume-before",file.Path),16_384).AsSpan().SequenceEqual(file.Before))throw new CryptographicException("PKI volume before-image differs.");
            using var keyCertificate=X509Certificate2.CreateFromPemFile(Path.Combine(root,file.Path),Path.Combine(root,service,"secrets/server.key"));
        }
        return plan;
    }

    internal static void Install(string custodyRoot)
    {
        var root=RequireRoot(custodyRoot);var plan=Validate(root);
        foreach(var file in plan.Files){
            var target=Path.Combine(root,file.Path);var stage=target+".stage-"+Guid.NewGuid().ToString("N");WriteNew(stage,file.After);File.Move(stage,target,true);
        }
        Console.WriteLine("Whitelisted same-key dev certificates and signed CRL installed; current runtime verification remains required.");
    }
    internal static void ValidateCrl(byte[] exact,X509Certificate2 ca)
    {
        _=CertificateRevocationListBuilder.Load(exact,out _);VerifySigned(exact,ca);
        var reader=new AsnReader(exact,AsnEncodingRules.DER).ReadSequence();var body=new AsnReader(reader.ReadEncodedValue(),AsnEncodingRules.DER).ReadSequence();
        _=body.ReadInteger();_=body.ReadEncodedValue();
        if(!body.ReadEncodedValue().Span.SequenceEqual(ca.SubjectName.RawData))throw new CryptographicException("CRL issuer differs.");
    }
    internal static async Task CacheWindowsCrlAsync(string publicRoot)
    {
        var root=Path.GetFullPath(publicRoot);
        if(!OperatingSystem.IsWindows() || !string.Equals(root,Path.GetFullPath("C:/Work/DeepSession/secrets/dev/deep-dev-current/public"),StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("CRL cache accepts only the exact current-dev public root.");
        RequireNoLinks(root);var path=Path.Combine(root,"dev-ca.crl");RequireNoLinks(path);
        using var held=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read);
        if(held.Length is < 1 or > 65_536)throw new InvalidDataException("Dev CRL cache input exceeds bounds.");
        var bytes=new byte[checked((int)held.Length)];held.ReadExactly(bytes);
        using var ca=X509Certificate2.CreateFromPem(Encoding.ASCII.GetString(Read(Path.Combine(root,"dev-ca.crt"),16_384)));
        ValidateCrl(bytes,ca);
        var start=new System.Diagnostics.ProcessStartInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows),"System32/certutil.exe")) {
            UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true };
        foreach(var argument in new[]{"-user","-addstore","CA",path})start.ArgumentList.Add(argument);
        using var process=System.Diagnostics.Process.Start(start)??throw new IOException("CRL cache process unavailable.");
        using var budget=new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var stdout=process.StandardOutput.ReadToEndAsync();var stderr=process.StandardError.ReadToEndAsync();
        try{await process.WaitForExitAsync(budget.Token);_=await stdout;_=await stderr;}
        catch{if(!process.HasExited)process.Kill();throw;}
        if(process.ExitCode!=0)throw new IOException("Current-user signed CRL cache import failed.");
        Console.WriteLine("Verified signed dev CRL cached in current-user CA store; no ROOT certificate or machine-store change.");
    }
    internal static void VerifySigned(byte[] exact,X509Certificate2 ca)
    {
        var reader=new AsnReader(exact,AsnEncodingRules.DER);var sequence=reader.ReadSequence();reader.ThrowIfNotEmpty();
        var body=sequence.ReadEncodedValue();var algorithm=sequence.ReadSequence();
        if(algorithm.ReadObjectIdentifier()!="1.2.840.113549.1.1.11")throw new CryptographicException("Unexpected dev PKI signature algorithm.");
        if(algorithm.HasData)algorithm.ReadNull();algorithm.ThrowIfNotEmpty();var signature=sequence.ReadBitString(out var unused);sequence.ThrowIfNotEmpty();
        using var key=ca.GetRSAPublicKey();if(unused!=0 || key is null || !key.VerifyData(body.Span,signature,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1))throw new CryptographicException("Dev PKI signature differs.");
    }
    private static string RequireRoot(string root)
    {
        root=Path.GetFullPath(root);
        if(!OperatingSystem.IsWindows() || !root.StartsWith(Path.GetFullPath("C:/Work/DeepSession/secrets/dev")+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase))throw new ArgumentException("Not local dev PKI custody.");
        RequireNoLinks(root);return root;
    }
    private static void WriteNew(string path,byte[] bytes){RequireNoLinks(path);using var stream=new FileStream(path,FileMode.CreateNew,FileAccess.Write,FileShare.None,4096,FileOptions.WriteThrough);stream.Write(bytes);stream.Flush(true);}
}
