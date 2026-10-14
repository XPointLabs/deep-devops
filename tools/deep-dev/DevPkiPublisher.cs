using System.Security.Cryptography.X509Certificates;
using Deep.Protocol.AccountDirectoryV1;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using static DevOfflineAuthorityRenewal;

// Public signed revocation bytes only. No app API or key-signing endpoint.
internal static class DevPkiPublisher
{
    internal static async Task RunAsync(string publicRoot,string operatorRoot,string executable,
        Func<string,AccountDirectoryDts1Source[],Task<ulong>> observe)
    {
        if(!OperatingSystem.IsLinux() || publicRoot!="/run/deep-public" || operatorRoot!="/run/deep-operator")throw new ArgumentException("Wrong dev PKI publisher mounts.");
        var builder=WebApplication.CreateSlimBuilder(Array.Empty<string>());builder.Logging.ClearProviders();
        builder.WebHost.UseUrls("http://0.0.0.0:8080");
        await using var app=builder.Build();
        app.MapGet("/deep-dev-ca.crl",(HttpContext context)=>{
            if(context.Request.QueryString.HasValue)return Results.BadRequest();
            try{
                var bytes=Read(Path.Combine(publicRoot,"dev-ca.crl"),65_536);
                using var ca=X509Certificate2.CreateFromPem(System.Text.Encoding.ASCII.GetString(Read(Path.Combine(publicRoot,"dev-ca.crt"),16_384)));
                DevPki.ValidateCrl(bytes,ca);
                context.Response.Headers.CacheControl="no-store";context.Response.Headers.XContentTypeOptions="nosniff";
                return Results.Bytes(bytes,"application/pkix-crl");
            }catch(Exception error)when(error is IOException or InvalidDataException or UnauthorizedAccessException or
                System.Security.Cryptography.CryptographicException or ArgumentException or InvalidOperationException){return Results.StatusCode(503);}
        });
        await app.StartAsync();
        try{await DevPublisher.RunAsync(publicRoot,operatorRoot,executable,observe,stoppingToken:app.Lifetime.ApplicationStopping);}
        finally{await app.StopAsync();}
    }
}
