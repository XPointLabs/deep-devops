using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Deep.Protocol.AccountDirectoryV1;
using static DevOfflineAuthorityRenewal;

// Operator-only first enrollment inputs; runtime never owns DDL or empty roots.
internal static class DevContactCoordinationPreparation
{
    internal static async Task PrepareAsync(string custodyRoot,string executable,
        Func<string,AccountDirectoryDts1Source[],Task<ulong>> observe)
    {
        var root=Path.GetFullPath(custodyRoot);
        if(!OperatingSystem.IsWindows() || !root.StartsWith(Path.GetFullPath("C:/Work/DeepSession/secrets/dev")+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("Coordination preparation requires local dev custody.");
        RequireNoLinks(root);
        var policy=await DevNodeMailboxProvisioning.PolicyAsync(Path.Combine(root,"public"),executable,observe);
        var keys=new List<string>();
        foreach(var number in Enumerable.Range(1,3)) {
            var config=Path.Combine(root,$"node-{number}/appsettings.Development.json");RequireNoLinks(config);
            using var document=JsonDocument.Parse(Read(config,65_536));
            var key=document.RootElement.GetProperty("Node").GetProperty("RouterId").GetString();
            if(key is not {Length:64} || !key.All(Uri.IsHexDigit) || Convert.FromHexString(key).AsSpan().IndexOfAnyExcept((byte)0)<0)
                throw new CryptographicException("Configured node identity binding is invalid.");
            keys.Add(key.ToLowerInvariant());
        }
        if(keys.Distinct(StringComparer.Ordinal).Count()!=3)throw new CryptographicException("Node transport identities must be distinct.");
        var directory=Path.Combine(root,"mailbox/coordination");RequireNoLinks(directory);Directory.CreateDirectory(directory);
        WriteExact(Path.Combine(directory,"bindings.json"),JsonSerializer.SerializeToUtf8Bytes(new {
            NetworkIdHex=Convert.ToHexStringLower(policy.NetworkId.Span),Nodes=keys.ToArray() }));
        WriteExact(Path.Combine(directory,"roots.sql"),Encoding.ASCII.GetBytes(RootSql(policy.NetworkId.Span)));
        Console.WriteLine("Current dev coordination transport bindings and first journal roots prepared; not runtime authority or activation.");
    }

    internal static string RootSql(ReadOnlySpan<byte> network)
    {
        if(network.Length!=16 || network.IndexOfAnyExcept((byte)0)<0)throw new ArgumentException("Exact network binding required.");
        var hex=Convert.ToHexString(network);
        return string.Join("\n",new[]{"deep_did2_route_journal_network","deep_did2_publication_journal_network"}.Select(table=>
            $"INSERT INTO {table} (network_id,entry_count,maximum_entries) VALUES (decode('{hex}','hex'),0,1048576);"))+"\n";
    }

    private static void WriteExact(string path,byte[] bytes)
    {
        RequireNoLinks(path);
        if(File.Exists(path)){if(!Read(path,16_384).AsSpan().SequenceEqual(bytes))throw new IOException("Prepared coordination input differs; no overwrite.");return;}
        using var output=new FileStream(path,FileMode.CreateNew,FileAccess.Write,FileShare.None,4096,FileOptions.WriteThrough);
        output.Write(bytes);output.Flush(true);
    }
}
