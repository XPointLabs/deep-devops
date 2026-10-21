using System.Text.Json;
using Deep.Protocol.AccountDirectoryV1;

// Explicit public input to the offline root ceremony; never a runtime override.
internal sealed class DevTimeSourceUpdate
{
    private readonly string path;
    private readonly byte[] exactBytes;
    internal AccountDirectoryDts1Source[] Sources { get; }

    private DevTimeSourceUpdate(string path, byte[] exactBytes, AccountDirectoryDts1Source[] sources)
    { this.path = path; this.exactBytes = exactBytes; Sources = sources; }

    internal static DevTimeSourceUpdate? Capture(string? path, AccountDirectoryDts1 prior)
    {
        if (path is null) return null;
        var fullPath = Path.GetFullPath(path);
        var bytes = DevOfflineAuthorityRenewal.Read(fullPath, 16_384);
        return new(fullPath, bytes, Parse(bytes, prior));
    }

    internal void RequireUnchanged()
    {
        if (!DevOfflineAuthorityRenewal.Read(path, 16_384).AsSpan().SequenceEqual(exactBytes))
            throw new IOException("Offline time-source input changed during the ceremony.");
    }

    internal static AccountDirectoryDts1Source[] Parse(ReadOnlyMemory<byte> bytes, AccountDirectoryDts1 prior)
    {
        if (bytes.Length is < 1 or > 16_384) throw new InvalidDataException("Time-source input is unbounded.");
        using var json = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 4 });
        RequireProperties(json.RootElement, "schema", "sources");
        if (json.RootElement.GetProperty("schema").GetString() != "deep-dev-time-sources.v1")
            throw new InvalidDataException("Unknown offline time-source input schema.");
        var entries = json.RootElement.GetProperty("sources");
        if (entries.ValueKind != JsonValueKind.Array || entries.GetArrayLength() is < 2 or > 8)
            throw new InvalidDataException("Time-source input requires two to eight entries.");
        var sources = entries.EnumerateArray().Select(entry => {
            RequireProperties(entry, "id", "family", "protocol", "host", "port", "pin", "radius");
            return new AccountDirectoryDts1Source(Hex(entry, "id"), Hex(entry, "family"),
                entry.GetProperty("protocol").GetUInt16(), entry.GetProperty("host").GetString()!,
                entry.GetProperty("port").GetUInt16(), Hex(entry, "pin"), entry.GetProperty("radius").GetUInt16());
        }).ToArray();
        // Reuse the canonical DTS grammar, including order, tuple/ID uniqueness,
        // source byte limit and family diversity. The Protocol author enforces additivity.
        return new AccountDirectoryDts1(prior.NetworkId.Span, prior.PolicyGeneration, prior.PredecessorPolicyHash.Span,
            sources, prior.RequiredSourceCount, prior.RequiredDistinctFailureFamilies, prior.MaximumIntervalWidthSeconds,
            prior.MaximumSourceSampleAgeSeconds, prior.NotBefore, prior.ExpiresAt, prior.MinimumReader,
            prior.RootAuthorityGeneration, prior.RootReceipts).Sources.ToArray();
    }

    internal static void RequireProperties(JsonElement value, params string[] expected)
    {
        if (value.ValueKind != JsonValueKind.Object) throw new InvalidDataException("Expected a closed JSON object.");
        var found = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in value.EnumerateObject())
            if (!expected.Contains(property.Name, StringComparer.Ordinal) || !found.Add(property.Name))
                throw new InvalidDataException("Unknown or duplicate JSON field.");
        if (found.Count != expected.Length) throw new InvalidDataException("Missing JSON field.");
    }

    private static byte[] Hex(JsonElement value, string field)
    {
        var text = value.GetProperty(field).GetString();
        if (text is null || text.Length != 64 || text.Any(c => c is not (>= '0' and <= '9' or >= 'a' and <= 'f')))
            throw new InvalidDataException("Time-source hashes must be canonical lowercase 32-byte hex.");
        return Convert.FromHexString(text);
    }
}
