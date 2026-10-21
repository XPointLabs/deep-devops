using System.Security.Cryptography;
using System.Text.Json;
using Deep.Protocol.AccountDirectoryV1;

internal static class DevNtsObservation
{
    // The offline observer uses the retained signed source set. Its ten-second
    // acquisition budget does not grant live authority or extend expired policy.
    internal static ulong Parse(ReadOnlyMemory<byte> response, AccountDirectoryDts1Source[] sources, TimeSpan elapsed)
    {
        if (sources.Length is < 2 or > 8 || response.Length is < 1 or > 8192 ||
            elapsed < TimeSpan.Zero || elapsed > TimeSpan.FromSeconds(10))
            throw new CryptographicException("NTS observation bounds or monotonic age are invalid.");
        var age = checked((ulong)Math.Ceiling(elapsed.TotalSeconds));
        using var json = JsonDocument.Parse(response, new JsonDocumentOptions { MaxDepth = 4 });
        DevTimeSourceUpdate.RequireProperties(json.RootElement, "observations");
        var entries = json.RootElement.GetProperty("observations");
        if (entries.ValueKind != JsonValueKind.Array || entries.GetArrayLength() < 2 || entries.GetArrayLength() > sources.Length)
            throw new CryptographicException("Authenticated NTS quorum count is invalid.");
        var policy = sources.ToDictionary(source => Convert.ToHexStringLower(source.SourceId.Span), StringComparer.Ordinal);
        var ids = new HashSet<string>(StringComparer.Ordinal);
        var families = new HashSet<string>(StringComparer.Ordinal);
        ulong lower = 0, upper = ulong.MaxValue;
        foreach (var entry in entries.EnumerateArray())
        {
            DevTimeSourceUpdate.RequireProperties(entry, "id", "unixSeconds", "radiusSeconds");
            var id = entry.GetProperty("id").GetString();
            if (id is null || !ids.Add(id) || !policy.TryGetValue(id, out var source))
                throw new CryptographicException("NTS source differs from the retained signed policy.");
            var time = entry.GetProperty("unixSeconds").GetUInt64();
            var observedRadius = entry.GetProperty("radiusSeconds").GetUInt32();
            var radius = checked((ulong)observedRadius + age);
            if (observedRadius == 0 || radius > source.MaximumRadiusSeconds || time <= radius)
                throw new CryptographicException("NTS observation is unbounded or stale.");
            families.Add(Convert.ToHexStringLower(source.FailureFamilyHash.Span));
            lower = Math.Max(lower, time - radius);
            upper = Math.Min(upper, checked(time + radius));
        }
        if (families.Count < 2 || lower > upper || upper - lower > 30)
            throw new CryptographicException("Independent authenticated NTS intervals do not intersect.");
        return lower + (upper - lower) / 2;
    }
}
