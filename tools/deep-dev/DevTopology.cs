internal sealed record DevTopology(string ProjectName, string Ipv4Prefix)
{
    internal static DevTopology ForProject(string projectName) => projectName switch
    {
        "deep-dev" => new(projectName, "172.31.240"),
        "deep-dev-current" => new(projectName, "172.31.241"),
        _ => throw new ArgumentException("Unknown isolated development project.", nameof(projectName))
    };
}
