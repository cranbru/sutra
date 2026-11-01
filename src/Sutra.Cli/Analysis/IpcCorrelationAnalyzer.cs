using Sutra.Cli.Models;

namespace Sutra.Cli.Analysis;

public static class IpcCorrelationAnalyzer
{
    private static readonly TimeSpan ActivityWindow = TimeSpan.FromMinutes(15);
    private const int DistinctClientThreshold = 10;

    public static IReadOnlyList<PipeEndpoint> Enrich(IReadOnlyList<PipeEndpoint> endpoints,
        IReadOnlyList<SysmonPipeEvent> events)
    {
        var findingsByEndpoint = new Dictionary<string, List<RiskFinding>>(StringComparer.Ordinal);

        var sharedServices = endpoints.SelectMany(endpoint => (endpoint.ServiceNames ?? Array.Empty<string>())
                .Select(service => (Endpoint: endpoint, Service: service)))
            .GroupBy(item => item.Service, StringComparer.OrdinalIgnoreCase)
            .Where(group => group.Select(item => item.Endpoint.IpcMechanism).Distinct(StringComparer.OrdinalIgnoreCase).Count() > 1);
        foreach (var group in sharedServices)
        {
            var mechanisms = string.Join(", ", group.Select(item => item.Endpoint.IpcMechanism).Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(value => value));
            foreach (var item in group)
                Add(findingsByEndpoint, item.Endpoint.IpcMechanism, item.Endpoint.Name, new RiskFinding(
                    "Service registration spans IPC mechanisms",
                    RiskSeverity.Informational,
                    $"Service '{group.Key}' appears in registrations or endpoint context for multiple mechanisms: {mechanisms}. This is a correlation clue, not proof that the registrations share a runtime process or are exposed to the same clients.",
                    "Confirm each registration is expected and review its activation context and access controls."));
        }

        var endpointNames = new HashSet<string>(endpoints.Where(endpoint => endpoint.IpcMechanism == "NamedPipe")
            .Select(endpoint => endpoint.Name), StringComparer.OrdinalIgnoreCase);
        foreach (var group in events.Where(item => item.IsCorrelated && item.EventId == 18 && endpointNames.Contains(item.PipeName))
                     .GroupBy(item => item.PipeName, StringComparer.OrdinalIgnoreCase))
        {
            if (group.Count() == 0) continue;
            var latest = group.Max(item => item.TimeUtc);
            var clients = group.Where(item => item.TimeUtc >= latest - ActivityWindow)
                .Select(item => item.ProcessId?.ToString() ?? item.ProcessName)
                .Where(value => !string.IsNullOrWhiteSpace(value))
                .Distinct(StringComparer.OrdinalIgnoreCase).Count();
            if (clients < DistinctClientThreshold) continue;
            Add(findingsByEndpoint, "NamedPipe", group.Key, new RiskFinding(
                "High client diversity observed",
                RiskSeverity.Medium,
                $"Sysmon recorded {clients} distinct client processes connecting to this pipe within a 15-minute window. High client diversity can be expected for shared services; it is a review signal and does not prove malicious activity.",
                "Compare the client list with expected consumers and investigate unexpected callers or changes from the normal activity pattern."));
        }

        return endpoints.Select(endpoint => findingsByEndpoint.TryGetValue(EndpointKey(endpoint.IpcMechanism, endpoint.Name), out var additions)
            ? endpoint with { Findings = (endpoint.Findings ?? Array.Empty<RiskFinding>()).Concat(additions).ToArray() }
            : endpoint).ToArray();
    }

    private static void Add(IDictionary<string, List<RiskFinding>> findings,
        string mechanism, string endpointName, RiskFinding finding)
    {
        var key = EndpointKey(mechanism, endpointName);
        if (!findings.TryGetValue(key, out var list)) findings[key] = list = [];
        list.Add(finding);
    }

    private static string EndpointKey(string mechanism, string name) =>
        mechanism.ToUpperInvariant() + "\0" + name.ToUpperInvariant();
}
