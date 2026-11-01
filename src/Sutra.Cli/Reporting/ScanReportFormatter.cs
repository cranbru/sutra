using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Sutra.Cli.Correlation;
using Sutra.Cli.Discovery;
using Sutra.Cli.Models;

namespace Sutra.Cli.Reporting;

public static class ScanReportFormatter
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() }
    };

    public static IReadOnlyList<PipeEndpoint> FilterAndSort(IReadOnlyList<PipeEndpoint> endpoints, EndpointReportFilter filter)
    {
        IEnumerable<PipeEndpoint> query = endpoints;
        if (!string.IsNullOrWhiteSpace(filter.ScopePrefix))
            query = query.Where(endpoint => endpoint.Name.StartsWith(filter.ScopePrefix, StringComparison.OrdinalIgnoreCase));
        if (!string.IsNullOrWhiteSpace(filter.Mechanism))
            query = query.Where(endpoint => endpoint.IpcMechanism.Equals(filter.Mechanism, StringComparison.OrdinalIgnoreCase));
        if (!string.IsNullOrWhiteSpace(filter.Search))
            query = query.Where(endpoint => Contains(endpoint.Name, filter.Search)
                || Contains(endpoint.ProcessName, filter.Search)
                || (endpoint.ServiceNames?.Any(service => Contains(service, filter.Search)) ?? false));
        if (!string.IsNullOrWhiteSpace(filter.Process))
            query = query.Where(endpoint => Contains(endpoint.ProcessName, filter.Process));
        if (!string.IsNullOrWhiteSpace(filter.Service))
            query = query.Where(endpoint => endpoint.ServiceNames?.Any(service => Contains(service, filter.Service)) ?? false);
        if (filter.Elevated.HasValue)
            query = query.Where(endpoint => endpoint.ProcessIsElevated == filter.Elevated.Value);
        if (filter.Severity.HasValue)
            query = query.Where(endpoint => endpoint.Findings?.Any(finding => finding.Severity == filter.Severity.Value) ?? false);

        query = filter.Sort switch
        {
            ReportSort.Pid => filter.Order == ReportOrder.Asc
                ? query.OrderBy(endpoint => endpoint.ServerProcessId ?? uint.MaxValue).ThenBy(endpoint => endpoint.Name, StringComparer.OrdinalIgnoreCase)
                : query.OrderByDescending(endpoint => endpoint.ServerProcessId ?? 0).ThenBy(endpoint => endpoint.Name, StringComparer.OrdinalIgnoreCase),
            ReportSort.Severity => filter.Order == ReportOrder.Asc
                ? query.OrderBy(endpoint => SeverityRank(endpoint.Findings)).ThenBy(endpoint => endpoint.Name, StringComparer.OrdinalIgnoreCase)
                : query.OrderByDescending(endpoint => SeverityRank(endpoint.Findings)).ThenBy(endpoint => endpoint.Name, StringComparer.OrdinalIgnoreCase),
            _ => filter.Order == ReportOrder.Asc
                ? query.OrderBy(endpoint => endpoint.Name, StringComparer.OrdinalIgnoreCase)
                : query.OrderByDescending(endpoint => endpoint.Name, StringComparer.OrdinalIgnoreCase)
        };
        return query.Take(Math.Clamp(filter.Limit, 1, 100_000)).ToArray();
    }

    public static ScanReportDocument CreateDocument(IReadOnlyList<PipeEndpoint> endpoints, string source,
        IReadOnlyList<SysmonPipeEvent>? events = null, IReadOnlyList<DiscoveryResult>? discovery = null)
    {
        var counts = Enum.GetValues<RiskSeverity>().ToDictionary(
            severity => severity.ToString(),
            severity => endpoints.Sum(endpoint => endpoint.Findings?.Count(finding => finding.Severity == severity) ?? 0));
        var mechanisms = endpoints.GroupBy(endpoint => endpoint.IpcMechanism, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(group => group.Key, group => group.Count(), StringComparer.OrdinalIgnoreCase);
        var moduleSummaries = discovery?.Select(item => new ModuleDiscoverySummary(item.Mechanism, item.Endpoints.Count, item.Error, item.Coverage));
        return new ScanReportDocument("SUTRA", DateTimeOffset.UtcNow, source, endpoints.Count, counts,
            events ?? Array.Empty<SysmonPipeEvent>(), endpoints, mechanisms, moduleSummaries?.ToArray());
    }

    public static string ToJson(ScanReportDocument report) => JsonSerializer.Serialize(report, JsonOptions);

    public static string ToPlainText(ScanReportDocument report)
    {
        var output = new StringBuilder();
        output.AppendLine($"SUTRA scan report · {report.GeneratedUtc:O}");
        output.AppendLine($"Source: {report.Source}");
        output.AppendLine($"Endpoints: {report.EndpointCount}");
        output.AppendLine("Mechanisms: " + string.Join("  ", (report.MechanismCounts ?? new Dictionary<string, int>()).Select(item => $"{item.Key}={item.Value}")));
        output.AppendLine("Risk findings: " + string.Join("  ", report.SeverityCounts.Select(item => $"{item.Key}={item.Value}")));
        output.AppendLine();
        output.AppendLine("MECHANISM\tNAME\tPID\tPROCESS\tSERVICES\tDETAILS\tFINDINGS");
        foreach (var endpoint in report.Endpoints)
        {
            var findings = endpoint.Findings is { Count: > 0 }
                ? string.Join(", ", endpoint.Findings.Select(finding => $"{finding.Severity}: {finding.Title}"))
                : "—";
            output.AppendLine(string.Join('\t', Clean(endpoint.IpcMechanism), Clean(endpoint.Name), endpoint.ServerProcessId?.ToString() ?? "—",
                Clean(endpoint.ProcessName ?? "—"), Clean(endpoint.ServiceNames is { Count: > 0 } ? string.Join(", ", endpoint.ServiceNames) : "—"),
                Clean(endpoint.DiscoveryDetails ?? "—"), Clean(findings)));
        }
        return output.ToString();
    }

    public static string ToAscii(IReadOnlyList<PipeEndpoint> endpoints, IReadOnlyList<SysmonPipeEvent>? observedEvents = null)
    {
        var output = new StringBuilder("SUTRA IPC RELATIONSHIPS\n");
        for (var i = 0; i < endpoints.Count; i++)
        {
            var endpoint = endpoints[i];
            var lastEndpoint = i == endpoints.Count - 1;
            var branch = lastEndpoint ? "`-" : "+-";
            output.AppendLine($"{branch} {Clean(endpoint.IpcMechanism.ToUpperInvariant())} {Clean(endpoint.Name)}");
            var childPrefix = lastEndpoint ? "   " : "|  ";
            var relations = new List<string>();
            if (endpoint.ServerProcessId.HasValue || endpoint.ProcessName is not null)
                relations.Add($"{(endpoint.DiscoveryStatus == "Registered" ? "REGISTERED SERVER" : "SERVER")} {Clean(endpoint.ProcessName ?? "process")} (PID {endpoint.ServerProcessId?.ToString() ?? "—"}, {Clean(endpoint.ProcessUserSid ?? "identity unknown")})");
            relations.AddRange((endpoint.ServiceNames ?? Array.Empty<string>()).Select(service => $"SERVICE {Clean(service)}"));
            if (!string.IsNullOrWhiteSpace(endpoint.DiscoveryDetails))
                relations.Add($"DETAILS {Clean(endpoint.DiscoveryDetails)}");
            relations.AddRange((observedEvents ?? Array.Empty<SysmonPipeEvent>())
                .Where(item => endpoint.IpcMechanism == "NamedPipe" && item.IsCorrelated
                    && string.Equals(item.PipeName, endpoint.Name, StringComparison.OrdinalIgnoreCase))
                .Select(item => $"OBSERVED {Clean(item.EventType)} {Clean(item.ProcessName ?? "process")} (PID {item.ProcessId?.ToString() ?? "—"})"));
            for (var relationIndex = 0; relationIndex < relations.Count; relationIndex++)
                output.AppendLine($"{childPrefix}{(relationIndex == relations.Count - 1 ? "`-" : "+-")} {relations[relationIndex]}");
        }
        return output.ToString();
    }

    public static string ToDot(IReadOnlyList<PipeEndpoint> endpoints, IReadOnlyList<SysmonPipeEvent>? observedEvents = null)
    {
        var output = new StringBuilder();
        output.AppendLine("digraph SUTRA {");
        output.AppendLine("  rankdir=LR;");
        output.AppendLine("  graph [bgcolor=\"transparent\", fontname=\"Segoe UI\"];");
        output.AppendLine("  node [fontname=\"Segoe UI\", style=\"rounded,filled\", color=\"#36546D\", fillcolor=\"#142536\", fontcolor=\"#E7F1FA\"];");
        output.AppendLine("  edge [fontname=\"Segoe UI\", color=\"#7194B4\", fontcolor=\"#B8CBE0\"];");

        var endpointNames = new HashSet<string>(endpoints.Where(endpoint => endpoint.IpcMechanism == "NamedPipe")
            .Select(endpoint => endpoint.Name), StringComparer.OrdinalIgnoreCase);
        foreach (var endpoint in endpoints)
        {
            var ipcId = NodeId("ipc", endpoint.IpcMechanism + ":" + endpoint.Name);
            var ipcLabel = endpoint.IpcMechanism.ToUpperInvariant() + "\n" + endpoint.Name;
            if (!string.IsNullOrWhiteSpace(endpoint.DiscoveryDetails)) ipcLabel += "\n" + endpoint.DiscoveryDetails;
            output.AppendLine($"  {ipcId} [shape=box, label=\"{EscapeDot(ipcLabel)}\", fillcolor=\"#11364A\"];");
            var processId = endpoint.ServerProcessId.HasValue
                ? NodeId("process", endpoint.ServerProcessId.Value.ToString())
                : endpoint.ProcessName is not null ? NodeId("process", endpoint.ProcessName) : null;
            if (processId is not null)
            {
                var processLabel = endpoint.ServerProcessId.HasValue
                    ? $"{endpoint.ProcessName ?? "Process"}\nPID {endpoint.ServerProcessId}\n{endpoint.ProcessUserSid ?? "user unknown"}"
                    : endpoint.ProcessName!;
                output.AppendLine($"  {processId} [shape=ellipse, label=\"{EscapeDot(processLabel)}\", fillcolor=\"#23314B\"];");
                var processEdge = endpoint.DiscoveryStatus == "Registered" ? "registered server" : "serves";
                output.AppendLine($"  {processId} -> {ipcId} [label=\"{processEdge}\"];");
            }
            foreach (var service in endpoint.ServiceNames ?? Array.Empty<string>())
            {
                var serviceId = NodeId("service", service);
                output.AppendLine($"  {serviceId} [shape=component, label=\"{EscapeDot(service)}\", fillcolor=\"#30264B\"];");
                if (processId is not null) output.AppendLine($"  {serviceId} -> {processId} [label=\"hosted by\"];");
            }
        }

        foreach (var item in observedEvents ?? Array.Empty<SysmonPipeEvent>())
        {
            if (!endpointNames.Contains(item.PipeName)) continue;
            var pipeId = NodeId("ipc", "NamedPipe:" + item.PipeName);
            if (!item.ProcessId.HasValue && item.ProcessName is null) continue;
            var clientKey = item.ProcessId?.ToString() ?? item.ProcessName!;
            var processId = NodeId("process", clientKey);
            var label = item.ProcessId.HasValue ? $"{item.ProcessName ?? "Process"}\nPID {item.ProcessId}" : item.ProcessName!;
            output.AppendLine($"  {processId} [shape=ellipse, label=\"{EscapeDot(label)}\", fillcolor=\"#23314B\"];");
            output.AppendLine($"  {processId} -> {pipeId} [style=dashed, label=\"{EscapeDot(item.EventType)}\"];");
        }
        output.AppendLine("}");
        return output.ToString();
    }

    public static string NodeId(string kind, string value)
    {
        var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value.ToUpperInvariant())))[..16].ToLowerInvariant();
        return $"{kind}_{hash}";
    }

    private static int SeverityRank(IReadOnlyList<RiskFinding>? findings) => findings?.Count > 0
        ? findings.Min(finding => finding.Severity switch
        {
            RiskSeverity.Critical => 5,
            RiskSeverity.High => 4,
            RiskSeverity.Medium => 3,
            RiskSeverity.Low => 2,
            _ => 1
        })
        : 0;

    private static bool Contains(string? value, string search) =>
        value?.Contains(search, StringComparison.OrdinalIgnoreCase) ?? false;

    private static string Clean(string value) => value.Replace('\t', ' ').Replace('\r', ' ').Replace('\n', ' ');

    private static string EscapeDot(string value) => value.Replace("\\", "\\\\", StringComparison.Ordinal)
        .Replace("\"", "\\\"", StringComparison.Ordinal).Replace("\r", string.Empty, StringComparison.Ordinal)
        .Replace("\n", "\\n", StringComparison.Ordinal);
}
