using Sutra.Cli.Models;

namespace Sutra.Cli.Reporting;

public enum ReportFormat { Table, Ascii, Json, Dot }
public enum ReportSort { Name, Pid, Severity }
public enum ReportOrder { Asc, Desc }

public sealed record EndpointReportFilter(
    string? ScopePrefix = null,
    string? Mechanism = null,
    string? Search = null,
    string? Process = null,
    string? Service = null,
    bool? Elevated = null,
    RiskSeverity? Severity = null,
    ReportSort Sort = ReportSort.Name,
    ReportOrder Order = ReportOrder.Asc,
    int Limit = 100_000);

public sealed record ScanReportDocument(
    string Application,
    DateTimeOffset GeneratedUtc,
    string Source,
    int EndpointCount,
    IReadOnlyDictionary<string, int> SeverityCounts,
    IReadOnlyList<SysmonPipeEvent> ObservedEvents,
    IReadOnlyList<PipeEndpoint> Endpoints,
    IReadOnlyDictionary<string, int>? MechanismCounts = null,
    IReadOnlyList<ModuleDiscoverySummary>? DiscoveryModules = null,
    Sutra.Cli.Models.SensitiveHandleScanResult? SensitiveHandles = null);

public sealed record ModuleDiscoverySummary(string Mechanism, int EndpointCount, string? Error, string Coverage);
