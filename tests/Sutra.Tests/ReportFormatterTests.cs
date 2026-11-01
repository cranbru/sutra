using Sutra.Cli.Models;
using Sutra.Cli.Reporting;

namespace Sutra.Tests;

public sealed class ReportFormatterTests
{
    [Fact]
    public void FiltersBySearchScopeProcessServiceElevationAndSeverity()
    {
        var endpoints = new[]
        {
            Endpoint("AlphaPipe", process: "AlphaService", pid: 12, elevated: true, service: "AlphaSvc", severity: RiskSeverity.High),
            Endpoint("BetaPipe", process: "BetaWorker", pid: 5, elevated: false, service: "BetaSvc", severity: RiskSeverity.Low)
        };
        var filter = new EndpointReportFilter(
            ScopePrefix: "alpha", Search: "Alpha", Process: "service", Service: "svc", Elevated: true,
            Severity: RiskSeverity.High, Sort: ReportSort.Pid, Order: ReportOrder.Desc, Limit: 20);

        var selected = ScanReportFormatter.FilterAndSort(endpoints, filter);

        Assert.Equal("AlphaPipe", Assert.Single(selected).Name);
    }

    [Fact]
    public void SortsByPidAndAppliesLimit()
    {
        var endpoints = new[] { Endpoint("Alpha", pid: 30), Endpoint("Beta", pid: 10), Endpoint("Gamma", pid: 20) };

        var selected = ScanReportFormatter.FilterAndSort(endpoints, new EndpointReportFilter(Sort: ReportSort.Pid, Limit: 2));

        Assert.Equal(["Beta", "Gamma"], selected.Select(endpoint => endpoint.Name));
    }

    [Fact]
    public void DescendingSeverityPutsCriticalFindingFirst()
    {
        var endpoints = new[]
        {
            Endpoint("Low", severity: RiskSeverity.Low),
            Endpoint("Critical", severity: RiskSeverity.Critical),
            Endpoint("Medium", severity: RiskSeverity.Medium)
        };

        var selected = ScanReportFormatter.FilterAndSort(endpoints,
            new EndpointReportFilter(Sort: ReportSort.Severity, Order: ReportOrder.Desc));

        Assert.Equal(["Critical", "Medium", "Low"], selected.Select(endpoint => endpoint.Name));
    }

    [Fact]
    public void JsonContainsSummaryAndStructuredFindings()
    {
        var endpoint = Endpoint("ServicePipe", process: "svc", pid: 77, severity: RiskSeverity.Medium);
        var report = ScanReportFormatter.CreateDocument([endpoint], "test scan");

        var json = ScanReportFormatter.ToJson(report);

        Assert.Contains("\"EndpointCount\": 1", json);
        Assert.Contains("\"Medium\": 1", json);
        Assert.Contains("\"Severity\": \"Medium\"", json);
    }

    [Fact]
    public void DotGraphLinksServicesServerProcessesAndObservedClients()
    {
        var endpoint = Endpoint("Pipe\"A", process: "server.exe", pid: 77, service: "ExampleService");
        var observedEvent = new SysmonPipeEvent("Sysmon", 10, 18, DateTimeOffset.UtcNow, 99, "client.exe", "Pipe\"A", "Pipe Connected", true);

        var dot = ScanReportFormatter.ToDot([endpoint], [observedEvent]);

        Assert.Contains("digraph SUTRA", dot);
        Assert.Contains("serves", dot);
        Assert.Contains("hosted by", dot);
        Assert.Contains("Pipe Connected", dot);
        Assert.Contains("Pipe\\\"A", dot);
    }

    [Fact]
    public void AsciiGraphUsesPlainTextRelationshipBranches()
    {
        var endpoint = Endpoint("Example", process: "server", pid: 4);

        var graph = ScanReportFormatter.ToAscii([endpoint]);

        Assert.Contains("`- PIPE Example", graph);
        Assert.Contains("`- SERVER server (PID 4", graph);
    }

    private static PipeEndpoint Endpoint(string name, string? process = null, uint? pid = null, bool? elevated = null,
        string? service = null, RiskSeverity? severity = null)
    {
        var findings = severity is null ? null : new[]
        {
            new RiskFinding("Test finding", severity.Value, "Explanation", "Recommendation")
        };
        return new PipeEndpoint(name, $@"\\.\pipe\{name}", "Discovered", pid, process,
            ProcessUserSid: "S-1-5-18", ProcessIsElevated: elevated,
            ServiceNames: service is null ? Array.Empty<string>() : [service],
            SecurityStatus: "Inspected", Findings: findings);
    }
}
