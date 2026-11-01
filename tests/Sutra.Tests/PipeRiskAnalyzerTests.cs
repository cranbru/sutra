using Sutra.Cli.Analysis;
using Sutra.Cli.Models;

namespace Sutra.Tests;

public sealed class PipeRiskAnalyzerTests
{
    private readonly PipeRiskAnalyzer _analyzer = new();

    [Fact]
    public void BroadReadPermissionIsInformational()
    {
        var endpoint = InspectedEndpoint(new PipeAce("Allow", "S-1-1-0", "0x80000000", "None"));

        var finding = Assert.Single(_analyzer.Analyze(endpoint));

        Assert.Equal(RiskSeverity.Informational, finding.Severity);
        Assert.Contains("sensitive data", finding.Explanation);
    }

    [Fact]
    public void BroadWriteToElevatedServiceIsHighRisk()
    {
        var endpoint = InspectedEndpoint(new PipeAce("Allow", "S-1-5-11", "0x40000000", "None"))
            with { ProcessIsElevated = true, ProcessName = "example-service", ServiceNames = ["ExampleService"] };

        var finding = Assert.Single(_analyzer.Analyze(endpoint));

        Assert.Equal(RiskSeverity.High, finding.Severity);
        Assert.Contains("server process context", finding.Explanation);
        Assert.Contains("trusted clients", finding.Recommendation);
    }

    [Fact]
    public void BroadWriteWithoutServerContextIsMediumRisk()
    {
        var endpoint = InspectedEndpoint(new PipeAce("Allow", "S-1-5-32-545", "0x40000000", "None"));

        var finding = Assert.Single(_analyzer.Analyze(endpoint));

        Assert.Equal(RiskSeverity.Medium, finding.Severity);
        Assert.Contains("does not establish code execution", finding.Explanation);
    }

    [Fact]
    public void DenyAceDoesNotCreateAllowFinding()
    {
        var endpoint = InspectedEndpoint(new PipeAce("Deny", "S-1-1-0", "0x10000000", "None"));

        var finding = Assert.Single(_analyzer.Analyze(endpoint));

        Assert.Equal(RiskSeverity.Informational, finding.Severity);
        Assert.Contains("No broad write permission", finding.Title);
    }

    [Fact]
    public void UninspectedEndpointProducesNoFindings()
    {
        var endpoint = new PipeEndpoint("Example", @"\\.\pipe\Example", "Discovered");

        Assert.Empty(_analyzer.Analyze(endpoint));
    }

    [Theory]
    [InlineData("Null DACL", false, RiskSeverity.High)]
    [InlineData("DACL absent", true, RiskSeverity.Critical)]
    public void UnrestrictedDaclIsScoredUsingKnownServerContext(string daclState, bool elevated, RiskSeverity expected)
    {
        var endpoint = InspectedEndpoint() with { DaclState = daclState, ProcessIsElevated = elevated };

        var finding = Assert.Single(_analyzer.Analyze(endpoint));

        Assert.Equal(expected, finding.Severity);
        Assert.Contains("explicit DACL", finding.Recommendation);
    }

    private static PipeEndpoint InspectedEndpoint(params PipeAce[] aces) =>
        new("Example", @"\\.\pipe\Example", "Discovered", SecurityStatus: "Inspected", AccessEntries: aces);
}
