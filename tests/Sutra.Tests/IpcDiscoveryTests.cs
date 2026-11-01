using Sutra.Cli.Analysis;
using Sutra.Cli.Discovery;
using Sutra.Cli.Models;

namespace Sutra.Tests;

public sealed class IpcDiscoveryTests
{
    [Fact]
    public void CoordinatorKeepsOtherMechanismsWhenOneModuleFails()
    {
        var coordinator = new IpcDiscoveryCoordinator([
            new TestModule("RPC", throwOnDiscover: true),
            new TestModule("COM")
        ]);

        var results = coordinator.Discover(["all"]);

        Assert.Equal(2, results.Count);
        Assert.Equal("Unavailable", results[0].Coverage);
        Assert.NotNull(results[0].Error);
        Assert.Null(results[1].Error);
    }

    [Fact]
    public void CorrelationFindingsStayAttachedToTheirMechanismAndName()
    {
        var endpoints = new[]
        {
            new PipeEndpoint("Shared", "pipe", "Discovered", IpcMechanism: "NamedPipe"),
            new PipeEndpoint("Shared", "rpc", "Registered", ServiceNames: ["shared-service"], IpcMechanism: "RPC"),
            new PipeEndpoint("Class", "com", "Registered", ServiceNames: ["shared-service"], IpcMechanism: "COM")
        };

        var enriched = IpcCorrelationAnalyzer.Enrich(endpoints, Array.Empty<SysmonPipeEvent>());

        Assert.Empty(enriched[0].Findings ?? Array.Empty<RiskFinding>());
        Assert.Contains(enriched[1].Findings!, item => item.Title == "Service registration spans IPC mechanisms");
        Assert.Contains(enriched[2].Findings!, item => item.Title == "Service registration spans IPC mechanisms");
    }

    private sealed class TestModule(string mechanism, bool throwOnDiscover = false) : IIpcDiscoveryModule
    {
        public string Mechanism => mechanism;
        public DiscoveryResult Discover() => throwOnDiscover
            ? throw new InvalidOperationException("Unavailable in test")
            : new DiscoveryResult(Mechanism, Array.Empty<PipeEndpoint>());
    }
}
