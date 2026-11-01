using System.IO.Pipes;
using Sutra.Cli.Models;
using Sutra.Cli.Native;

namespace Sutra.Tests;

public sealed class PipeSecurityInspectorTests
{
    [Fact]
    public async Task ReadsSecurityAndServerContextFromOwnedTestPipe()
    {
        if (!OperatingSystem.IsWindows()) return;

        var name = $"sutra-test-{Guid.NewGuid():N}";
        using var server = new NamedPipeServerStream(name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
        var waiting = server.WaitForConnectionAsync();
        var endpoint = new PipeEndpoint(name, $@"\\.\pipe\{name}", "Discovered");

        var inspected = new PipeSecurityInspector().Inspect(endpoint);

        await waiting.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.True(inspected.SecurityStatus == "Inspected", inspected.Error);
        Assert.NotNull(inspected.OwnerSid);
        Assert.NotNull(inspected.AccessEntries);
        Assert.Equal((uint)Environment.ProcessId, inspected.ServerProcessId);
        Assert.NotNull(inspected.ProcessName);
        Assert.NotNull(inspected.ProcessUserSid);
    }
}
