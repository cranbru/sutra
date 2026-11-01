using Sutra.Cli.Models;
using Sutra.Cli.Storage;
using Microsoft.Data.Sqlite;

namespace Sutra.Tests;

public sealed class HistoryStoreTests
{
    [Fact]
    public void SnapshotsDetectAddedRemovedAndModifiedEndpoints()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"sutra-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        try
        {
            var store = new SqliteHistoryStore(Path.Combine(directory, "history.db"));
            var baseline = store.SaveSnapshot([Endpoint("alpha"), Endpoint("beta")]);

            var current = store.SaveSnapshot([Endpoint("alpha", "Inspected"), Endpoint("gamma")]);

            Assert.Equal(2, store.GetRecentSnapshots().Count);
            Assert.Equal(2, baseline.Changes.Count);
            Assert.Contains(current.Changes, change => change is { Kind: EndpointChangeKind.Modified, EndpointName: "alpha" });
            Assert.Contains(current.Changes, change => change is { Kind: EndpointChangeKind.Added, EndpointName: "gamma" });
            Assert.Contains(current.Changes, change => change is { Kind: EndpointChangeKind.Removed, EndpointName: "beta" });
            Assert.Equal(current.Changes, store.GetLatestChanges());
        }
        finally { SqliteConnection.ClearAllPools(); Directory.Delete(directory, recursive: true); }
    }

    [Fact]
    public void SysmonEventsAreDeduplicatedByChannelAndRecordId()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"sutra-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        try
        {
            var store = new SqliteHistoryStore(Path.Combine(directory, "history.db"));
            var item = new SysmonPipeEvent("Sysmon/Operational", 42, 17, DateTimeOffset.UtcNow,
                1234, "service.exe", "sample", "Pipe Created", true);

            Assert.Equal(1, store.SaveEvents([item]));
            Assert.Equal(0, store.SaveEvents([item]));
            Assert.Equal(item with { TimeUtc = item.TimeUtc.ToUniversalTime() }, Assert.Single(store.GetRecentEvents()));
        }
        finally { SqliteConnection.ClearAllPools(); Directory.Delete(directory, recursive: true); }
    }

    private static PipeEndpoint Endpoint(string name, string? securityStatus = null) =>
        new(name, $@"\\.\pipe\{name}", "Discovered", SecurityStatus: securityStatus);
}
