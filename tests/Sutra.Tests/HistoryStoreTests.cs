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

    [Fact]
    public void SnapshotStoresSensitiveHandleFindingsForLaterReports()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"sutra-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        try
        {
            var store = new SqliteHistoryStore(Path.Combine(directory, "history.db"));
            var handles = new SensitiveHandleScanResult(100, 25, 1,
                [new SensitiveHandleFinding(42, "sample.exe", "Security token", "Access token", 2, 0x0008)],
                "Partial coverage");

            var saved = store.SaveSnapshot([Endpoint("alpha")], handles);

            var loaded = store.GetSnapshotSensitiveHandles(saved.Snapshot.Id);
            Assert.NotNull(loaded);
            Assert.Equal(handles.SystemHandleCount, loaded.SystemHandleCount);
            Assert.Equal(handles.CandidateHandleCount, loaded.CandidateHandleCount);
            Assert.Equal(handles.InaccessibleProcessCount, loaded.InaccessibleProcessCount);
            Assert.Equal(handles.Findings, loaded.Findings);
            Assert.Equal(handles.Coverage, loaded.Coverage);
        }
        finally { SqliteConnection.ClearAllPools(); Directory.Delete(directory, recursive: true); }
    }

    [Fact]
    public void ExistingSnapshotDatabaseGainsSensitiveHandleStorage()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"sutra-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, "history.db");
        try
        {
            using (var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = path }.ToString()))
            {
                connection.Open();
                using var command = connection.CreateCommand();
                command.CommandText = """
                    CREATE TABLE Snapshots (Id TEXT PRIMARY KEY, CapturedUtc TEXT NOT NULL, EndpointCount INTEGER NOT NULL);
                    CREATE TABLE SnapshotEndpoints (
                        SnapshotId TEXT NOT NULL REFERENCES Snapshots(Id) ON DELETE CASCADE,
                        Name TEXT NOT NULL COLLATE NOCASE,
                        Fingerprint TEXT NOT NULL,
                        EndpointJson TEXT NOT NULL,
                        PRIMARY KEY (SnapshotId, Name)
                    );
                    INSERT INTO Snapshots (Id, CapturedUtc, EndpointCount) VALUES ('legacy', '2026-01-01T00:00:00.0000000Z', 1);
                    INSERT INTO SnapshotEndpoints (SnapshotId, Name, Fingerprint, EndpointJson)
                    VALUES ('legacy', 'old-pipe', 'legacy-fingerprint', '{"Name":"old-pipe","Path":"p","DiscoveryStatus":"Discovered"}');
                    """;
                command.ExecuteNonQuery();
            }

            var store = new SqliteHistoryStore(path);
            var handles = new SensitiveHandleScanResult(50, 10, 0, Array.Empty<SensitiveHandleFinding>(), "Complete");
            Assert.Equal("old-pipe", Assert.Single(store.GetSnapshotEndpoints("legacy")).Name);
            var saved = store.SaveSnapshot([Endpoint("alpha"), new PipeEndpoint("alpha", "rpc", "Registered", IpcMechanism: "RPC")], handles);

            Assert.Equal(handles.SystemHandleCount, store.GetSnapshotSensitiveHandles(saved.Snapshot.Id)!.SystemHandleCount);
            Assert.Equal(2, store.GetSnapshotEndpoints(saved.Snapshot.Id).Count);
        }
        finally { SqliteConnection.ClearAllPools(); Directory.Delete(directory, recursive: true); }
    }

    private static PipeEndpoint Endpoint(string name, string? securityStatus = null) =>
        new(name, $@"\\.\pipe\{name}", "Discovered", SecurityStatus: securityStatus);
}
