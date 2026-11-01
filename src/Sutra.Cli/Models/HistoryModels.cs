namespace Sutra.Cli.Models;

public sealed record ScanSnapshot(string Id, DateTimeOffset CapturedUtc, int EndpointCount);

public enum EndpointChangeKind { Added, Removed, Modified }

public sealed record EndpointChange(EndpointChangeKind Kind, string EndpointName);

public sealed record SnapshotSaveResult(ScanSnapshot Snapshot, IReadOnlyList<EndpointChange> Changes);

public sealed record SysmonPipeEvent(
    string Channel,
    long RecordId,
    int EventId,
    DateTimeOffset TimeUtc,
    uint? ProcessId,
    string? ProcessName,
    string PipeName,
    string EventType,
    bool IsCorrelated);
