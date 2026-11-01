namespace Sutra.Cli.Models;

public sealed record PipeEndpoint(
    string Name,
    string Path,
    string DiscoveryStatus,
    uint? ServerProcessId = null,
    string? ProcessName = null,
    string? SecurityStatus = null,
    string? OwnerSid = null,
    IReadOnlyList<PipeAce>? AccessEntries = null,
    string? Error = null);

public sealed record PipeAce(string Type, string Sid, string Rights, string Flags);
