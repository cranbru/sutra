namespace Sutra.Cli.Models;

public sealed record PipeEndpoint(
    string Name,
    string Path,
    string DiscoveryStatus,
    uint? ServerProcessId = null,
    string? ProcessName = null,
    string? ProcessUserSid = null,
    bool? ProcessIsElevated = null,
    IReadOnlyList<string>? ServiceNames = null,
    string? SecurityStatus = null,
    string? OwnerSid = null,
    string? DaclState = null,
    IReadOnlyList<PipeAce>? AccessEntries = null,
    IReadOnlyList<RiskFinding>? Findings = null,
    string? Error = null);

public sealed record PipeAce(string Type, string Sid, string Rights, string Flags);

public enum RiskSeverity { Critical, High, Medium, Low, Informational }

public sealed record RiskFinding(string Title, RiskSeverity Severity, string Explanation, string Recommendation);
