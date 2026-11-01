namespace Sutra.Cli.Models;

public sealed record SensitiveHandleFinding(
    int HolderProcessId,
    string HolderProcessName,
    string ObjectCategory,
    string Target,
    int HandleCount,
    uint GrantedAccess,
    string AccessRights = "");

public sealed record SensitiveHandleScanResult(
    int SystemHandleCount,
    int CandidateHandleCount,
    int InaccessibleProcessCount,
    IReadOnlyList<SensitiveHandleFinding> Findings,
    string Coverage,
    string? Error = null,
    int FileHandleCandidateCount = 0,
    int FileNameQueryCount = 0,
    int FileNameQueryTimeoutCount = 0);
