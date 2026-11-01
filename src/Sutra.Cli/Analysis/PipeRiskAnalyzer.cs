using Sutra.Cli.Models;

namespace Sutra.Cli.Analysis;

public sealed class PipeRiskAnalyzer
{
    private const uint GenericAll = 0x10000000;
    private const uint GenericWrite = 0x40000000;
    private const uint WriteDac = 0x00040000;
    private const uint WriteOwner = 0x00080000;
    private const uint WriteData = 0x00000002;
    private const uint CreatePipeInstance = 0x00000004;
    private const uint GenericRead = 0x80000000;

    private static readonly HashSet<string> BroadPrincipals = new(StringComparer.OrdinalIgnoreCase)
    {
        "S-1-1-0",       // Everyone
        "S-1-5-11",      // Authenticated Users
        "S-1-5-32-545",  // Builtin Users
        "S-1-5-4",       // Interactive
        "S-1-5-7",       // Anonymous
        "S-1-5-113",     // Local account
        "S-1-5-32-546"   // Builtin Guests
    };

    public IReadOnlyList<RiskFinding> Analyze(PipeEndpoint endpoint)
    {
        if (endpoint.SecurityStatus != "Inspected" || endpoint.AccessEntries is null)
            return Array.Empty<RiskFinding>();

        var findings = new List<RiskFinding>();
        if (endpoint.DaclState is "Null DACL" or "DACL absent")
        {
            var elevated = endpoint.ProcessIsElevated == true
                || endpoint.ProcessUserSid is "S-1-5-18" or "S-1-5-19" or "S-1-5-20";
            findings.Add(new RiskFinding(
                "Pipe access is unrestricted by a DACL",
                elevated ? RiskSeverity.Critical : RiskSeverity.High,
                $"The security descriptor reports {endpoint.DaclState}. Windows does not use a DACL to restrict access in this state, so any caller that can reach the endpoint may be able to connect. The server protocol and actual impact still require review.",
                "Apply an explicit DACL that grants only the required client identities. Review the server protocol and test access using the intended client accounts."));
            return findings;
        }

        foreach (var ace in endpoint.AccessEntries)
        {
            if (!string.Equals(ace.Type, "Allow", StringComparison.OrdinalIgnoreCase)
                || !BroadPrincipals.Contains(ace.Sid)
                || !TryParseMask(ace.Rights, out var mask))
                continue;

            var elevatedServer = endpoint.ProcessIsElevated == true
                || endpoint.ProcessUserSid is "S-1-5-18" or "S-1-5-19" or "S-1-5-20";

            if ((mask & (GenericAll | WriteDac | WriteOwner)) != 0)
            {
                findings.Add(new RiskFinding(
                    "Broad principal can control the pipe",
                    elevatedServer ? RiskSeverity.High : RiskSeverity.Medium,
                    $"An allow ACE grants {ace.Rights} to {PrincipalName(ace.Sid)}. This can permit broad pipe access or changes to its security. Server privilege is {(endpoint.ProcessUserSid is null ? "unknown" : elevatedServer ? "elevated" : "not identified as elevated")}; the ACE alone does not prove an exploitable protocol or impact.",
                    "Restrict the ACE to the specific service identities and client groups that require access. Review the server protocol and validate effective access, including deny and inherited ACEs."));
            }
            else if ((mask & GenericWrite) != 0 || (mask & (WriteData | CreatePipeInstance)) == (WriteData | CreatePipeInstance))
            {
                findings.Add(new RiskFinding(
                    "Broad principal can write to the pipe",
                    elevatedServer ? RiskSeverity.High : RiskSeverity.Medium,
                    $"An allow ACE grants write-capable access to {PrincipalName(ace.Sid)}. Risk depends on what the server accepts and the server process context; the permission by itself does not establish code execution or privilege escalation.",
                    "Limit write access to trusted clients and review how the server validates requests, impersonates clients, and handles privileged operations."));
            }
            else if ((mask & GenericRead) != 0)
            {
                findings.Add(new RiskFinding(
                    "Broad principal can read from the pipe",
                    RiskSeverity.Informational,
                    $"An allow ACE grants generic read access to {PrincipalName(ace.Sid)}. This only becomes a confidentiality issue if the server returns sensitive data to an unauthorized client.",
                    "Confirm that the pipe protocol returns only data the allowed clients are authorized to receive."));
            }
        }

        if (findings.Count == 0)
            findings.Add(new RiskFinding("No broad write permission identified", RiskSeverity.Informational,
                "No allow ACE for the recognized broad local principals grants generic write, generic all, write data plus pipe-instance creation, or security descriptor modification. This is not a complete effective-access evaluation.",
                "Review the complete DACL and server protocol when validating this endpoint."));

        return findings;
    }

    private static bool TryParseMask(string value, out uint mask)
    {
        var normalized = value.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? value[2..] : value;
        return uint.TryParse(normalized, System.Globalization.NumberStyles.HexNumber,
            System.Globalization.CultureInfo.InvariantCulture, out mask);
    }

    private static string PrincipalName(string sid) => sid switch
    {
        "S-1-1-0" => "Everyone",
        "S-1-5-11" => "Authenticated Users",
        "S-1-5-32-545" => "Builtin Users",
        "S-1-5-4" => "Interactive users",
        "S-1-5-7" => "Anonymous users",
        "S-1-5-113" => "local accounts",
        "S-1-5-32-546" => "Builtin Guests",
        _ => sid
    };
}
