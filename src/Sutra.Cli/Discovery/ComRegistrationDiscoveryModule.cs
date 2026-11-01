using System.Security;
using System.Runtime.Versioning;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using Sutra.Cli.Models;

namespace Sutra.Cli.Discovery;

[SupportedOSPlatform("windows")]
public sealed class ComRegistrationDiscoveryModule : IIpcDiscoveryModule
{
    private static readonly Regex ExecutablePattern = new("^\\\"(?<quoted>[^\\\"]+\\.exe)\\\"|^(?<plain>.+?\\.exe)(?:\\s|$)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    public string Mechanism => "COM";

    public DiscoveryResult Discover()
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("COM registration discovery requires Windows.");
        using var classes = Registry.ClassesRoot.OpenSubKey("CLSID", writable: false)
            ?? throw new IOException("The merged CLSID registry view is unavailable.");
        var endpoints = new List<PipeEndpoint>();
        foreach (var clsid in classes.GetSubKeyNames())
        {
            try
            {
                using var classKey = classes.OpenSubKey(clsid, writable: false);
                if (classKey is null) continue;
                var displayName = classKey.GetValue(null) as string;
                var appId = classKey.GetValue("AppID") as string;
                var localServer = ReadDefault(classKey, "LocalServer32");
                var serviceName = ReadAppIdValue(appId, "LocalService");
                var runAs = ReadAppIdValue(appId, "RunAs");
                if (string.IsNullOrWhiteSpace(localServer) && string.IsNullOrWhiteSpace(serviceName)) continue;

                var executable = ParseExecutable(localServer);
                var services = string.IsNullOrWhiteSpace(serviceName) ? Array.Empty<string>() : [serviceName];
                var details = string.Join("; ", new[]
                {
                    string.IsNullOrWhiteSpace(displayName) ? null : $"Class={displayName}",
                    string.IsNullOrWhiteSpace(appId) ? null : $"AppID={appId}",
                    string.IsNullOrWhiteSpace(localServer) ? null : $"LocalServer32={localServer}",
                    string.IsNullOrWhiteSpace(serviceName) ? null : $"LocalService={serviceName}",
                    string.IsNullOrWhiteSpace(runAs) ? null : $"RunAs={runAs}"
                }.Where(value => value is not null));
                endpoints.Add(new PipeEndpoint(
                    $"CLSID {{{clsid}}}",
                    $@"HKCR\CLSID\{clsid}",
                    "Registered",
                    ProcessName: executable is null ? null : Path.GetFileNameWithoutExtension(executable),
                    ServiceNames: services,
                    IpcMechanism: Mechanism,
                    DiscoveryDetails: details));
            }
            catch (Exception ex) when (ex is IOException or SecurityException or UnauthorizedAccessException or ArgumentException)
            {
                // Individual class registrations can be unreadable or change while enumerating.
            }
        }
        return new DiscoveryResult(Mechanism, endpoints.OrderBy(item => item.Name, StringComparer.OrdinalIgnoreCase).ToArray(),
            Coverage: "Out-of-process COM registrations; not proof of a running server");
    }

    private static string? ReadDefault(RegistryKey key, string subKeyName)
    {
        using var subKey = key.OpenSubKey(subKeyName, writable: false);
        return subKey?.GetValue(null) as string;
    }

    private static string? ReadAppIdValue(string? appId, string valueName)
    {
        if (string.IsNullOrWhiteSpace(appId)) return null;
        using var key = Registry.ClassesRoot.OpenSubKey($@"AppID\{appId}", writable: false);
        return key?.GetValue(valueName) as string;
    }

    private static string? ParseExecutable(string? command)
    {
        if (string.IsNullOrWhiteSpace(command)) return null;
        var match = ExecutablePattern.Match(Environment.ExpandEnvironmentVariables(command.Trim()));
        return match.Success ? match.Groups["quoted"].Success ? match.Groups["quoted"].Value : match.Groups["plain"].Value : null;
    }
}
