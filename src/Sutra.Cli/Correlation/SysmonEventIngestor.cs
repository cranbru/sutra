using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.Runtime.Versioning;
using System.Xml.Linq;
using Sutra.Cli.Models;

namespace Sutra.Cli.Correlation;

public sealed class SysmonEventIngestor
{
    public const string Channel = "Microsoft-Windows-Sysmon/Operational";
    private const string Query = "*[System[(EventID=17 or EventID=18)]]";

    [SupportedOSPlatform("windows")]
    public IReadOnlyList<SysmonPipeEvent> ReadSince(DateTimeOffset sinceUtc, IReadOnlySet<string> activePipes, int limit = 10_000)
    {
        var activeNames = new HashSet<string>(activePipes.Select(PipeNameNormalizer.Normalize), StringComparer.OrdinalIgnoreCase);
        var query = new EventLogQuery(Channel, PathType.LogName, Query) { ReverseDirection = true };
        using var reader = new EventLogReader(query);
        var results = new List<SysmonPipeEvent>();
        for (var count = 0; count < limit; count++)
        {
            using var record = reader.ReadEvent();
            if (record is null) break;
            if (record.TimeCreated is not { } localTime || record.RecordId is not { } recordId) continue;
            var timeUtc = new DateTimeOffset(localTime.ToUniversalTime());
            if (timeUtc < sinceUtc) break;
            if (record.Id is not (17 or 18)) continue;

            var data = ParseEventData(record.ToXml());
            var pipeName = Get(data, "PipeName");
            if (string.IsNullOrWhiteSpace(pipeName)) continue;
            var normalizedName = PipeNameNormalizer.Normalize(pipeName);
            var processPath = Get(data, "Image");
            var eventType = Get(data, "EventType") ?? (record.Id == 17 ? "Pipe Created" : "Pipe Connected");
            results.Add(new SysmonPipeEvent(
                Channel,
                recordId,
                record.Id,
                timeUtc,
                ParseProcessId(Get(data, "ProcessId")),
                processPath is null ? null : Path.GetFileName(processPath),
                normalizedName,
                eventType,
                activeNames.Contains(normalizedName)));
        }
        return results;
    }

    public static IReadOnlyDictionary<string, string> ParseEventData(string xml)
    {
        var document = XDocument.Parse(xml);
        return document.Descendants().Where(element => element.Name.LocalName == "Data")
            .Select(element => (Name: (string?)element.Attribute("Name"), Value: element.Value))
            .Where(item => !string.IsNullOrWhiteSpace(item.Name))
            .GroupBy(item => item.Name!, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(group => group.Key, group => group.Last().Value, StringComparer.OrdinalIgnoreCase);
    }

    private static string? Get(IReadOnlyDictionary<string, string> data, string name) =>
        data.TryGetValue(name, out var value) && !string.IsNullOrWhiteSpace(value) ? value : null;

    private static uint? ParseProcessId(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        if (value.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
            && uint.TryParse(value.AsSpan(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var hex)) return hex;
        return uint.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var pid) ? pid : null;
    }
}
