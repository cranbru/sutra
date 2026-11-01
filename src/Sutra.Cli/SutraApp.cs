using Spectre.Console;
using System.Runtime.Versioning;
using Sutra.Cli.Analysis;
using Sutra.Cli.Correlation;
using Sutra.Cli.Models;
using Sutra.Cli.Native;
using Sutra.Cli.Storage;

namespace Sutra.Cli;

public static class SutraApp
{
    public static async Task<int> RunAsync(string[] args)
    {
        if (args.Length == 0 || args[0] is "help" or "--help" or "-h")
        {
            ShowBanner();
            ShowHelp();
            return 0;
        }

        return args[0] switch
        {
            "scan" => await RunScanAsync(args[1..]),
            "history" => RunHistory(args[1..]),
            "changes" => RunChanges(args[1..]),
            "events" => RunEvents(args[1..]),
            "activity" => RunActivity(args[1..]),
            _ => UnknownCommand(args[0])
        };
    }

    private static int UnknownCommand(string command)
    {
        AnsiConsole.MarkupLine($"[red]Unknown command:[/] {Markup.Escape(command)}. Run [cyan]sutra help[/] for usage.");
        return 2;
    }

    private static async Task<int> RunScanAsync(string[] args)
    {
        if (!TryParseOptions(args, ["--inspect-acl", "--snapshot"], ["--db"], out var options, out var error))
        {
            AnsiConsole.MarkupLine($"[red]{Markup.Escape(error!)}[/]");
            return 2;
        }
        var inspectAcl = options.ContainsKey("--inspect-acl");
        var saveSnapshot = options.ContainsKey("--snapshot");
        if (options.ContainsKey("--db") && !saveSnapshot)
        {
            AnsiConsole.MarkupLine("[red]--db is only valid with --snapshot.[/]");
            return 2;
        }
        if (!OperatingSystem.IsWindows()) { RequireWindows(); return 2; }

        ShowBanner();
        var scanDescription = saveSnapshot ? "named-pipe inventory · snapshot capture" : "named-pipe inventory · read-only scan";
        AnsiConsole.MarkupLine($"[grey]{scanDescription}[/]");
        AnsiConsole.WriteLine();
        IReadOnlyList<PipeEndpoint> endpoints;
        try
        {
            endpoints = await AnsiConsole.Status()
                .Spinner(Spinner.Known.Dots)
                .SpinnerStyle(Style.Parse("cyan"))
                .StartAsync("Discovering named-pipe endpoints…", _ => Task.FromResult(new PipeEnumerator().Discover()));
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or PlatformNotSupportedException)
        {
            AnsiConsole.MarkupLine($"[red]Discovery failed:[/] {Markup.Escape(ex.Message)}");
            return 1;
        }

        var inspected = inspectAcl ? await InspectSecurityWindowsAsync(endpoints) : endpoints;
        RenderResults(inspected, inspectAcl);
        if (saveSnapshot)
        {
            try
            {
                var result = new SqliteHistoryStore(GetDatabasePath(options)).SaveSnapshot(inspected);
                AnsiConsole.MarkupLine($"[cyan]Snapshot saved[/]  {result.Snapshot.Id}  ·  {result.Snapshot.CapturedUtc.ToLocalTime():yyyy-MM-dd HH:mm:ss}  ·  {result.Snapshot.EndpointCount} endpoints");
                RenderChanges(result.Changes, "Changes since previous snapshot");
            }
            catch (Exception ex) when (ex is Microsoft.Data.Sqlite.SqliteException or IOException or UnauthorizedAccessException)
            {
                AnsiConsole.MarkupLine($"[red]Could not save snapshot:[/] {Markup.Escape(ex.Message)}");
                return 1;
            }
        }
        return 0;
    }

    private static int RunHistory(string[] args)
    {
        if (!TryParseOptions(args, [], ["--db", "--limit"], out var options, out var error))
        {
            AnsiConsole.MarkupLine($"[red]{Markup.Escape(error!)}[/]");
            return 2;
        }
        if (!TryGetIntOption(options, "--limit", 20, 1, 200, out var limit))
        {
            AnsiConsole.MarkupLine("[red]--limit must be between 1 and 200.[/]");
            return 2;
        }
        try
        {
            var store = new SqliteHistoryStore(GetDatabasePath(options));
            var snapshots = store.GetRecentSnapshots(limit);
            if (snapshots.Count == 0)
            {
                AnsiConsole.MarkupLine("[grey]No scan snapshots found. Run [cyan]sutra scan --snapshot[/] to save one.[/]");
                return 0;
            }
            var table = new Table().Border(TableBorder.Rounded);
            table.AddColumn("Captured (local time)"); table.AddColumn("Snapshot"); table.AddColumn("Endpoints");
            foreach (var item in snapshots)
                table.AddRow(item.CapturedUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss"), item.Id, item.EndpointCount.ToString());
            AnsiConsole.Write(table);
            return 0;
        }
        catch (Exception ex) when (ex is Microsoft.Data.Sqlite.SqliteException or IOException or UnauthorizedAccessException)
        {
            AnsiConsole.MarkupLine($"[red]Could not read scan history:[/] {Markup.Escape(ex.Message)}");
            return 1;
        }
    }

    private static int RunChanges(string[] args)
    {
        if (!TryParseOptions(args, [], ["--db"], out var options, out var error))
        {
            AnsiConsole.MarkupLine($"[red]{Markup.Escape(error!)}[/]");
            return 2;
        }
        try
        {
            var store = new SqliteHistoryStore(GetDatabasePath(options));
            var snapshots = store.GetRecentSnapshots(2);
            if (snapshots.Count < 2)
            {
                AnsiConsole.MarkupLine("[yellow]Two snapshots are required to compare changes. Run [cyan]sutra scan --snapshot[/] twice.[/]");
                return 0;
            }
            AnsiConsole.MarkupLine($"[grey]{snapshots[1].CapturedUtc.ToLocalTime():yyyy-MM-dd HH:mm:ss} → {snapshots[0].CapturedUtc.ToLocalTime():yyyy-MM-dd HH:mm:ss}[/]");
            RenderChanges(store.GetLatestChanges() ?? Array.Empty<EndpointChange>(), "Latest snapshot changes");
            return 0;
        }
        catch (Exception ex) when (ex is Microsoft.Data.Sqlite.SqliteException or IOException or UnauthorizedAccessException)
        {
            AnsiConsole.MarkupLine($"[red]Could not compare snapshots:[/] {Markup.Escape(ex.Message)}");
            return 1;
        }
    }

    private static int RunEvents(string[] args)
    {
        if (!TryParseOptions(args, [], ["--db", "--since-hours"], out var options, out var error))
        {
            AnsiConsole.MarkupLine($"[red]{Markup.Escape(error!)}[/]");
            return 2;
        }
        if (!TryGetIntOption(options, "--since-hours", 24, 1, 720, out var hours))
        {
            AnsiConsole.MarkupLine("[red]--since-hours must be between 1 and 720.[/]");
            return 2;
        }
        if (!OperatingSystem.IsWindows()) { RequireWindows(); return 2; }
        return RunEventsWindows(options, hours);
    }

    [SupportedOSPlatform("windows")]
    private static int RunEventsWindows(IReadOnlyDictionary<string, string?> options, int hours)
    {
        try
        {
            var endpoints = new PipeEnumerator().Discover();
            var activePipes = new HashSet<string>(endpoints.Select(endpoint => endpoint.Name), StringComparer.OrdinalIgnoreCase);
            var events = new SysmonEventIngestor().ReadSince(DateTimeOffset.UtcNow.AddHours(-hours), activePipes);
            var store = new SqliteHistoryStore(GetDatabasePath(options));
            var inserted = store.SaveEvents(events);
            AnsiConsole.MarkupLine($"[cyan]Sysmon pipe events[/]  read {events.Count}  ·  new {inserted}  ·  matched to current inventory {events.Count(item => item.IsCorrelated)}  ·  last {hours} hours");
            RenderEvents(events.Take(40).ToArray());
            return 0;
        }
        catch (Exception ex) when (ex is System.Diagnostics.Eventing.Reader.EventLogException or UnauthorizedAccessException or Microsoft.Data.Sqlite.SqliteException or IOException or ArgumentException)
        {
            AnsiConsole.MarkupLine($"[red]Could not ingest Sysmon events:[/] {Markup.Escape(ex.Message)}");
            AnsiConsole.MarkupLine("[grey]Confirm that Sysmon is installed, Event ID 17/18 logging is enabled, and this account can read the Operational channel.[/]");
            return 1;
        }
    }

    private static int RunActivity(string[] args)
    {
        if (!TryParseOptions(args, [], ["--db", "--limit"], out var options, out var error))
        {
            AnsiConsole.MarkupLine($"[red]{Markup.Escape(error!)}[/]");
            return 2;
        }
        if (!TryGetIntOption(options, "--limit", 50, 1, 500, out var limit))
        {
            AnsiConsole.MarkupLine("[red]--limit must be between 1 and 500.[/]");
            return 2;
        }
        try
        {
            var events = new SqliteHistoryStore(GetDatabasePath(options)).GetRecentEvents(limit);
            RenderEvents(events);
            return 0;
        }
        catch (Exception ex) when (ex is Microsoft.Data.Sqlite.SqliteException or IOException or UnauthorizedAccessException)
        {
            AnsiConsole.MarkupLine($"[red]Could not read the activity history:[/] {Markup.Escape(ex.Message)}");
            return 1;
        }
    }

    private static bool RequireWindows()
    {
        if (OperatingSystem.IsWindows()) return true;
        AnsiConsole.MarkupLine("[red]SUTRA requires Windows.[/]");
        return false;
    }

    private static bool TryParseOptions(string[] args, string[] flags, string[] valueOptions,
        out Dictionary<string, string?> options, out string? error)
    {
        options = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        var flagSet = new HashSet<string>(flags, StringComparer.OrdinalIgnoreCase);
        var valueOptionSet = new HashSet<string>(valueOptions, StringComparer.OrdinalIgnoreCase);
        error = null;
        for (var i = 0; i < args.Length; i++)
        {
            var option = args[i];
            if (flagSet.Contains(option))
            {
                if (!options.TryAdd(option, null)) { error = $"Option {option} was supplied more than once."; return false; }
            }
            else if (valueOptionSet.Contains(option))
            {
                if (i + 1 >= args.Length || args[i + 1].StartsWith("--", StringComparison.Ordinal))
                { error = $"Option {option} requires a value."; return false; }
                if (!options.TryAdd(option, args[++i])) { error = $"Option {option} was supplied more than once."; return false; }
            }
            else { error = $"Unknown option: {option}"; return false; }
        }
        return true;
    }

    private static bool TryGetIntOption(IReadOnlyDictionary<string, string?> options, string key, int defaultValue,
        int minimum, int maximum, out int value)
    {
        value = defaultValue;
        return !options.TryGetValue(key, out var raw) || (int.TryParse(raw, out value) && value >= minimum && value <= maximum);
    }

    private static string GetDatabasePath(IReadOnlyDictionary<string, string?> options) =>
        options.TryGetValue("--db", out var path) && !string.IsNullOrWhiteSpace(path) ? path : SqliteHistoryStore.DefaultDatabasePath;

    private static void RenderChanges(IReadOnlyList<EndpointChange> changes, string title)
    {
        AnsiConsole.WriteLine();
        AnsiConsole.MarkupLine($"[cyan]{Markup.Escape(title)}[/]  ·  added [green]{changes.Count(change => change.Kind == EndpointChangeKind.Added)}[/]  modified [yellow]{changes.Count(change => change.Kind == EndpointChangeKind.Modified)}[/]  removed [red]{changes.Count(change => change.Kind == EndpointChangeKind.Removed)}[/]");
        if (changes.Count == 0) return;
        var table = new Table().Border(TableBorder.Simple);
        table.AddColumn("Change"); table.AddColumn("Endpoint");
        foreach (var change in changes.Take(100))
        {
            var kind = change.Kind switch
            {
                EndpointChangeKind.Added => "[green]Added[/]",
                EndpointChangeKind.Modified => "[yellow]Modified[/]",
                _ => "[red]Removed[/]"
            };
            table.AddRow(kind, Markup.Escape(change.EndpointName));
        }
        AnsiConsole.Write(table);
        if (changes.Count > 100) AnsiConsole.MarkupLine("[grey]Additional changes omitted from display.[/]");
    }

    private static void RenderEvents(IReadOnlyList<SysmonPipeEvent> events)
    {
        if (events.Count == 0)
        {
            AnsiConsole.MarkupLine("[grey]No Sysmon pipe events were found in the requested time window.[/]");
            return;
        }
        var table = new Table().Border(TableBorder.Rounded);
        table.AddColumn("UTC"); table.AddColumn("Event"); table.AddColumn("Pipe"); table.AddColumn("PID"); table.AddColumn("Process"); table.AddColumn("Current");
        foreach (var item in events)
            table.AddRow(item.TimeUtc.ToString("yyyy-MM-dd HH:mm:ss"), item.EventType, Markup.Escape(Shorten(item.PipeName, 38)),
                item.ProcessId?.ToString() ?? "—", Markup.Escape(item.ProcessName ?? "—"), item.IsCorrelated ? "[green]Matched[/]" : "[grey]Not found[/]");
        AnsiConsole.Write(table);
    }

    [SupportedOSPlatform("windows")]
    private static async Task<IReadOnlyList<PipeEndpoint>> InspectSecurityWindowsAsync(IReadOnlyList<PipeEndpoint> endpoints)
    {
        if (endpoints.Count == 0) return endpoints;
        var inspector = new PipeSecurityInspector();
        var analyzer = new PipeRiskAnalyzer();
        return await AnsiConsole.Progress()
            .Columns(new TaskDescriptionColumn(), new ProgressBarColumn(), new PercentageColumn(), new SpinnerColumn())
            .StartAsync(context =>
        {
            var task = context.AddTask("Inspecting permissions and process context", maxValue: endpoints.Count);
            var results = new List<PipeEndpoint>(endpoints.Count);
            foreach (var endpoint in endpoints)
            {
                var inspected = inspector.Inspect(endpoint);
                results.Add(inspected.SecurityStatus == "Inspected"
                    ? inspected with { Findings = analyzer.Analyze(inspected) }
                    : inspected);
                task.Increment(1);
            }
            return Task.FromResult<IReadOnlyList<PipeEndpoint>>(results);
        });
    }

    private static void ShowBanner()
    {
        var art = new FigletText("SUTRA").Color(Color.Cyan1);
        AnsiConsole.Write(Align.Center(art));
        AnsiConsole.Write(Align.Center(new Markup("[grey]Windows IPC Attack Surface Mapper[/]")));
        AnsiConsole.WriteLine();
    }

    private static void ShowHelp()
    {
        var table = new Table().Border(TableBorder.Rounded).BorderColor(Color.Grey35);
        table.AddColumn(new TableColumn("[cyan]Command[/]"));
        table.AddColumn(new TableColumn("[cyan]Description[/]"));
        table.AddRow("[white]sutra scan[/]", "Discover named pipes without connecting to endpoints.");
        table.AddRow("[white]sutra scan --inspect-acl[/]", "Inspect ACLs, server process context, services, and permissions.");
        table.AddRow("[white]sutra scan --snapshot[/]", "Save endpoint metadata and compare it with the prior snapshot.");
        table.AddRow("[white]sutra history[/]", "List saved scan snapshots.");
        table.AddRow("[white]sutra changes[/]", "Compare the two most recent snapshots.");
        table.AddRow("[white]sutra events[/]", "Ingest and correlate Sysmon pipe events 17 and 18.");
        table.AddRow("[white]sutra events --since-hours 48[/]", "Set the event lookback window (1–720 hours).");
        table.AddRow("[white]sutra activity[/]", "Show the saved Sysmon pipe event timeline.");
        table.AddRow("[white]--db <path>[/]", "Select the SQLite database file for history and events.");
        table.AddRow("[white]sutra help[/]", "Show this help.");
        AnsiConsole.Write(table);
        AnsiConsole.MarkupLine("[grey]Inspection opens each pipe and may briefly connect to its server. This can trigger server connection handling; use only when acceptable.[/]");
        AnsiConsole.MarkupLine("[grey]Permission findings are contextual indicators. They do not prove exploitability or evaluate effective access across all ACEs.[/]");
        AnsiConsole.MarkupLine("[grey]Sysmon correlation requires Sysmon and readable Event ID 17/18 records in Microsoft-Windows-Sysmon/Operational.[/]");
    }

    private static void RenderResults(IReadOnlyList<PipeEndpoint> endpoints, bool aclRequested)
    {
        var table = new Table().Border(TableBorder.Rounded).BorderColor(Color.Grey35);
        table.AddColumn(new TableColumn("Endpoint").NoWrap());
        table.AddColumn("Found");
        if (aclRequested)
        {
            table.AddColumn("ACL");
            table.AddColumn("Owner SID");
            table.AddColumn("ACEs");
        }
        table.AddColumn("PID");

        foreach (var endpoint in endpoints)
        {
            var discovery = endpoint.DiscoveryStatus == "Discovered" ? "[green]Found[/]" : "[red]Unavailable[/]";
            var pid = endpoint.ServerProcessId?.ToString() ?? "[grey]—[/]";
            if (aclRequested)
            {
                var status = endpoint.SecurityStatus == "Inspected" ? "[green]Read[/]" : "[yellow]Unavailable[/]";
                table.AddRow(Markup.Escape(Shorten(endpoint.Name, 38)), discovery, status,
                    Markup.Escape(Shorten(endpoint.OwnerSid ?? "—", 24)), endpoint.AccessEntries?.Count.ToString() ?? "—", pid);
            }
            else table.AddRow(Markup.Escape(Shorten(endpoint.Name, 46)), discovery, pid);
        }

        AnsiConsole.Write(table);
        AnsiConsole.WriteLine();
        var inspectedCount = endpoints.Count(e => e.SecurityStatus == "Inspected");
        AnsiConsole.MarkupLine($"[cyan]Scan summary[/]  endpoints [white]{endpoints.Count}[/]  ·  security descriptors [white]{inspectedCount}[/]/{(aclRequested ? endpoints.Count : 0)}  ·  process contexts [white]{endpoints.Count(e => e.ServerProcessId.HasValue)}[/]");
        if (aclRequested)
        {
            var allFindings = endpoints.SelectMany(e => e.Findings ?? Array.Empty<RiskFinding>()).ToArray();
            var counters = Enum.GetValues<RiskSeverity>().Select(severity => $"{severity} [white]{allFindings.Count(f => f.Severity == severity)}[/]");
            AnsiConsole.MarkupLine("[cyan]Risk summary[/]  " + string.Join("  ·  ", counters));
        }

        if (aclRequested)
        {
            var aclRows = endpoints.Where(e => e.AccessEntries is not null).ToArray();
            foreach (var endpoint in aclRows)
            {
                AnsiConsole.WriteLine();
                AnsiConsole.MarkupLine($"[cyan]{Markup.Escape(endpoint.Name)}[/] [grey]· owner {Markup.Escape(endpoint.OwnerSid ?? "—")} · DACL {Markup.Escape(endpoint.DaclState ?? "unknown")}[/]");
                var context = $"[white]Process:[/] {Markup.Escape(endpoint.ProcessName ?? "unavailable")} (PID {endpoint.ServerProcessId?.ToString() ?? "—"}) · [white]User SID:[/] {Markup.Escape(endpoint.ProcessUserSid ?? "unavailable")} · [white]Elevated:[/] {endpoint.ProcessIsElevated?.ToString() ?? "unknown"} · [white]Services:[/] {Markup.Escape(endpoint.ServiceNames is { Count: > 0 } ? string.Join(", ", endpoint.ServiceNames) : "none identified")}";
                AnsiConsole.MarkupLine(context);
                var aceTable = new Table().Border(TableBorder.Simple);
                aceTable.AddColumn("Type"); aceTable.AddColumn("Trustee SID"); aceTable.AddColumn("Mask"); aceTable.AddColumn("Flags");
                foreach (var ace in endpoint.AccessEntries!)
                    aceTable.AddRow(ace.Type, ace.Sid, ace.Rights, ace.Flags);
                if (endpoint.AccessEntries!.Count == 0)
                {
                    var emptyMessage = endpoint.DaclState is "Null DACL" or "DACL absent"
                        ? "No DACL restriction is present"
                        : endpoint.DaclState == "Present" ? "Empty DACL; no ACEs" : "No DACL entries returned";
                    aceTable.AddRow("—", emptyMessage, "—", "—");
                }
                AnsiConsole.Write(aceTable);
                RenderFindings(endpoint);
            }
        }

        var unavailable = endpoints.Where(e => e.SecurityStatus == "Unavailable" && e.Error is not null).Take(5).ToArray();
        if (unavailable.Length > 0)
        {
            AnsiConsole.WriteLine();
            var panel = new Panel(string.Join(Environment.NewLine, unavailable.Select(e => $"[yellow]{Markup.Escape(e.Name)}[/]: {Markup.Escape(e.Error!)}")))
            { Header = new PanelHeader("Security descriptor access details"), Border = BoxBorder.Rounded, BorderStyle = new Style(Color.Grey) };
            AnsiConsole.Write(panel);
            if (endpoints.Count(e => e.SecurityStatus == "Unavailable") > unavailable.Length)
                AnsiConsole.MarkupLine("[grey]Additional errors omitted.[/]");
        }
    }

    private static void RenderFindings(PipeEndpoint endpoint)
    {
        if (endpoint.Findings is not { Count: > 0 } findings) return;
        AnsiConsole.WriteLine();
        var counts = Enum.GetValues<RiskSeverity>().Select(severity => $"{severity}: {findings.Count(f => f.Severity == severity)}");
        AnsiConsole.MarkupLine("[cyan]Permission analysis[/]  " + Markup.Escape(string.Join(" · ", counts)));
        foreach (var finding in findings)
        {
            var color = finding.Severity switch
            {
                RiskSeverity.Critical => "red bold",
                RiskSeverity.High => "red",
                RiskSeverity.Medium => "yellow",
                RiskSeverity.Low => "blue",
                _ => "grey"
            };
            var panelContent = $"{Markup.Escape(finding.Explanation)}\n\n[white]Recommendation:[/] {Markup.Escape(finding.Recommendation)}";
            AnsiConsole.Write(new Panel(panelContent)
            {
                Header = new PanelHeader($"[{color}]{finding.Severity}: {Markup.Escape(finding.Title)}[/]"),
                Border = BoxBorder.Rounded,
                BorderStyle = new Style(finding.Severity is RiskSeverity.High or RiskSeverity.Critical ? Color.Red : Color.Grey)
            });
        }
    }

    private static string Shorten(string value, int maxLength) => value.Length <= maxLength ? value : value[..(maxLength - 1)] + "…";
}
