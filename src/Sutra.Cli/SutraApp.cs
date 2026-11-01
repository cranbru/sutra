using Spectre.Console;
using System.Text;
using System.Runtime.Versioning;
using Sutra.Cli.Analysis;
using Sutra.Cli.Correlation;
using Sutra.Cli.Discovery;
using Sutra.Cli.Models;
using Sutra.Cli.Native;
using Sutra.Cli.Reporting;
using Sutra.Cli.Storage;

namespace Sutra.Cli;

public static class SutraApp
{
    public static async Task<int> RunAsync(string[] args)
    {
        if (args.Length == 0)
        {
            if (!Console.IsInputRedirected) return await RunDashboardAsync();
            ShowBanner();
            ShowHelp();
            return 0;
        }

        if (args[0] is "help" or "--help" or "-h")
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
            "report" => RunStoredReport(args[1..]),
            "dashboard" => await RunDashboardAsync(),
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
        string[] values = ["--db", "--format", "--output", "--scope", "--mechanism", "--mechanisms", "--search", "--process", "--service", "--elevated", "--severity", "--sort", "--order", "--limit"];
        if (!TryParseOptions(args, ["--inspect-acl", "--snapshot"], values, out var options, out var error))
        {
            AnsiConsole.MarkupLine($"[red]{Markup.Escape(error!)}[/]");
            return 2;
        }
        var inspectAcl = options.ContainsKey("--inspect-acl");
        var saveSnapshot = options.ContainsKey("--snapshot");
        if (!TryGetFormat(options, out var format, out error))
        {
            AnsiConsole.MarkupLine($"[red]{Markup.Escape(error!)}[/]");
            return 2;
        }
        if (!TryBuildFilter(options, out var filter, out error))
        {
            AnsiConsole.MarkupLine($"[red]{Markup.Escape(error!)}[/]");
            return 2;
        }
        if (!TryGetMechanisms(options, out var mechanisms, out error))
        {
            AnsiConsole.MarkupLine($"[red]{Markup.Escape(error!)}[/]");
            return 2;
        }
        if (options.ContainsKey("--severity") && !inspectAcl)
        {
            AnsiConsole.MarkupLine("[red]--severity requires --inspect-acl.[/]");
            return 2;
        }
        if (!OperatingSystem.IsWindows()) { RequireWindows(); return 2; }

        var terminalOutput = format == ReportFormat.Table && !options.ContainsKey("--output");
        if (terminalOutput)
        {
            ShowBanner();
            var scanDescription = saveSnapshot ? "IPC and sensitive-handle inventory · snapshot capture" : "IPC and sensitive-handle investigation";
            AnsiConsole.MarkupLine($"[grey]{scanDescription}[/]");
            AnsiConsole.WriteLine();
        }
        IReadOnlyList<PipeEndpoint> endpoints;
        IReadOnlyList<DiscoveryResult> discoveryResults;
        try
        {
            var coordinator = DiscoveryModuleFactory.CreateDefault();
            var discover = new Func<IReadOnlyList<DiscoveryResult>>(() => coordinator.Discover(mechanisms));
            var results = terminalOutput
                ? await AnsiConsole.Status().Spinner(Spinner.Known.Dots).SpinnerStyle(Style.Parse("cyan"))
                    .StartAsync("Discovering IPC endpoints…", _ => Task.FromResult(discover()))
                : discover();
            discoveryResults = results;
            endpoints = results.SelectMany(result => result.Endpoints).ToArray();
            if (results.Count > 0 && results.All(result => result.Error is not null))
                throw new InvalidOperationException(string.Join("; ", results.Select(result => $"{result.Mechanism}: {result.Error}")));
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or PlatformNotSupportedException or InvalidOperationException)
        {
            AnsiConsole.MarkupLine($"[red]Discovery failed:[/] {Markup.Escape(ex.Message)}");
            return 1;
        }

        var sensitiveHandles = terminalOutput
            ? await AnsiConsole.Status().Spinner(Spinner.Known.Dots).SpinnerStyle(Style.Parse("cyan"))
                .StartAsync("Reviewing sensitive process handles…", _ => Task.FromResult(SensitiveHandleScanner.Scan()))
            : SensitiveHandleScanner.Scan();
        if (sensitiveHandles.Error is not null)
        {
            var message = $"Sensitive handle inspection unavailable: {sensitiveHandles.Error}";
            if (terminalOutput) AnsiConsole.MarkupLine($"[yellow]{Markup.Escape(message)}[/]");
            else Console.Error.WriteLine(message);
        }

        var inspected = inspectAcl ? await InspectSecurityWindowsAsync(endpoints, terminalOutput) : endpoints;
        foreach (var result in discoveryResults.Where(result => result.Error is not null))
        {
            var message = $"{result.Mechanism} discovery unavailable: {result.Error}";
            if (terminalOutput) AnsiConsole.MarkupLine($"[yellow]{Markup.Escape(message)}[/]");
            else Console.Error.WriteLine(message);
        }
        var existingEvents = ReadEventsForEndpoints(inspected, GetDatabasePath(options));
        inspected = IpcCorrelationAnalyzer.Enrich(inspected, existingEvents);
        SnapshotSaveResult? snapshotResult = null;
        if (saveSnapshot)
        {
            try
            {
                snapshotResult = new SqliteHistoryStore(GetDatabasePath(options)).SaveSnapshot(inspected, sensitiveHandles);
            }
            catch (Exception ex) when (ex is Microsoft.Data.Sqlite.SqliteException or IOException or UnauthorizedAccessException)
            {
                AnsiConsole.MarkupLine($"[red]Could not save snapshot:[/] {Markup.Escape(ex.Message)}");
                return 1;
            }
        }

        var selected = ScanReportFormatter.FilterAndSort(inspected, filter);
        var selectedNames = new HashSet<string>(selected.Where(endpoint => endpoint.IpcMechanism == "NamedPipe")
            .Select(endpoint => endpoint.Name), StringComparer.OrdinalIgnoreCase);
        var recentEvents = existingEvents.Where(item => selectedNames.Contains(item.PipeName)).ToArray();
        var source = snapshotResult is null ? "Live scan" : $"Snapshot {snapshotResult.Snapshot.Id}";
        var report = ScanReportFormatter.CreateDocument(selected, source, recentEvents, discoveryResults, sensitiveHandles);
        if (options.TryGetValue("--output", out var outputPath))
        {
            try
            {
                WriteReportFile(outputPath!, RenderFormat(format, report, selected, recentEvents, sensitiveHandles));
                AnsiConsole.MarkupLine($"[green]Report written:[/] {Markup.Escape(Path.GetFullPath(outputPath!))}");
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
            {
                AnsiConsole.MarkupLine($"[red]Could not write report:[/] {Markup.Escape(ex.Message)}");
                return 1;
            }
        }
        else if (terminalOutput) RenderResults(selected, inspectAcl, discoveryResults, sensitiveHandles);
        else Console.Write(RenderFormat(format, report, selected, recentEvents, sensitiveHandles));

        if (snapshotResult is not null)
        {
            var structuredStdout = !options.ContainsKey("--output")
                && format is (ReportFormat.Json or ReportFormat.Dot or ReportFormat.Ascii);
            var destination = structuredStdout ? Console.Error : Console.Out;
            destination.WriteLine($"Snapshot saved: {snapshotResult.Snapshot.Id} ({snapshotResult.Snapshot.EndpointCount} endpoints)");
            if (terminalOutput) RenderChanges(snapshotResult.Changes, "Changes since previous snapshot");
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

    private static int RunStoredReport(string[] args)
    {
        string[] reportOptions = ["--db", "--snapshot", "--format", "--output", "--scope", "--mechanism", "--search", "--process", "--service", "--elevated", "--severity", "--sort", "--order", "--limit"];
        if (!TryParseOptions(args, [], reportOptions, out var options, out var error))
        {
            AnsiConsole.MarkupLine($"[red]{Markup.Escape(error!)}[/]");
            return 2;
        }
        if (!TryGetFormat(options, out var format, out error) || !TryBuildFilter(options, out var filter, out error))
        {
            AnsiConsole.MarkupLine($"[red]{Markup.Escape(error!)}[/]");
            return 2;
        }
        try
        {
            var store = new SqliteHistoryStore(GetDatabasePath(options));
            var snapshotId = options.TryGetValue("--snapshot", out var requestedId) ? requestedId! : "latest";
            var snapshot = store.GetSnapshot(snapshotId);
            if (snapshot is null)
            {
                AnsiConsole.MarkupLine("[yellow]No matching snapshot was found. Run [cyan]sutra scan --snapshot[/] first.[/]");
                return 0;
            }
            var endpoints = ScanReportFormatter.FilterAndSort(store.GetSnapshotEndpoints(snapshot.Id), filter);
            var events = ReadEventsForEndpoints(endpoints, GetDatabasePath(options));
            var sensitiveHandles = store.GetSnapshotSensitiveHandles(snapshot.Id);
            var report = ScanReportFormatter.CreateDocument(endpoints, $"Snapshot {snapshot.Id}", events,
                sensitiveHandles: sensitiveHandles);
            if (options.TryGetValue("--output", out var outputPath))
            {
                WriteReportFile(outputPath!, RenderFormat(format, report, endpoints, events, sensitiveHandles));
                AnsiConsole.MarkupLine($"[green]Report written:[/] {Markup.Escape(Path.GetFullPath(outputPath!))}");
            }
            else if (format == ReportFormat.Table)
                RenderResults(endpoints, endpoints.Any(endpoint => endpoint.SecurityStatus == "Inspected"), sensitiveHandles: sensitiveHandles);
            else Console.Write(RenderFormat(format, report, endpoints, events, sensitiveHandles));
            return 0;
        }
        catch (Exception ex) when (ex is Microsoft.Data.Sqlite.SqliteException or IOException or UnauthorizedAccessException or ArgumentException)
        {
            AnsiConsole.MarkupLine($"[red]Could not generate report:[/] {Markup.Escape(ex.Message)}");
            return 1;
        }
    }

    private static async Task<int> RunDashboardAsync()
    {
        if (Console.IsInputRedirected)
        {
            AnsiConsole.MarkupLine("[yellow]The interactive dashboard needs a terminal. Run [cyan]sutra help[/] for commands.[/]");
            return 2;
        }
        while (true)
        {
            var choice = AnsiConsole.Prompt(new SelectionPrompt<string>()
                .Title("[cyan]SUTRA dashboard[/]")
                .PageSize(8)
                .AddChoices("Scan IPC", "Scan and save snapshot", "History", "Changes", "Recent activity", "Help", "Exit"));
            switch (choice)
            {
                case "Scan IPC": await RunScanAsync([]); break;
                case "Scan and save snapshot": await RunScanAsync(["--snapshot"]); break;
                case "History": RunHistory([]); break;
                case "Changes": RunChanges([]); break;
                case "Recent activity": RunActivity([]); break;
                case "Help": ShowHelp(); break;
                default: return 0;
            }
            AnsiConsole.WriteLine();
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

    private static bool TryGetFormat(IReadOnlyDictionary<string, string?> options, out ReportFormat format, out string? error)
    {
        error = null;
        var value = options.TryGetValue("--format", out var raw) ? raw : "table";
        if (Enum.TryParse(value, true, out format) && Enum.IsDefined(format)) return true;
        error = "--format must be table, ascii, json, or dot.";
        return false;
    }

    private static bool TryBuildFilter(IReadOnlyDictionary<string, string?> options, out EndpointReportFilter filter, out string? error)
    {
        error = null;
        var sortValue = options.TryGetValue("--sort", out var sortRaw) ? sortRaw : "name";
        if (!Enum.TryParse<ReportSort>(sortValue, true, out var sort))
        { filter = new EndpointReportFilter(); error = "--sort must be name, pid, or severity."; return false; }
        var orderValue = options.TryGetValue("--order", out var orderRaw) ? orderRaw : "asc";
        if (!Enum.TryParse<ReportOrder>(orderValue, true, out var order))
        { filter = new EndpointReportFilter(); error = "--order must be asc or desc."; return false; }
        bool? elevated = null;
        if (options.TryGetValue("--elevated", out var elevatedRaw))
        {
            if (!bool.TryParse(elevatedRaw, out var isElevated))
            { filter = new EndpointReportFilter(); error = "--elevated must be true or false."; return false; }
            elevated = isElevated;
        }
        RiskSeverity? severity = null;
        if (options.TryGetValue("--severity", out var severityRaw))
        {
            if (!Enum.TryParse<RiskSeverity>(severityRaw, true, out var parsedSeverity) || !Enum.IsDefined(parsedSeverity))
            { filter = new EndpointReportFilter(); error = "--severity must be critical, high, medium, low, or informational."; return false; }
            severity = parsedSeverity;
        }
        if (!TryGetIntOption(options, "--limit", 100_000, 1, 100_000, out var limit))
        { filter = new EndpointReportFilter(); error = "--limit must be between 1 and 100000."; return false; }

        var mechanism = Value(options, "--mechanism");
        if (mechanism is not null && !TryNormalizeMechanism(mechanism, out mechanism))
        { filter = new EndpointReportFilter(); error = "--mechanism must be named-pipe, rpc, com, or alpc."; return false; }

        filter = new EndpointReportFilter(
            Value(options, "--scope"), mechanism, Value(options, "--search"), Value(options, "--process"), Value(options, "--service"),
            elevated, severity, sort, order, limit);
        return true;
    }

    private static bool TryGetMechanisms(IReadOnlyDictionary<string, string?> options,
        out IReadOnlyList<string> mechanisms, out string? error)
    {
        error = null;
        if (!options.TryGetValue("--mechanisms", out var raw))
        {
            mechanisms = ["all"];
            return true;
        }
        var selected = new List<string>();
        foreach (var value in raw!.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
        {
            if (value.Equals("all", StringComparison.OrdinalIgnoreCase))
            {
                if (selected.Count != 0 || raw.Contains(','))
                { mechanisms = Array.Empty<string>(); error = "Use 'all' by itself in --mechanisms."; return false; }
                selected.Add("all");
            }
            else if (TryNormalizeMechanism(value, out var normalized)) selected.Add(normalized);
            else { mechanisms = Array.Empty<string>(); error = $"Unknown IPC mechanism '{value}'. Choose named-pipe, rpc, com, alpc, or all."; return false; }
        }
        if (selected.Count == 0) { mechanisms = Array.Empty<string>(); error = "--mechanisms requires at least one mechanism."; return false; }
        mechanisms = selected.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        return true;
    }

    private static bool TryNormalizeMechanism(string value, out string normalized)
    {
        normalized = value.Trim().ToUpperInvariant() switch
        {
            "PIPE" or "PIPES" or "NAMEDPIPE" or "NAMED-PIPES" or "NAMED-PIPE" => "NamedPipe",
            "RPC" => "RPC",
            "COM" => "COM",
            "ALPC" => "ALPC",
            _ => string.Empty
        };
        return normalized.Length > 0;
    }

    private static string? Value(IReadOnlyDictionary<string, string?> options, string key) =>
        options.TryGetValue(key, out var value) ? value : null;

    private static string RenderFormat(ReportFormat format, ScanReportDocument report,
        IReadOnlyList<PipeEndpoint> endpoints, IReadOnlyList<SysmonPipeEvent> events,
        SensitiveHandleScanResult? sensitiveHandles = null) => format switch
    {
        ReportFormat.Json => ScanReportFormatter.ToJson(report),
        ReportFormat.Dot => ScanReportFormatter.ToDot(endpoints, events, sensitiveHandles),
        ReportFormat.Ascii => ScanReportFormatter.ToAscii(endpoints, events, sensitiveHandles),
        _ => ScanReportFormatter.ToPlainText(report)
    };

    private static void WriteReportFile(string path, string contents)
    {
        var fullPath = Path.GetFullPath(path);
        Directory.CreateDirectory(Path.GetDirectoryName(fullPath)!);
        File.WriteAllText(fullPath, contents, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
    }

    private static IReadOnlyList<SysmonPipeEvent> ReadEventsForEndpoints(IReadOnlyList<PipeEndpoint> endpoints, string databasePath)
    {
        if (endpoints.Count == 0 || !File.Exists(databasePath)) return Array.Empty<SysmonPipeEvent>();
        try
        {
            var names = new HashSet<string>(endpoints.Select(endpoint => endpoint.Name), StringComparer.OrdinalIgnoreCase);
            return new SqliteHistoryStore(databasePath).GetRecentEvents(500)
                .Where(item => item.IsCorrelated && names.Contains(item.PipeName)).ToArray();
        }
        catch (Microsoft.Data.Sqlite.SqliteException ex)
        {
            Console.Error.WriteLine($"Unable to read cached activity for report: {ex.Message}");
            return Array.Empty<SysmonPipeEvent>();
        }
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
    private static async Task<IReadOnlyList<PipeEndpoint>> InspectSecurityWindowsAsync(IReadOnlyList<PipeEndpoint> endpoints, bool showProgress)
    {
        if (endpoints.Count == 0) return endpoints;
        var inspector = new PipeSecurityInspector();
        var analyzer = new PipeRiskAnalyzer();
        if (!showProgress)
        {
            var directResults = new List<PipeEndpoint>(endpoints.Count);
            foreach (var endpoint in endpoints)
            {
                if (endpoint.IpcMechanism != "NamedPipe") { directResults.Add(endpoint); continue; }
                var inspected = inspector.Inspect(endpoint);
                directResults.Add(inspected.SecurityStatus == "Inspected"
                    ? inspected with { Findings = analyzer.Analyze(inspected) }
                    : inspected);
            }
            return directResults;
        }
        return await AnsiConsole.Progress()
            .Columns(new TaskDescriptionColumn(), new ProgressBarColumn(), new PercentageColumn(), new SpinnerColumn())
            .StartAsync(context =>
        {
            var task = context.AddTask("Inspecting permissions and process context", maxValue: endpoints.Count);
            var results = new List<PipeEndpoint>(endpoints.Count);
            foreach (var endpoint in endpoints)
            {
                if (endpoint.IpcMechanism != "NamedPipe")
                {
                    results.Add(endpoint);
                    task.Increment(1);
                    continue;
                }
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
        AnsiConsole.Write(Align.Center(new Markup("[grey]Windows IPC and Sensitive Handle Mapper[/]")));
        AnsiConsole.WriteLine();
    }

    private static void ShowHelp()
    {
        var table = new Table().Border(TableBorder.Rounded).BorderColor(Color.Grey35);
        table.AddColumn(new TableColumn("[cyan]Command[/]"));
        table.AddColumn(new TableColumn("[cyan]Description[/]"));
        table.AddRow("[white]sutra scan[/]", "Inventory IPC and investigate handles to LSASS, browsers, tokens, and critical files.");
        table.AddRow("[white]sutra scan --inspect-acl[/]", "Also inspect named-pipe ACLs, process context, services, and permissions.");
        table.AddRow("[white]sutra scan --mechanisms named-pipe,rpc[/]", "Select one or more IPC discovery modules.");
        table.AddRow("[white]sutra scan --snapshot[/]", "Save IPC and sensitive-handle findings for later reports.");
        table.AddRow("[white]sutra history[/]", "List saved scan snapshots.");
        table.AddRow("[white]sutra changes[/]", "Compare the two most recent snapshots.");
        table.AddRow("[white]sutra events[/]", "Ingest and correlate Sysmon pipe events 17 and 18.");
        table.AddRow("[white]sutra events --since-hours 48[/]", "Set the event lookback window (1–720 hours).");
        table.AddRow("[white]sutra activity[/]", "Show the saved Sysmon pipe event timeline.");
        table.AddRow("[white]sutra report[/]", "Render the latest saved snapshot or export a report.");
        table.AddRow("[white]sutra dashboard[/]", "Open the interactive terminal menu.");
        table.AddRow("[white]--db <path>[/]", "Select the SQLite database file for history and events.");
        table.AddRow("[white]--format table|ascii|json|dot[/]", "Choose a terminal view or report format for scan/report.");
        table.AddRow("[white]--search <text> --sort <field>[/]", "Search and order endpoint results.");
        table.AddRow("[white]--mechanism <type>[/]", "Filter results by named-pipe, rpc, com, or alpc.");
        table.AddRow("[white]--mechanisms <list>[/]", "Select discovery modules, for example named-pipe,rpc.");
        table.AddRow("[white]--output <path>[/]", "Write the selected report format to a file.");
        table.AddRow("[white]sutra help[/]", "Show this help.");
        AnsiConsole.Write(table);
        AnsiConsole.MarkupLine("[grey]ACL inspection opens named pipes and may briefly connect to their servers. This can trigger server connection handling.[/]");
        AnsiConsole.MarkupLine("[grey]RPC, COM, and ALPC results are registration or name inventories. They do not identify every live server process. ALPC coverage is best effort.[/]");
        AnsiConsole.MarkupLine("[grey]Sensitive handle findings are best effort and limited by process access; SUTRA does not enable debug privileges.[/]");
        AnsiConsole.MarkupLine("[grey]Permission findings are contextual indicators. They do not prove exploitability or evaluate effective access across all ACEs.[/]");
        AnsiConsole.MarkupLine("[grey]Sysmon correlation requires Sysmon and readable Event ID 17/18 records in Microsoft-Windows-Sysmon/Operational.[/]");
    }

    private static void RenderResults(IReadOnlyList<PipeEndpoint> endpoints, bool aclRequested,
        IReadOnlyList<DiscoveryResult>? discoveryResults = null, SensitiveHandleScanResult? sensitiveHandles = null)
    {
        var table = new Table().Border(TableBorder.Rounded).BorderColor(Color.Grey35);
        table.AddColumn("Mechanism");
        table.AddColumn(new TableColumn("Endpoint").NoWrap());
        table.AddColumn("Status");
        if (aclRequested)
        {
            table.AddColumn("ACL");
            table.AddColumn("Owner SID");
            table.AddColumn("ACEs");
        }
        table.AddColumn("PID");

        foreach (var endpoint in endpoints)
        {
            var discovery = endpoint.DiscoveryStatus switch
            {
                "Discovered" => "[green]Found[/]",
                "Registered" => "[cyan]Registered[/]",
                _ => "[red]Unavailable[/]"
            };
            var pid = endpoint.ServerProcessId?.ToString() ?? "[grey]—[/]";
            if (aclRequested)
            {
                var status = endpoint.IpcMechanism != "NamedPipe" ? "[grey]N/A[/]"
                    : endpoint.SecurityStatus == "Inspected" ? "[green]Read[/]" : "[yellow]Unavailable[/]";
                table.AddRow(Markup.Escape(endpoint.IpcMechanism), Markup.Escape(Shorten(endpoint.Name, 38)), discovery, status,
                    Markup.Escape(Shorten(endpoint.OwnerSid ?? "—", 24)), endpoint.AccessEntries?.Count.ToString() ?? "—", pid);
            }
            else table.AddRow(Markup.Escape(endpoint.IpcMechanism), Markup.Escape(Shorten(endpoint.Name, 46)), discovery, pid);
        }

        AnsiConsole.Write(table);
        AnsiConsole.WriteLine();
        var inspectedCount = endpoints.Count(e => e.SecurityStatus == "Inspected");
        var pipeCount = endpoints.Count(endpoint => endpoint.IpcMechanism == "NamedPipe");
        AnsiConsole.MarkupLine($"[cyan]Scan summary[/]  endpoints [white]{endpoints.Count}[/]  ·  security descriptors [white]{inspectedCount}[/]/{(aclRequested ? pipeCount : 0)} pipes  ·  process contexts [white]{endpoints.Count(e => e.ServerProcessId.HasValue)}[/]");
        var mechanismSummary = string.Join("  ·  ", endpoints.GroupBy(endpoint => endpoint.IpcMechanism, StringComparer.OrdinalIgnoreCase)
            .OrderBy(group => group.Key, StringComparer.OrdinalIgnoreCase).Select(group => $"{Markup.Escape(group.Key)} [white]{group.Count()}[/]"));
        AnsiConsole.MarkupLine("[cyan]Mechanisms[/]  " + (mechanismSummary.Length == 0 ? "[grey]none[/]" : mechanismSummary));
        if (discoveryResults is { Count: > 0 })
        {
            var coverage = new Table().Border(TableBorder.Simple);
            coverage.AddColumn("Module"); coverage.AddColumn("Endpoints"); coverage.AddColumn("Coverage");
            foreach (var result in discoveryResults)
                coverage.AddRow(result.Mechanism, result.Error is null ? result.Endpoints.Count.ToString() : "[yellow]Unavailable[/]",
                    Markup.Escape(Shorten(result.Error ?? result.Coverage, 52)));
            AnsiConsole.Write(coverage);
        }
        if (aclRequested)
        {
            var allFindings = endpoints.SelectMany(e => e.Findings ?? Array.Empty<RiskFinding>()).ToArray();
            var counters = Enum.GetValues<RiskSeverity>().Select(severity => $"{severity} [white]{allFindings.Count(f => f.Severity == severity)}[/]");
            AnsiConsole.MarkupLine("[cyan]Risk summary[/]  " + string.Join("  ·  ", counters));
        }

        if (aclRequested)
        {
            var aclRows = endpoints.Where(e => e.IpcMechanism == "NamedPipe" && e.AccessEntries is not null).ToArray();
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
        RenderSensitiveHandles(sensitiveHandles);
    }

    private static void RenderSensitiveHandles(SensitiveHandleScanResult? scan)
    {
        if (scan is null) return;
        AnsiConsole.WriteLine();
        AnsiConsole.MarkupLine($"[cyan]Sensitive handle review[/]  findings [white]{scan.Findings.Count}[/]  · system handles [white]{scan.SystemHandleCount}[/]  · candidates [white]{scan.CandidateHandleCount}[/]  · inaccessible processes [white]{scan.InaccessibleProcessCount}[/]");
        AnsiConsole.MarkupLine($"[grey]{Markup.Escape(scan.Error ?? scan.Coverage)}[/]");
        if (scan.Findings.Count == 0)
        {
            AnsiConsole.MarkupLine("[grey]No matching sensitive handles were identified in the accessible handle set.[/]");
            return;
        }
        var table = new Table().Border(TableBorder.Rounded);
        table.AddColumn("Holder"); table.AddColumn("PID"); table.AddColumn("Object"); table.AddColumn("Target"); table.AddColumn("Handles"); table.AddColumn("Access");
        foreach (var finding in scan.Findings)
            table.AddRow(Markup.Escape(finding.HolderProcessName), finding.HolderProcessId.ToString(),
                Markup.Escape(finding.ObjectCategory), Markup.Escape(Shorten(finding.Target, 70)),
                finding.HandleCount.ToString(), $"0x{finding.GrantedAccess:X8} {Markup.Escape(finding.AccessRights)}");
        AnsiConsole.Write(table);
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
