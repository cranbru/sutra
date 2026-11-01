using Spectre.Console;
using System.Runtime.Versioning;
using Sutra.Cli.Analysis;
using Sutra.Cli.Models;
using Sutra.Cli.Native;

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

        if (args[0] is not "scan")
        {
            AnsiConsole.MarkupLine("[red]Unknown command.[/] Run [cyan]sutra help[/] for usage.");
            return 2;
        }

        var inspectAcl = args.Contains("--inspect-acl", StringComparer.OrdinalIgnoreCase);
        var unknown = args.Skip(1).Where(a => a != "--inspect-acl").ToArray();
        if (unknown.Length > 0)
        {
            AnsiConsole.MarkupLine($"[red]Unknown scan option:[/] {Markup.Escape(unknown[0])}");
            return 2;
        }
        if (!OperatingSystem.IsWindows())
        {
            AnsiConsole.MarkupLine("[red]SUTRA requires Windows.[/]");
            return 2;
        }

        ShowBanner();
        AnsiConsole.MarkupLine("[grey]Named-pipe inventory · read-only metadata scan[/]");
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
        return 0;
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
        table.AddRow("[white]sutra help[/]", "Show this help.");
        AnsiConsole.Write(table);
        AnsiConsole.MarkupLine("[grey]Inspection opens each pipe and may briefly connect to its server. This can trigger server connection handling; use only when acceptable.[/]");
        AnsiConsole.MarkupLine("[grey]Permission findings are contextual indicators. They do not prove exploitability or evaluate effective access across all ACEs.[/]");
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
            table.AddColumn("PID");
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
