using Spectre.Console;
using System.Runtime.Versioning;
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
            AnsiConsole.MarkupLine("[red]SUTRA Stage 1 requires Windows.[/]");
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

        var inspected = inspectAcl ? InspectSecurityWindows(endpoints) : endpoints;
        RenderResults(inspected, inspectAcl);
        return 0;
    }

    [SupportedOSPlatform("windows")]
    private static IReadOnlyList<PipeEndpoint> InspectSecurityWindows(IReadOnlyList<PipeEndpoint> endpoints)
    {
        var inspector = new PipeSecurityInspector();
        var results = new List<PipeEndpoint>(endpoints.Count);
        foreach (var endpoint in endpoints) results.Add(inspector.Inspect(endpoint));
        return results;
    }

    private static void ShowBanner()
    {
        var art = new FigletText("SUTRA").Color(Color.Cyan1);
        AnsiConsole.Write(Align.Center(art));
        AnsiConsole.Write(Align.Center(new Markup("[grey]Windows IPC Attack Surface Mapper · Stage 1[/]")));
        AnsiConsole.WriteLine();
    }

    private static void ShowHelp()
    {
        var table = new Table().Border(TableBorder.Rounded).BorderColor(Color.Grey35);
        table.AddColumn(new TableColumn("[cyan]Command[/]"));
        table.AddColumn(new TableColumn("[cyan]Description[/]"));
        table.AddRow("[white]sutra scan[/]", "Discover named pipes without connecting to endpoints.");
        table.AddRow("[white]sutra scan --inspect-acl[/]", "Request owner and DACL metadata for discovered endpoints.");
        table.AddRow("[white]sutra help[/]", "Show this help.");
        AnsiConsole.Write(table);
        AnsiConsole.MarkupLine("[grey]ACL inspection opens pipe names through the Windows security API and may briefly connect to an available server. Use only when that side effect is acceptable.[/]");
        AnsiConsole.MarkupLine("[grey]Server process IDs are not queried; the available named-pipe API requires connecting to the endpoint.[/]");
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
        AnsiConsole.MarkupLine($"[cyan]Scan summary[/]  endpoints [white]{endpoints.Count}[/]  ·  security descriptors [white]{inspectedCount}[/]/{(aclRequested ? endpoints.Count : 0)}  ·  process IDs [grey]not queried[/]");

        if (aclRequested)
        {
            var aclRows = endpoints.Where(e => e.AccessEntries is not null).ToArray();
            foreach (var endpoint in aclRows)
            {
                AnsiConsole.WriteLine();
                AnsiConsole.MarkupLine($"[cyan]{Markup.Escape(endpoint.Name)}[/] [grey]· owner {Markup.Escape(endpoint.OwnerSid ?? "—")}[/]");
                var aceTable = new Table().Border(TableBorder.Simple);
                aceTable.AddColumn("Type"); aceTable.AddColumn("Trustee SID"); aceTable.AddColumn("Mask"); aceTable.AddColumn("Flags");
                foreach (var ace in endpoint.AccessEntries!)
                    aceTable.AddRow(ace.Type, ace.Sid, ace.Rights, ace.Flags);
                if (endpoint.AccessEntries!.Count == 0) aceTable.AddRow("—", "No DACL entries returned", "—", "—");
                AnsiConsole.Write(aceTable);
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

    private static string Shorten(string value, int maxLength) => value.Length <= maxLength ? value : value[..(maxLength - 1)] + "…";
}
