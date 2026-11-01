# SUTRA

SUTRA is a Windows command-line tool for inspecting the named-pipe IPC attack surface. It inventories pipe endpoints and can inspect their security owners, access-control entries (ACEs), server process contexts, and associated Windows services. It presents contextual permission findings with severity, explanations, and remediation guidance.

The default scan enumerates pipe names without connecting to endpoints. Security and process inspection is opt-in because it opens a client handle to each available pipe. This can briefly connect to a server and trigger its connection handling. Use inspection only where that side effect is acceptable.

## Requirements

- Windows 10 or later
- .NET 10 SDK to build from source

## Install from source

Clone the repository and publish a self-contained Windows executable:

```powershell
git clone https://github.com/cranbru/sutra.git
Set-Location sutra
dotnet publish .\src\Sutra.Cli\Sutra.Cli.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true
```

The executable is created at:

```text
src/Sutra.Cli/bin/Release/net10.0/win-x64/publish/sutra.exe
```

The self-contained build includes the .NET runtime. To build for Windows on ARM64, use `-r win-arm64` in the publish command.

## Usage

Run a named-pipe inventory:

```powershell
& .\src\Sutra.Cli\bin\Release\net10.0\win-x64\publish\sutra.exe scan
```

Inspect permissions and server context:

```powershell
& .\src\Sutra.Cli\bin\Release\net10.0\win-x64\publish\sutra.exe scan --inspect-acl
```

Save a point-in-time inventory and compare it with the prior saved snapshot:

```powershell
& .\src\Sutra.Cli\bin\Release\net10.0\win-x64\publish\sutra.exe scan --snapshot
```

Save ACL and process metadata in the snapshot by combining `--inspect-acl` and `--snapshot`. These snapshots contain the inspection results gathered at that time.

Review snapshots, compare the latest pair, ingest Sysmon pipe events, or view the stored event timeline:

```powershell
& .\src\Sutra.Cli\bin\Release\net10.0\win-x64\publish\sutra.exe history
& .\src\Sutra.Cli\bin\Release\net10.0\win-x64\publish\sutra.exe changes
& .\src\Sutra.Cli\bin\Release\net10.0\win-x64\publish\sutra.exe events --since-hours 24
& .\src\Sutra.Cli\bin\Release\net10.0\win-x64\publish\sutra.exe activity
```

Open the interactive menu or export a report from the latest saved snapshot:

```powershell
& .\src\Sutra.Cli\bin\Release\net10.0\win-x64\publish\sutra.exe dashboard
& .\src\Sutra.Cli\bin\Release\net10.0\win-x64\publish\sutra.exe report --format json --output .\sutra-report.json
& .\src\Sutra.Cli\bin\Release\net10.0\win-x64\publish\sutra.exe report --format dot --output .\sutra-relationships.dot
```

Choose `table`, `ascii`, `json`, or `dot` with `--format`. `scan` and `report` accept `--output <path>`; JSON contains scan metadata, severity totals, observed events, endpoint security information, and findings. DOT exports process, service, pipe, and correlated event relationships when that metadata is available.

Filter and order scan results with `--scope <pipe-name-prefix>`, `--search <text>`, `--process <name>`, `--service <name>`, `--elevated true|false`, `--severity <level>`, `--sort name|pid|severity`, `--order asc|desc`, and `--limit <count>`. For example:

```powershell
& .\src\Sutra.Cli\bin\Release\net10.0\win-x64\publish\sutra.exe scan --inspect-acl --severity high --sort severity --order desc --format json --output .\high-risk.json
```

Use `--db <path>` with snapshot capture, scan or snapshot reports, history, changes, events, or activity commands to select a database other than the default `%LOCALAPPDATA%\Sutra\sutra.db`.

For `scan`, `--snapshot` saves the complete discovered inventory before display filters are applied. A report can filter that snapshot without changing the stored baseline. `report --snapshot <id>` exports a specific saved snapshot; `latest` is the default.

Show command help:

```powershell
& .\src\Sutra.Cli\bin\Release\net10.0\win-x64\publish\sutra.exe help
```

`--inspect-acl` opens each available endpoint to retrieve its security descriptor and server process ID. It also attempts to read the process user SID, elevation state, and services hosted in that process. Busy, inaccessible, exited, or protected processes may provide incomplete metadata. Use this option only where briefly triggering endpoint connection handling is acceptable.

`events` reads Event IDs 17 and 18 from `Microsoft-Windows-Sysmon/Operational` for the selected lookback window, normalizes pipe-name prefixes, and matches event names against the current name-only inventory. It stores distinct events by channel and record ID. Sysmon must be installed with pipe event logging enabled, and the current account must be able to read the channel. `activity` reads previously ingested events from SQLite without querying the event log.

SUTRA stores snapshots and event history in a local SQLite database under `%LOCALAPPDATA%\Sutra\sutra.db` by default. The database can contain pipe names, process names and IDs, SIDs, ACL entries, findings, timestamps, and event data. Keep it local or protect it according to your organization’s data-handling rules.

## What the results mean

- **Endpoint** is the pipe name discovered in the Windows named-pipe namespace.
- **Found** means the endpoint appeared in the enumeration.
- **ACL** indicates whether its security descriptor could be read.
- **Owner SID** identifies the descriptor owner when available.
- **DACL state** distinguishes a present DACL from a null or absent DACL. A null or absent DACL does not restrict access.
- **ACEs** lists access-control entries with the type, trustee SID, access mask, and flags.
- **PID** identifies the server process when Windows returns it for the connected pipe handle.
- **Process context** shows the process name, user SID, token elevation state, and associated services when available.

Permission findings focus on allow ACEs for broad local principals and distinguish read access from write or security-control permissions. A null or absent DACL is reported as unrestricted. Severity reflects the known server context; when that context is unknown, write findings remain medium rather than assuming a privileged server. Recommendations are provided with each finding.

Findings are indicators for review, not proof of exploitability. The current analysis does not fully evaluate effective access across ordered, inherited, conditional, or group-derived ACEs, nor does it inspect each server's application protocol. Pipe names and process metadata are a point-in-time view and can change during a scan. Event correlation matches names against the live inventory at import time; it does not prove that an event created or connected to the same endpoint instance.

## Build and test

```powershell
dotnet build .\Sutra.slnx -c Release
dotnet test .\Sutra.slnx -c Release
```
