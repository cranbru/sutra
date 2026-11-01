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

Show command help:

```powershell
& .\src\Sutra.Cli\bin\Release\net10.0\win-x64\publish\sutra.exe help
```

`--inspect-acl` opens each available endpoint to retrieve its security descriptor and server process ID. It also attempts to read the process user SID, elevation state, and services hosted in that process. Busy, inaccessible, exited, or protected processes may provide incomplete metadata. Use this option only where briefly triggering endpoint connection handling is acceptable.

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

Findings are indicators for review, not proof of exploitability. The current analysis does not fully evaluate effective access across ordered, inherited, conditional, or group-derived ACEs, nor does it inspect each server's application protocol. Pipe names and process metadata are a point-in-time view and can change during a scan.

## Build and test

```powershell
dotnet build .\Sutra.slnx -c Release
dotnet test .\Sutra.slnx -c Release
```

## License

No license has been specified yet.
