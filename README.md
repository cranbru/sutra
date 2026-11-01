# SUTRA

SUTRA is a Windows command-line tool for inspecting the named-pipe IPC attack surface. It inventories pipe endpoints and can retrieve their security owners and access-control entries (ACEs), presenting results in a readable terminal interface.

The default scan enumerates pipe names without connecting to endpoints. Security inspection is optional because Windows may need to open a client handle to retrieve a pipe’s security descriptor. This can briefly connect to an available server and trigger its connection handling.

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

Request owner and DACL metadata as well:

```powershell
& .\src\Sutra.Cli\bin\Release\net10.0\win-x64\publish\sutra.exe scan --inspect-acl
```

Show command help:

```powershell
& .\src\Sutra.Cli\bin\Release\net10.0\win-x64\publish\sutra.exe help
```

`--inspect-acl` can briefly connect to an available endpoint while Windows retrieves its security descriptor. Busy or inaccessible endpoints are reported with the associated error. Use this option where that connection side effect is acceptable.

## What the results mean

- **Endpoint** is the pipe name discovered in the Windows named-pipe namespace.
- **Found** means the endpoint appeared in the enumeration.
- **ACL** indicates whether its security descriptor could be read.
- **Owner SID** identifies the descriptor owner when available.
- **ACEs** lists access-control entries with the type, trustee SID, access mask, and flags.
- **PID** is unavailable because SUTRA does not connect to endpoints to query server process IDs.

Pipe names are a point-in-time inventory. Endpoints can disappear or become busy between enumeration and optional security inspection. Process and service attribution, risk scoring, event correlation, and report export are not provided by the current command set.

## Build and test

```powershell
dotnet build .\Sutra.slnx -c Release
dotnet test .\Sutra.slnx -c Release
```

## License

No license has been specified yet.
