# SUTRA

Windows attack surface mapper for named pipes, RPC, COM, ALPC, and sensitive process handles.

![SUTRA scan output](sutra-image.png)

## Install

Requires Windows 10 or later and the .NET 10 SDK.

```powershell
git clone https://github.com/cranbru/sutra.git
Set-Location sutra
dotnet publish .\src\Sutra.Cli\Sutra.Cli.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true
```

## Run

Run `scan` for the full IPC and sensitive-handle investigation. It reports processes holding handles to LSASS, browser processes, access tokens, Windows security files, and browser credential stores. Double-click `sutra.exe` to open the menu, or run commands in PowerShell:

```powershell
$sutra = ".\src\Sutra.Cli\bin\Release\net10.0\win-x64\publish\sutra.exe"
& $sutra scan
& $sutra scan --inspect-acl
& $sutra scan --snapshot
& $sutra scan --format json --output .\report.json
& $sutra history
& $sutra changes
& $sutra events
& $sutra activity
```

Handle results include holder process, target, handle count, and access mask with decoded rights. Coverage is best effort because protected or inaccessible processes may be omitted; SUTRA does not enable debug privileges. `--snapshot` saves handle findings for later reports.

With no arguments, SUTRA opens the interactive menu. Use `sutra help` to see all options.
