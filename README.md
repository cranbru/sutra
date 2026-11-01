# SUTRA

SUTRA is a Windows only, read only IPC attack surface mapper. Stage 1 inventories named pipes from the Windows pipe namespace and can request owner and DACL metadata.

## Run

```powershell
dotnet run --project src/Sutra.Cli -- scan
dotnet run --project src/Sutra.Cli -- scan --inspect-acl
dotnet run --project src/Sutra.Cli -- help
```

`scan` enumerates pipe names only. `--inspect-acl` calls the Windows security API for each discovered pipe. Windows may need to open a client handle to obtain a pipe security descriptor; this can briefly connect to an available server and trigger its connection handling. Use the option only where that effect is acceptable. Inaccessible or busy pipes are reported with their Windows error.

Server process IDs are not queried in Stage 1. The documented named pipe server PID API requires a connected pipe handle, which can have the same endpoint side effect. SUTRA leaves the PID unavailable rather than connect silently or infer a process from a pipe name.

## Build and test

```powershell
dotnet build Sutra.slnx
dotnet test Sutra.slnx
```

## Stage 1 structure

```text
src/Sutra.Cli/
  Models/       Pipe endpoint and ACE records
  Native/       Windows pipe enumeration and security descriptor access
  Program.cs    CLI entry point
  SutraApp.cs   Spectre.Console startup, commands and result views
tests/Sutra.Tests/
  PipePathTests.cs
```

## Known limits

- Pipe names are a point in time inventory; endpoints can disappear during later inspection.
- Owner and DACL inspection can fail because the pipe is busy or access is denied.
- Process and service attribution is not included yet.
- Stage 1 does not score permissions or classify risk.
