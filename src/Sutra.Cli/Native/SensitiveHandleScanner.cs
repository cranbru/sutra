using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using Sutra.Cli.Models;

namespace Sutra.Cli.Native;

public static class SensitiveHandleScanner
{
    private const int SystemExtendedHandleInformation = 64;
    private const int ObjectTypeInformation = 2;
    private const int StatusInfoLengthMismatch = unchecked((int)0xC0000004);
    private const uint ProcessDuplicateHandle = 0x0040;
    private const uint ProcessQueryLimitedInformation = 0x1000;
    private const uint TokenQuery = 0x0008;
    private const uint DuplicateSameAccess = 0x00000002;
    private const int MaximumHandleEntries = 2_000_000;
    private const int MaximumNativeBufferBytes = 256 * 1024 * 1024;
    private const int MaximumFileNameQueries = 20_000;
    private static readonly TimeSpan FileQueryBudget = TimeSpan.FromSeconds(8);
    private static readonly TimeSpan FileQueryTimeout = TimeSpan.FromMilliseconds(200);
    private const int MaximumFileQueryTimeouts = 16;

    private static readonly HashSet<string> BrowserProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "chrome", "msedge", "firefox", "brave", "opera", "vivaldi", "iexplore"
    };

    public static SensitiveHandleScanResult Scan()
    {
        if (!OperatingSystem.IsWindows())
            return new SensitiveHandleScanResult(0, 0, 0, Array.Empty<SensitiveHandleFinding>(), "Unavailable",
                "Sensitive handle inspection requires Windows.");

        try
        {
            return ScanWindows();
        }
        catch (Exception ex) when (ex is not OutOfMemoryException and not StackOverflowException)
        {
            return new SensitiveHandleScanResult(0, 0, 0, Array.Empty<SensitiveHandleFinding>(), "Unavailable", ex.Message);
        }
    }

    public static string? ClassifyCriticalFilePath(string path)
    {
        var normalized = path.Replace('/', '\\').TrimEnd('\\');
        if (normalized.StartsWith("\\\\?\\", StringComparison.Ordinal)) normalized = normalized[4..];
        var lower = normalized.ToLowerInvariant();
        var fileName = Path.GetFileName(lower);

        if (lower.Contains("\\windows\\system32\\config\\", StringComparison.Ordinal)
            && fileName is "sam" or "system" or "security" or "software" or "default" or "components")
            return "Windows registry hive";
        if (lower.EndsWith("\\windows\\ntds\\ntds.dit", StringComparison.Ordinal)) return "Directory database";
        if (lower.Contains("\\microsoft\\protect\\", StringComparison.Ordinal)) return "DPAPI master key";
        if ((lower.Contains("\\google\\chrome\\user data\\", StringComparison.Ordinal)
                || lower.Contains("\\microsoft\\edge\\user data\\", StringComparison.Ordinal)
                || lower.Contains("\\mozilla\\firefox\\profiles\\", StringComparison.Ordinal))
            && fileName is "login data" or "cookies" or "web data" or "local state" or "key4.db" or "logins.json" or "cookies.sqlite")
            return "Browser credential store";
        if (fileName is "lsass.exe" or "winlogon.exe" or "csrss.exe" or "services.exe")
            return "Windows security process image";
        return null;
    }

    private static SensitiveHandleScanResult ScanWindows()
    {
        var currentPid = Environment.ProcessId;
        var sampleProcess = OpenProcess(ProcessDuplicateHandle | ProcessQueryLimitedInformation, false, currentPid);
        if (sampleProcess == IntPtr.Zero)
            throw new InvalidOperationException("Could not open a handle to the SUTRA process.");

        IntPtr sampleToken = IntPtr.Zero;
        IntPtr sampleFile = IntPtr.Zero;
        try
        {
            if (!OpenProcessToken(sampleProcess, TokenQuery, out sampleToken))
                throw new InvalidOperationException("Could not open a sample access token to identify token handles.");
            sampleFile = CreateFileW(Path.Combine(Environment.SystemDirectory, "kernel32.dll"), 0,
                0x00000001 | 0x00000002 | 0x00000004, IntPtr.Zero, 3, 0, IntPtr.Zero);

            var snapshot = QueryHandleSnapshot();
            try
            {
                var processType = FindTypeIndex(snapshot.Entries, currentPid, (ulong)sampleProcess.ToInt64(), "Process");
                var tokenType = FindTypeIndex(snapshot.Entries, currentPid, (ulong)sampleToken.ToInt64(), "Token");
                var fileType = sampleFile != new IntPtr(-1)
                    ? FindTypeIndex(snapshot.Entries, currentPid, (ulong)sampleFile.ToInt64(), "File")
                    : null;

                var processNames = ReadProcessNames();
                var lsassIds = processNames.Where(item => item.Value.Equals("lsass", StringComparison.OrdinalIgnoreCase))
                    .Select(item => item.Key).ToHashSet();
                var processHandles = new Dictionary<(int HolderPid, int TargetPid, uint Access), int>();
                var tokenHandles = new Dictionary<(int HolderPid, uint Access), int>();
                var fileHandles = new Dictionary<(int HolderPid, string Category, string Target, uint Access), int>();
                Stopwatch? fileQueryTimer = null;
                var fileNameQueries = 0;
                var timedOutFileQueries = 0;
                var fileScanLimited = false;
                var candidateEntries = new List<SystemHandleEntry>();
                foreach (var entry in snapshot.Entries)
                {
                    if (entry.ObjectTypeIndex == processType || entry.ObjectTypeIndex == tokenType
                        || (fileType.HasValue && entry.ObjectTypeIndex == fileType.Value))
                        candidateEntries.Add(entry);
                }
                var fileCandidateCount = fileType.HasValue
                    ? candidateEntries.Count(entry => entry.ObjectTypeIndex == fileType.Value)
                    : 0;

                var inaccessible = new HashSet<int>();
                var blockedFileHolders = new HashSet<int>();
                var fileTimeoutsByHolder = new Dictionary<int, int>();
                var sourceHandles = new Dictionary<int, IntPtr>();
                try
                {
                    foreach (var entry in candidateEntries)
                    {
                        var holderPid = unchecked((int)entry.UniqueProcessId.ToUInt64());
                        if (holderPid <= 0 || holderPid == currentPid) continue;
                        if (!sourceHandles.TryGetValue(holderPid, out var sourceProcess))
                        {
                            sourceProcess = OpenProcess(ProcessDuplicateHandle, false, holderPid);
                            if (sourceProcess == IntPtr.Zero)
                            {
                                inaccessible.Add(holderPid);
                                sourceHandles[holderPid] = IntPtr.Zero;
                                continue;
                            }
                            sourceHandles[holderPid] = sourceProcess;
                        }
                        if (sourceProcess == IntPtr.Zero) continue;

                        var duplicated = IntPtr.Zero;
                        if (!DuplicateHandle(sourceProcess, new IntPtr(unchecked((long)entry.HandleValue.ToUInt64())),
                                GetCurrentProcess(), out duplicated, 0, false, DuplicateSameAccess))
                            continue;
                        try
                        {
                            if (entry.ObjectTypeIndex == processType)
                            {
                                var targetPid = GetProcessId(duplicated);
                                if (targetPid == 0 || targetPid == holderPid) continue;
                                var targetName = processNames.TryGetValue(unchecked((int)targetPid), out var knownName)
                                    ? knownName : "unknown process";
                                var isLsass = lsassIds.Contains(unchecked((int)targetPid));
                                var isBrowser = BrowserProcesses.Contains(targetName);
                                if (!isLsass && !isBrowser) continue;
                                var key = (holderPid, unchecked((int)targetPid), entry.GrantedAccess);
                                processHandles[key] = processHandles.GetValueOrDefault(key) + 1;
                            }
                            else if (entry.ObjectTypeIndex == tokenType)
                            {
                                var key = (holderPid, entry.GrantedAccess);
                                tokenHandles[key] = tokenHandles.GetValueOrDefault(key) + 1;
                            }
                            else if (fileType.HasValue && entry.ObjectTypeIndex == fileType.Value)
                            {
                                if (fileScanLimited || blockedFileHolders.Contains(holderPid)) continue;
                                fileQueryTimer ??= Stopwatch.StartNew();
                                if (fileNameQueries >= MaximumFileNameQueries || fileQueryTimer.Elapsed >= FileQueryBudget
                                    || timedOutFileQueries >= MaximumFileQueryTimeouts)
                                {
                                    fileScanLimited = true;
                                    continue;
                                }
                                fileNameQueries++;
                                var fileHandle = duplicated;
                                var pathQuery = Task.Run(() => ReadFilePath(fileHandle));
                                if (!pathQuery.Wait(FileQueryTimeout))
                                {
                                    timedOutFileQueries++;
                                    var holderTimeouts = fileTimeoutsByHolder.GetValueOrDefault(holderPid) + 1;
                                    fileTimeoutsByHolder[holderPid] = holderTimeouts;
                                    if (holderTimeouts >= 2) blockedFileHolders.Add(holderPid);
                                    duplicated = IntPtr.Zero;
                                    _ = pathQuery.ContinueWith(_ => CloseHandle(fileHandle), CancellationToken.None,
                                        TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
                                    continue;
                                }
                                var path = pathQuery.GetAwaiter().GetResult();
                                if (path is null) continue;
                                var category = ClassifyCriticalFilePath(path);
                                if (category is null) continue;
                                var key = (holderPid, category, path, entry.GrantedAccess);
                                fileHandles[key] = fileHandles.GetValueOrDefault(key) + 1;
                            }
                        }
                        finally { if (duplicated != IntPtr.Zero) CloseHandle(duplicated); }
                    }
                }
                finally
                {
                    foreach (var handle in sourceHandles.Values.Where(handle => handle != IntPtr.Zero)) CloseHandle(handle);
                }

                var findings = new List<SensitiveHandleFinding>();
                foreach (var item in processHandles)
                {
                    var targetName = processNames.TryGetValue(item.Key.TargetPid, out var value) ? value : "unknown process";
                    var category = lsassIds.Contains(item.Key.TargetPid) ? "LSASS process" : "Browser process";
                    findings.Add(new SensitiveHandleFinding(item.Key.HolderPid, ProcessLabel(item.Key.HolderPid, processNames),
                        category, $"{targetName} (PID {item.Key.TargetPid})", item.Value, item.Key.Access,
                        DescribeAccess(category, item.Key.Access)));
                }
                foreach (var item in tokenHandles)
                    findings.Add(new SensitiveHandleFinding(item.Key.HolderPid, ProcessLabel(item.Key.HolderPid, processNames),
                        "Security token", "Access token", item.Value, item.Key.Access,
                        DescribeAccess("Security token", item.Key.Access)));
                foreach (var item in fileHandles)
                    findings.Add(new SensitiveHandleFinding(item.Key.HolderPid, ProcessLabel(item.Key.HolderPid, processNames),
                        item.Key.Category, item.Key.Target, item.Value, item.Key.Access,
                        DescribeAccess(item.Key.Category, item.Key.Access)));

                var coverage = inaccessible.Count == 0
                    ? "Best effort; protected or transient handles may not be visible, and some process targets may lack query rights. SUTRA does not enable debug privileges."
                    : $"Partial; {inaccessible.Count} processes could not be opened for handle duplication, and some process targets may lack query rights. SUTRA does not enable debug privileges.";
                if (snapshot.Truncated) coverage += " The system handle table exceeded the scan limit.";
                if (!fileType.HasValue) coverage += " Critical file handles could not be identified on this system.";
                if (fileScanLimited) coverage += " Critical file-name inspection reached its time, query, or timeout limit.";
                coverage += $" Checked {fileNameQueries} of {fileCandidateCount} file handles; {timedOutFileQueries} name queries timed out.";
                return new SensitiveHandleScanResult(checked((int)Math.Min(snapshot.TotalCount, (ulong)int.MaxValue)), candidateEntries.Count, inaccessible.Count,
                    findings.OrderBy(item => item.ObjectCategory, StringComparer.OrdinalIgnoreCase)
                        .ThenBy(item => item.HolderProcessName, StringComparer.OrdinalIgnoreCase)
                        .ThenBy(item => item.Target, StringComparer.OrdinalIgnoreCase).ToArray(), coverage,
                    FileHandleCandidateCount: fileCandidateCount, FileNameQueryCount: fileNameQueries,
                    FileNameQueryTimeoutCount: timedOutFileQueries);
            }
            finally { Marshal.FreeHGlobal(snapshot.Buffer); }
        }
        finally
        {
            if (sampleFile != IntPtr.Zero && sampleFile != new IntPtr(-1)) CloseHandle(sampleFile);
            if (sampleToken != IntPtr.Zero) CloseHandle(sampleToken);
            CloseHandle(sampleProcess);
        }
    }

    private static HandleSnapshot QueryHandleSnapshot()
    {
        var bufferSize = 1024 * 1024;
        for (var attempt = 0; attempt < 8; attempt++)
        {
            if (bufferSize > MaximumNativeBufferBytes) throw new InvalidOperationException("System handle inventory exceeds the supported size.");
            var buffer = Marshal.AllocHGlobal(bufferSize);
            var status = NtQuerySystemInformation(SystemExtendedHandleInformation, buffer, bufferSize, out var returned);
            if (status == 0)
            {
                var count = Marshal.ReadIntPtr(buffer).ToInt64();
                if (count < 0) { Marshal.FreeHGlobal(buffer); throw new InvalidOperationException("The system returned an invalid handle count."); }
                var total = (ulong)count;
                var scanCount = (int)Math.Min(total, MaximumHandleEntries);
                var entrySize = Marshal.SizeOf<SystemHandleEntry>();
                var entries = new List<SystemHandleEntry>(scanCount);
                var firstEntry = IntPtr.Add(buffer, IntPtr.Size * 2);
                for (var index = 0; index < scanCount; index++)
                    entries.Add(Marshal.PtrToStructure<SystemHandleEntry>(IntPtr.Add(firstEntry, checked(index * entrySize))));
                return new HandleSnapshot(buffer, total, entries, total > (ulong)MaximumHandleEntries);
            }
            Marshal.FreeHGlobal(buffer);
            if (status != StatusInfoLengthMismatch) throw new InvalidOperationException($"System handle inventory query failed (NTSTATUS 0x{status:X8}).");
            bufferSize = returned > bufferSize ? checked((int)returned + 64 * 1024) : checked(bufferSize * 2);
        }
        throw new InvalidOperationException("System handle inventory changed too quickly to read.");
    }

    private static ushort? FindTypeIndex(IReadOnlyList<SystemHandleEntry> entries, int pid, ulong handleValue,
        string expectedType)
    {
        var entry = entries.FirstOrDefault(item => item.UniqueProcessId.ToUInt64() == (ulong)pid
            && item.HandleValue.ToUInt64() == handleValue);
        if (entry.HandleValue == UIntPtr.Zero) return null;
        var typeName = QueryObjectString(new IntPtr(unchecked((long)handleValue)), ObjectTypeInformation);
        if (typeName is null || !typeName.Equals(expectedType, StringComparison.OrdinalIgnoreCase)) return null;
        return entry.ObjectTypeIndex;
    }

    private static string? QueryObjectString(IntPtr handle, int informationClass)
    {
        var size = 1024;
        for (var attempt = 0; attempt < 5; attempt++)
        {
            var buffer = Marshal.AllocHGlobal(size);
            try
            {
                var status = NtQueryObject(handle, informationClass, buffer, size, out var returned);
                if (status == 0)
                {
                    var value = Marshal.PtrToStructure<UnicodeString>(buffer);
                    return value.Buffer == IntPtr.Zero || value.Length == 0
                        ? string.Empty : Marshal.PtrToStringUni(value.Buffer, value.Length / 2);
                }
                if (status != StatusInfoLengthMismatch) return null;
                size = returned > size ? checked((int)returned + 1024) : checked(size * 2);
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }
        return null;
    }

    private static string? ReadFilePath(IntPtr handle)
    {
        var buffer = new StringBuilder(32768);
        var length = GetFinalPathNameByHandleW(handle, buffer, (uint)buffer.Capacity, 0);
        return length == 0 || length >= buffer.Capacity ? null : buffer.ToString();
    }

    private static Dictionary<int, string> ReadProcessNames()
    {
        var result = new Dictionary<int, string>();
        foreach (var process in Process.GetProcesses())
        {
            using (process)
            {
                try { result[process.Id] = process.ProcessName; }
                catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception or NotSupportedException) { }
            }
        }
        return result;
    }

    private static string ProcessLabel(int pid, IReadOnlyDictionary<int, string> processNames) =>
        processNames.TryGetValue(pid, out var name) ? name : "unknown process";

    private static string DescribeAccess(string category, uint access)
    {
        var rights = new List<string>();
        if (category is "LSASS process" or "Browser process")
        {
            Add(0x0001, "TERMINATE"); Add(0x0002, "CREATE_THREAD"); Add(0x0008, "VM_OPERATION");
            Add(0x0010, "VM_READ"); Add(0x0020, "VM_WRITE"); Add(0x0040, "DUP_HANDLE");
            Add(0x0080, "CREATE_PROCESS"); Add(0x0100, "SET_QUOTA"); Add(0x0200, "SET_INFORMATION");
            Add(0x0400, "QUERY_INFORMATION"); Add(0x0800, "SUSPEND_RESUME"); Add(0x1000, "QUERY_LIMITED");
            Add(0x20000, "READ_CONTROL"); Add(0x40000, "WRITE_DAC"); Add(0x80000, "WRITE_OWNER");
        }
        else if (category == "Security token")
        {
            Add(0x0001, "ASSIGN_PRIMARY"); Add(0x0002, "DUPLICATE"); Add(0x0004, "IMPERSONATE");
            Add(0x0008, "QUERY"); Add(0x0020, "ADJUST_PRIVILEGES"); Add(0x0040, "ADJUST_GROUPS");
            Add(0x0080, "ADJUST_DEFAULT"); Add(0x0100, "ADJUST_SESSIONID"); Add(0x20000, "READ_CONTROL");
            Add(0x40000, "WRITE_DAC"); Add(0x80000, "WRITE_OWNER");
        }
        else
        {
            Add(0x0001, "READ_DATA"); Add(0x0002, "WRITE_DATA"); Add(0x0004, "APPEND_DATA");
            Add(0x0008, "READ_EA"); Add(0x0010, "WRITE_EA"); Add(0x00010000, "DELETE");
            Add(0x00000080, "READ_ATTRIBUTES"); Add(0x00000100, "WRITE_ATTRIBUTES");
            Add(0x00020000, "READ_CONTROL"); Add(0x00040000, "WRITE_DAC"); Add(0x00080000, "WRITE_OWNER");
            Add(0x80000000, "GENERIC_READ"); Add(0x40000000, "GENERIC_WRITE");
        }
        return rights.Count == 0 ? "No mapped rights" : string.Join(", ", rights);

        void Add(uint mask, string name) { if ((access & mask) != 0) rights.Add(name); }
    }

    private sealed record HandleSnapshot(IntPtr Buffer, ulong TotalCount, IReadOnlyList<SystemHandleEntry> Entries, bool Truncated);

    [StructLayout(LayoutKind.Sequential)]
    private struct SystemHandleEntry
    {
        public IntPtr Object;
        public UIntPtr UniqueProcessId;
        public UIntPtr HandleValue;
        public uint GrantedAccess;
        public ushort CreatorBackTraceIndex;
        public ushort ObjectTypeIndex;
        public uint HandleAttributes;
        public uint Reserved;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct UnicodeString
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    [DllImport("ntdll.dll")]
    private static extern int NtQuerySystemInformation(int informationClass, IntPtr information, int informationLength, out uint returnLength);

    [DllImport("ntdll.dll")]
    private static extern int NtQueryObject(IntPtr handle, int informationClass, IntPtr information, int informationLength, out uint returnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint desiredAccess, bool inheritHandle, int processId);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DuplicateHandle(IntPtr sourceProcess, IntPtr sourceHandle, IntPtr targetProcess,
        out IntPtr targetHandle, uint desiredAccess, bool inheritHandle, uint options);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll")]
    private static extern uint GetProcessId(IntPtr processHandle);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandleW(IntPtr fileHandle, StringBuilder filePath, uint filePathLength, uint flags);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateFileW(string fileName, uint desiredAccess, uint shareMode, IntPtr securityAttributes,
        uint creationDisposition, uint flagsAndAttributes, IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);
}
