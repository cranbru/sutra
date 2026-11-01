using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;
using Sutra.Cli.Models;

namespace Sutra.Cli.Native;

[SupportedOSPlatform("windows")]
public sealed class PipeSecurityInspector
{
    private const uint ReadControl = 0x00020000;
    private const uint GenericRead = 0x80000000;
    private const uint OwnerInformation = 0x00000001;
    private const uint DaclInformation = 0x00000004;
    private const int SeKernelObject = 6;
    private static readonly Lazy<IReadOnlyDictionary<uint, IReadOnlyList<string>>> ServiceProcessMap = new(BuildServiceProcessMap);

    public PipeEndpoint Inspect(PipeEndpoint endpoint)
    {
        using var pipe = CreateFileW(endpoint.Path, GenericRead | ReadControl, 3, IntPtr.Zero, 3, 0, IntPtr.Zero);
        if (pipe.IsInvalid)
            return endpoint with { SecurityStatus = "Unavailable", Error = new Win32Exception(Marshal.GetLastWin32Error(), "Opening pipe failed.").Message };

        IntPtr descriptor = IntPtr.Zero;
        try
        {
            var result = GetSecurityInfo(pipe, SeKernelObject, OwnerInformation | DaclInformation,
                out var owner, out _, out _, out _, out descriptor);
            if (result != 0) throw new Win32Exception(result, "GetSecurityInfo failed.");

            var length = GetSecurityDescriptorLength(descriptor);
            if (length == 0 || length > 1024 * 1024)
                throw new InvalidOperationException("Windows returned an invalid security descriptor length.");

            var bytes = new byte[length];
            Marshal.Copy(descriptor, bytes, 0, (int)length);
            var raw = new RawSecurityDescriptor(bytes, 0);
            var ownerSid = raw.Owner?.Value ?? ReadSid(owner);
            var daclState = raw.DiscretionaryAcl is not null ? "Present"
                : (raw.ControlFlags & ControlFlags.DiscretionaryAclPresent) != 0 ? "Null DACL" : "DACL absent";
            var entries = new List<PipeAce>();
            if (raw.DiscretionaryAcl is not null)
            {
                foreach (GenericAce ace in raw.DiscretionaryAcl)
                {
                    if (ace is not QualifiedAce qualified) continue;
                    var type = qualified.AceQualifier == AceQualifier.AccessAllowed ? "Allow"
                        : qualified.AceQualifier == AceQualifier.AccessDenied ? "Deny" : qualified.AceQualifier.ToString();
                    var sid = qualified.SecurityIdentifier?.Value ?? "(unknown SID)";
                    var flags = qualified.AceFlags == AceFlags.None ? "None" : qualified.AceFlags.ToString();
                    entries.Add(new PipeAce(type, sid, $"0x{qualified.AccessMask:X8}", flags));
                }
            }

            var context = ReadServerContext(pipe);
            return endpoint with
            {
                SecurityStatus = "Inspected",
                OwnerSid = ownerSid,
                DaclState = daclState,
                AccessEntries = entries,
                ServerProcessId = context.ProcessId,
                ProcessName = context.ProcessName,
                ProcessUserSid = context.UserSid,
                ProcessIsElevated = context.IsElevated,
                ServiceNames = context.ServiceNames
            };
        }
        catch (Exception ex) when (ex is Win32Exception or InvalidOperationException or ArgumentException or System.Security.SecurityException)
        {
            return endpoint with { SecurityStatus = "Unavailable", Error = ex.Message };
        }
        finally
        {
            if (descriptor != IntPtr.Zero) LocalFree(descriptor);
        }
    }

    private static ProcessContext ReadServerContext(SafeFileHandle pipe)
    {
        if (!GetNamedPipeServerProcessId(pipe, out var pid))
            return new ProcessContext(null, null, null, null, Array.Empty<string>());

        string? name = null;
        string? userSid = null;
        bool? elevated = null;
        try
        {
            using var process = Process.GetProcessById(checked((int)pid));
            name = process.ProcessName;
            using var processHandle = OpenProcess(0x1000, false, pid);
            if (!processHandle.IsInvalid && OpenProcessToken(processHandle, 0x0008, out var token))
            {
                using (token)
                {
                    userSid = ReadTokenUserSid(token);
                    elevated = ReadTokenElevation(token);
                }
            }
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or Win32Exception or OverflowException)
        {
            // The process can exit or deny metadata access after pipe enumeration.
        }

        return new ProcessContext(pid, name, userSid, elevated, FindServices(pid));
    }

    private static string? ReadTokenUserSid(SafeAccessTokenHandle token)
    {
        GetTokenInformation(token, 1, IntPtr.Zero, 0, out var size);
        if (size == 0) return null;
        var buffer = Marshal.AllocHGlobal((int)size);
        try
        {
            if (!GetTokenInformation(token, 1, buffer, size, out _)) return null;
            var sidAndAttributes = Marshal.PtrToStructure<SidAndAttributes>(buffer);
            return sidAndAttributes.Sid == IntPtr.Zero ? null : new SecurityIdentifier(sidAndAttributes.Sid).Value;
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }

    private static bool? ReadTokenElevation(SafeAccessTokenHandle token)
    {
        var elevation = 0;
        var buffer = Marshal.AllocHGlobal(sizeof(int));
        try
        {
            if (!GetTokenInformation(token, 20, buffer, sizeof(int), out _)) return null;
            elevation = Marshal.ReadInt32(buffer);
            return elevation != 0;
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }

    private static IReadOnlyList<string> FindServices(uint processId) =>
        ServiceProcessMap.Value.TryGetValue(processId, out var services) ? services : Array.Empty<string>();

    private static IReadOnlyDictionary<uint, IReadOnlyList<string>> BuildServiceProcessMap()
    {
        var manager = OpenSCManagerW(null, null, 0x0004);
        if (manager == IntPtr.Zero) return new Dictionary<uint, IReadOnlyList<string>>();
        try
        {
            uint bytesNeeded, count, resume = 0;
            EnumServicesStatusExW(manager, 0, 0x30, 0x03, IntPtr.Zero, 0, out bytesNeeded, out _, ref resume, null);
            if (bytesNeeded == 0) return new Dictionary<uint, IReadOnlyList<string>>();
            var buffer = Marshal.AllocHGlobal(checked((int)bytesNeeded));
            try
            {
                resume = 0;
                if (!EnumServicesStatusExW(manager, 0, 0x30, 0x03, buffer, bytesNeeded, out _, out count, ref resume, null))
                    return new Dictionary<uint, IReadOnlyList<string>>();
                var size = Marshal.SizeOf<EnumServiceStatusProcess>();
                var matches = new Dictionary<uint, List<string>>();
                for (var i = 0; i < count; i++)
                {
                    var item = Marshal.PtrToStructure<EnumServiceStatusProcess>(IntPtr.Add(buffer, checked((int)i * size)));
                    if (item.ProcessId != 0 && item.ServiceName != IntPtr.Zero)
                    {
                        var serviceName = Marshal.PtrToStringUni(item.ServiceName);
                        if (!string.IsNullOrWhiteSpace(serviceName))
                        {
                            if (!matches.TryGetValue(item.ProcessId, out var services)) matches[item.ProcessId] = services = new List<string>();
                            services.Add(serviceName);
                        }
                    }
                }
                return matches.ToDictionary(pair => pair.Key, pair => (IReadOnlyList<string>)pair.Value);
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }
        catch (Exception ex) when (ex is OverflowException or AccessViolationException)
        {
            return new Dictionary<uint, IReadOnlyList<string>>();
        }
        finally { CloseServiceHandle(manager); }
    }

    private static string? ReadSid(IntPtr pointer)
    {
        if (pointer == IntPtr.Zero) return null;
        try { return new SecurityIdentifier(pointer).Value; }
        catch (ArgumentException) { return null; }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SidAndAttributes { public IntPtr Sid; public uint Attributes; }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct EnumServiceStatusProcess
    {
        public IntPtr ServiceName;
        public IntPtr DisplayName;
        public uint ServiceType;
        public uint CurrentState;
        public uint ControlsAccepted;
        public uint Win32ExitCode;
        public uint ServiceSpecificExitCode;
        public uint CheckPoint;
        public uint WaitHint;
        public uint ProcessId;
        public uint ServiceFlags;
    }

    private sealed record ProcessContext(uint? ProcessId, string? ProcessName, string? UserSid, bool? IsElevated, IReadOnlyList<string> ServiceNames);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "CreateFileW")]
    private static extern SafeFileHandle CreateFileW(string fileName, uint desiredAccess, uint shareMode, IntPtr securityAttributes,
        uint creationDisposition, uint flagsAndAttributes, IntPtr templateFile);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern int GetSecurityInfo(SafeFileHandle handle, int objectType, uint securityInfo,
        out IntPtr owner, out IntPtr group, out IntPtr dacl, out IntPtr sacl, out IntPtr securityDescriptor);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetNamedPipeServerProcessId(SafeFileHandle pipe, out uint serverProcessId);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern uint GetSecurityDescriptorLength(IntPtr securityDescriptor);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr memory);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern SafeProcessHandle OpenProcess(uint desiredAccess, bool inheritHandle, uint processId);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(SafeProcessHandle processHandle, uint desiredAccess, out SafeAccessTokenHandle tokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetTokenInformation(SafeAccessTokenHandle tokenHandle, int tokenInformationClass,
        IntPtr tokenInformation, uint tokenInformationLength, out uint returnLength);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "OpenSCManagerW")]
    private static extern IntPtr OpenSCManagerW(string? machineName, string? databaseName, uint desiredAccess);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "EnumServicesStatusExW")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool EnumServicesStatusExW(IntPtr serviceManager, int infoLevel, uint serviceType, uint serviceState,
        IntPtr services, uint bufferSize, out uint bytesNeeded, out uint servicesReturned, ref uint resumeHandle, string? groupName);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseServiceHandle(IntPtr serviceHandle);
}
