using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using Sutra.Cli.Models;

namespace Sutra.Cli.Discovery;

[SupportedOSPlatform("windows")]
public sealed class AlpcDirectoryDiscoveryModule : IIpcDiscoveryModule
{
    private const uint DirectoryQuery = 0x0001;
    private const uint ObjectCaseInsensitive = 0x00000040;
    private const int StatusSuccess = 0;
    private const int StatusNoMoreEntries = unchecked((int)0x8000001A);

    public string Mechanism => "ALPC";

    public DiscoveryResult Discover()
    {
        var directory = OpenRpcControlDirectory();
        try
        {
            var endpoints = new List<PipeEndpoint>();
            var buffer = Marshal.AllocHGlobal(4096);
            try
            {
                uint context = 0;
                var restart = true;
                while (true)
                {
                    var status = NtQueryDirectoryObject(directory, buffer, 4096, true, restart, ref context, out _);
                    restart = false;
                    if (status == StatusNoMoreEntries) break;
                    if (status != StatusSuccess)
                        throw new Win32Exception(unchecked((int)RtlNtStatusToDosError(status)), $"ALPC directory enumeration failed (NTSTATUS 0x{status:X8}).");

                    var entry = Marshal.PtrToStructure<ObjectDirectoryInformation>(buffer);
                    var name = ReadUnicodeString(entry.Name);
                    var type = ReadUnicodeString(entry.TypeName);
                    if (!string.Equals(type, "ALPC Port", StringComparison.OrdinalIgnoreCase)
                        || string.IsNullOrWhiteSpace(name)) continue;
                    endpoints.Add(new PipeEndpoint(name, $@"\RPC Control\{name}", "Discovered",
                        IpcMechanism: Mechanism, DiscoveryDetails: $"ObjectType={type}; Directory=\\RPC Control"));
                }
            }
            finally { Marshal.FreeHGlobal(buffer); }

            return new DiscoveryResult(Mechanism, endpoints.OrderBy(item => item.Name, StringComparer.OrdinalIgnoreCase).ToArray(),
                Coverage: "Best-effort names visible in the RPC Control object directory; native enumeration is undocumented and does not reveal all ALPC ports or owning processes");
        }
        finally { NtClose(directory); }
    }

    private static IntPtr OpenRpcControlDirectory()
    {
        const string directoryName = @"\RPC Control";
        var nameBytes = Encoding.Unicode.GetBytes(directoryName);
        var nameBuffer = Marshal.AllocHGlobal(nameBytes.Length + 2);
        var unicodeStringPointer = Marshal.AllocHGlobal(Marshal.SizeOf<UnicodeString>());
        try
        {
            Marshal.Copy(nameBytes, 0, nameBuffer, nameBytes.Length);
            Marshal.WriteInt16(nameBuffer, nameBytes.Length, 0);
            Marshal.StructureToPtr(new UnicodeString
            {
                Length = checked((ushort)nameBytes.Length),
                MaximumLength = checked((ushort)(nameBytes.Length + 2)),
                Buffer = nameBuffer
            }, unicodeStringPointer, false);
            var attributes = new ObjectAttributes
            {
                Length = checked((uint)Marshal.SizeOf<ObjectAttributes>()),
                ObjectName = unicodeStringPointer,
                Attributes = ObjectCaseInsensitive
            };
            var status = NtOpenDirectoryObject(out var directory, DirectoryQuery, ref attributes);
            if (status != StatusSuccess)
                throw new Win32Exception(unchecked((int)RtlNtStatusToDosError(status)), $"Could not open \\RPC Control (NTSTATUS 0x{status:X8}).");
            return directory;
        }
        finally
        {
            Marshal.FreeHGlobal(unicodeStringPointer);
            Marshal.FreeHGlobal(nameBuffer);
        }
    }

    private static string ReadUnicodeString(UnicodeString value) => value.Buffer == IntPtr.Zero || value.Length == 0
        ? string.Empty
        : Marshal.PtrToStringUni(value.Buffer, value.Length / 2) ?? string.Empty;

    [StructLayout(LayoutKind.Sequential)]
    private struct UnicodeString
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ObjectAttributes
    {
        public uint Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public uint Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ObjectDirectoryInformation
    {
        public UnicodeString Name;
        public UnicodeString TypeName;
    }

    [DllImport("ntdll.dll")]
    private static extern int NtOpenDirectoryObject(out IntPtr directoryHandle, uint desiredAccess, ref ObjectAttributes objectAttributes);

    [DllImport("ntdll.dll")]
    private static extern int NtQueryDirectoryObject(IntPtr directoryHandle, IntPtr buffer, uint length,
        [MarshalAs(UnmanagedType.U1)] bool returnSingleEntry, [MarshalAs(UnmanagedType.U1)] bool restartScan,
        ref uint context, out uint returnLength);

    [DllImport("ntdll.dll")]
    private static extern int NtClose(IntPtr handle);

    [DllImport("ntdll.dll")]
    private static extern uint RtlNtStatusToDosError(int status);
}
