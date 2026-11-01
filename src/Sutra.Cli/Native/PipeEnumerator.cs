using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using Sutra.Cli.Models;

namespace Sutra.Cli.Native;

public sealed class PipeEnumerator
{
    private const int ErrorNoMoreFiles = 18;

    public IReadOnlyList<PipeEndpoint> Discover()
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("SUTRA named-pipe discovery requires Windows.");

        var results = new List<PipeEndpoint>();
        var handle = FindFirstFileW(@"\\.\pipe\*", out var data);
        if (handle == InvalidHandleValue)
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not enumerate the Windows named-pipe namespace.");

        using (new FindHandle(handle))
        {
            do
            {
                if (!string.IsNullOrWhiteSpace(data.FileName) && data.FileName is not "." and not "..")
                    results.Add(new PipeEndpoint(data.FileName, PipePath.FromName(data.FileName), "Discovered"));
            }
            while (FindNextFileW(handle, out data));

            var error = Marshal.GetLastWin32Error();
            if (error != ErrorNoMoreFiles)
                throw new Win32Exception(error, "Named-pipe enumeration ended unexpectedly.");
        }

        return results.OrderBy(p => p.Name, StringComparer.OrdinalIgnoreCase).ToArray();
    }

    private static readonly IntPtr InvalidHandleValue = new(-1);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct Win32FindData
    {
        public uint FileAttributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint Reserved0;
        public uint Reserved1;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string FileName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 14)] public string AlternateFileName;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "FindFirstFileW")]
    private static extern IntPtr FindFirstFileW(string fileName, out Win32FindData findData);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "FindNextFileW")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool FindNextFileW(IntPtr findHandle, out Win32FindData findData);

    [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "FindClose")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool FindClose(IntPtr findHandle);

    private sealed class FindHandle(IntPtr handle) : IDisposable
    {
        public void Dispose() => FindClose(handle);
    }
}

public static class PipePath
{
    public static string FromName(string name) => @"\\.\pipe\" + name;
}
