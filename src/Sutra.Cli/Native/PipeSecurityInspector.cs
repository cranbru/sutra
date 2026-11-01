using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Runtime.Versioning;
using Sutra.Cli.Models;

namespace Sutra.Cli.Native;

[SupportedOSPlatform("windows")]
public sealed class PipeSecurityInspector
{
    private const uint OwnerInformation = 0x00000001;
    private const uint DaclInformation = 0x00000004;
    private const int SeFileObject = 1;
    private const int ErrorSuccess = 0;

    public PipeEndpoint Inspect(PipeEndpoint endpoint)
    {
        IntPtr descriptor = IntPtr.Zero;
        try
        {
            var result = GetNamedSecurityInfoW(endpoint.Path, SeFileObject, OwnerInformation | DaclInformation,
                out var owner, out _, out var dacl, out _, out descriptor);
            if (result != ErrorSuccess)
                throw new Win32Exception(result);

            var length = GetSecurityDescriptorLength(descriptor);
            if (length == 0 || length > 1024 * 1024)
                throw new InvalidOperationException("Windows returned an invalid security descriptor length.");

            var bytes = new byte[length];
            Marshal.Copy(descriptor, bytes, 0, (int)length);
            var raw = new RawSecurityDescriptor(bytes, 0);
            var ownerSid = raw.Owner?.Value ?? ReadSid(owner);
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

            return endpoint with { SecurityStatus = "Inspected", OwnerSid = ownerSid, AccessEntries = entries };
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

    private static string? ReadSid(IntPtr pointer)
    {
        if (pointer == IntPtr.Zero) return null;
        try { return new SecurityIdentifier(pointer).Value; }
        catch (ArgumentException) { return null; }
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "GetNamedSecurityInfoW")]
    private static extern int GetNamedSecurityInfoW(string objectName, int objectType, uint securityInfo,
        out IntPtr owner, out IntPtr group, out IntPtr dacl, out IntPtr sacl, out IntPtr securityDescriptor);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern uint GetSecurityDescriptorLength(IntPtr securityDescriptor);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr memory);
}
