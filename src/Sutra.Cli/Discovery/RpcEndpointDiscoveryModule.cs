using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Sutra.Cli.Models;

namespace Sutra.Cli.Discovery;

[SupportedOSPlatform("windows")]
public sealed class RpcEndpointDiscoveryModule : IIpcDiscoveryModule
{
    private const int RpcSuccess = 0;
    private const int RpcNoMoreEntries = 1772;
    private const uint AllEndpointElements = 0;

    public string Mechanism => "RPC";

    public DiscoveryResult Discover()
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("RPC endpoint discovery requires Windows.");
        var status = RpcMgmtEpEltInqBegin(IntPtr.Zero, AllEndpointElements, IntPtr.Zero, 0, IntPtr.Zero, out var inquiry);
        if (status != RpcSuccess) throw new Win32Exception(status, "The local RPC endpoint mapper query could not start.");

        var endpoints = new Dictionary<string, PipeEndpoint>(StringComparer.OrdinalIgnoreCase);
        try
        {
            for (var index = 0; index < 100_000; index++)
            {
                status = RpcMgmtEpEltInqNextW(inquiry, out var interfaceId, out var binding, IntPtr.Zero, out var annotation);
                if (status == RpcNoMoreEntries) break;
                if (status != RpcSuccess) throw new Win32Exception(status, "The local RPC endpoint mapper query failed.");
                try
                {
                    if (binding == IntPtr.Zero) continue;
                    var parsed = ParseBinding(binding);
                    var uuid = interfaceId.Uuid.ToString("D");
                    var version = $"{interfaceId.Major}.{interfaceId.Minor}";
                    var endpointName = string.IsNullOrWhiteSpace(parsed.Endpoint) ? "dynamic" : parsed.Endpoint;
                    var address = string.IsNullOrWhiteSpace(parsed.NetworkAddress) ? string.Empty : $"@{parsed.NetworkAddress}";
                    var name = $"{parsed.ProtocolSequence}:{endpointName}{address} [{uuid} v{version}]";
                    var detail = string.Join("; ", new[]
                    {
                        $"Interface={uuid}", $"Version={version}", $"Protocol={parsed.ProtocolSequence}",
                        string.IsNullOrWhiteSpace(parsed.NetworkAddress) ? null : $"Address={parsed.NetworkAddress}",
                        string.IsNullOrWhiteSpace(parsed.Endpoint) ? null : $"Endpoint={parsed.Endpoint}",
                        string.IsNullOrWhiteSpace(Marshal.PtrToStringUni(annotation)) ? null : $"Annotation={Marshal.PtrToStringUni(annotation)}"
                    }.Where(value => value is not null));
                    endpoints.TryAdd(name, new PipeEndpoint(name, parsed.StringBinding, "Registered",
                        IpcMechanism: Mechanism, DiscoveryDetails: detail));
                }
                finally
                {
                    if (binding != IntPtr.Zero) RpcBindingFree(ref binding);
                    if (annotation != IntPtr.Zero) RpcStringFreeW(ref annotation);
                }
            }
            return new DiscoveryResult(Mechanism, endpoints.Values.OrderBy(item => item.Name, StringComparer.OrdinalIgnoreCase).ToArray(),
                Coverage: "Local RPC endpoint mapper registrations; server process attribution is not provided");
        }
        finally { RpcMgmtEpEltInqDone(ref inquiry); }
    }

    private static BindingParts ParseBinding(IntPtr binding)
    {
        var status = RpcBindingToStringBindingW(binding, out var stringBinding);
        if (status != RpcSuccess) throw new Win32Exception(status, "An RPC binding could not be formatted.");
        IntPtr objectUuid = IntPtr.Zero, protocolSequence = IntPtr.Zero, networkAddress = IntPtr.Zero,
            endpoint = IntPtr.Zero, networkOptions = IntPtr.Zero;
        try
        {
            status = RpcStringBindingParseW(stringBinding, out objectUuid, out protocolSequence,
                out networkAddress, out endpoint, out networkOptions);
            if (status != RpcSuccess) throw new Win32Exception(status, "An RPC binding could not be parsed.");
            return new BindingParts(
                Marshal.PtrToStringUni(protocolSequence) ?? "unknown",
                Marshal.PtrToStringUni(networkAddress),
                Marshal.PtrToStringUni(endpoint),
                Marshal.PtrToStringUni(stringBinding) ?? string.Empty);
        }
        finally
        {
            FreeRpcString(ref objectUuid); FreeRpcString(ref protocolSequence); FreeRpcString(ref networkAddress);
            FreeRpcString(ref endpoint); FreeRpcString(ref networkOptions); FreeRpcString(ref stringBinding);
        }
    }

    private static void FreeRpcString(ref IntPtr value)
    {
        if (value != IntPtr.Zero) RpcStringFreeW(ref value);
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct RpcIfId
    {
        public Guid Uuid;
        public ushort Major;
        public ushort Minor;
    }

    private sealed record BindingParts(string ProtocolSequence, string? NetworkAddress, string? Endpoint, string StringBinding);

    [DllImport("Rpcrt4.dll", ExactSpelling = true)]
    private static extern int RpcMgmtEpEltInqBegin(IntPtr endpointMapperBinding, uint inquiryType, IntPtr interfaceId,
        uint versionOption, IntPtr objectUuid, out IntPtr inquiryContext);

    [DllImport("Rpcrt4.dll", ExactSpelling = true, EntryPoint = "RpcMgmtEpEltInqNextW")]
    private static extern int RpcMgmtEpEltInqNextW(IntPtr inquiryContext, out RpcIfId interfaceId, out IntPtr binding,
        IntPtr objectUuid, out IntPtr annotation);

    [DllImport("Rpcrt4.dll", ExactSpelling = true)]
    private static extern int RpcMgmtEpEltInqDone(ref IntPtr inquiryContext);

    [DllImport("Rpcrt4.dll", ExactSpelling = true)]
    private static extern int RpcBindingToStringBindingW(IntPtr binding, out IntPtr stringBinding);

    [DllImport("Rpcrt4.dll", ExactSpelling = true)]
    private static extern int RpcStringBindingParseW(IntPtr stringBinding, out IntPtr objectUuid, out IntPtr protocolSequence,
        out IntPtr networkAddress, out IntPtr endpoint, out IntPtr networkOptions);

    [DllImport("Rpcrt4.dll", ExactSpelling = true)]
    private static extern int RpcBindingFree(ref IntPtr binding);

    [DllImport("Rpcrt4.dll", ExactSpelling = true, EntryPoint = "RpcStringFreeW")]
    private static extern int RpcStringFreeW(ref IntPtr stringValue);
}
