using System.Runtime.Versioning;

namespace Sutra.Cli.Discovery;

public static class DiscoveryModuleFactory
{
    [SupportedOSPlatform("windows")]
    public static IpcDiscoveryCoordinator CreateDefault() => new(
    [
        new NamedPipeDiscoveryModule(),
        new RpcEndpointDiscoveryModule(),
        new ComRegistrationDiscoveryModule(),
        new AlpcDirectoryDiscoveryModule()
    ]);
}
