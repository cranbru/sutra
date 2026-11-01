using Sutra.Cli.Models;
using Sutra.Cli.Native;

namespace Sutra.Cli.Discovery;

public sealed class NamedPipeDiscoveryModule : IIpcDiscoveryModule
{
    public string Mechanism => "NamedPipe";

    public DiscoveryResult Discover() => new(Mechanism, new PipeEnumerator().Discover());
}
