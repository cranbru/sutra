using Sutra.Cli.Models;

namespace Sutra.Cli.Discovery;

public sealed record DiscoveryResult(string Mechanism, IReadOnlyList<PipeEndpoint> Endpoints, string? Error = null, string Coverage = "Complete");

public interface IIpcDiscoveryModule
{
    string Mechanism { get; }
    DiscoveryResult Discover();
}

public sealed class IpcDiscoveryCoordinator(IEnumerable<IIpcDiscoveryModule> modules)
{
    private readonly IReadOnlyList<IIpcDiscoveryModule> _modules = modules.ToArray();

    public IReadOnlyList<IIpcDiscoveryModule> Modules => _modules;

    public IReadOnlyList<DiscoveryResult> Discover(IEnumerable<string> requestedMechanisms)
    {
        var requested = new HashSet<string>(requestedMechanisms, StringComparer.OrdinalIgnoreCase);
        return _modules.Where(module => requested.Contains("all") || requested.Contains(module.Mechanism))
            .Select(module =>
            {
                try { return module.Discover(); }
                catch (Exception ex) when (ex is not OutOfMemoryException and not StackOverflowException)
                {
                    return new DiscoveryResult(module.Mechanism, Array.Empty<PipeEndpoint>(), ex.Message, "Unavailable");
                }
            })
            .ToArray();
    }
}
