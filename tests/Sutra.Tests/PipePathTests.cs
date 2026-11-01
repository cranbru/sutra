using Sutra.Cli.Native;

namespace Sutra.Tests;

public sealed class PipePathTests
{
    [Theory]
    [InlineData("Example", @"\\.\pipe\Example")]
    [InlineData(@"service\endpoint", @"\\.\pipe\service\endpoint")]
    public void FromNameUsesWindowsNamedPipeNamespace(string name, string expected)
    {
        Assert.Equal(expected, PipePath.FromName(name));
    }
}
