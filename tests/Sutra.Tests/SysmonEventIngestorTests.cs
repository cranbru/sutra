using Sutra.Cli.Correlation;

namespace Sutra.Tests;

public sealed class SysmonEventIngestorTests
{
    [Theory]
    [InlineData(@"\\.\pipe\Example", "Example")]
    [InlineData(@"\Device\NamedPipe\Example", "Example")]
    [InlineData(@"\??\pipe\Example", "Example")]
    [InlineData("Example", "Example")]
    public void NormalizesPipePathPrefixes(string input, string expected) =>
        Assert.Equal(expected, PipeNameNormalizer.Normalize(input));

    [Fact]
    public void ParsesNamedSysmonEventDataFields()
    {
        const string xml = """
            <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
              <EventData>
                <Data Name="ProcessId">1234</Data>
                <Data Name="PipeName">\Device\NamedPipe\Example</Data>
                <Data Name="Image">C:\Windows\service.exe</Data>
              </EventData>
            </Event>
            """;

        var fields = SysmonEventIngestor.ParseEventData(xml);

        Assert.Equal("1234", fields["ProcessId"]);
        Assert.Equal(@"\Device\NamedPipe\Example", fields["PipeName"]);
        Assert.Equal(@"C:\Windows\service.exe", fields["Image"]);
    }
}
