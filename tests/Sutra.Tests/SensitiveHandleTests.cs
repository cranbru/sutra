using Sutra.Cli.Models;
using Sutra.Cli.Native;
using Sutra.Cli.Reporting;

namespace Sutra.Tests;

public sealed class SensitiveHandleTests
{
    [Theory]
    [InlineData(@"\\?\C:\Windows\System32\config\SAM", "Windows registry hive")]
    [InlineData(@"C:\Users\analyst\AppData\Local\Google\Chrome\User Data\Default\Login Data", "Browser credential store")]
    [InlineData(@"C:\Temp\ordinary.txt", null)]
    public void CriticalFileClassifierMatchesSensitiveTargets(string path, string? expected)
    {
        Assert.Equal(expected, SensitiveHandleScanner.ClassifyCriticalFilePath(path));
    }

    [Fact]
    public void ScanReportsIncludeSensitiveHandleResults()
    {
        var scan = new SensitiveHandleScanResult(100, 30, 2,
            [new SensitiveHandleFinding(42, "sample.exe", "LSASS process", "lsass (PID 500)", 1, 0x0010, "VM_READ")],
            "Partial coverage");

        var document = ScanReportFormatter.CreateDocument([], "Live scan", sensitiveHandles: scan);
        var json = ScanReportFormatter.ToJson(document);
        var dot = ScanReportFormatter.ToDot([], sensitiveHandles: scan);
        var text = ScanReportFormatter.ToPlainText(document);
        var ascii = ScanReportFormatter.ToAscii([], sensitiveHandles: scan);

        Assert.Contains("SensitiveHandles", json);
        Assert.Contains("LSASS process", json);
        Assert.Contains("sensitive_", dot);
        Assert.Contains("0x10", dot);
        Assert.Contains("VM_READ", text);
        Assert.Contains("VM_READ", ascii);
    }
}
