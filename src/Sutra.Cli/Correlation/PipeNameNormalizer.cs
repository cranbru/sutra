namespace Sutra.Cli.Correlation;

public static class PipeNameNormalizer
{
    private static readonly string[] Prefixes =
    [
        @"\\.\pipe\",
        @"\\?\pipe\",
        @"\Device\NamedPipe\",
        @"\??\pipe\",
        @"\pipe\"
    ];

    public static string Normalize(string pipeName)
    {
        var normalized = pipeName.Trim().Replace('/', '\\');
        foreach (var prefix in Prefixes)
        {
            if (normalized.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            {
                normalized = normalized[prefix.Length..];
                break;
            }
        }
        return normalized.TrimStart('\\');
    }
}
