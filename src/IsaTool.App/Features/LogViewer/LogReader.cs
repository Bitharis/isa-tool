using System.Text.RegularExpressions;

namespace IsaTool.App.Features.LogViewer;

/// <summary>Filters log lines using text or a bounded regular expression.</summary>
public sealed class LogFilter
{
    private readonly Regex? _regex;
    private readonly string _text;
    private readonly bool _invert;

    /// <summary>Initializes a log-line filter.</summary>
    public LogFilter(string pattern, bool useRegex, bool ignoreCase = true, bool invert = false)
    {
        _text = pattern;
        _invert = invert;
        if (useRegex && pattern.Length > 0)
        {
            _regex = new Regex(pattern,
                ignoreCase ? RegexOptions.IgnoreCase : RegexOptions.None,
                TimeSpan.FromMilliseconds(100));
        }

        IgnoreCase = ignoreCase;
    }

    private bool IgnoreCase { get; }

    /// <summary>Determines whether a log line matches the filter.</summary>
    public bool Matches(string line)
    {
        if (_text.Length == 0)
        {
            return true;
        }

        bool hit;
        try
        {
            hit = _regex is not null
                ? _regex.IsMatch(line)
                : line.Contains(_text, IgnoreCase ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal);
        }
        catch (RegexMatchTimeoutException)
        {
            hit = false;
        }

        return hit != _invert;
    }
}

/// <summary>Reads complete lines from log files that may be actively written.</summary>
public static class LogReader
{
    /// <summary>Reads the last <paramref name="maxLines"/> lines without loading the whole file.</summary>
    public static async Task<(IReadOnlyList<string> Lines, long EndOffset)> ReadTailAsync(
        string path, int maxLines, CancellationToken ct = default)
    {
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        var length = stream.Length;
        var window = Math.Min(length, 4L * 1024 * 1024);
        stream.Seek(length - window, SeekOrigin.Begin);

        using var reader = new StreamReader(stream);
        var all = new List<string>();
        string? line;
        while ((line = await reader.ReadLineAsync(ct).ConfigureAwait(false)) is not null)
        {
            all.Add(line);
        }

        // First line of a mid-file window is likely partial.
        if (window < length && all.Count > 0)
        {
            all.RemoveAt(0);
        }

        return (all.Count > maxLines ? all[^maxLines..] : all, length);
    }

    /// <summary>Reads lines appended after <paramref name="offset"/>; resets if the file was truncated.</summary>
    public static async Task<(IReadOnlyList<string> Lines, long NewOffset)> ReadAppendedAsync(
        string path, long offset, CancellationToken ct = default)
    {
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        if (stream.Length < offset)
        {
            offset = 0;
        }

        stream.Seek(offset, SeekOrigin.Begin);
        using var reader = new StreamReader(stream);
        var lines = new List<string>();
        string? line;
        while ((line = await reader.ReadLineAsync(ct).ConfigureAwait(false)) is not null)
        {
            lines.Add(line);
        }

        return (lines, stream.Length);
    }
}
