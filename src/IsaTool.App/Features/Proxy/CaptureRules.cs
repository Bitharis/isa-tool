using System.Text.RegularExpressions;

namespace IsaTool.App.Features.Proxy;

/// <summary>Comma/space separated host patterns; '*' is a wildcard, so "*.example.com" does not match "example.com".</summary>
public sealed class HostMatcher
{
    private readonly Regex[] _patterns;

    public HostMatcher(string? patterns)
    {
        _patterns =
        [
            .. (patterns ?? string.Empty)
                .Split([',', ';', ' '], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Select(p => new Regex("^" + Regex.Escape(p).Replace("\\*", ".*", StringComparison.Ordinal) + "$",
                    RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(50))),
        ];
    }

    /// <summary>Gets whether no host patterns were supplied.</summary>
    public bool IsEmpty => _patterns.Length == 0;

    /// <summary>Determines whether a host matches any configured pattern.</summary>
    public bool IsMatch(string host) => _patterns.Any(p => p.IsMatch(host));
}

/// <summary>Decides which hosts are decrypted and recorded; others are tunnelled or forwarded untouched.</summary>
public sealed class CaptureRules(string? include = null, string? ignore = null)
{
    private readonly HostMatcher _include = new(include);
    private readonly HostMatcher _ignore = new(ignore);

    /// <summary>Gets rules that intercept every host.</summary>
    public static CaptureRules All { get; } = new();

    /// <summary>Determines whether the host should be decrypted and captured.</summary>
    public bool ShouldIntercept(string host) =>
        (_include.IsEmpty || _include.IsMatch(host)) && !_ignore.IsMatch(host);
}
