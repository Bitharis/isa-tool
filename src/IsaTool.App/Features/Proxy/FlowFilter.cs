namespace IsaTool.App.Features.Proxy;

/// <summary>View-side filter over captured flows; empty fields match everything.</summary>
public sealed class FlowFilter(string? text = null, string? status = null, string? contentTypes = null)
{
    private readonly string _text = text?.Trim() ?? string.Empty;
    private readonly string[] _status = Split(status);
    private readonly string[] _types = Split(contentTypes);

    public static FlowFilter None { get; } = new();

    public bool Matches(CapturedFlow f) => MatchesStatus(f) && MatchesType(f) && MatchesText(f);

    private static string[] Split(string? value) =>
        (value ?? string.Empty).Split([',', ';', ' '], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    private bool MatchesStatus(CapturedFlow f)
    {
        if (_status.Length == 0)
        {
            return true;
        }

        return _status.Any(s =>
        {
            if (s.Equals("err", StringComparison.OrdinalIgnoreCase))
            {
                return f.Error is not null || f.StatusCode is null;
            }

            if (f.StatusCode is not { } code)
            {
                return false;
            }

            return StatusMatches([s], code);
        });
    }

    /// <summary>Tokens are exact codes ("404") or classes ("5xx").</summary>
    public static bool StatusMatches(IEnumerable<string> tokens, int code) =>
        tokens.Any(s => s.Length == 3 && s.EndsWith("xx", StringComparison.OrdinalIgnoreCase)
            ? s[0] - '0' == code / 100
            : int.TryParse(s, out var exact) && exact == code);

    private bool MatchesType(CapturedFlow f)
    {
        if (_types.Length == 0)
        {
            return true;
        }

        var type = Header(f.ResponseHeaders, "Content-Type") ?? Header(f.RequestHeaders, "Content-Type") ?? string.Empty;
        return _types.Any(t => type.Contains(t, StringComparison.OrdinalIgnoreCase));
    }

    private bool MatchesText(CapturedFlow f)
    {
        if (_text.Length == 0)
        {
            return true;
        }

        return Has(f.Url) || Has(f.Error) ||
               f.RequestHeaders.Concat(f.ResponseHeaders).Any(h => Has(h.Key) || Has(h.Value)) ||
               Has(FlowFormatter.BodyText(f.RequestHeaders, f.RequestBody, f.Url, isRequest: true)) ||
               Has(FlowFormatter.BodyText(f.ResponseHeaders, f.ResponseBody, f.Url, isRequest: false));
    }

    private bool Has(string? value) => value?.Contains(_text, StringComparison.OrdinalIgnoreCase) == true;

    private static string? Header(IReadOnlyList<KeyValuePair<string, string>> headers, string name) =>
        headers.FirstOrDefault(h => h.Key.Equals(name, StringComparison.OrdinalIgnoreCase)).Value;
}
