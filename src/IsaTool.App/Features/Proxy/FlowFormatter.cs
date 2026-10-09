using System.IO.Compression;
using System.Text;
using System.Text.Json;
using IsaTool.Plugins;

namespace IsaTool.App.Features.Proxy;

/// <summary>Formats captured proxy flows and decodes displayable response bodies.</summary>
public static class FlowFormatter
{
    private const int MaxDisplayChars = 64 * 1024;
    private const int MaxDecodedBytes = 8 * 1024 * 1024;
    private static readonly JsonSerializerOptions Pretty = new() { WriteIndented = true };

    /// <summary>Set once at startup to let plugins render bodies; returns null when no decoder applies.</summary>
    public static Func<DecoderInput, string?>? CustomDecoder { get; set; }

    /// <summary>Formats flows as a compact list.</summary>
    public static string FormatList(IEnumerable<CapturedFlow> flows)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"{"#",4} {"TIME",-8} {"METHOD",-7} {"STATUS",-6} {"MS",6} {"SIZE",8}  URL   (* = rewrite rule or plugin applied)");
        foreach (var f in flows)
        {
            var status = f.StatusCode?.ToString() ?? (f.Error is null ? "..." : "ERR");
            sb.AppendLine($"{f.Id,4}{(f.AppliedRules.Count > 0 ? '*' : ' ')}{f.StartedAt:HH:mm:ss} {f.Method,-7} {status,-6} {f.Duration.TotalMilliseconds,6:F0} {f.ResponseBody.Length,8}  {f.Url}");
        }

        return sb.ToString();
    }

    /// <summary>Formats the complete details of one flow.</summary>
    public static string FormatDetail(CapturedFlow f)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"#{f.Id}  {f.StartedAt:u}  {f.Duration.TotalMilliseconds:F0} ms");
        sb.AppendLine($"{f.Method} {f.Url}");
        if (f.Error is not null)
        {
            sb.AppendLine($"ERROR: {f.Error}");
        }

        foreach (var rule in f.AppliedRules)
        {
            sb.AppendLine($"RULE: {rule}");
        }

        sb.AppendLine().AppendLine("--- REQUEST HEADERS");
        AppendHeaders(sb, f.RequestHeaders);
        sb.AppendLine().AppendLine($"--- REQUEST BODY ({f.RequestBody.Length} bytes)");
        sb.AppendLine(BodyText(f.RequestHeaders, f.RequestBody, f.Url, isRequest: true));

        if (f.StatusCode is not null)
        {
            sb.AppendLine().AppendLine($"--- RESPONSE {f.StatusCode} {f.ReasonPhrase}");
            AppendHeaders(sb, f.ResponseHeaders);
            sb.AppendLine().AppendLine($"--- RESPONSE BODY ({f.ResponseBody.Length} bytes on the wire)");
            sb.AppendLine(BodyText(f.ResponseHeaders, f.ResponseBody, f.Url, isRequest: false));
        }

        return sb.ToString();
    }

    /// <summary>Decodes and formats a request or response body for display.</summary>
    public static string BodyText(
        IReadOnlyList<KeyValuePair<string, string>> headers, byte[] body, string url = "", bool isRequest = false)
    {
        if (body.Length == 0)
        {
            return string.Empty;
        }

        string? Find(string n) => headers.FirstOrDefault(h => h.Key.Equals(n, StringComparison.OrdinalIgnoreCase)).Value;

        var bytes = Decode(Find("Content-Encoding"), body, out var note);
        if (CustomDecoder?.Invoke(new DecoderInput(url, isRequest, headers, bytes)) is { } custom)
        {
            return note + (custom.Length > MaxDisplayChars ? custom[..MaxDisplayChars] + "\n[truncated]" : custom);
        }
        string text;
        try
        {
            text = new UTF8Encoding(false, true).GetString(bytes);
        }
        catch (ArgumentException)
        {
            return note + HexDump(bytes);
        }

        if (Find("Content-Type")?.Contains("json", StringComparison.OrdinalIgnoreCase) == true)
        {
            try
            {
                using var doc = JsonDocument.Parse(text);
                text = JsonSerializer.Serialize(doc.RootElement, Pretty);
            }
            catch (JsonException)
            {
                // Show as-is.
            }
        }

        if (text.Length > MaxDisplayChars)
        {
            text = text[..MaxDisplayChars] + "\n[truncated]";
        }

        return note + text;
    }

    /// <summary>Decompresses a supported content encoding within a safe size limit.</summary>
    public static byte[] Decode(string? encoding, byte[] body, out string note)
    {
        note = string.Empty;
        Func<Stream, Stream>? wrap = encoding?.Trim().ToLowerInvariant() switch
        {
            "gzip" or "x-gzip" => s => new GZipStream(s, CompressionMode.Decompress),
            "deflate" => s => new ZLibStream(s, CompressionMode.Decompress),
            "br" => s => new BrotliStream(s, CompressionMode.Decompress),
            _ => null,
        };
        if (wrap is null)
        {
            return body;
        }

        try
        {
            using var input = new MemoryStream(body);
            using var decoder = wrap(input);
            using var output = new MemoryStream();
            var buffer = new byte[16 * 1024];
            int read;
            while ((read = decoder.Read(buffer)) > 0)
            {
                output.Write(buffer, 0, read);
                if (output.Length > MaxDecodedBytes)
                {
                    note = "[decoded output truncated]\n";
                    break;
                }
            }

            return output.ToArray();
        }
        catch (InvalidDataException)
        {
            note = $"[could not decode {encoding}]\n";
            return body;
        }
    }

    private static void AppendHeaders(StringBuilder sb, IEnumerable<KeyValuePair<string, string>> headers)
    {
        foreach (var (name, value) in headers)
        {
            sb.AppendLine($"{name}: {value}");
        }
    }

    private static string HexDump(byte[] bytes)
    {
        var sb = new StringBuilder("[binary data]\n");
        var length = Math.Min(bytes.Length, 512);
        for (var i = 0; i < length; i += 16)
        {
            var row = bytes.AsSpan(i, Math.Min(16, length - i));
            sb.Append($"{i:X4}  ").Append(string.Join(' ', row.ToArray().Select(b => b.ToString("X2"))).PadRight(48));
            sb.Append(' ').AppendLine(new string([.. row.ToArray().Select(b => b is >= 32 and < 127 ? (char)b : '.')]));
        }

        if (bytes.Length > length)
        {
            sb.AppendLine($"... {bytes.Length - length} more bytes");
        }

        return sb.ToString();
    }
}
