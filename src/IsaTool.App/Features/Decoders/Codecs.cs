using System.Text;
using System.Text.Json;

namespace IsaTool.App.Features.Decoders;

/// <summary>Contains the decoded portions and expiration state of a JWT.</summary>
public sealed record JwtDecoded(string Header, string Payload, string Signature, DateTimeOffset? Expires, bool? Expired);

/// <summary>Formats and decodes common textual data formats.</summary>
public static class Codecs
{
    private static readonly JsonSerializerOptions Pretty = new() { WriteIndented = true };

    /// <summary>Formats JSON with indentation.</summary>
    public static string FormatJson(string json)
    {
        using var doc = JsonDocument.Parse(json);
        return JsonSerializer.Serialize(doc.RootElement, Pretty);
    }

    /// <summary>Encodes UTF-8 text as Base64.</summary>
    public static string Base64Encode(string text) => Convert.ToBase64String(Encoding.UTF8.GetBytes(text));

    /// <summary>Decodes Base64 or Base64URL text as UTF-8.</summary>
    public static string Base64Decode(string text) => Encoding.UTF8.GetString(DecodeBase64Url(text));

    /// <summary>Decodes without verifying the signature; for inspection only.</summary>
    public static JwtDecoded DecodeJwt(string token, DateTimeOffset? now = null)
    {
        var parts = token.Trim().Split('.');
        if (parts.Length != 3)
        {
            throw new FormatException("A JWT must have three dot-separated parts.");
        }

        var header = FormatJson(Encoding.UTF8.GetString(DecodeBase64Url(parts[0])));
        var payloadJson = Encoding.UTF8.GetString(DecodeBase64Url(parts[1]));

        DateTimeOffset? expires = null;
        bool? expired = null;
        using (var doc = JsonDocument.Parse(payloadJson))
        {
            if (doc.RootElement.ValueKind == JsonValueKind.Object &&
                doc.RootElement.TryGetProperty("exp", out var exp) && exp.TryGetInt64(out var seconds))
            {
                expires = DateTimeOffset.FromUnixTimeSeconds(seconds);
                expired = expires <= (now ?? DateTimeOffset.UtcNow);
            }
        }

        return new JwtDecoded(header, FormatJson(payloadJson), parts[2], expires, expired);
    }

    private static byte[] DecodeBase64Url(string text)
    {
        var s = text.Trim().Replace('-', '+').Replace('_', '/');
        s = s.PadRight(s.Length + ((4 - (s.Length % 4)) % 4), '=');
        return Convert.FromBase64String(s);
    }
}
