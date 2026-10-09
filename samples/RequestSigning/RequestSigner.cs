using System.Security.Cryptography;
using System.Text;
using IsaTool.Plugins;

namespace RequestSigning;

/// <summary>
/// Example request hook: adds "X-Signature: sha256=HMAC(key, METHOD \n path+query \n sha256(body))".
/// Needs ISATOOL_SIGNING_KEY; ISATOOL_SIGNING_HOST optionally limits it to one host.
/// </summary>
public sealed class RequestSigner : IRequestHook
{
    /// <summary>Gets the plugin display name.</summary>
    public string Name => "Request signer";

    /// <summary>Gets a description of the signature behavior.</summary>
    public string Description => "Adds an HMAC-SHA256 X-Signature header (key from ISATOOL_SIGNING_KEY).";

    /// <summary>Adds a request signature when the configured environment variables allow it.</summary>
    public RequestOutcome OnRequest(MutableRequest request)
    {
        var key = Environment.GetEnvironmentVariable("ISATOOL_SIGNING_KEY");
        if (string.IsNullOrEmpty(key))
        {
            return RequestOutcome.Continue;
        }

        var host = Environment.GetEnvironmentVariable("ISATOOL_SIGNING_HOST");
        if (!string.IsNullOrEmpty(host) && !request.Uri.Host.Equals(host, StringComparison.OrdinalIgnoreCase))
        {
            return RequestOutcome.Continue;
        }

        var message = $"{request.Method}\n{request.Uri.PathAndQuery}\n{Convert.ToHexStringLower(SHA256.HashData(request.Body))}";
        var mac = HMACSHA256.HashData(Encoding.UTF8.GetBytes(key), Encoding.UTF8.GetBytes(message));
        request.SetHeader("X-Signature", "sha256=" + Convert.ToHexStringLower(mac));
        return RequestOutcome.Continue;
    }
}

/// <summary>Example body decoder: shows form posts as one "key = value" per line.</summary>
public sealed class FormBodyDecoder : IBodyDecoder
{
    /// <summary>Gets the plugin display name.</summary>
    public string Name => "Form body decoder";

    /// <summary>Gets a description of the decoding behavior.</summary>
    public string Description => "Shows application/x-www-form-urlencoded bodies as key = value lines.";

    /// <summary>Formats URL-encoded form bodies as key-value lines.</summary>
    public string? TryDecode(DecoderInput input)
    {
        if (input.ContentType?.StartsWith("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase) != true)
        {
            return null;
        }

        var lines = Encoding.UTF8.GetString(input.Body)
            .Split('&', StringSplitOptions.RemoveEmptyEntries)
            .Select(pair =>
            {
                var eq = pair.IndexOf('=', StringComparison.Ordinal);
                var key = eq < 0 ? pair : pair[..eq];
                var value = eq < 0 ? string.Empty : pair[(eq + 1)..];
                return $"{Unescape(key)} = {Unescape(value)}";
            });
        return string.Join('\n', lines);
    }

    private static string Unescape(string s) => Uri.UnescapeDataString(s.Replace('+', ' '));
}
