using System.Diagnostics;
using System.Text;

namespace IsaTool.App.Features.Http;

/// <summary>Describes an HTTP request to send through the probe.</summary>
public sealed record HttpProbeRequest(
    string Url,
    string Method = "GET",
    IReadOnlyDictionary<string, string>? Headers = null,
    string? Body = null,
    bool FollowRedirects = true,
    bool IgnoreCertificateErrors = false,
    TimeSpan? Timeout = null);

/// <summary>Represents one HTTP response in a request or redirect chain.</summary>
public sealed record HttpHop(string Url, int StatusCode, string ReasonPhrase, TimeSpan TimeToHeaders);

/// <summary>Contains the response data collected by an HTTP probe.</summary>
public sealed record HttpProbeResult(
    IReadOnlyList<HttpHop> Hops,
    IReadOnlyList<KeyValuePair<string, string>> Headers,
    string Body,
    bool BodyTruncated,
    TimeSpan Total,
    string? Error)
{
    /// <summary>Gets the final response hop, if one was received.</summary>
    public HttpHop? Final => Hops.Count > 0 ? Hops[^1] : null;
}

/// <summary>Sends HTTP requests and captures redirects, headers, and a bounded response body.</summary>
public static class HttpProbe
{
    private const int MaxRedirects = 10;
    private const int MaxBodyChars = 64 * 1024;

    /// <summary>Sends an HTTP request and returns the observed response chain.</summary>
    public static async Task<HttpProbeResult> SendAsync(HttpProbeRequest request, CancellationToken ct = default)
    {
        var total = Stopwatch.StartNew();
        var hops = new List<HttpHop>();

        if (!Uri.TryCreate(request.Url, UriKind.Absolute, out var uri) ||
            uri.Scheme is not ("http" or "https"))
        {
            return Failure("Invalid URL (expected http:// or https://).");
        }

        using var handler = new SocketsHttpHandler { AllowAutoRedirect = false };
        if (request.IgnoreCertificateErrors)
        {
            handler.SslOptions.RemoteCertificateValidationCallback = (_, _, _, _) => true;
        }

        using var client = new HttpClient(handler, disposeHandler: false)
        {
            Timeout = request.Timeout ?? TimeSpan.FromSeconds(30),
        };

        var method = new HttpMethod(request.Method.ToUpperInvariant());
        try
        {
            for (var i = 0; i <= MaxRedirects; i++)
            {
                using var message = Build(request, method, uri);
                var hop = Stopwatch.StartNew();
                using var response = await client.SendAsync(message, HttpCompletionOption.ResponseHeadersRead, ct)
                    .ConfigureAwait(false);
                hops.Add(new HttpHop(uri.ToString(), (int)response.StatusCode,
                    response.ReasonPhrase ?? string.Empty, hop.Elapsed));

                var isRedirect = (int)response.StatusCode is >= 300 and < 400 && response.Headers.Location is not null;
                if (request.FollowRedirects && isRedirect)
                {
                    uri = new Uri(uri, response.Headers.Location!);
                    if ((int)response.StatusCode is 301 or 302 or 303 && method != HttpMethod.Head)
                    {
                        method = HttpMethod.Get;
                    }

                    continue;
                }

                var headers = response.Headers.Concat(response.Content.Headers)
                    .SelectMany(h => h.Value.Select(v => new KeyValuePair<string, string>(h.Key, v)))
                    .ToList();
                var (body, truncated) = await ReadBodyAsync(response, ct).ConfigureAwait(false);
                return new HttpProbeResult(hops, headers, body, truncated, total.Elapsed, null);
            }

            return Failure($"Too many redirects (>{MaxRedirects}).");
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or InvalidOperationException)
        {
            var message = ex is TaskCanceledException ? "Request timed out." : ex.InnerException?.Message ?? ex.Message;
            return Failure(message);
        }

        HttpProbeResult Failure(string error) =>
            new(hops, [], string.Empty, false, total.Elapsed, error);
    }

    private static HttpRequestMessage Build(HttpProbeRequest request, HttpMethod method, Uri uri)
    {
        var message = new HttpRequestMessage(method, uri);
        if (!string.IsNullOrEmpty(request.Body) && method != HttpMethod.Get && method != HttpMethod.Head)
        {
            message.Content = new StringContent(request.Body, Encoding.UTF8);
        }

        foreach (var (name, value) in request.Headers ?? new Dictionary<string, string>())
        {
            if (!message.Headers.TryAddWithoutValidation(name, value))
            {
                message.Content?.Headers.TryAddWithoutValidation(name, value);
            }
        }

        return message;
    }

    private static async Task<(string Body, bool Truncated)> ReadBodyAsync(HttpResponseMessage response, CancellationToken ct)
    {
        await using var stream = await response.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
        using var reader = new StreamReader(stream, Encoding.UTF8);
        var buffer = new char[MaxBodyChars + 1];
        var read = await reader.ReadBlockAsync(buffer.AsMemory(), ct).ConfigureAwait(false);
        return read > MaxBodyChars ? (new string(buffer, 0, MaxBodyChars), true) : (new string(buffer, 0, read), false);
    }

    /// <summary>Parses newline-separated <c>Name: value</c> header entries.</summary>
    public static IReadOnlyDictionary<string, string> ParseHeaders(string text)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var line in text.Split('\n', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
        {
            var colon = line.IndexOf(':', StringComparison.Ordinal);
            if (colon > 0)
            {
                result[line[..colon].Trim()] = line[(colon + 1)..].Trim();
            }
        }

        return result;
    }
}
