using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Text;
using IsaTool.Core.Hosts;
using IsaTool.Plugins;
using IsaTool.App.Features.Plugins;

namespace IsaTool.App.Features.Proxy;

/// <summary>Configures an intercepting proxy server.</summary>
public sealed record ProxyOptions(
    int Port = 8888,
    bool IgnoreUpstreamCertErrors = false,
    CaptureRules? Rules = null,
    RewriteRuleSet? Rewrites = null,
    PluginHost? Plugins = null);

/// <summary>
/// Loopback-only HTTP/HTTPS intercepting proxy. HTTPS is decrypted with leaf certificates from the local CA.
/// Bodies are buffered, so streaming responses and WebSocket upgrades are not supported.
/// </summary>
public sealed class ProxyServer(CertificateAuthority ca, FlowStore store, ProxyOptions options) : IDisposable
{
    private static readonly HashSet<string> HopByHop = new(StringComparer.OrdinalIgnoreCase)
    {
        "Connection", "Proxy-Connection", "Keep-Alive", "TE", "Trailer", "Transfer-Encoding", "Upgrade",
        "Proxy-Authorization", "Proxy-Authenticate", "Content-Length", "Expect", "Host",
    };

    private readonly HttpClient _upstream = CreateUpstream(options);
    private readonly CaptureRules _rules = options.Rules ?? CaptureRules.All;
    private volatile RewriteRuleSet _rewrites = options.Rewrites ?? RewriteRuleSet.Empty;
    private TcpListener? _listener;

    /// <summary>Gets the bound loopback port after the server starts.</summary>
    public int Port { get; private set; }

    /// <summary>Swaps the rewrite rules; applies to requests that start afterwards.</summary>
    public void SetRewrites(RewriteRuleSet rewrites) => _rewrites = rewrites;

    /// <summary>Starts listening on the configured loopback port.</summary>
    public int Start()
    {
        _listener = new TcpListener(IPAddress.Loopback, options.Port);
        _listener.Start();
        Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
        return Port;
    }

    /// <summary>Accepts proxy clients until cancellation is requested.</summary>
    public async Task RunAsync(CancellationToken ct)
    {
        var listener = _listener ?? throw new InvalidOperationException("Call Start() first.");
        try
        {
            while (!ct.IsCancellationRequested)
            {
                var client = await listener.AcceptTcpClientAsync(ct).ConfigureAwait(false);
                _ = HandleClientAsync(client, ct);
            }
        }
        catch (OperationCanceledException)
        {
            // Normal shutdown.
        }
        finally
        {
            listener.Stop();
        }
    }

    public void Dispose()
    {
        _listener?.Stop();
        _upstream.Dispose();
    }

    private static HttpClient CreateUpstream(ProxyOptions options)
    {
        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.None,
            UseCookies = false,
            UseProxy = false,
        };
        if (options.IgnoreUpstreamCertErrors)
        {
            handler.SslOptions.RemoteCertificateValidationCallback = (_, _, _, _) => true;
        }

        return new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(100) };
    }

    private async Task HandleClientAsync(TcpClient client, CancellationToken ct)
    {
        using (client)
        {
            try
            {
                Stream stream = client.GetStream();
                var reader = new WireReader(stream);
                while (!ct.IsCancellationRequested)
                {
                    var head = await reader.ReadRequestHeadAsync(ct).ConfigureAwait(false);
                    if (head is null)
                    {
                        return;
                    }

                    if (head.Method.Equals("CONNECT", StringComparison.OrdinalIgnoreCase))
                    {
                        await HandleConnectAsync(stream, head, ct).ConfigureAwait(false);
                        return;
                    }

                    if (!await ForwardAsync(reader, stream, head, null, ct).ConfigureAwait(false))
                    {
                        return;
                    }
                }
            }
            catch (Exception ex) when (ex is IOException or SocketException or InvalidDataException or
                OperationCanceledException or ObjectDisposedException or BodyTooLargeException)
            {
                // Client went away or sent garbage; nothing to report.
            }
        }
    }

    private async Task HandleConnectAsync(Stream stream, RequestHead head, CancellationToken ct)
    {
        if (!HostTarget.TryParse(head.Target, 443, out var host, out var port))
        {
            await WriteSimpleAsync(stream, 400, "Bad CONNECT target", ct).ConfigureAwait(false);
            return;
        }

        if (!_rules.ShouldIntercept(host))
        {
            await TunnelAsync(stream, host, port, ct).ConfigureAwait(false);
            return;
        }

        await stream.WriteAsync(Encoding.ASCII.GetBytes("HTTP/1.1 200 Connection Established\r\n\r\n"), ct)
            .ConfigureAwait(false);

        using var ssl = new SslStream(stream, false);
        try
        {
            await ssl.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
            {
                ServerCertificate = ca.GetLeaf(host),
                ApplicationProtocols = [SslApplicationProtocol.Http11],
            }, ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException or System.Security.Authentication.AuthenticationException)
        {
            store.Add(new CapturedFlow
            {
                Method = "CONNECT",
                Url = $"{host}:{port}",
                Error = $"TLS handshake with client failed (certificate pinning or CA not trusted?): {ex.InnerException?.Message ?? ex.Message}",
            });
            return;
        }

        var reader = new WireReader(ssl);
        var authority = port == 443 ? host : $"{host}:{port}";
        while (!ct.IsCancellationRequested)
        {
            var inner = await reader.ReadRequestHeadAsync(ct).ConfigureAwait(false);
            if (inner is null || !await ForwardAsync(reader, ssl, inner, authority, ct).ConfigureAwait(false))
            {
                return;
            }
        }
    }

    private static async Task TunnelAsync(Stream client, string host, int port, CancellationToken ct)
    {
        using var upstream = new TcpClient();
        try
        {
            await upstream.ConnectAsync(host, port, ct).ConfigureAwait(false);
        }
        catch (SocketException ex)
        {
            await WriteSimpleAsync(client, 502, "Upstream error: " + ex.Message, ct).ConfigureAwait(false);
            return;
        }

        await client.WriteAsync(Encoding.ASCII.GetBytes("HTTP/1.1 200 Connection Established\r\n\r\n"), ct)
            .ConfigureAwait(false);
        var remote = upstream.GetStream();
        await Task.WhenAny(client.CopyToAsync(remote, ct), remote.CopyToAsync(client, ct)).ConfigureAwait(false);
    }

    /// <summary>Returns whether the client connection can be reused.</summary>
    private async Task<bool> ForwardAsync(
        WireReader reader, Stream client, RequestHead head, string? tunnelAuthority, CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        byte[] body;
        try
        {
            body = await reader.ReadBodyAsync(head.Headers, ct).ConfigureAwait(false);
        }
        catch (BodyTooLargeException)
        {
            await WriteSimpleAsync(client, 413, "Request body too large for proxy", ct).ConfigureAwait(false);
            return false;
        }

        var closeAfter = string.Equals(head.Header("Connection"), "close", StringComparison.OrdinalIgnoreCase) ||
                         (head.Version == "HTTP/1.0" &&
                          !string.Equals(head.Header("Connection"), "keep-alive", StringComparison.OrdinalIgnoreCase));

        if (!TryBuildUri(head, tunnelAuthority, out var uri))
        {
            await WriteSimpleAsync(client, 400, "Cannot determine target URL", ct).ConfigureAwait(false);
            return false;
        }

        // Capture and rewrite rules only apply to hosts that are not ignored.
        var capture = _rules.ShouldIntercept(uri.Host);

        if (head.Header("Upgrade") is not null)
        {
            if (capture)
            {
                store.Add(new CapturedFlow
                {
                    Method = head.Method,
                    Url = uri.ToString(),
                    RequestHeaders = head.Headers,
                    StatusCode = 501,
                    Error = "Upgrade/WebSocket is not supported by this proxy.",
                });
            }

            await WriteSimpleAsync(client, 501, "Upgrade not supported", ct).ConfigureAwait(false);
            return false;
        }

        var rewrites = capture ? _rewrites : RewriteRuleSet.Empty;
        var applied = new List<string>();
        var request = new MutableRequest(uri, head.Method, [.. head.Headers], body);
        var outcome = rewrites.ApplyRequest(request, applied);
        if (capture && options.Plugins is { } plugins && outcome is { Mock: null, Drop: false })
        {
            var pluginOutcome = plugins.ApplyRequest(request, applied);
            outcome.Mock = pluginOutcome.Mock;
            outcome.Drop = pluginOutcome.Drop;
        }

        var flow = new CapturedFlow
        {
            Method = head.Method,
            Url = request.Uri.ToString(),
            RequestHeaders = request.Headers,
            RequestBody = request.Body,
            AppliedRules = applied,
        };

        void Save()
        {
            flow.Duration = sw.Elapsed;
            if (capture)
            {
                store.Add(flow);
            }
        }

        if (outcome.Delay > TimeSpan.Zero)
        {
            await Task.Delay(outcome.Delay, ct).ConfigureAwait(false);
        }

        if (outcome.Drop)
        {
            flow.Error = "Connection dropped by rewrite rule.";
            Save();
            return false;
        }

        MutableResponse response;
        if (outcome.Mock is { } mock)
        {
            response = mock;
        }
        else
        {
            try
            {
                using var message = BuildRequest(request);
                using var upstream = await _upstream.SendAsync(message, HttpCompletionOption.ResponseContentRead, ct)
                    .ConfigureAwait(false);
                response = new MutableResponse((int)upstream.StatusCode, upstream.ReasonPhrase ?? string.Empty,
                    Flatten(upstream), await upstream.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false));
            }
            catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or InvalidOperationException)
            {
                if (ct.IsCancellationRequested)
                {
                    throw new OperationCanceledException(ct);
                }

                flow.Error = ex.InnerException?.Message ?? ex.Message;
                Save();
                await WriteSimpleAsync(client, 502, "Upstream error: " + flow.Error, ct).ConfigureAwait(false);
                return false;
            }
        }

        var responseDelay = rewrites.ApplyResponse(request, response, applied);
        if (capture)
        {
            options.Plugins?.ApplyResponse(request, response, applied);
        }
        if (responseDelay > TimeSpan.Zero)
        {
            await Task.Delay(responseDelay, ct).ConfigureAwait(false);
        }

        flow.StatusCode = response.Status;
        flow.ReasonPhrase = response.Reason;
        flow.ResponseHeaders = response.Headers;
        flow.ResponseBody = response.Body;
        Save();

        await WriteResponseAsync(client, response, head.Method, closeAfter, ct).ConfigureAwait(false);
        return !closeAfter;
    }

    private static bool TryBuildUri(RequestHead head, string? tunnelAuthority, out Uri uri)
    {
        if (head.Target.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
            head.Target.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            return Uri.TryCreate(head.Target, UriKind.Absolute, out uri!);
        }

        var authority = tunnelAuthority ?? head.Header("Host");
        var scheme = tunnelAuthority is null ? "http" : "https";
        if (authority is null || !head.Target.StartsWith('/'))
        {
            uri = null!;
            return false;
        }

        return Uri.TryCreate($"{scheme}://{authority}{head.Target}", UriKind.Absolute, out uri!);
    }

    private static HttpRequestMessage BuildRequest(MutableRequest request)
    {
        var method = new HttpMethod(request.Method.ToUpperInvariant());
        var message = new HttpRequestMessage(method, request.Uri) { Version = HttpVersion.Version11 };
        var hasBody = request.Body.Length > 0 ||
                      (method != HttpMethod.Get && method != HttpMethod.Head && method != HttpMethod.Delete);
        if (hasBody)
        {
            message.Content = new ByteArrayContent(request.Body);
        }

        foreach (var (name, value) in request.Headers)
        {
            if (HopByHop.Contains(name))
            {
                continue;
            }

            if (!message.Headers.TryAddWithoutValidation(name, value))
            {
                message.Content?.Headers.TryAddWithoutValidation(name, value);
            }
        }

        return message;
    }

    private static List<KeyValuePair<string, string>> Flatten(HttpResponseMessage response) =>
        [.. response.Headers.Concat(response.Content.Headers)
            .SelectMany(h => h.Value.Select(v => new KeyValuePair<string, string>(h.Key, v)))];

    private static async Task WriteResponseAsync(
        Stream client, MutableResponse response, string requestMethod, bool close, CancellationToken ct)
    {
        var isHead = requestMethod.Equals("HEAD", StringComparison.OrdinalIgnoreCase);
        var noBody = isHead || response.Status is 204 or 304 or < 200;
        var head = new StringBuilder($"HTTP/1.1 {response.Status} {response.Reason}\r\n");
        foreach (var (name, value) in response.Headers)
        {
            if (!HopByHop.Contains(name))
            {
                head.Append(name).Append(": ").Append(value).Append("\r\n");
            }
        }

        if (!noBody)
        {
            head.Append("Content-Length: ").Append(response.Body.Length).Append("\r\n");
        }
        else if (isHead)
        {
            head.Append("Content-Length: ").Append(RewriteRuleSet.Header(response.Headers, "Content-Length") ?? "0").Append("\r\n");
        }

        head.Append(close ? "Connection: close\r\n" : "Connection: keep-alive\r\n").Append("\r\n");
        await client.WriteAsync(Encoding.Latin1.GetBytes(head.ToString()), ct).ConfigureAwait(false);
        if (!noBody)
        {
            await client.WriteAsync(response.Body, ct).ConfigureAwait(false);
        }

        await client.FlushAsync(ct).ConfigureAwait(false);
    }

    private static async Task WriteSimpleAsync(Stream client, int status, string message, CancellationToken ct)
    {
        var text = Encoding.UTF8.GetBytes(message);
        var head = $"HTTP/1.1 {status} {(status == 502 ? "Bad Gateway" : "Error")}\r\n" +
                   $"Content-Type: text/plain; charset=utf-8\r\nContent-Length: {text.Length}\r\nConnection: close\r\n\r\n";
        await client.WriteAsync(Encoding.ASCII.GetBytes(head), ct).ConfigureAwait(false);
        await client.WriteAsync(text, ct).ConfigureAwait(false);
        await client.FlushAsync(ct).ConfigureAwait(false);
    }
}
