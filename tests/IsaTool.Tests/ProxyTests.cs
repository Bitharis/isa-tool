using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using IsaTool.App.Features.Proxy;

namespace IsaTool.Tests;

/// <summary>Tests certificate and traffic handling behavior of the intercepting proxy.</summary>
public sealed class ProxyTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());

    public void Dispose()
    {
        if (Directory.Exists(_dir))
        {
            Directory.Delete(_dir, true);
        }
    }

    [Fact]
    public void Ca_HasObviousNameAndPersists()
    {
        var ca = CertificateAuthority.LoadOrCreate(_dir);
        var again = CertificateAuthority.LoadOrCreate(_dir);

        Assert.Contains("IsaTool", ca.Certificate.Subject);
        Assert.Contains("REMOVE WHEN DONE", ca.Certificate.Subject);
        Assert.Equal(ca.Certificate.Thumbprint, again.Certificate.Thumbprint);
        Assert.True(File.Exists(ca.CertificatePath));

        CertificateAuthority.DeleteFiles(_dir);
        Assert.False(CertificateAuthority.Exists(_dir));
    }

    [Fact]
    public void Leaf_IsSignedByCaAndNamedForHost()
    {
        var ca = CertificateAuthority.LoadOrCreate(_dir);
        var leaf = ca.GetLeaf("example.test");

        Assert.Contains("IsaTool", leaf.Subject);
        Assert.Equal(ca.Certificate.Subject, leaf.Issuer);
        Assert.True(Trusts(ca.Certificate, leaf));
    }

    [Fact]
    public async Task Proxy_ForwardsPlainHttpAndRecordsFlow()
    {
        using var upstream = new HttpListener();
        var upstreamPort = FreePort();
        upstream.Prefixes.Add($"http://127.0.0.1:{upstreamPort}/");
        upstream.Start();
        _ = Task.Run(async () =>
        {
            var ctx = await upstream.GetContextAsync();
            ctx.Response.Headers["X-Test"] = "1";
            ctx.Response.ContentType = "application/json";
            await ctx.Response.OutputStream.WriteAsync("{\"a\":1}"u8.ToArray());
            ctx.Response.Close();
        });

        var (proxy, store, cts) = StartProxy(false);
        using (proxy)
        {
            using var client = ClientVia(proxy.Port, null);
            var response = await client.GetAsync($"http://127.0.0.1:{upstreamPort}/hello");

            Assert.Equal("{\"a\":1}", await response.Content.ReadAsStringAsync());
            Assert.Equal("1", response.Headers.GetValues("X-Test").Single());
            var flow = Assert.Single(store.Snapshot());
            Assert.Equal(200, flow.StatusCode);
            Assert.EndsWith("/hello", flow.Url);
            Assert.Contains("\"a\": 1", FlowFormatter.FormatDetail(flow));
            await cts.CancelAsync();
        }
    }

    [Fact]
    public async Task Proxy_DecryptsHttpsWithCaCertificate()
    {
        var upstreamCa = CertificateAuthority.LoadOrCreate(Path.Combine(_dir, "upstream"));
        using var tcp = new TcpListener(IPAddress.Loopback, 0);
        tcp.Start();
        var upstreamPort = ((IPEndPoint)tcp.LocalEndpoint).Port;
        _ = Task.Run(async () =>
        {
            using var socket = await tcp.AcceptTcpClientAsync();
            await using var ssl = new SslStream(socket.GetStream());
            await ssl.AuthenticateAsServerAsync(upstreamCa.GetLeaf("localhost"));
            var buffer = new byte[4096];
            _ = await ssl.ReadAsync(buffer);
            await ssl.WriteAsync(Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello"));
            await ssl.FlushAsync();
        });

        var (proxy, store, cts) = StartProxy(true);
        using (proxy)
        {
            using var client = ClientVia(proxy.Port, proxy.CaCertificate);
            var body = await client.GetStringAsync($"https://localhost:{upstreamPort}/secure");

            Assert.Equal("hello", body);
            var flow = Assert.Single(store.Snapshot());
            Assert.Equal($"https://localhost:{upstreamPort}/secure", flow.Url);
            await cts.CancelAsync();
        }
    }

    [Theory]
    [InlineData("", "", "a.com", true)]
    [InlineData("*.corp.com", "", "api.corp.com", true)]
    [InlineData("*.corp.com", "", "corp.com", false)]
    [InlineData("api.corp.com, other.com", "", "other.com", true)]
    [InlineData("", "*.microsoft.com", "update.microsoft.com", false)]
    [InlineData("*.corp.com", "secret.corp.com", "secret.corp.com", false)]
    public void CaptureRules_IncludeAndIgnore(string include, string ignore, string host, bool expected) =>
        Assert.Equal(expected, new CaptureRules(include, ignore).ShouldIntercept(host));

    [Fact]
    public void FlowFilter_MatchesStatusTypeAndText()
    {
        var ok = new CapturedFlow
        {
            Url = "http://h/a",
            StatusCode = 200,
            ResponseHeaders = [new("Content-Type", "application/json")],
            ResponseBody = "{\"token\":\"abc\"}"u8.ToArray(),
        };
        var bad = new CapturedFlow { Url = "http://h/b", StatusCode = 503 };
        var failed = new CapturedFlow { Url = "http://h/c", Error = "boom" };

        Assert.True(new FlowFilter(status: "5xx").Matches(bad));
        Assert.False(new FlowFilter(status: "5xx").Matches(ok));
        Assert.True(new FlowFilter(status: "err").Matches(failed));
        Assert.True(new FlowFilter(status: "404,200").Matches(ok));
        Assert.True(new FlowFilter(contentTypes: "json").Matches(ok));
        Assert.False(new FlowFilter(contentTypes: "json").Matches(bad));
        Assert.True(new FlowFilter(text: "TOKEN").Matches(ok));
        Assert.False(new FlowFilter(text: "TOKEN").Matches(bad));
    }

    [Fact]
    public async Task Proxy_TunnelsIgnoredHttpsHostWithoutDecryptingOrRecording()
    {
        var upstreamCa = CertificateAuthority.LoadOrCreate(Path.Combine(_dir, "upstream"));
        using var tcp = new TcpListener(IPAddress.Loopback, 0);
        tcp.Start();
        var upstreamPort = ((IPEndPoint)tcp.LocalEndpoint).Port;
        _ = Task.Run(async () =>
        {
            using var socket = await tcp.AcceptTcpClientAsync();
            await using var ssl = new SslStream(socket.GetStream());
            await ssl.AuthenticateAsServerAsync(upstreamCa.GetLeaf("localhost"));
            _ = await ssl.ReadAsync(new byte[4096]);
            await ssl.WriteAsync(Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"));
            await ssl.FlushAsync();
        });

        var (proxy, store, cts) = StartProxy(false, new CaptureRules(ignore: "localhost"));
        using (proxy)
        {
            // Trusting only the upstream CA proves the proxy did not substitute its own certificate.
            using var client = ClientVia(proxy.Port, upstreamCa.Certificate);
            Assert.Equal("ok", await client.GetStringAsync($"https://localhost:{upstreamPort}/"));
            Assert.Empty(store.Snapshot());
            await cts.CancelAsync();
        }
    }

    [Fact]
    public async Task Mitm_TerminatesTlsForwardsToServerAndRecordsFlow()
    {
        var upstreamCa = CertificateAuthority.LoadOrCreate(Path.Combine(_dir, "upstream"));
        using var tcp = new TcpListener(IPAddress.Loopback, 0);
        tcp.Start();
        var upstreamPort = ((IPEndPoint)tcp.LocalEndpoint).Port;
        _ = Task.Run(async () =>
        {
            using var socket = await tcp.AcceptTcpClientAsync();
            await using var ssl = new SslStream(socket.GetStream());
            await ssl.AuthenticateAsServerAsync(upstreamCa.GetLeaf("localhost"));
            _ = await ssl.ReadAsync(new byte[4096]);
            await ssl.WriteAsync(Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello"));
            await ssl.FlushAsync();
        });

        var ca = CertificateAuthority.LoadOrCreate(Path.Combine(_dir, "proxy"));
        var store = new FlowStore();
        using var server = new ProxyServer(ca, store, new ProxyOptions(
            0, true, null, null, null, IPAddress.Loopback, new Uri($"https://localhost:{upstreamPort}")));
        using var cts = new CancellationTokenSource();
        var port = server.Start();
        _ = server.RunAsync(cts.Token);

        // No proxy settings: the client talks to the MITM listener as if it were the server.
        using var client = new HttpClient(new SocketsHttpHandler
        {
            SslOptions = { RemoteCertificateValidationCallback = (_, cert, _, _) => cert is X509Certificate2 c && Trusts(ca.Certificate, c) },
        });
        Assert.Equal("hello", await client.GetStringAsync($"https://localhost:{port}/secure"));

        var flow = Assert.Single(store.Snapshot());
        Assert.Equal($"https://localhost:{upstreamPort}/secure", flow.Url);
        Assert.Equal(200, flow.StatusCode);
        await cts.CancelAsync();
    }

    [Fact]
    public async Task Mitm_EndToEndOnLocalhost_CapturesGetAndPostOverOneKeepAliveConnection()
    {
        var serverCa = CertificateAuthority.LoadOrCreate(Path.Combine(_dir, "server"));
        using var tcp = new TcpListener(IPAddress.Loopback, 0);
        tcp.Start();
        var serverPort = ((IPEndPoint)tcp.LocalEndpoint).Port;
        var serverTask = Task.Run(async () =>
        {
            using var socket = await tcp.AcceptTcpClientAsync();
            await using var ssl = new SslStream(socket.GetStream());
            await ssl.AuthenticateAsServerAsync(serverCa.GetLeaf("localhost"));
            var reader = new StreamReader(ssl, Encoding.ASCII);
            while (true)
            {
                var requestLine = await reader.ReadLineAsync();
                if (requestLine is null)
                {
                    return;
                }

                var length = 0;
                string? line;
                while (!string.IsNullOrEmpty(line = await reader.ReadLineAsync()))
                {
                    if (line.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase))
                    {
                        length = int.Parse(line["Content-Length:".Length..].Trim());
                    }
                }

                var buffer = new char[length];
                if (length > 0)
                {
                    await reader.ReadBlockAsync(buffer, 0, length);
                }
                var reply = $"{requestLine.Split(' ')[0]}:{new string(buffer)}";
                await ssl.WriteAsync(Encoding.ASCII.GetBytes(
                    $"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {reply.Length}\r\n\r\n{reply}"));
                await ssl.FlushAsync();
            }
        });

        var proxyCa = CertificateAuthority.LoadOrCreate(Path.Combine(_dir, "proxy"));
        var store = new FlowStore();
        using var mitm = new ProxyServer(proxyCa, store, new ProxyOptions(
            0, true, null, null, null, IPAddress.Loopback, new Uri($"https://localhost:{serverPort}")));
        using var cts = new CancellationTokenSource();
        var mitmPort = mitm.Start();
        _ = mitm.RunAsync(cts.Token);

        using var client = new HttpClient(new SocketsHttpHandler
        {
            SslOptions = { RemoteCertificateValidationCallback = (_, cert, _, _) => cert is X509Certificate2 c && Trusts(proxyCa.Certificate, c) },
        }) { Timeout = TimeSpan.FromSeconds(15) };
        var get = await client.GetStringAsync($"https://localhost:{mitmPort}/status");
        var post = await (await client.PostAsync($"https://localhost:{mitmPort}/login", new StringContent("user=bob"))).Content
            .ReadAsStringAsync();

        Assert.Equal("GET:", get);
        Assert.Equal("POST:user=bob", post);
        var flows = store.Snapshot();
        Assert.Equal(2, flows.Count);
        Assert.Contains(flows, f => f.Method == "GET" && f.Url.EndsWith("/status") && f.StatusCode == 200);
        var captured = Assert.Single(flows, f => f.Method == "POST");
        Assert.Equal("user=bob", Encoding.UTF8.GetString(captured.RequestBody));
        Assert.Equal("POST:user=bob", Encoding.UTF8.GetString(captured.ResponseBody));

        await cts.CancelAsync();
        client.Dispose();
        mitm.Dispose();
        await serverTask.WaitAsync(TimeSpan.FromSeconds(10));
    }

    [Fact]
    public async Task Mitm_RejectsAbsoluteFormTargetsSoItIsNotAnOpenProxy()
    {
        var ca = CertificateAuthority.LoadOrCreate(Path.Combine(_dir, "proxy"));
        var store = new FlowStore();
        using var server = new ProxyServer(ca, store, new ProxyOptions(
            0, false, null, null, null, IPAddress.Loopback, new Uri("http://127.0.0.1:1")));
        using var cts = new CancellationTokenSource();
        var port = server.Start();
        _ = server.RunAsync(cts.Token);

        using var tcpClient = new TcpClient();
        await tcpClient.ConnectAsync(IPAddress.Loopback, port);
        var stream = tcpClient.GetStream();
        await stream.WriteAsync(Encoding.ASCII.GetBytes("GET http://other.test/ HTTP/1.1\r\nHost: other.test\r\n\r\n"));
        var buffer = new byte[256];
        var read = await stream.ReadAsync(buffer);

        Assert.StartsWith("HTTP/1.1 400", Encoding.ASCII.GetString(buffer, 0, read));
        Assert.Empty(store.Snapshot());
        await cts.CancelAsync();
    }

    private (TestProxy Proxy, FlowStore Store, CancellationTokenSource Cts) StartProxy(
        bool ignoreUpstreamErrors, CaptureRules? rules = null)
    {
        var ca = CertificateAuthority.LoadOrCreate(Path.Combine(_dir, "proxy"));
        var store = new FlowStore();
        var server = new ProxyServer(ca, store, new ProxyOptions(0, ignoreUpstreamErrors, rules));
        var cts = new CancellationTokenSource();
        var port = server.Start();
        _ = server.RunAsync(cts.Token);
        return (new TestProxy(server, port, ca.Certificate), store, cts);
    }

    private static HttpClient ClientVia(int proxyPort, X509Certificate2? trustedRoot)
    {
        var handler = new SocketsHttpHandler { Proxy = new WebProxy($"http://127.0.0.1:{proxyPort}") };
        if (trustedRoot is not null)
        {
            handler.SslOptions.RemoteCertificateValidationCallback = (_, cert, _, _) =>
                cert is X509Certificate2 c && Trusts(trustedRoot, c);
        }

        return new HttpClient(handler);
    }

    private static bool Trusts(X509Certificate2 root, X509Certificate2 leaf)
    {
        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(root);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        return chain.Build(leaf);
    }

    private static int FreePort()
    {
        using var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        return ((IPEndPoint)l.LocalEndpoint).Port;
    }

    private sealed class TestProxy(ProxyServer server, int port, X509Certificate2 ca) : IDisposable
    {
        public int Port { get; } = port;

        public X509Certificate2 CaCertificate { get; } = ca;

        public void Dispose() => server.Dispose();
    }
}
