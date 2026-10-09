using System.Net;
using System.Net.Sockets;
using System.Text;
using IsaTool.App.Features.Proxy;
using IsaTool.Plugins;

namespace IsaTool.Tests;

/// <summary>Tests proxy rewrite-rule parsing and execution behavior.</summary>
public sealed class RewriteTests : IDisposable
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
    public void Load_ReportsInvalidRulesAndSkipsDisabled()
    {
        var path = WriteRules("""
            { // comments allowed
              "rules": [
                { "name": "ok", "actions": [ { "type": "tag", "value": "x" } ] },
                { "name": "off", "enabled": false, "actions": [ { "type": "drop" } ] },
                { "name": "bad type", "actions": [ { "type": "explode" } ] },
                { "name": "missing", "actions": [ { "type": "setRequestHeader" } ] },
                { "name": "status+request", "match": { "status": "5xx" }, "actions": [ { "type": "drop" } ] },
              ]
            }
            """);

        var set = RewriteRuleSet.Load(path, out var errors);

        Assert.Equal(1, set.Count);
        Assert.Equal(3, errors.Count);
        Assert.Contains(errors, e => e.Contains("explode"));
        Assert.Contains(errors, e => e.Contains("'name'"));
    }

    [Fact]
    public void Load_ReportsBadJson()
    {
        var set = RewriteRuleSet.Load(WriteRules("{ nope"), out var errors);
        Assert.Equal(0, set.Count);
        Assert.Single(errors);
    }

    [Fact]
    public void Sample_IsValidAndDisabled()
    {
        var set = RewriteRuleSet.Load(WriteRules(RewriteRuleSet.SampleJson), out var errors);
        Assert.Empty(errors);
        Assert.Equal(0, set.Count);
    }

    [Fact]
    public void Request_SetsHeaderRedirectsAndReplacesBody()
    {
        var set = Compile("""
            { "rules": [ { "name": "r", "match": { "host": "api.example.com", "method": "POST", "path": "/v1/*" },
              "actions": [
                { "type": "setRequestHeader", "name": "X-A", "value": "1" },
                { "type": "removeRequestHeader", "name": "Cookie" },
                { "type": "redirectHost", "host": "staging.example.com:8443" },
                { "type": "replaceRequestBody", "find": "prod", "replace": "test" } ] } ] }
            """);
        var request = new MutableRequest(new Uri("https://api.example.com/v1/items?x=1"), "POST",
            [new("Cookie", "a=b"), new("x-a", "old")], "env=prod"u8.ToArray());
        var applied = new List<string>();

        var result = set.ApplyRequest(request, applied);

        Assert.Null(result.Mock);
        Assert.Equal("https://staging.example.com:8443/v1/items?x=1", request.Uri.ToString());
        Assert.Equal("1", Assert.Single(request.Headers).Value);
        Assert.Equal("env=test", Encoding.UTF8.GetString(request.Body));
        Assert.Equal(4, applied.Count);
    }

    [Fact]
    public void Request_NonMatchingRuleDoesNothing()
    {
        var set = Compile("""{ "rules": [ { "name": "r", "match": { "host": "other.com" }, "actions": [ { "type": "drop" } ] } ] }""");
        var request = new MutableRequest(new Uri("http://api.example.com/"), "GET", [], []);

        var result = set.ApplyRequest(request, []);

        Assert.False(result.Drop);
    }

    [Fact]
    public void Request_MockStopsProcessing()
    {
        var set = Compile("""
            { "rules": [ { "name": "m", "actions": [
              { "type": "mockResponse", "status": 404, "body": "nope", "contentType": "text/plain" },
              { "type": "drop" } ] } ] }
            """);

        var result = set.ApplyRequest(new MutableRequest(new Uri("http://h/"), "GET", [], []), []);

        Assert.Equal(404, result.Mock!.Status);
        Assert.Equal("Not Found", result.Mock.Reason);
        Assert.False(result.Drop);
        Assert.Equal("nope", Encoding.UTF8.GetString(result.Mock.Body));
    }

    [Fact]
    public void Response_StatusMatchTagsAndSetsStatus()
    {
        var set = Compile("""
            { "rules": [
              { "name": "flag", "match": { "status": "5xx" }, "actions": [ { "type": "tag", "value": "bad" }, { "type": "setStatus", "status": 200 } ] },
              { "name": "ok-only", "match": { "status": "404" }, "actions": [ { "type": "tag", "value": "nf" } ] } ] }
            """);
        var request = new MutableRequest(new Uri("http://h/"), "GET", [], []);
        var response = new MutableResponse(503, "Service Unavailable", [], []);
        var applied = new List<string>();

        set.ApplyResponse(request, response, applied);

        Assert.Equal(200, response.Status);
        Assert.Equal(2, applied.Count);
        Assert.DoesNotContain(applied, a => a.Contains("ok-only"));
    }

    [Fact]
    public void Response_ReplacesGzippedBodyAndDropsEncodingHeader()
    {
        var set = Compile("""
            { "rules": [ { "name": "r", "actions": [ { "type": "replaceResponseBody", "find": "secret", "replace": "XXXX" } ] } ] }
            """);
        using var compressed = new MemoryStream();
        using (var gz = new System.IO.Compression.GZipStream(compressed, System.IO.Compression.CompressionMode.Compress, true))
        {
            gz.Write("my secret value"u8);
        }

        var response = new MutableResponse(200, "OK", [new("Content-Encoding", "gzip")], compressed.ToArray());
        set.ApplyResponse(new MutableRequest(new Uri("http://h/"), "GET", [], []), response, []);

        Assert.Equal("my XXXX value", Encoding.UTF8.GetString(response.Body));
        Assert.Empty(response.Headers);
    }

    [Fact]
    public void Tag_AppearsOncePerFlow()
    {
        var set = Compile("""{ "rules": [ { "name": "t", "actions": [ { "type": "tag", "value": "x" } ] } ] }""");
        var request = new MutableRequest(new Uri("http://h/"), "GET", [], []);
        var applied = new List<string>();

        set.ApplyRequest(request, applied);
        set.ApplyResponse(request, new MutableResponse(200, "OK", [], []), applied);

        Assert.Single(applied);
    }

    [Fact]
    public async Task Proxy_AppliesRulesEndToEnd()
    {
        using var upstream = new HttpListener();
        var port = FreePort();
        upstream.Prefixes.Add($"http://127.0.0.1:{port}/");
        upstream.Start();
        string? seenHeader = null;
        _ = Task.Run(async () =>
        {
            var ctx = await upstream.GetContextAsync();
            seenHeader = ctx.Request.Headers["X-Injected"];
            await ctx.Response.OutputStream.WriteAsync("token=secret"u8.ToArray());
            ctx.Response.Close();
        });

        var rules = Compile($$"""
            { "rules": [
              { "name": "inject", "match": { "path": "/data" }, "actions": [
                  { "type": "setRequestHeader", "name": "X-Injected", "value": "yes" },
                  { "type": "replaceResponseBody", "find": "secret", "replace": "REDACTED" } ] },
              { "name": "mock", "match": { "path": "/health" }, "actions": [
                  { "type": "mockResponse", "status": 200, "body": "mocked" } ] },
              { "name": "dead", "match": { "path": "/drop" }, "actions": [ { "type": "drop" } ] } ] }
            """);
        var ca = CertificateAuthority.LoadOrCreate(Path.Combine(_dir, "ca"));
        var store = new FlowStore();
        using var server = new ProxyServer(ca, store, new ProxyOptions(0, Rewrites: rules));
        using var cts = new CancellationTokenSource();
        var proxyPort = server.Start();
        _ = server.RunAsync(cts.Token);
        using var client = new HttpClient(new SocketsHttpHandler { Proxy = new WebProxy($"http://127.0.0.1:{proxyPort}") });

        Assert.Equal("token=REDACTED", await client.GetStringAsync($"http://127.0.0.1:{port}/data"));
        Assert.Equal("yes", seenHeader);
        Assert.Equal("mocked", await client.GetStringAsync($"http://127.0.0.1:{port}/health"));
        await Assert.ThrowsAsync<HttpRequestException>(() => client.GetStringAsync($"http://127.0.0.1:{port}/drop"));

        var flows = store.Snapshot();
        Assert.True(flows.Count >= 3); // HttpClient may retry the dropped request
        Assert.All(flows, f => Assert.NotEmpty(f.AppliedRules));
        Assert.Contains(flows, f => f.Error?.Contains("dropped") == true);
        await cts.CancelAsync();
    }

    private static RewriteRuleSet Compile(string json)
    {
        var path = Path.GetTempFileName();
        try
        {
            File.WriteAllText(path, json);
            var set = RewriteRuleSet.Load(path, out var errors);
            Assert.Empty(errors);
            return set;
        }
        finally
        {
            File.Delete(path);
        }
    }

    private string WriteRules(string json)
    {
        Directory.CreateDirectory(_dir);
        var path = Path.Combine(_dir, Path.GetRandomFileName() + ".json");
        File.WriteAllText(path, json);
        return path;
    }

    private static int FreePort()
    {
        using var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        return ((IPEndPoint)l.LocalEndpoint).Port;
    }
}
