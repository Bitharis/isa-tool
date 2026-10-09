using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using IsaTool.App.Features.Plugins;
using IsaTool.App.Features.Proxy;
using IsaTool.Plugins;

namespace IsaTool.Tests;

/// <summary>Tests plugin approval, loading, and proxy integration behavior.</summary>
public sealed class PluginTests : IDisposable
{
    private const string KeyVar = "ISATOOL_SIGNING_KEY";
    private readonly string _dir = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());

    public void Dispose()
    {
        try
        {
            Directory.Delete(_dir, true);
        }
        catch (IOException)
        {
            // Loaded plugin assemblies stay locked on Windows until the process exits.
        }
        catch (UnauthorizedAccessException)
        {
        }
    }

    [Fact]
    public void Unapproved_PluginIsListedButNotLoaded()
    {
        InstallSamplePlugin();
        var host = new PluginHost(_dir);

        host.Reload();

        var info = Assert.Single(host.Plugins);
        Assert.Equal(PluginStatus.NotAllowed, info.Status);
        Assert.Empty(info.Instances);
        Assert.Equal(64, info.Sha256.Length);
    }

    [Fact]
    public void Approved_PluginLoadsAndSignsRequests()
    {
        InstallSamplePlugin();
        var host = new PluginHost(_dir);
        host.Allow("RequestSigning");

        var info = Assert.Single(host.Plugins);
        Assert.Equal(PluginStatus.Loaded, info.Status);
        Assert.Equal(2, info.Instances.Count);

        var old = Environment.GetEnvironmentVariable(KeyVar);
        Environment.SetEnvironmentVariable(KeyVar, "k");
        try
        {
            var body = "x=1"u8.ToArray();
            var request = new MutableRequest(new Uri("https://h.test/p?q=1"), "POST", [], body);
            var applied = new List<string>();

            host.ApplyRequest(request, applied);

            var expected = "sha256=" + Convert.ToHexStringLower(HMACSHA256.HashData("k"u8,
                Encoding.UTF8.GetBytes($"POST\n/p?q=1\n{Convert.ToHexStringLower(SHA256.HashData(body))}")));
            Assert.Equal(expected, request.GetHeader("X-Signature"));
            Assert.Contains(applied, a => a.Contains("Request signer"));
        }
        finally
        {
            Environment.SetEnvironmentVariable(KeyVar, old);
        }
    }

    [Fact]
    public void Approved_PluginDecoderRendersFormBodies()
    {
        InstallSamplePlugin();
        var host = new PluginHost(_dir);
        host.Allow("RequestSigning");

        var text = host.TryDecode(new DecoderInput("http://h/", true,
            [new("Content-Type", "application/x-www-form-urlencoded")], "a=1&b=x+y%21"u8.ToArray()));

        Assert.NotNull(text);
        Assert.Contains("[decoded by plugin: Form body decoder]", text);
        Assert.Contains("b = x y!", text);
        Assert.Null(host.TryDecode(new DecoderInput("http://h/", true, [new("Content-Type", "text/plain")], "a"u8.ToArray())));
    }

    [Fact]
    public void ChangedFolder_IsRefusedUntilApprovedAgain()
    {
        var folder = InstallSamplePlugin();
        new PluginHost(_dir).Allow("RequestSigning");

        File.WriteAllText(Path.Combine(folder, "extra.dll"), "tampered");
        var host = new PluginHost(_dir);
        host.Reload();

        var info = Assert.Single(host.Plugins);
        Assert.Equal(PluginStatus.HashMismatch, info.Status);
        Assert.Empty(info.Instances);
        Assert.NotEqual(info.ApprovedSha256, info.Sha256);
    }

    [Fact]
    public void DisabledPlugin_DoesNothing()
    {
        InstallSamplePlugin();
        var host = new PluginHost(_dir);
        host.Allow("RequestSigning");
        host.SetEnabled("RequestSigning", false);

        Assert.Equal(PluginStatus.Disabled, Assert.Single(host.Plugins).Status);
        Assert.Null(host.TryDecode(new DecoderInput("u", true, [new("Content-Type", "application/x-www-form-urlencoded")], "a=1"u8.ToArray())));

        host.SetEnabled("RequestSigning", true);
        Assert.Equal(PluginStatus.Loaded, Assert.Single(host.Plugins).Status);
    }

    [Fact]
    public void Folder_WithoutMainDll_FailsWithMessage()
    {
        Directory.CreateDirectory(Path.Combine(_dir, "Broken"));
        File.WriteAllText(Path.Combine(_dir, "Broken", "readme.txt"), "x");
        var host = new PluginHost(_dir);
        host.Allow("Broken");

        var info = Assert.Single(host.Plugins);
        Assert.Equal(PluginStatus.Failed, info.Status);
        Assert.Contains("Broken.dll", info.Error);
    }

    [Fact]
    public void FailingPlugin_IsDisabledAfterRepeatedErrors()
    {
        var host = new PluginHost(_dir);
        host.AddBuiltIn(new ThrowingPlugin());
        var request = new MutableRequest(new Uri("http://h/"), "GET", [], []);
        var applied = new List<string>();

        for (var i = 0; i < 5; i++)
        {
            host.ApplyRequest(request, applied);
        }

        Assert.Equal(3, applied.Count(a => a.Contains("ERROR")));
        var instance = Assert.Single(Assert.Single(host.Plugins).Instances);
        Assert.True(instance.Disabled);
        Assert.Contains("disabled after 3 errors", instance.LastError);
    }

    [Fact]
    public async Task Proxy_RunsPluginHooksOnCapturedTraffic()
    {
        using var upstream = new HttpListener();
        var port = FreePort();
        upstream.Prefixes.Add($"http://127.0.0.1:{port}/");
        upstream.Start();
        string? seen = null;
        _ = Task.Run(async () =>
        {
            var ctx = await upstream.GetContextAsync();
            seen = ctx.Request.Headers["X-From-Plugin"];
            await ctx.Response.OutputStream.WriteAsync("ok"u8.ToArray());
            ctx.Response.Close();
        });

        var plugins = new PluginHost(_dir);
        plugins.AddBuiltIn(new HeaderPlugin());
        var store = new FlowStore();
        var ca = CertificateAuthority.LoadOrCreate(Path.Combine(_dir, "ca"));
        using var server = new ProxyServer(ca, store, new ProxyOptions(0, Plugins: plugins));
        using var cts = new CancellationTokenSource();
        var proxyPort = server.Start();
        _ = server.RunAsync(cts.Token);
        using var client = new HttpClient(new SocketsHttpHandler { Proxy = new WebProxy($"http://127.0.0.1:{proxyPort}") });

        var response = await client.GetAsync($"http://127.0.0.1:{port}/");

        Assert.Equal("1", seen);
        Assert.Equal("on", response.Headers.GetValues("X-Plugin-Resp").Single());
        var flow = Assert.Single(store.Snapshot());
        Assert.Contains(flow.AppliedRules, a => a.Contains("request hook"));
        Assert.Contains(flow.AppliedRules, a => a.Contains("response hook"));
        await cts.CancelAsync();
    }

    // Copies the sample plugin that the test project builds as a project reference.
    private string InstallSamplePlugin()
    {
        var folder = Path.Combine(_dir, "RequestSigning");
        Directory.CreateDirectory(folder);
        foreach (var name in new[] { "RequestSigning.dll", "RequestSigning.deps.json" })
        {
            var source = Path.Combine(AppContext.BaseDirectory, name);
            if (File.Exists(source))
            {
                File.Copy(source, Path.Combine(folder, name));
            }
        }

        return folder;
    }

    private static int FreePort()
    {
        using var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        return ((IPEndPoint)l.LocalEndpoint).Port;
    }

    private sealed class ThrowingPlugin : IRequestHook
    {
        public string Name => "Thrower";

        public string Description => "Always fails.";

        public RequestOutcome OnRequest(MutableRequest request) => throw new InvalidOperationException("boom");
    }

    private sealed class HeaderPlugin : IRequestHook, IResponseHook
    {
        public string Name => "Header plugin";

        public string Description => "Adds headers.";

        public RequestOutcome OnRequest(MutableRequest request)
        {
            request.SetHeader("X-From-Plugin", "1");
            return RequestOutcome.Continue;
        }

        public void OnResponse(MutableRequest request, MutableResponse response) =>
            response.SetHeader("X-Plugin-Resp", "on");
    }
}
