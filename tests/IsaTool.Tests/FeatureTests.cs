using System.Net;
using System.Net.Sockets;
using System.Text;
using IsaTool.App.Features.Decoders;
using IsaTool.App.Features.Http;
using IsaTool.App.Features.LogViewer;
using IsaTool.App.Features.PortScan;
using IsaTool.Core.Hosts;
using IsaTool.Core.Settings;

namespace IsaTool.Tests;

/// <summary>Tests shared feature utility behavior.</summary>
public class FeatureTests
{
    [Fact]
    public void Base64_RoundTrips()
    {
        Assert.Equal("hello", Codecs.Base64Decode(Codecs.Base64Encode("hello")));
    }

    [Fact]
    public void Jwt_DecodesAndReportsExpiry()
    {
        static string B64(string s) => Convert.ToBase64String(Encoding.UTF8.GetBytes(s)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var token = $"{B64("{\"alg\":\"none\"}")}.{B64("{\"sub\":\"x\",\"exp\":1000}")}.sig";

        var jwt = Codecs.DecodeJwt(token, DateTimeOffset.FromUnixTimeSeconds(2000));

        Assert.True(jwt.Expired);
        Assert.Contains("\"sub\"", jwt.Payload);
    }

    [Fact]
    public void Jwt_RejectsMalformed() => Assert.Throws<FormatException>(() => Codecs.DecodeJwt("abc"));

    [Fact]
    public void ParsePorts_HandlesRangesAndLists()
    {
        Assert.Equal([22, 80, 81, 82], PortScanner.ParsePorts("22, 80-82"));
        Assert.Throws<FormatException>(() => PortScanner.ParsePorts("70000"));
    }

    [Fact]
    public async Task PortScan_FindsOpenLoopbackPort()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var open = ((IPEndPoint)listener.LocalEndpoint).Port;

        var results = await PortScanner.ScanAsync("127.0.0.1", [open], TimeSpan.FromSeconds(2), 4);

        Assert.True(Assert.Single(results).Open);
    }

    [Fact]
    public async Task Http_FollowsRedirectsAndCapturesChain()
    {
        using var server = new HttpListener();
        var port = FreePort();
        server.Prefixes.Add($"http://127.0.0.1:{port}/");
        server.Start();
        _ = Task.Run(async () =>
        {
            for (var i = 0; i < 2; i++)
            {
                var ctx = await server.GetContextAsync();
                if (ctx.Request.Url!.AbsolutePath == "/a")
                {
                    ctx.Response.StatusCode = 302;
                    ctx.Response.RedirectLocation = "/b";
                }
                else
                {
                    await ctx.Response.OutputStream.WriteAsync("done"u8.ToArray());
                }

                ctx.Response.Close();
            }
        });

        var result = await HttpProbe.SendAsync(new HttpProbeRequest($"http://127.0.0.1:{port}/a"));

        Assert.Null(result.Error);
        Assert.Equal([302, 200], result.Hops.Select(h => h.StatusCode));
        Assert.Equal("done", result.Body);
    }

    [Fact]
    public async Task Http_ReportsInvalidUrl()
    {
        var result = await HttpProbe.SendAsync(new HttpProbeRequest("nope"));
        Assert.NotNull(result.Error);
    }

    [Fact]
    public void LogFilter_SupportsTextRegexAndInvert()
    {
        Assert.True(new LogFilter("error", false).Matches("An ERROR occurred"));
        Assert.True(new LogFilter(@"\d{3}", true).Matches("code 404"));
        Assert.False(new LogFilter("debug", false, invert: true).Matches("debug line"));
    }

    [Fact]
    public async Task LogReader_ReadsTailAndAppended()
    {
        var path = Path.GetTempFileName();
        try
        {
            await File.WriteAllLinesAsync(path, ["1", "2", "3", "4"]);
            var (tail, offset) = await LogReader.ReadTailAsync(path, 2);
            Assert.Equal(["3", "4"], tail);

            await File.AppendAllLinesAsync(path, ["5"]);
            var (added, _) = await LogReader.ReadAppendedAsync(path, offset);
            Assert.Equal(["5"], added);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Theory]
    [InlineData("example.com", 443, "example.com", 443)]
    [InlineData("example.com:8443", 443, "example.com", 8443)]
    [InlineData("https://example.com/x", 0, "example.com", 443)]
    [InlineData("[::1]:80", 443, "::1", 80)]
    public void HostTarget_Parses(string input, int defaultPort, string host, int port)
    {
        Assert.True(HostTarget.TryParse(input, defaultPort, out var h, out var p));
        Assert.Equal((host, port), (h, p));
    }

    [Fact]
    public void SettingsStore_RoundTripsAndDefaultsOnMissing()
    {
        var dir = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
        var store = new SettingsStore(dir);
        Assert.Equal("", store.Load<Sample>("s").Name);
        store.Save("s", new Sample { Name = "x" });
        Assert.Equal("x", store.Load<Sample>("s").Name);
        Directory.Delete(dir, true);
    }

    private static int FreePort()
    {
        using var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        return ((IPEndPoint)l.LocalEndpoint).Port;
    }

    private sealed class Sample
    {
        public string Name { get; set; } = "";
    }
}
