using System.Net;
using System.Net.Sockets;
using IsaTool.App.Features.Assessment;

namespace IsaTool.Tests;

/// <summary>Tests assessment validation, execution, persistence, and comparison behavior.</summary>
public sealed class AssessmentTests : IDisposable
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
    public void BuildDefinition_RequiresExactValidTargetsAndLimits()
    {
        Assert.True(AssessmentService.TryBuildDefinition("test", "https://example.com;localhost:8443", "80,443,8000-8002",
            out var definition, out _));
        Assert.Equal(2, definition.Targets.Count);
        Assert.Equal([80, 443, 8000, 8001, 8002], definition.Ports);

        Assert.False(AssessmentService.TryBuildDefinition("test", "*.example.com", "", out _, out _));
        Assert.False(AssessmentService.TryBuildDefinition("test", "10.0.0.0/24", "", out _, out _));
        Assert.False(AssessmentService.TryBuildDefinition("test", "https://user:secret@example.com/", "", out _, out _));
        Assert.False(AssessmentService.TryBuildDefinition("test", "https://example.com", "1-100", out _, out _));
        Assert.False(AssessmentService.TryBuildDefinition("", "example.com", "", out _, out _));
    }

    [Fact]
    public async Task RunAsync_ChecksLocalHttpAndFindsMissingHeaders()
    {
        using var server = new HttpListener();
        var port = FreePort();
        server.Prefixes.Add($"http://127.0.0.1:{port}/");
        server.Start();
        _ = Task.Run(async () =>
        {
            var context = await server.GetContextAsync();
            context.Response.ContentType = "text/plain";
            context.Response.Headers.Add("Set-Cookie", "session=private-cookie-value; Path=/");
            await context.Response.OutputStream.WriteAsync("ok"u8.ToArray());
            context.Response.Close();
        });

        var definition = new AssessmentDefinition
        {
            Name = "local test",
            Targets = [$"http://127.0.0.1:{port}/"],
        };

        var run = await AssessmentService.RunAsync(definition);

        Assert.Contains(run.Findings, f => f.Key == "dns" && f.Summary == "Host name resolved");
        Assert.Contains(run.Findings, f => f.Key == "http:status" && f.Summary.Contains("200"));
        Assert.Contains(run.Findings, f => f.Key == "http:header:Content-Security-Policy");
        Assert.DoesNotContain(run.Findings, f => f.Key == "http:header:Strict-Transport-Security");
        Assert.Contains(run.Findings, f => f.Key == "cookie:session:httponly");
        Assert.DoesNotContain(run.Findings, f => f.Evidence.Contains("private-cookie-value", StringComparison.Ordinal));
    }

    [Fact]
    public void Store_SavesDefinitionsRunsAndFindsPreviousRun()
    {
        var store = new AssessmentStore(Path.Combine(_dir, "archive.json"));
        var definition = new AssessmentDefinition { Name = "one", Targets = ["example.com"] };
        store.SaveDefinition(definition);
        var older = new AssessmentRun { AssessmentName = "one", StartedAt = DateTimeOffset.UtcNow.AddMinutes(-1) };
        var newer = new AssessmentRun { AssessmentName = "one", StartedAt = DateTimeOffset.UtcNow };
        store.SaveRun(older);
        store.SaveRun(newer);

        Assert.Single(store.List());
        Assert.Equal(2, store.Runs("one").Count);
        Assert.Equal(older.Id, store.PreviousRun("one", newer.Id)!.Id);
    }

    [Fact]
    public void Compare_ReportsNewAndResolvedFindings()
    {
        var old = new AssessmentRun
        {
            Findings =
            [
                new AssessmentFinding { Target = "host", Key = "dns", Summary = "DNS" },
                new AssessmentFinding { Target = "host", Key = "tls", Summary = "TLS" },
            ],
        };
        var current = new AssessmentRun
        {
            Findings =
            [
                new AssessmentFinding { Target = "host", Key = "dns", Summary = "DNS" },
                new AssessmentFinding { Target = "other", Key = "tls", Summary = "TLS" },
            ],
        };

        var diff = AssessmentService.Compare(old, current);

        Assert.Equal("other", Assert.Single(diff.NewFindings).Target);
        Assert.Equal("host", Assert.Single(diff.ResolvedFindings).Target);
    }

    private static int FreePort()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        return ((IPEndPoint)listener.LocalEndpoint).Port;
    }
}
