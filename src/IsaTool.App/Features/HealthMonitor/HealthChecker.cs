using System.Diagnostics;

namespace IsaTool.App.Features.HealthMonitor;

/// <summary>Represents the result of one health endpoint check.</summary>
public sealed record HealthCheckResult(DateTime At, bool Healthy, int? StatusCode, TimeSpan Elapsed, string? Error);

/// <summary>Tracks health-check history for an HTTP endpoint.</summary>
public sealed class HealthEndpoint(string url, int expectedStatus = 0)
{
    private const int HistoryLimit = 100;
    private readonly List<HealthCheckResult> _history = [];

    /// <summary>Gets the endpoint URL.</summary>
    public string Url { get; } = url;

    /// <summary>0 means any 2xx/3xx is healthy.</summary>
    public int ExpectedStatus { get; } = expectedStatus;

    /// <summary>Gets a snapshot of recent health-check results.</summary>
    public IReadOnlyList<HealthCheckResult> History
    {
        get { lock (_history) { return [.. _history]; } }
    }

    /// <summary>Gets the most recent result, if any.</summary>
    public HealthCheckResult? Last
    {
        get { lock (_history) { return _history.Count > 0 ? _history[^1] : null; } }
    }

    /// <summary>Records a result while retaining a bounded history.</summary>
    public void Record(HealthCheckResult result)
    {
        lock (_history)
        {
            _history.Add(result);
            if (_history.Count > HistoryLimit)
            {
                _history.RemoveAt(0);
            }
        }
    }

    /// <summary>Gets the percentage of retained checks that were healthy.</summary>
    public double UptimePercent
    {
        get
        {
            var h = History;
            return h.Count == 0 ? 0 : h.Count(r => r.Healthy) * 100.0 / h.Count;
        }
    }
}

/// <summary>Executes single and recurring HTTP health checks.</summary>
public static class HealthChecker
{
    private static readonly HttpClient Client = new(new SocketsHttpHandler { AllowAutoRedirect = false })
    {
        Timeout = TimeSpan.FromSeconds(10),
    };

    /// <summary>Checks an endpoint once.</summary>
    public static async Task<HealthCheckResult> CheckAsync(HealthEndpoint endpoint, CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        try
        {
            using var response = await Client.GetAsync(endpoint.Url, HttpCompletionOption.ResponseHeadersRead, ct)
                .ConfigureAwait(false);
            var code = (int)response.StatusCode;
            var healthy = endpoint.ExpectedStatus == 0 ? code is >= 200 and < 400 : code == endpoint.ExpectedStatus;
            return new HealthCheckResult(DateTime.Now, healthy, code, sw.Elapsed, healthy ? null : $"HTTP {code}");
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or InvalidOperationException)
        {
            var error = ex is TaskCanceledException ? "Timed out" : ex.InnerException?.Message ?? ex.Message;
            return new HealthCheckResult(DateTime.Now, false, null, sw.Elapsed, error);
        }
    }

    /// <summary>Repeatedly checks endpoints until cancellation is requested.</summary>
    public static async Task RunAsync(
        IReadOnlyList<HealthEndpoint> endpoints, TimeSpan interval, Action onUpdate, CancellationToken ct)
    {
        using var timer = new PeriodicTimer(interval);
        do
        {
            await Task.WhenAll(endpoints.Select(async e => e.Record(await CheckAsync(e, ct).ConfigureAwait(false))))
                .ConfigureAwait(false);
            onUpdate();
        }
        while (await timer.WaitForNextTickAsync(ct).ConfigureAwait(false));
    }
}
