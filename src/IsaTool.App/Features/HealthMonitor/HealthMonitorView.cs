using System.Text;
using IsaTool.App.Shell;

namespace IsaTool.App.Features.HealthMonitor;

/// <summary>Provides the interactive interface for recurring endpoint health checks.</summary>
public sealed class HealthMonitorView : FeatureView
{
    public HealthMonitorView()
    {
        var urls = AddField("URLs (; sep)", "https://example.com");
        var interval = AddField("Interval (s)", "10");
        AddButton("Start", async ct =>
        {
            var endpoints = urls.Text.Split(';', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
                .Select(u => new HealthEndpoint(u)).ToList();
            _ = int.TryParse(interval.Text, out var seconds);
            await HealthChecker.RunAsync(endpoints, TimeSpan.FromSeconds(Math.Max(seconds, 1)),
                () => SetOutput(Render(endpoints)), ct);
        });
        AddStopButton();
        Build();
    }

    /// <inheritdoc />
    public override string FeatureName => "Health monitor";

    private static string Render(IEnumerable<HealthEndpoint> endpoints)
    {
        var sb = new StringBuilder();
        foreach (var e in endpoints)
        {
            var last = e.Last;
            var state = last is null ? "..." : last.Healthy ? "UP  " : "DOWN";
            sb.AppendLine($"{state} {e.UptimePercent,5:F0}%  {last?.Elapsed.TotalMilliseconds ?? 0,6:F0} ms  {last?.Error ?? last?.StatusCode.ToString()}  {e.Url}");
        }

        return sb.ToString();
    }
}
