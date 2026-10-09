using IsaTool.App.Shell;

namespace IsaTool.App.Features.Ping;

/// <summary>Provides the interactive interface for ping and traceroute probes.</summary>
public sealed class PingView : FeatureView
{
    public PingView()
    {
        var host = AddField("Host", "example.com");
        AddButton("Ping", async ct =>
        {
            SetOutput(string.Empty);
            var progress = new Progress<PingReply>(r =>
                AppendOutput($"#{r.Sequence} {r.Address} {r.Status} {r.RoundTripMs} ms\n"));
            await NetworkProbe.PingAsync(host.Text.Trim(), 4, 2000, progress, ct);
        });
        AddButtonSameRow("Traceroute", async ct =>
        {
            SetOutput(string.Empty);
            var progress = new Progress<TraceHop>(h =>
                AppendOutput($"{h.Ttl,2}  {(h.Address?.ToString() ?? "*"),-40} {h.Status} {h.RoundTripMs} ms\n"));
            await NetworkProbe.TraceAsync(host.Text.Trim(), 30, 2000, progress, ct);
        });
        AddStopButton();
        Build();
    }

    /// <inheritdoc />
    public override string FeatureName => "Ping / traceroute";
}
