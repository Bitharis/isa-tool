using IsaTool.App.Shell;

namespace IsaTool.App.Features.PortScan;

/// <summary>Provides the interactive interface for TCP port scanning.</summary>
public sealed class PortScanView : FeatureView
{
    public PortScanView()
    {
        var host = AddField("Host", "127.0.0.1");
        var ports = AddField("Ports", "22,80,443,8080");
        var timeout = AddField("Timeout (ms)", "1000");
        AddButton("Scan", async ct =>
        {
            IReadOnlyList<int> list;
            try
            {
                list = PortScanner.ParsePorts(ports.Text);
            }
            catch (FormatException ex)
            {
                SetOutput(ex.Message);
                return;
            }

            _ = int.TryParse(timeout.Text, out var ms);
            SetOutput($"Scanning {list.Count} port(s) on {host.Text.Trim()}...\n");
            var progress = new Progress<PortResult>(r =>
            {
                if (r.Open)
                {
                    AppendOutput($"{r.Port,5}/tcp open ({r.Elapsed.TotalMilliseconds:F0} ms)\n");
                }
            });
            var results = await PortScanner.ScanAsync(host.Text.Trim(), list,
                TimeSpan.FromMilliseconds(ms > 0 ? ms : 1000), 200, progress, ct);
            AppendOutput($"Done. {results.Count(r => r.Open)} open of {results.Count}.\n");
        });
        AddStopButton();
        Build();
    }

    /// <inheritdoc />
    public override string FeatureName => "Port scan";
}
