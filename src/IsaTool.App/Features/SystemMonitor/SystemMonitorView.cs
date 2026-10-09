using System.Text;
using IsaTool.App.Shell;

namespace IsaTool.App.Features.SystemMonitor;

/// <summary>Provides the interactive interface for process monitoring.</summary>
public sealed class SystemMonitorView : FeatureView
{
    private readonly ProcessSampler _sampler = new();

    public SystemMonitorView()
    {
        var sort = AddField("Sort (cpu/mem)", "cpu");
        AddButton("Start", async ct =>
        {
            using var timer = new PeriodicTimer(TimeSpan.FromSeconds(2));
            do
            {
                SetOutput(Render(_sampler.Sample(), sort.Text.Trim().StartsWith('m')));
            }
            while (await timer.WaitForNextTickAsync(ct));
        });
        AddStopButton();
        Build();
    }

    /// <inheritdoc />
    public override string FeatureName => "Processes";

    private static string Render(SystemSnapshot s, bool byMemory)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"CPUs: {s.ProcessorCount}   Memory: {s.TotalMemoryBytes / 1048576} MB total, ~{s.AvailableMemoryBytes / 1048576} MB free");
        sb.AppendLine($"{"PID",7} {"CPU%",6} {"MEM MB",8} {"THR",4}  NAME");
        var rows = byMemory ? s.Processes.OrderByDescending(p => p.WorkingSetBytes) : s.Processes.OrderByDescending(p => p.CpuPercent);
        foreach (var p in rows.Take(60))
        {
            sb.AppendLine($"{p.Pid,7} {p.CpuPercent,6:F1} {p.WorkingSetBytes / 1048576,8} {p.Threads,4}  {p.Name}");
        }

        return sb.ToString();
    }
}
