using System.Diagnostics;

namespace IsaTool.App.Features.SystemMonitor;

/// <summary>Represents process resource usage at one sampling instant.</summary>
public sealed record ProcessRow(int Pid, string Name, long WorkingSetBytes, double CpuPercent, int Threads);

/// <summary>Contains a process and memory usage snapshot.</summary>
public sealed record SystemSnapshot(
    IReadOnlyList<ProcessRow> Processes, long TotalMemoryBytes, long AvailableMemoryBytes, int ProcessorCount);

/// <summary>Samples processes and computes CPU utilization between samples.</summary>
public sealed class ProcessSampler
{
    private Dictionary<int, TimeSpan> _previousCpu = [];
    private DateTime _previousAt = DateTime.UtcNow;

    /// <summary>Collects the current process and managed-memory snapshot.</summary>
    public SystemSnapshot Sample()
    {
        var now = DateTime.UtcNow;
        var elapsed = Math.Max((now - _previousAt).TotalSeconds, 0.001);
        var current = new Dictionary<int, TimeSpan>();
        var rows = new List<ProcessRow>();

        foreach (var process in Process.GetProcesses())
        {
            using (process)
            {
                try
                {
                    var cpu = process.TotalProcessorTime;
                    current[process.Id] = cpu;
                    var percent = _previousCpu.TryGetValue(process.Id, out var before)
                        ? (cpu - before).TotalSeconds / elapsed / Environment.ProcessorCount * 100
                        : 0;
                    rows.Add(new ProcessRow(process.Id, process.ProcessName, process.WorkingSet64,
                        Math.Max(percent, 0), process.Threads.Count));
                }
                catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception or NotSupportedException)
                {
                    // Process exited or access denied.
                }
            }
        }

        _previousCpu = current;
        _previousAt = now;

        var info = GC.GetGCMemoryInfo();
        return new SystemSnapshot(rows, info.TotalAvailableMemoryBytes,
            Math.Max(info.TotalAvailableMemoryBytes - rows.Sum(r => r.WorkingSetBytes), 0), Environment.ProcessorCount);
    }
}
