using System.Net.Sockets;

namespace IsaTool.App.Features.PortScan;

/// <summary>Represents the result of a TCP port probe.</summary>
public sealed record PortResult(int Port, bool Open, TimeSpan Elapsed);

/// <summary>Parses port specifications and performs bounded concurrent TCP connect scans.</summary>
public static class PortScanner
{
    /// <summary>Parses comma- or space-separated ports and port ranges.</summary>
    public static IReadOnlyList<int> ParsePorts(string spec)
    {
        var ports = new SortedSet<int>();
        foreach (var part in spec.Split([',', ' '], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var dash = part.IndexOf('-', StringComparison.Ordinal);
            if (dash > 0 && int.TryParse(part[..dash], out var from) && int.TryParse(part[(dash + 1)..], out var to))
            {
                if (from < 1 || to > 65535 || from > to)
                {
                    throw new FormatException($"Invalid port range '{part}'.");
                }

                for (var p = from; p <= to; p++)
                {
                    ports.Add(p);
                }
            }
            else if (int.TryParse(part, out var single) && single is >= 1 and <= 65535)
            {
                ports.Add(single);
            }
            else
            {
                throw new FormatException($"Invalid port '{part}'.");
            }
        }

        return [.. ports];
    }

    /// <summary>Scans ports concurrently and returns results ordered by port.</summary>
    public static async Task<IReadOnlyList<PortResult>> ScanAsync(
        string host, IReadOnlyList<int> ports, TimeSpan timeout, int concurrency,
        IProgress<PortResult>? progress = null, CancellationToken ct = default)
    {
        var results = new List<PortResult>();
        await Parallel.ForEachAsync(ports,
            new ParallelOptions { MaxDegreeOfParallelism = Math.Clamp(concurrency, 1, 1000), CancellationToken = ct },
            async (port, token) =>
            {
                var result = await ProbeAsync(host, port, timeout, token).ConfigureAwait(false);
                lock (results)
                {
                    results.Add(result);
                }

                progress?.Report(result);
            }).ConfigureAwait(false);

        return [.. results.OrderBy(r => r.Port)];
    }

    /// <summary>Attempts a TCP connection to one port.</summary>
    public static async Task<PortResult> ProbeAsync(string host, int port, TimeSpan timeout, CancellationToken ct)
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout);
        try
        {
            using var client = new TcpClient();
            await client.ConnectAsync(host, port, cts.Token).ConfigureAwait(false);
            return new PortResult(port, true, sw.Elapsed);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex) when (ex is SocketException or OperationCanceledException)
        {
            return new PortResult(port, false, sw.Elapsed);
        }
    }
}
