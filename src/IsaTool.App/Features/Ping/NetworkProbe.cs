using System.Net;
using System.Net.NetworkInformation;

namespace IsaTool.App.Features.Ping;

/// <summary>Represents one ICMP echo response.</summary>
public sealed record PingReply(int Sequence, IPStatus Status, IPAddress? Address, long RoundTripMs);

/// <summary>Represents one hop discovered during a traceroute.</summary>
public sealed record TraceHop(int Ttl, IPAddress? Address, long RoundTripMs, IPStatus Status);

/// <summary>Runs ICMP ping and TTL-based traceroute probes.</summary>
public static class NetworkProbe
{
    /// <summary>Sends the requested number of ICMP echo probes.</summary>
    public static async Task<IReadOnlyList<PingReply>> PingAsync(
        string host, int count, int timeoutMs, IProgress<PingReply>? progress = null, CancellationToken ct = default)
    {
        var replies = new List<PingReply>();
        using var ping = new System.Net.NetworkInformation.Ping();
        for (var i = 1; i <= count; i++)
        {
            ct.ThrowIfCancellationRequested();
            var reply = await SendAsync(ping, host, timeoutMs, ttl: 128).ConfigureAwait(false);
            var row = new PingReply(i, reply.Status, reply.Address, reply.RoundtripTime);
            replies.Add(row);
            progress?.Report(row);
            if (i < count)
            {
                await Task.Delay(500, ct).ConfigureAwait(false);
            }
        }

        return replies;
    }

    /// <summary>Discovers route hops by sending ICMP probes with increasing TTL values.</summary>
    public static async Task<IReadOnlyList<TraceHop>> TraceAsync(
        string host, int maxHops, int timeoutMs, IProgress<TraceHop>? progress = null, CancellationToken ct = default)
    {
        var hops = new List<TraceHop>();
        using var ping = new System.Net.NetworkInformation.Ping();
        for (var ttl = 1; ttl <= maxHops; ttl++)
        {
            ct.ThrowIfCancellationRequested();
            var reply = await SendAsync(ping, host, timeoutMs, ttl).ConfigureAwait(false);
            var hop = new TraceHop(ttl, reply.Address, reply.RoundtripTime, reply.Status);
            hops.Add(hop);
            progress?.Report(hop);
            if (reply.Status == IPStatus.Success)
            {
                break;
            }
        }

        return hops;
    }

    private static async Task<System.Net.NetworkInformation.PingReply> SendAsync(
        System.Net.NetworkInformation.Ping ping, string host, int timeoutMs, int ttl)
    {
        try
        {
            return await ping.SendPingAsync(host, TimeSpan.FromMilliseconds(timeoutMs), new byte[32],
                new PingOptions(ttl, dontFragment: true)).ConfigureAwait(false);
        }
        catch (PingException ex)
        {
            throw new InvalidOperationException(ex.InnerException?.Message ?? ex.Message, ex);
        }
    }
}
