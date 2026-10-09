namespace IsaTool.Core.Hosts;

/// <summary>Parses "host", "host:port", "[v6]:port" and URL inputs.</summary>
public static class HostTarget
{
    /// <summary>Parses a host input and resolves its port, using <paramref name="defaultPort"/> when needed.</summary>
    public static bool TryParse(string? input, int defaultPort, out string host, out int port)
    {
        host = string.Empty;
        port = defaultPort;
        input = input?.Trim();
        if (string.IsNullOrEmpty(input))
        {
            return false;
        }

        if (input.Contains("://", StringComparison.Ordinal))
        {
            if (!Uri.TryCreate(input, UriKind.Absolute, out var uri) || string.IsNullOrEmpty(uri.Host))
            {
                return false;
            }

            host = uri.IdnHost;
            port = uri.IsDefaultPort && defaultPort != 0 ? defaultPort : uri.Port;
            return true;
        }

        if (input.StartsWith('['))
        {
            var end = input.IndexOf(']', StringComparison.Ordinal);
            if (end < 0)
            {
                return false;
            }

            host = input[1..end];
            var rest = input[(end + 1)..];
            return rest.Length == 0 || (rest[0] == ':' && TryPort(rest[1..], out port));
        }

        var colon = input.LastIndexOf(':');
        if (colon >= 0 && input.IndexOf(':', StringComparison.Ordinal) == colon)
        {
            host = input[..colon];
            return host.Length > 0 && TryPort(input[(colon + 1)..], out port);
        }

        host = input;
        return true;
    }

    private static bool TryPort(string text, out int port) =>
        int.TryParse(text, out port) && port is > 0 and <= 65535;
}
