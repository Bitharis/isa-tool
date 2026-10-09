using System.Text;

namespace IsaTool.App.Features.Proxy;

/// <summary>Represents the request line and headers read from the proxy client.</summary>
public sealed record RequestHead(string Method, string Target, string Version, List<KeyValuePair<string, string>> Headers)
{
    public string? Header(string name) =>
        Headers.FirstOrDefault(h => h.Key.Equals(name, StringComparison.OrdinalIgnoreCase)).Value;
}

/// <summary>Indicates that a buffered HTTP body exceeds the configured proxy limit.</summary>
public sealed class BodyTooLargeException() : Exception("Body exceeds the proxy's buffer limit.");

/// <summary>Minimal buffered HTTP/1.1 reader over a stream.</summary>
public sealed class WireReader(Stream stream)
{
    /// <summary>Gets the maximum buffered request-body size.</summary>
    public const int MaxBodyBytes = 32 * 1024 * 1024;
    private const int MaxLine = 16 * 1024;
    private const int MaxHeaders = 200;

    private readonly byte[] _buffer = new byte[8192];
    private int _pos;
    private int _len;

    /// <summary>Reads an HTTP request line and headers.</summary>
    public async Task<RequestHead?> ReadRequestHeadAsync(CancellationToken ct)
    {
        var first = await ReadLineAsync(ct).ConfigureAwait(false);
        while (first is { Length: 0 })
        {
            first = await ReadLineAsync(ct).ConfigureAwait(false);
        }

        if (first is null)
        {
            return null;
        }

        var parts = first.Split(' ', 3);
        if (parts.Length != 3)
        {
            throw new InvalidDataException("Malformed request line.");
        }

        return new RequestHead(parts[0], parts[1], parts[2], await ReadHeadersAsync(ct).ConfigureAwait(false));
    }

    /// <summary>Reads headers through the terminating empty line.</summary>
    public async Task<List<KeyValuePair<string, string>>> ReadHeadersAsync(CancellationToken ct)
    {
        var headers = new List<KeyValuePair<string, string>>();
        while (true)
        {
            var line = await ReadLineAsync(ct).ConfigureAwait(false) ?? throw new EndOfStreamException();
            if (line.Length == 0)
            {
                return headers;
            }

            var colon = line.IndexOf(':', StringComparison.Ordinal);
            if (colon <= 0 || headers.Count >= MaxHeaders)
            {
                throw new InvalidDataException("Malformed header.");
            }

            headers.Add(new(line[..colon].Trim(), line[(colon + 1)..].Trim()));
        }
    }

    /// <summary>Reads a length-delimited or chunked HTTP body.</summary>
    public async Task<byte[]> ReadBodyAsync(IReadOnlyList<KeyValuePair<string, string>> headers, CancellationToken ct)
    {
        string? Find(string n) => headers.FirstOrDefault(h => h.Key.Equals(n, StringComparison.OrdinalIgnoreCase)).Value;

        if (Find("Transfer-Encoding") is { } te && te.Contains("chunked", StringComparison.OrdinalIgnoreCase))
        {
            return await ReadChunkedAsync(ct).ConfigureAwait(false);
        }

        if (long.TryParse(Find("Content-Length"), out var length) && length > 0)
        {
            if (length > MaxBodyBytes)
            {
                throw new BodyTooLargeException();
            }

            var body = new byte[length];
            await ReadExactlyAsync(body, ct).ConfigureAwait(false);
            return body;
        }

        return [];
    }

    private async Task<byte[]> ReadChunkedAsync(CancellationToken ct)
    {
        using var body = new MemoryStream();
        while (true)
        {
            var sizeLine = await ReadLineAsync(ct).ConfigureAwait(false) ?? throw new EndOfStreamException();
            var semicolon = sizeLine.IndexOf(';', StringComparison.Ordinal);
            var hex = (semicolon >= 0 ? sizeLine[..semicolon] : sizeLine).Trim();
            if (!int.TryParse(hex, System.Globalization.NumberStyles.HexNumber, null, out var size) || size < 0)
            {
                throw new InvalidDataException("Bad chunk size.");
            }

            if (size == 0)
            {
                await ReadHeadersAsync(ct).ConfigureAwait(false); // trailers
                return body.ToArray();
            }

            if (body.Length + size > MaxBodyBytes)
            {
                throw new BodyTooLargeException();
            }

            var chunk = new byte[size];
            await ReadExactlyAsync(chunk, ct).ConfigureAwait(false);
            body.Write(chunk);
            await ReadLineAsync(ct).ConfigureAwait(false);
        }
    }

    private async Task<string?> ReadLineAsync(CancellationToken ct)
    {
        var line = new StringBuilder();
        while (true)
        {
            if (_pos == _len)
            {
                _len = await stream.ReadAsync(_buffer, ct).ConfigureAwait(false);
                _pos = 0;
                if (_len == 0)
                {
                    return line.Length == 0 ? null : throw new EndOfStreamException();
                }
            }

            var b = _buffer[_pos++];
            if (b == '\n')
            {
                if (line.Length > 0 && line[^1] == '\r')
                {
                    line.Length--;
                }

                return line.ToString();
            }

            if (line.Length >= MaxLine)
            {
                throw new InvalidDataException("Line too long.");
            }

            line.Append((char)b);
        }
    }

    private async Task ReadExactlyAsync(byte[] target, CancellationToken ct)
    {
        var offset = 0;
        while (offset < target.Length)
        {
            if (_pos < _len)
            {
                var n = Math.Min(_len - _pos, target.Length - offset);
                Buffer.BlockCopy(_buffer, _pos, target, offset, n);
                _pos += n;
                offset += n;
            }
            else
            {
                var n = await stream.ReadAsync(target.AsMemory(offset), ct).ConfigureAwait(false);
                if (n == 0)
                {
                    throw new EndOfStreamException();
                }

                offset += n;
            }
        }
    }
}
