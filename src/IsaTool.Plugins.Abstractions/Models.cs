namespace IsaTool.Plugins;

/// <summary>Header list helpers shared by <see cref="MutableRequest"/> and <see cref="MutableResponse"/>.</summary>
public static class HeaderList
{
    /// <summary>Gets a header value by name, using case-insensitive matching.</summary>
    public static string? Get(IReadOnlyList<KeyValuePair<string, string>> headers, string name) =>
        headers.FirstOrDefault(h => h.Key.Equals(name, StringComparison.OrdinalIgnoreCase)).Value;

    /// <summary>Replaces all values for a header with one value.</summary>
    public static void Set(List<KeyValuePair<string, string>> headers, string name, string value)
    {
        Remove(headers, name);
        headers.Add(new(name, value));
    }

    /// <summary>Removes every value for a header.</summary>
    public static bool Remove(List<KeyValuePair<string, string>> headers, string name) =>
        headers.RemoveAll(h => h.Key.Equals(name, StringComparison.OrdinalIgnoreCase)) > 0;
}

/// <summary>Represents a request that plugins can inspect and modify.</summary>
public sealed class MutableRequest(Uri uri, string method, List<KeyValuePair<string, string>> headers, byte[] body)
{
    /// <summary>Gets or sets the destination URI.</summary>
    public Uri Uri { get; set; } = uri;

    /// <summary>Gets the HTTP method.</summary>
    public string Method { get; } = method;

    /// <summary>Gets the request headers.</summary>
    public List<KeyValuePair<string, string>> Headers { get; } = headers;

    /// <summary>Gets or sets the request body.</summary>
    public byte[] Body { get; set; } = body;

    /// <summary>Gets a request header by name.</summary>
    public string? GetHeader(string name) => HeaderList.Get(Headers, name);

    /// <summary>Sets a request header.</summary>
    public void SetHeader(string name, string value) => HeaderList.Set(Headers, name, value);

    /// <summary>Removes a request header.</summary>
    public bool RemoveHeader(string name) => HeaderList.Remove(Headers, name);
}

/// <summary>Represents a response that plugins can inspect and modify.</summary>
public sealed class MutableResponse(int status, string reason, List<KeyValuePair<string, string>> headers, byte[] body)
{
    /// <summary>Gets or sets the HTTP status code.</summary>
    public int Status { get; set; } = status;

    /// <summary>Gets or sets the HTTP reason phrase.</summary>
    public string Reason { get; set; } = reason;

    /// <summary>Gets the response headers.</summary>
    public List<KeyValuePair<string, string>> Headers { get; } = headers;

    /// <summary>Gets or sets the response body.</summary>
    public byte[] Body { get; set; } = body;

    /// <summary>Gets a response header by name.</summary>
    public string? GetHeader(string name) => HeaderList.Get(Headers, name);

    /// <summary>Sets a response header.</summary>
    public void SetHeader(string name, string value) => HeaderList.Set(Headers, name, value);

    /// <summary>Removes a response header.</summary>
    public bool RemoveHeader(string name) => HeaderList.Remove(Headers, name);
}

/// <summary>What a request hook wants the proxy to do next.</summary>
public sealed class RequestOutcome
{
    /// <summary>Gets the outcome that continues processing normally.</summary>
    public static RequestOutcome Continue { get; } = new();

    /// <summary>Gets the response to return without contacting the destination.</summary>
    public MutableResponse? Mock { get; init; }

    /// <summary>Gets whether the client connection should be closed.</summary>
    public bool Drop { get; init; }

    /// <summary>Answer the client with <paramref name="response"/> without contacting the server.</summary>
    public static RequestOutcome MockWith(MutableResponse response) => new() { Mock = response };

    /// <summary>Close the client connection without any response.</summary>
    public static RequestOutcome DropConnection() => new() { Drop = true };
}

/// <summary>A body about to be shown to the user, already decompressed.</summary>
public sealed record DecoderInput(
    string Url, bool IsRequest, IReadOnlyList<KeyValuePair<string, string>> Headers, byte[] Body)
{
    /// <summary>Gets the body content type, if specified.</summary>
    public string? ContentType => HeaderList.Get(Headers, "Content-Type");
}
