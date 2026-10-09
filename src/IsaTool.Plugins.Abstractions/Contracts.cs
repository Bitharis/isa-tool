namespace IsaTool.Plugins;

/// <summary>
/// Base contract. A plugin class needs a public parameterless constructor and implements this plus
/// one or more hook interfaces. Plugins run with the full rights of the IsaTool process.
/// </summary>
public interface IPlugin
{
    /// <summary>Gets the display name of the plugin.</summary>
    string Name { get; }

    /// <summary>Gets a description of the plugin's behavior.</summary>
    string Description { get; }
}

/// <summary>Called for each captured request before it is sent; may change it, answer it, or drop it.</summary>
public interface IRequestHook : IPlugin
{
    /// <summary>Processes a request before it is sent to its destination.</summary>
    RequestOutcome OnRequest(MutableRequest request);
}

/// <summary>Called for each response before it reaches the client; may change it.</summary>
public interface IResponseHook : IPlugin
{
    /// <summary>Processes a response before it is returned to the client.</summary>
    void OnResponse(MutableRequest request, MutableResponse response);
}

/// <summary>Turns a body into readable text for the flow detail view; return null when not applicable.</summary>
public interface IBodyDecoder : IPlugin
{
    /// <summary>Returns a readable representation of the input body, when supported.</summary>
    string? TryDecode(DecoderInput input);
}
