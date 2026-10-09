namespace IsaTool.App.Features.Proxy;

/// <summary>Represents one HTTP transaction captured by the proxy.</summary>
public sealed class CapturedFlow
{
    public int Id { get; set; }

    public DateTime StartedAt { get; init; } = DateTime.Now;

    public string Method { get; init; } = string.Empty;

    public string Url { get; init; } = string.Empty;

    public int? StatusCode { get; set; }

    public string ReasonPhrase { get; set; } = string.Empty;

    public IReadOnlyList<KeyValuePair<string, string>> RequestHeaders { get; init; } = [];

    public byte[] RequestBody { get; init; } = [];

    public IReadOnlyList<KeyValuePair<string, string>> ResponseHeaders { get; set; } = [];

    public byte[] ResponseBody { get; set; } = [];

    public TimeSpan Duration { get; set; }

    public string? Error { get; set; }

    /// <summary>Rewrite-rule actions that changed this flow.</summary>
    public IReadOnlyList<string> AppliedRules { get; set; } = [];
}

/// <summary>Maintains a bounded, thread-safe collection of captured flows.</summary>
public sealed class FlowStore
{
    private const int Capacity = 2000;
    private readonly List<CapturedFlow> _flows = [];
    private int _nextId = 1;

    /// <summary>Incremented on every change so a UI can cheaply detect updates.</summary>
    public int Version { get; private set; }

    /// <summary>Adds a captured flow and assigns its identifier.</summary>
    public void Add(CapturedFlow flow)
    {
        lock (_flows)
        {
            flow.Id = _nextId++;
            _flows.Add(flow);
            if (_flows.Count > Capacity)
            {
                _flows.RemoveAt(0);
            }

            Version++;
        }
    }

    /// <summary>Gets a snapshot of all retained flows.</summary>
    public IReadOnlyList<CapturedFlow> Snapshot()
    {
        lock (_flows)
        {
            return [.. _flows];
        }
    }

    /// <summary>Finds a retained flow by identifier.</summary>
    public CapturedFlow? Get(int id)
    {
        lock (_flows)
        {
            return _flows.Find(f => f.Id == id);
        }
    }

    /// <summary>Removes all retained flows.</summary>
    public void Clear()
    {
        lock (_flows)
        {
            _flows.Clear();
            Version++;
        }
    }
}
