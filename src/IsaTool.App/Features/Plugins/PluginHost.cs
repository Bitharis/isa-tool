using System.Diagnostics;
using System.Reflection;
using System.Runtime.Loader;
using System.Security.Cryptography;
using System.Text;
using IsaTool.Core.Settings;
using IsaTool.Plugins;

namespace IsaTool.App.Features.Plugins;

/// <summary>Describes a plugin's approval and load state.</summary>
public enum PluginStatus
{
    NotAllowed,
    HashMismatch,
    Disabled,
    Loaded,
    Failed,
}

/// <summary>Tracks an instantiated plugin and its runtime health.</summary>
public sealed class PluginInstance(IPlugin plugin)
{
    public IPlugin Plugin { get; } = plugin;

    public bool Disabled { get; set; }

    public int Errors { get; set; }

    public string? LastError { get; set; }

    public string Capabilities =>
        string.Join(", ", new[]
        {
            Plugin is IRequestHook ? "request hook" : null,
            Plugin is IResponseHook ? "response hook" : null,
            Plugin is IBodyDecoder ? "body decoder" : null,
        }.Where(c => c is not null));
}

/// <summary>Describes a discovered plugin folder and its loaded instances.</summary>
public sealed class PluginInfo(string folder, string path)
{
    public string Folder { get; } = folder;

    public string Path { get; } = path;

    public string Sha256 { get; set; } = string.Empty;

    /// <summary>Hash of the files that were actually loaded into this process.</summary>
    public string? LoadedSha256 { get; set; }

    public string? ApprovedSha256 { get; set; }

    public bool Enabled { get; set; }

    public PluginStatus Status { get; set; } = PluginStatus.NotAllowed;

    public string? Error { get; set; }

    public List<PluginInstance> Instances { get; } = [];
}

/// <summary>Represents a persisted approval decision for a plugin folder.</summary>
public sealed class AllowedPlugin
{
    public string Folder { get; set; } = string.Empty;

    public string Sha256 { get; set; } = string.Empty;

    public bool Enabled { get; set; } = true;
}

/// <summary>Contains persisted approved plugin entries.</summary>
public sealed class AllowList
{
    public List<AllowedPlugin> Plugins { get; set; } = [];
}

/// <summary>
/// Loads plugins from &lt;dir&gt;/&lt;Name&gt;/&lt;Name&gt;.dll, but only folders whose content hash was approved by the user.
/// Plugins are not sandboxed: they run with the full rights of this process.
/// </summary>
public sealed class PluginHost
{
    private const int MaxErrors = 3;
    private const string AllowListName = "allowed-plugins";
    private const string ContractAssembly = "IsaTool.Plugins.Abstractions";

    private readonly string _directory;
    private readonly SettingsStore _store;
    private readonly object _gate = new();
    private readonly Dictionary<string, PluginInfo> _plugins = new(StringComparer.OrdinalIgnoreCase);
    private volatile PluginInstance[] _active = [];

    public PluginHost(string directory)
    {
        _directory = directory;
        _store = new SettingsStore(directory);
    }

    public static PluginHost Shared { get; } = new(DefaultDirectory);

    public static string DefaultDirectory => Path.Combine(SettingsStore.DefaultDirectory, "plugins");

    public string Directory => _directory;

    public IReadOnlyList<PluginInfo> Plugins
    {
        get
        {
            lock (_gate)
            {
                return [.. _plugins.Values.OrderBy(p => p.Folder, StringComparer.OrdinalIgnoreCase)];
            }
        }
    }

    /// <summary>Rescans the folder and loads approved plugins that are not loaded yet.</summary>
    public void Reload()
    {
        lock (_gate)
        {
            var allowed = _store.Load<AllowList>(AllowListName).Plugins;
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            if (System.IO.Directory.Exists(_directory))
            {
                foreach (var dir in System.IO.Directory.EnumerateDirectories(_directory))
                {
                    var folder = System.IO.Path.GetFileName(dir);
                    seen.Add(folder);
                    if (!_plugins.TryGetValue(folder, out var info))
                    {
                        info = new PluginInfo(folder, System.IO.Path.Combine(dir, folder + ".dll"));
                        _plugins[folder] = info;
                    }

                    Refresh(info, dir, allowed.Find(a => a.Folder.Equals(folder, StringComparison.OrdinalIgnoreCase)));
                }
            }

            foreach (var gone in _plugins.Keys.Where(k => !seen.Contains(k) && _plugins[k].Instances.Count == 0).ToList())
            {
                _plugins.Remove(gone);
            }

            RebuildActive();
        }
    }

    /// <summary>Approves the folder's current content hash and loads it.</summary>
    public void Allow(string folder)
    {
        lock (_gate)
        {
            var dir = System.IO.Path.Combine(_directory, folder);
            if (!System.IO.Directory.Exists(dir))
            {
                throw new InvalidOperationException($"Plugin folder '{folder}' not found.");
            }

            var list = _store.Load<AllowList>(AllowListName);
            list.Plugins.RemoveAll(a => a.Folder.Equals(folder, StringComparison.OrdinalIgnoreCase));
            list.Plugins.Add(new AllowedPlugin { Folder = folder, Sha256 = ComputeHash(dir), Enabled = true });
            _store.Save(AllowListName, list);
        }

        Reload();
    }

    public void SetEnabled(string folder, bool enabled)
    {
        lock (_gate)
        {
            var list = _store.Load<AllowList>(AllowListName);
            var entry = list.Plugins.Find(a => a.Folder.Equals(folder, StringComparison.OrdinalIgnoreCase))
                        ?? throw new InvalidOperationException($"'{folder}' is not in the allow-list; use Allow first.");
            entry.Enabled = enabled;
            _store.Save(AllowListName, list);
        }

        Reload();
    }

    /// <summary>Registers an in-process plugin (used by tests).</summary>
    public void AddBuiltIn(IPlugin plugin)
    {
        lock (_gate)
        {
            var info = new PluginInfo(plugin.Name, "(built-in)") { Status = PluginStatus.Loaded, Enabled = true };
            info.Instances.Add(new PluginInstance(plugin));
            _plugins[plugin.Name] = info;
            RebuildActive();
        }
    }

    public RequestOutcome ApplyRequest(MutableRequest request, List<string> applied)
    {
        var outcome = RequestOutcome.Continue;
        foreach (var instance in _active)
        {
            if (instance.Plugin is not IRequestHook hook || instance.Disabled)
            {
                continue;
            }

            var before = Fingerprint(request);
            if (!Run(instance, applied, "request hook", () => outcome = hook.OnRequest(request) ?? RequestOutcome.Continue))
            {
                continue;
            }

            if (before != Fingerprint(request) || outcome.Mock is not null || outcome.Drop)
            {
                applied.Add($"plugin {instance.Plugin.Name}: request hook" +
                            (outcome.Mock is not null ? " (mock)" : outcome.Drop ? " (drop)" : string.Empty));
            }

            if (outcome.Mock is not null || outcome.Drop)
            {
                break;
            }
        }

        return outcome;
    }

    public void ApplyResponse(MutableRequest request, MutableResponse response, List<string> applied)
    {
        foreach (var instance in _active)
        {
            if (instance.Plugin is not IResponseHook hook || instance.Disabled)
            {
                continue;
            }

            var before = Fingerprint(response);
            if (Run(instance, applied, "response hook", () => hook.OnResponse(request, response)) &&
                before != Fingerprint(response))
            {
                applied.Add($"plugin {instance.Plugin.Name}: response hook");
            }
        }
    }

    /// <summary>First decoder that recognises the body wins; the result names the plugin.</summary>
    public string? TryDecode(DecoderInput input)
    {
        foreach (var instance in _active)
        {
            if (instance.Plugin is not IBodyDecoder decoder || instance.Disabled)
            {
                continue;
            }

            string? text = null;
            if (Run(instance, null, "body decoder", () => text = decoder.TryDecode(input)) && text is not null)
            {
                return $"[decoded by plugin: {instance.Plugin.Name}]\n{text}";
            }
        }

        return null;
    }

    /// <summary>Hash over every file in the folder (except .pdb), so swapped or added files change it.</summary>
    public static string ComputeHash(string folder)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var files = System.IO.Directory.EnumerateFiles(folder, "*", SearchOption.AllDirectories)
            .Where(f => !f.EndsWith(".pdb", StringComparison.OrdinalIgnoreCase))
            .Select(f => (Full: f, Rel: System.IO.Path.GetRelativePath(folder, f).Replace('\\', '/').ToLowerInvariant()))
            .OrderBy(f => f.Rel, StringComparer.Ordinal);

        foreach (var (full, rel) in files)
        {
            var bytes = File.ReadAllBytes(full);
            hash.AppendData(Encoding.UTF8.GetBytes(rel + "\0"));
            hash.AppendData(BitConverter.GetBytes((long)bytes.Length));
            hash.AppendData(bytes);
        }

        return Convert.ToHexStringLower(hash.GetHashAndReset());
    }

    private void Refresh(PluginInfo info, string dir, AllowedPlugin? allowed)
    {
        info.Sha256 = ComputeHash(dir);
        info.ApprovedSha256 = allowed?.Sha256;
        info.Enabled = allowed?.Enabled ?? false;

        if (allowed is null)
        {
            info.Status = PluginStatus.NotAllowed;
            info.Error = null;
            return;
        }

        if (!allowed.Sha256.Equals(info.Sha256, StringComparison.OrdinalIgnoreCase))
        {
            info.Status = PluginStatus.HashMismatch;
            info.Error = "Files changed since you approved them. Review, then Allow again.";
            return;
        }

        if (info.Instances.Count > 0)
        {
            if (info.LoadedSha256 is not null && info.LoadedSha256 != info.Sha256)
            {
                info.Status = PluginStatus.Failed;
                info.Error = "Files changed after this plugin was loaded; restart IsaTool to load the new version.";
                foreach (var i in info.Instances)
                {
                    i.Disabled = true;
                }

                return;
            }

            info.Status = allowed.Enabled ? PluginStatus.Loaded : PluginStatus.Disabled;
            foreach (var i in info.Instances)
            {
                i.Disabled = !allowed.Enabled || i.Errors >= MaxErrors;
            }

            return;
        }

        if (!allowed.Enabled)
        {
            info.Status = PluginStatus.Disabled;
            return;
        }

        try
        {
            foreach (var plugin in LoadInstances(info))
            {
                info.Instances.Add(new PluginInstance(plugin));
            }

            info.Status = PluginStatus.Loaded;
            info.LoadedSha256 = info.Sha256;
            info.Error = null;
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            info.Status = PluginStatus.Failed;
            info.Error = ex.Message;
        }
    }

    private static List<IPlugin> LoadInstances(PluginInfo info)
    {
        if (!File.Exists(info.Path))
        {
            throw new FileNotFoundException($"Expected {System.IO.Path.GetFileName(info.Path)} in the plugin folder.");
        }

        var context = new PluginLoadContext(info.Path);
        var assembly = context.LoadFromAssemblyPath(info.Path);

        var wanted = typeof(IPlugin).Assembly.GetName().Version!.Major;
        var referenced = assembly.GetReferencedAssemblies().FirstOrDefault(a => a.Name == ContractAssembly)
                         ?? throw new InvalidOperationException("Plugin does not reference the IsaTool contracts assembly.");
        if (referenced.Version?.Major != wanted)
        {
            throw new InvalidOperationException(
                $"Plugin was built for contract v{referenced.Version?.Major}, this IsaTool expects v{wanted}.");
        }

        Type[] types;
        try
        {
            types = assembly.GetTypes();
        }
        catch (ReflectionTypeLoadException ex)
        {
            throw new InvalidOperationException(
                "Could not load plugin types: " + string.Join("; ", ex.LoaderExceptions.Select(e => e?.Message)), ex);
        }

        var plugins = types
            .Where(t => t is { IsAbstract: false, IsClass: true, IsPublic: true } && typeof(IPlugin).IsAssignableFrom(t) &&
                        t.GetConstructor(Type.EmptyTypes) is not null)
            .Select(t => (IPlugin)Activator.CreateInstance(t)!)
            .ToList();
        return plugins.Count > 0 ? plugins : throw new InvalidOperationException("No public IPlugin classes with a parameterless constructor found.");
    }

    private bool Run(PluginInstance instance, List<string>? applied, string what, Action action)
    {
        var sw = Stopwatch.StartNew();
        try
        {
            action();
            return true;
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            lock (_gate)
            {
                instance.Errors++;
                instance.LastError = $"{what}: {ex.GetType().Name}: {ex.Message} ({sw.ElapsedMilliseconds} ms)";
                if (instance.Errors >= MaxErrors && !instance.Disabled)
                {
                    instance.Disabled = true;
                    instance.LastError += $" - disabled after {MaxErrors} errors";
                    RebuildActive();
                }
            }

            applied?.Add($"plugin {instance.Plugin.Name}: ERROR in {what}: {ex.Message}");
            return false;
        }
    }

    private void RebuildActive() =>
        _active = [.. _plugins.Values
            .Where(p => p.Status == PluginStatus.Loaded && p.Enabled)
            .SelectMany(p => p.Instances)
            .Where(i => !i.Disabled)];

    private static string Fingerprint(MutableRequest r) =>
        string.Join('|', r.Uri, string.Join(';', r.Headers.Select(h => h.Key + ":" + h.Value)),
            Convert.ToHexString(SHA256.HashData(r.Body)));

    private static string Fingerprint(MutableResponse r) =>
        string.Join('|', r.Status, string.Join(';', r.Headers.Select(h => h.Key + ":" + h.Value)),
            Convert.ToHexString(SHA256.HashData(r.Body)));

    /// <summary>Resolves plugin dependencies from the plugin folder; the contracts assembly comes from the host.</summary>
    private sealed class PluginLoadContext(string mainPath) : AssemblyLoadContext(mainPath)
    {
        private readonly AssemblyDependencyResolver _resolver = new(mainPath);

        protected override Assembly? Load(AssemblyName assemblyName)
        {
            if (assemblyName.Name == ContractAssembly)
            {
                return null;
            }

            var path = _resolver.ResolveAssemblyToPath(assemblyName);
            return path is null ? null : LoadFromAssemblyPath(path);
        }
    }
}
