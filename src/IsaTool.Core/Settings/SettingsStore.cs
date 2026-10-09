using System.Text.Json;

namespace IsaTool.Core.Settings;

/// <summary>Persists named settings objects as JSON files in a directory.</summary>
public sealed class SettingsStore(string directory)
{
    private static readonly JsonSerializerOptions Options = new() { WriteIndented = true };

    /// <summary>Gets the default per-user directory for IsaTool settings.</summary>
    public static string DefaultDirectory => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "IsaTool");

    /// <summary>Loads a named settings object, returning a new instance when no valid file exists.</summary>
    public T Load<T>(string name) where T : new()
    {
        var path = PathFor(name);
        if (!File.Exists(path))
        {
            return new T();
        }

        try
        {
            return JsonSerializer.Deserialize<T>(File.ReadAllText(path), Options) ?? new T();
        }
        catch (JsonException)
        {
            return new T();
        }
    }

    /// <summary>Saves a settings object using the supplied name.</summary>
    public void Save<T>(string name, T value)
    {
        Directory.CreateDirectory(directory);
        File.WriteAllText(PathFor(name), JsonSerializer.Serialize(value, Options));
    }

    private string PathFor(string name) => Path.Combine(directory, name + ".json");
}
