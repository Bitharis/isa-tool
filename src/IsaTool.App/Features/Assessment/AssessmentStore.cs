using IsaTool.Core.Settings;

namespace IsaTool.App.Features.Assessment;

/// <summary>Stores assessment definitions and runs in a local JSON archive.</summary>
public sealed class AssessmentStore(string? filePath = null)
{
    private readonly object _gate = new();
    private readonly string _path = filePath ?? Path.Combine(SettingsStore.DefaultDirectory, "assessments.json");

    /// <summary>Lists all saved assessment definitions.</summary>
    public IReadOnlyList<AssessmentDefinition> List()
    {
        lock (_gate)
        {
            return [.. Load().Assessments];
        }
    }

    /// <summary>Lists saved runs for an assessment, newest first.</summary>
    public IReadOnlyList<AssessmentRun> Runs(string name)
    {
        lock (_gate)
        {
            return [.. Load().Runs.Where(r => r.AssessmentName.Equals(name, StringComparison.OrdinalIgnoreCase))
                .OrderByDescending(r => r.StartedAt)];
        }
    }

    /// <summary>Saves an assessment definition, replacing any definition with the same name.</summary>
    public void SaveDefinition(AssessmentDefinition definition)
    {
        lock (_gate)
        {
            var archive = Load();
            archive.Assessments.RemoveAll(a => a.Name.Equals(definition.Name, StringComparison.OrdinalIgnoreCase));
            archive.Assessments.Add(definition);
            Persist(archive);
        }
    }

    /// <summary>Saves an assessment run and retains the 500 newest runs.</summary>
    public void SaveRun(AssessmentRun run)
    {
        lock (_gate)
        {
            var archive = Load();
            archive.Runs.Add(run);
            if (archive.Runs.Count > 500)
            {
                archive.Runs = archive.Runs.OrderByDescending(r => r.StartedAt).Take(500).ToList();
            }

            Persist(archive);
        }
    }

    /// <summary>Gets the newest prior run for the named assessment.</summary>
    public AssessmentRun? PreviousRun(string name, Guid currentId)
    {
        lock (_gate)
        {
            return Load().Runs.Where(r => r.AssessmentName.Equals(name, StringComparison.OrdinalIgnoreCase) && r.Id != currentId)
                .OrderByDescending(r => r.StartedAt).FirstOrDefault();
        }
    }

    private AssessmentArchive Load()
    {
        if (!File.Exists(_path))
        {
            return new AssessmentArchive();
        }

        try
        {
            return System.Text.Json.JsonSerializer.Deserialize<AssessmentArchive>(File.ReadAllText(_path)) ?? new AssessmentArchive();
        }
        catch (System.Text.Json.JsonException)
        {
            return new AssessmentArchive();
        }
    }

    private void Persist(AssessmentArchive archive)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
        File.WriteAllText(_path, System.Text.Json.JsonSerializer.Serialize(archive,
            new System.Text.Json.JsonSerializerOptions { WriteIndented = true }));
    }
}
