namespace IsaTool.App.Features.Assessment;

/// <summary>Defines the authorized targets and ports for an assessment.</summary>
public sealed class AssessmentDefinition
{
    public string Name { get; set; } = "";

    public List<string> Targets { get; set; } = [];

    public List<int> Ports { get; set; } = [];
}

/// <summary>Represents one result produced by an assessment check.</summary>
public sealed class AssessmentFinding
{
    public string Key { get; set; } = "";

    public string Target { get; set; } = "";

    public string Check { get; set; } = "";

    public string Severity { get; set; } = "Info";

    public string Summary { get; set; } = "";

    public string Evidence { get; set; } = "";
}

/// <summary>Represents the recorded outcome of an assessment execution.</summary>
public sealed class AssessmentRun
{
    public Guid Id { get; set; } = Guid.NewGuid();

    public string AssessmentName { get; set; } = "";

    public DateTimeOffset StartedAt { get; set; } = DateTimeOffset.UtcNow;

    public DateTimeOffset FinishedAt { get; set; }

    public List<string> Scope { get; set; } = [];

    public List<AssessmentFinding> Findings { get; set; } = [];
}

/// <summary>Contains the persisted assessment definitions and their runs.</summary>
public sealed class AssessmentArchive
{
    public List<AssessmentDefinition> Assessments { get; set; } = [];

    public List<AssessmentRun> Runs { get; set; } = [];
}

/// <summary>Describes findings added and resolved between two assessment runs.</summary>
public sealed record AssessmentDifference(
    IReadOnlyList<AssessmentFinding> NewFindings,
    IReadOnlyList<AssessmentFinding> ResolvedFindings);
