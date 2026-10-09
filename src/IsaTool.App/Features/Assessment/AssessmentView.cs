using System.Net;
using System.Text;
using System.Text.Json;
using IsaTool.App.Shell;

namespace IsaTool.App.Features.Assessment;

/// <summary>Provides the interactive interface for authorized security assessments.</summary>
public sealed class AssessmentView : FeatureView
{
    private readonly AssessmentStore _store = new();
    private AssessmentRun? _latest;

    public AssessmentView()
    {
        var name = AddField("Assessment", "Company service check");
        var targets = AddField("Hosts / URLs", "https://example.com", 16);
        var ports = AddField("TCP ports", "", 16);
        var approval = AddField("Authorization", "", 16);
        var reportPath = AddField("Report file", Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "isatool-assessment"), 16);

        bool TryDefinition(out AssessmentDefinition definition)
        {
            if (!string.Equals(approval.Text.Trim(), "I AM AUTHORIZED", StringComparison.Ordinal))
            {
                definition = new AssessmentDefinition();
                SetOutput("Before running checks, type exactly: I AM AUTHORIZED");
                return false;
            }

            if (!AssessmentService.TryBuildDefinition(name.Text, targets.Text, ports.Text, out definition, out var error))
            {
                SetOutput(error);
                return false;
            }

            return true;
        }

        AddButton("Save scope", _ =>
        {
            if (!AssessmentService.TryBuildDefinition(name.Text, targets.Text, ports.Text, out var definition, out var error))
            {
                SetOutput(error);
                return Task.CompletedTask;
            }

            _store.SaveDefinition(definition);
            SetOutput($"Saved assessment '{definition.Name}' with {definition.Targets.Count} exact target(s) and {definition.Ports.Count} selected port(s).\n\n{RenderSaved()}");
            return Task.CompletedTask;
        });
        AddButtonSameRow("Run checks", async ct =>
        {
            if (!TryDefinition(out var definition))
            {
                return;
            }

            _store.SaveDefinition(definition);
            SetOutput($"Running checks for {definition.Targets.Count} target(s)...\n");
            var progress = new Progress<string>(message => SetOutput($"Running checks for {definition.Targets.Count} target(s)...\n{message}"));
            _latest = await AssessmentService.RunAsync(definition, progress, ct);
            _store.SaveRun(_latest);
            SetOutput(RenderRun(_latest));
        });
        AddStopButton();

        AddButton("Compare previous", _ =>
        {
            if (_latest is null)
            {
                SetOutput("Run an assessment first, then compare it with an earlier run.");
                return Task.CompletedTask;
            }

            var previous = _store.PreviousRun(_latest.AssessmentName, _latest.Id);
            SetOutput(previous is null ? "No earlier run of this assessment is saved." : RenderCompare(previous, _latest));
            return Task.CompletedTask;
        });
        AddButtonSameRow("Export JSON", _ => Export(reportPath.Text, ".json", run => JsonSerializer.Serialize(run,
            new JsonSerializerOptions { WriteIndented = true })));
        AddButtonSameRow("Export HTML", _ => Export(reportPath.Text, ".html", RenderHtml));
        AddButtonSameRow("Saved assessments", _ =>
        {
            SetOutput(RenderSaved());
            return Task.CompletedTask;
        });
        AddButton("Load saved", _ =>
        {
            var saved = _store.List().FirstOrDefault(a => a.Name.Equals(name.Text.Trim(), StringComparison.OrdinalIgnoreCase));
            if (saved is null)
            {
                SetOutput($"No saved assessment named '{name.Text.Trim()}'. Press Saved assessments to see names.");
                return Task.CompletedTask;
            }

            targets.Text = string.Join(';', saved.Targets);
            ports.Text = string.Join(',', saved.Ports);
            approval.Text = string.Empty;
            SetOutput($"Loaded '{saved.Name}'. Review its scope, then type I AM AUTHORIZED before running.");
            return Task.CompletedTask;
        });
        Build();
        SetOutput("Enter exact hosts or full http(s) URLs separated by semicolons. No wildcard or network ranges.\n" +
                  "Checks: DNS, HTTPS certificate, website headers/cookies, and only the TCP ports you enter.\n" +
                  "Before running, type I AM AUTHORIZED in the Authorization field. Results are saved locally.");

        Task Export(string basePath, string extension, Func<AssessmentRun, string> render)
        {
            if (_latest is null)
            {
                SetOutput("Run an assessment before exporting.");
                return Task.CompletedTask;
            }

            try
            {
                if (string.IsNullOrWhiteSpace(basePath))
                {
                    SetOutput("Enter a report file path.");
                    return Task.CompletedTask;
                }

                var path = Path.ChangeExtension(basePath.Trim(), extension);
                Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
                File.WriteAllText(path, render(_latest));
                SetOutput($"Saved report:\n{path}");
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
            {
                SetOutput($"Could not save report: {ex.Message}");
            }

            return Task.CompletedTask;
        }
    }

    /// <inheritdoc />
    public override string FeatureName => "Assessment";

    private string RenderSaved()
    {
        var definitions = _store.List();
        if (definitions.Count == 0)
        {
            return "No saved assessments yet.";
        }

        var sb = new StringBuilder("Saved assessments:\n");
        foreach (var definition in definitions)
        {
            var count = _store.Runs(definition.Name).Count;
            sb.AppendLine($"- {definition.Name}: {definition.Targets.Count} targets, {definition.Ports.Count} ports, {count} saved run(s)");
            foreach (var target in definition.Targets)
            {
                sb.AppendLine($"    {target}");
            }
        }

        return sb.ToString();
    }

    private static string RenderRun(AssessmentRun run)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"Assessment: {run.AssessmentName}");
        sb.AppendLine($"Started: {run.StartedAt.LocalDateTime:G}   Finished: {run.FinishedAt.LocalDateTime:G}");
        sb.AppendLine($"Scope: {string.Join("; ", run.Scope)}");
        sb.AppendLine($"Findings: {run.Findings.Count(f => f.Severity == "Error")} errors, {run.Findings.Count(f => f.Severity == "Warning")} warnings, {run.Findings.Count(f => f.Severity == "Medium")} medium, {run.Findings.Count(f => f.Severity == "Low")} low, {run.Findings.Count(f => f.Severity == "Info")} info");
        sb.AppendLine();
        AppendFindings(sb, run.Findings);
        return sb.ToString();
    }

    private static string RenderCompare(AssessmentRun previous, AssessmentRun current)
    {
        var difference = AssessmentService.Compare(previous, current);
        var sb = new StringBuilder($"Comparing {previous.StartedAt.LocalDateTime:G} with {current.StartedAt.LocalDateTime:G}\n");
        sb.AppendLine($"New findings: {difference.NewFindings.Count}; resolved: {difference.ResolvedFindings.Count}\n");
        if (difference.NewFindings.Count > 0)
        {
            sb.AppendLine("NEW:");
            AppendFindings(sb, difference.NewFindings);
        }

        if (difference.ResolvedFindings.Count > 0)
        {
            sb.AppendLine("RESOLVED:");
            AppendFindings(sb, difference.ResolvedFindings);
        }

        if (difference.NewFindings.Count == 0 && difference.ResolvedFindings.Count == 0)
        {
            sb.AppendLine("No findings changed.");
        }

        return sb.ToString();
    }

    private static void AppendFindings(StringBuilder sb, IEnumerable<AssessmentFinding> findings)
    {
        foreach (var finding in findings.OrderBy(f => f.Target).ThenBy(f => f.Severity))
        {
            sb.AppendLine($"[{finding.Severity}] {finding.Target} - {finding.Summary}");
            sb.AppendLine($"  Evidence: {finding.Evidence}");
        }
    }

    private static string RenderHtml(AssessmentRun run)
    {
        static string E(string? value) => WebUtility.HtmlEncode(value ?? "");
        var rows = string.Join(Environment.NewLine, run.Findings.Select(f =>
            $"<tr><td>{E(f.Severity)}</td><td>{E(f.Target)}</td><td>{E(f.Summary)}</td><td><pre>{E(f.Evidence)}</pre></td></tr>"));
        return $$"""
            <!doctype html>
            <html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width">
            <title>IsaTool assessment: {{E(run.AssessmentName)}}</title>
            <style>body{font:15px system-ui,sans-serif;margin:2rem;color:#18212b}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ccd3d9;padding:.55rem;text-align:left;vertical-align:top}th{background:#eef2f5}pre{white-space:pre-wrap;margin:0}.meta{color:#52606b}</style>
            <h1>{{E(run.AssessmentName)}}</h1>
            <p class="meta">{{E(run.StartedAt.LocalDateTime.ToString("f"))}} · Scope: {{E(string.Join("; ", run.Scope))}}</p>
            <p>Informational checks only; review findings in context before treating them as defects.</p>
            <table><thead><tr><th>Level</th><th>Target</th><th>Finding</th><th>Evidence</th></tr></thead><tbody>{{rows}}</tbody></table>
            </html>
            """;
    }
}
