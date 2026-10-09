using System.Text;
using IsaTool.App.Shell;

namespace IsaTool.App.Features.LogViewer;

/// <summary>Provides the interactive interface for viewing and following log files.</summary>
public sealed class LogViewerView : FeatureView
{
    public LogViewerView()
    {
        var path = AddField("File");
        var filter = AddField("Filter");
        var regex = AddField("Regex (y/n)", "n");
        AddButton("Show tail", async ct =>
        {
            var f = MakeFilter(filter.Text, regex.Text);
            var (lines, _) = await LogReader.ReadTailAsync(path.Text.Trim(), 2000, ct);
            SetOutput(Join(lines.Where(f.Matches)));
        });
        AddButtonSameRow("Follow", async ct =>
        {
            var file = path.Text.Trim();
            var f = MakeFilter(filter.Text, regex.Text);
            var (lines, offset) = await LogReader.ReadTailAsync(file, 500, ct);
            SetOutput(Join(lines.Where(f.Matches)));
            using var timer = new PeriodicTimer(TimeSpan.FromMilliseconds(500));
            while (await timer.WaitForNextTickAsync(ct))
            {
                (lines, offset) = await LogReader.ReadAppendedAsync(file, offset, ct);
                var matched = lines.Where(f.Matches).ToList();
                if (matched.Count > 0)
                {
                    AppendOutput(Join(matched));
                }
            }
        });
        AddStopButton();
        Build();
    }

    /// <inheritdoc />
    public override string FeatureName => "Log viewer";

    private static LogFilter MakeFilter(string pattern, string regex) =>
        new(pattern, regex.Trim().StartsWith('y'));

    private static string Join(IEnumerable<string> lines)
    {
        var sb = new StringBuilder();
        foreach (var l in lines)
        {
            sb.AppendLine(l);
        }

        return sb.ToString();
    }
}
