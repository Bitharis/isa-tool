using Terminal.Gui.App;
using Terminal.Gui.ViewBase;
using Terminal.Gui.Views;

namespace IsaTool.App.Shell;

/// <summary>Base for feature screens: input rows, action buttons and a scrollable read-only output pane.</summary>
public abstract class FeatureView : View
{
    private readonly List<View> _rows = [];
    private readonly TextView _output;
    private CancellationTokenSource? _cts;
    private View? _last;

    /// <summary>Initializes the common feature-screen layout.</summary>
    protected FeatureView()
    {
        Width = Dim.Fill();
        Height = Dim.Fill();
        CanFocus = true;
        _output = new TextView
        {
            X = 0,
            Y = 0,
            Width = Dim.Fill(),
            Height = Dim.Fill(),
            ReadOnly = true,
            WordWrap = false,
        };
    }

    /// <summary>Gets the display name of the feature.</summary>
    public abstract string FeatureName { get; }

    /// <summary>Set once by the shell before any view is created.</summary>
    public static IApplication? Application { get; set; }

    /// <summary>Finishes layout by adding the output pane below the input controls.</summary>
    protected void Build()
    {
        _output.Y = _last is null ? 0 : Pos.Bottom(_last) + 1;
        Add(_output);
    }

    /// <summary>Adds a labeled text field to the screen.</summary>
    protected TextField AddField(string label, string initial = "", int labelWidth = 14)
    {
        var y = _last is null ? 0 : Pos.Bottom(_last);
        var caption = new Label { Text = label, X = 0, Y = y, Width = labelWidth };
        var field = new TextField { Text = initial, X = labelWidth + 1, Y = y, Width = Dim.Fill() };
        Add(caption, field);
        _rows.Add(field);
        _last = field;
        return field;
    }

    /// <summary>Adds a button that runs a cancellable action.</summary>
    protected Button AddButton(string text, Func<CancellationToken, Task> action)
    {
        var button = new Button { Text = text, X = 0, Y = _last is null ? 0 : Pos.Bottom(_last) };
        button.Accepted += (_, _) => _ = RunAsync(action);
        Add(button);
        _rows.Add(button);
        _last = button;
        return button;
    }

    /// <summary>Places the next button on the same line as the previous one.</summary>
    protected Button AddButtonSameRow(string text, Func<CancellationToken, Task> action)
    {
        var prev = _last!;
        var button = new Button { Text = text, Y = prev.Y, X = Pos.Right(prev) + 1 };
        button.Accepted += (_, _) => _ = RunAsync(action);
        Add(button);
        _rows.Add(button);
        _last = button;
        return button;
    }

    /// <summary>Button whose action runs without cancelling a long-running action (e.g. a running proxy).</summary>
    protected Button AddQuickButton(string text, Action action, bool sameRow = true)
    {
        var prev = _last;
        var button = new Button
        {
            Text = text,
            X = sameRow && prev is not null ? Pos.Right(prev) + 1 : 0,
            Y = prev is null ? 0 : sameRow ? prev.Y : Pos.Bottom(prev),
        };
        button.Accepted += (_, _) =>
        {
            try
            {
                action();
            }
            catch (Exception ex)
            {
                SetOutput($"[error] {ex.Message}");
            }
        };
        Add(button);
        _rows.Add(button);
        _last = button;
        return button;
    }

    /// <summary>Adds a button that cancels the active action.</summary>
    protected Button AddStopButton()
    {
        var prev = _last!;
        var button = new Button { Text = "Stop", Y = prev.Y, X = Pos.Right(prev) + 1 };
        button.Accepted += (_, _) => _cts?.Cancel();
        Add(button);
        _rows.Add(button);
        _last = button;
        return button;
    }

    /// <summary>Replaces the output text on the application thread.</summary>
    protected void SetOutput(string text) => Invoke(() => _output.Text = text);

    /// <summary>Appends output text on the application thread.</summary>
    protected void AppendOutput(string text) => Invoke(() => _output.Text = _output.Text + text);

    /// <summary>Runs an action on the application thread when one is available.</summary>
    protected void Invoke(Action action)
    {
        if (Application is { } app)
        {
            app.Invoke(action);
        }
        else
        {
            action();
        }
    }

    private async Task RunAsync(Func<CancellationToken, Task> action)
    {
        _cts?.Cancel();
        _cts = new CancellationTokenSource();
        try
        {
            await action(_cts.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            AppendOutput("\n[stopped]\n");
        }
        catch (Exception ex)
        {
            AppendOutput($"\n[error] {ex.Message}\n");
        }
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _cts?.Cancel();
            _cts?.Dispose();
        }

        base.Dispose(disposing);
    }
}
