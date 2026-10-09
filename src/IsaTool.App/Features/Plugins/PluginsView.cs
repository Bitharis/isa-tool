using System.Text;
using IsaTool.App.Shell;

namespace IsaTool.App.Features.Plugins;

/// <summary>Provides the interactive interface for reviewing and enabling plugins.</summary>
public sealed class PluginsView : FeatureView
{
    private readonly PluginHost _host = PluginHost.Shared;

    public PluginsView()
    {
        var number = AddField("Plugin #");
        AddQuickButton("Refresh", Refresh, sameRow: false);
        AddQuickButton("Allow", () => Act(number.Text, p => _host.Allow(p.Folder), "Approved"));
        AddQuickButton("Disable", () => Act(number.Text, p => _host.SetEnabled(p.Folder, false), "Disabled"));
        AddQuickButton("Enable", () => Act(number.Text, p => _host.SetEnabled(p.Folder, true), "Enabled"));
        Build();
        Refresh();
    }

    /// <inheritdoc />
    public override string FeatureName => "Plugins";

    private void Act(string text, Action<PluginInfo> action, string verb)
    {
        var plugins = _host.Plugins;
        if (!int.TryParse(text, out var n) || n < 1 || n > plugins.Count)
        {
            SetOutput("Enter a plugin number from the list.\n\n" + Render());
            return;
        }

        var plugin = plugins[n - 1];
        action(plugin);
        SetOutput($"{verb}: {plugin.Folder}\n\n" + Render());
    }

    private void Refresh()
    {
        _host.Reload();
        SetOutput(Render());
    }

    private string Render()
    {
        var plugins = _host.Plugins;
        var sb = new StringBuilder();
        sb.AppendLine($"Plugin folder: {_host.Directory}");
        sb.AppendLine("Layout: <folder>/<Name>/<Name>.dll (copy the whole build output folder).");
        sb.AppendLine("WARNING: plugins are not sandboxed; they run with your full user rights and can read all");
        sb.AppendLine("decrypted proxy traffic. Only press Allow for code you wrote or reviewed. Allow records the");
        sb.AppendLine("SHA-256 of the folder; if any file changes later the plugin is refused until you Allow again.");
        sb.AppendLine();

        if (plugins.Count == 0)
        {
            sb.AppendLine("No plugins found. Build samples/RequestSigning and copy its output folder here as RequestSigning.");
            return sb.ToString();
        }

        for (var i = 0; i < plugins.Count; i++)
        {
            var p = plugins[i];
            sb.AppendLine($"[{i + 1}] {p.Folder}  -  {Describe(p.Status)}");
            sb.AppendLine($"    sha256:   {p.Sha256}");
            if (p.ApprovedSha256 is not null && p.ApprovedSha256 != p.Sha256)
            {
                sb.AppendLine($"    approved: {p.ApprovedSha256}");
            }

            if (p.Error is not null)
            {
                sb.AppendLine($"    ! {p.Error}");
            }

            foreach (var instance in p.Instances)
            {
                var state = instance.Disabled ? "disabled" : "active";
                sb.AppendLine($"    - {instance.Plugin.Name} ({instance.Capabilities}) [{state}, {instance.Errors} errors]");
                sb.AppendLine($"      {instance.Plugin.Description}");
                if (instance.LastError is not null)
                {
                    sb.AppendLine($"      last error: {instance.LastError}");
                }
            }

            sb.AppendLine();
        }

        return sb.ToString();
    }

    private static string Describe(PluginStatus status) => status switch
    {
        PluginStatus.NotAllowed => "NOT ALLOWED (review it, then press Allow)",
        PluginStatus.HashMismatch => "CHANGED SINCE APPROVED (not loaded)",
        PluginStatus.Disabled => "disabled",
        PluginStatus.Loaded => "loaded",
        _ => "FAILED",
    };
}
