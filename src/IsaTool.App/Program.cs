using System.Collections.ObjectModel;
using IsaTool.App.Features.Assessment;
using IsaTool.App.Features.Decoders;
using IsaTool.App.Features.Dns;
using IsaTool.App.Features.HealthMonitor;
using IsaTool.App.Features.Help;
using IsaTool.App.Features.Http;
using IsaTool.App.Features.LogViewer;
using IsaTool.App.Features.Plugins;
using IsaTool.App.Features.PortScan;
using IsaTool.App.Features.Proxy;
using IsaTool.App.Features.Ping;
using IsaTool.App.Features.SystemMonitor;
using IsaTool.App.Features.Tls;
using IsaTool.App.Shell;
using Terminal.Gui.App;
using Terminal.Gui.Input;
using Terminal.Gui.ViewBase;
using Terminal.Gui.Views;

Func<FeatureView>[] features =
[
    () => new HttpView(),
    () => new DnsView(),
    () => new TlsView(),
    () => new PortScanView(),
    () => new PingView(),
    () => new LogViewerView(),
    () => new SystemMonitorView(),
    () => new HealthMonitorView(),
    () => new DecodersView(),
    () => new ProxyView(),
    () => new PluginsView(),
    () => new AssessmentView(),
    () => new HelpView(),
];

Splash.Show(args);

using IApplication app = Application.Create();
app.Init();
PluginHost.Shared.Reload();
FlowFormatter.CustomDecoder = PluginHost.Shared.TryDecode;
FeatureView.Application = app;

var titles = features.Select(f => { using var v = f(); return v.FeatureName; }).ToList();

using Window window = new() { Title = "IsaTool - troubleshooting multi-tool (Ctrl+Q quits)" };
var list = new ListView { X = 0, Y = 0, Width = 22, Height = Dim.Fill() };
list.SetSource(new ObservableCollection<string>(titles));

var host = new FrameView { X = 23, Y = 0, Width = Dim.Fill(), Height = Dim.Fill() };
FeatureView? current = null;

void Show(int index)
{
    if (index < 0 || index >= features.Length)
    {
        return;
    }

    if (current is not null)
    {
        host.Remove(current);
        current.Dispose();
    }

    current = features[index]();
    host.Title = current.FeatureName;
    host.Add(current);
}

list.ValueChanged += (_, _) => Show(list.SelectedItem ?? 0);
window.KeyDown += (_, key) =>
{
    if (key == Key.Tab && list.HasFocus)
    {
        host.FocusDeepest(NavigationDirection.Forward, TabBehavior.TabStop);
        key.Handled = true;
    }
    else if (key == Key.Tab.WithShift && host.HasFocus)
    {
        list.SetFocus();
        key.Handled = true;
    }
    else if (key == Key.F6)
    {
        if (list.HasFocus)
        {
            host.FocusDeepest(NavigationDirection.Forward, TabBehavior.TabStop);
        }
        else
        {
            list.SetFocus();
        }

        key.Handled = true;
    }
    else if (key == Key.Q.WithCtrl)
    {
        app.RequestStop();
        key.Handled = true;
    }
};

window.Add(list, host);
Show(0);
app.Run(window);
return 0;
