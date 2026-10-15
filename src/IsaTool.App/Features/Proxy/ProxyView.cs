using IsaTool.App.Features.Plugins;
using IsaTool.App.Shell;
using IsaTool.Core.Settings;

namespace IsaTool.App.Features.Proxy;

/// <summary>Contains persisted proxy capture and view filter settings.</summary>
public sealed class ProxySettings
{
    public string OnlyHosts { get; set; } = string.Empty;

    public string IgnoreHosts { get; set; } = string.Empty;

    public string Search { get; set; } = string.Empty;

    public string Status { get; set; } = string.Empty;

    public string ContentType { get; set; } = string.Empty;

    public string ListenAddress { get; set; } = "127.0.0.1";

    public string ForwardTo { get; set; } = string.Empty;

    public string TrustServerCert { get; set; } = "no";
}

/// <summary>Provides the interactive interface for the intercepting proxy.</summary>
public sealed class ProxyView : FeatureView
{
    private const string SettingsName = "proxy";

    private readonly FlowStore _store = new();
    private readonly SettingsStore _settings = new(SettingsStore.DefaultDirectory);
    private volatile FlowFilter _filter = FlowFilter.None;
    private volatile ProxyServer? _server;
    private int? _detailId;

    public ProxyView()
    {
        var saved = _settings.Load<ProxySettings>(SettingsName);
        var port = AddField("Listen port", "8888");
        var address = AddField("Listen address", string.IsNullOrWhiteSpace(saved.ListenAddress) ? "127.0.0.1" : saved.ListenAddress);
        var forward = AddField("Forward to (MITM)", saved.ForwardTo);
        var trust = AddField("Trust server cert (yes/no)", saved.TrustServerCert);
        var only = AddField("Only hosts", saved.OnlyHosts);
        var ignore = AddField("Ignore hosts", saved.IgnoreHosts);
        var search = AddField("Search", saved.Search);
        var status = AddField("Status", saved.Status);
        var type = AddField("Content type", saved.ContentType);
        var flow = AddField("Flow #");

        void Persist() => _settings.Save(SettingsName, new ProxySettings
        {
            OnlyHosts = only.Text,
            IgnoreHosts = ignore.Text,
            Search = search.Text,
            Status = status.Text,
            ContentType = type.Text,
            ListenAddress = address.Text,
            ForwardTo = forward.Text,
            TrustServerCert = trust.Text,
        });

        void ApplyFilter()
        {
            _filter = new FlowFilter(search.Text, status.Text, type.Text);
            Persist();
            _detailId = null;
            Refresh();
        }

        _filter = new FlowFilter(saved.Search, saved.Status, saved.ContentType);

        AddButton("Start proxy", async ct =>
        {
            _ = int.TryParse(port.Text, out var p);
            var bindText = address.Text.Trim();
            if (!System.Net.IPAddress.TryParse(string.IsNullOrEmpty(bindText) ? "127.0.0.1" : bindText, out var bind))
            {
                SetOutput($"Invalid listen address \"{bindText}\". Use an IP such as 127.0.0.1 or 0.0.0.0.");
                return;
            }

            Uri? forwardTo = null;
            var forwardText = forward.Text.Trim();
            if (forwardText.Length > 0 &&
                (!Uri.TryCreate(forwardText, UriKind.Absolute, out forwardTo) ||
                 (forwardTo.Scheme != Uri.UriSchemeHttp && forwardTo.Scheme != Uri.UriSchemeHttps)))
            {
                SetOutput($"Invalid forward target \"{forwardText}\". Use http://host:port or https://host:port.");
                return;
            }

            var rules = new CaptureRules(only.Text, ignore.Text);
            var rewrites = LoadRules(out var rulesNote);
            PluginHost.Shared.Reload();
            Persist();
            var ca = CertificateAuthority.LoadOrCreate(CertificateAuthority.DefaultDirectory);
            var trustServer = trust.Text.Trim().StartsWith('y');
            using var server = new ProxyServer(ca, _store,
                new ProxyOptions(p > 0 ? p : 8888, trustServer, rules, rewrites, PluginHost.Shared, bind, forwardTo));
            int actual;
            try
            {
                actual = server.Start();
            }
            catch (System.Net.Sockets.SocketException ex)
            {
                SetOutput($"Cannot listen on {bind}:{p}: {ex.Message}");
                return;
            }

            _detailId = null;
            Refresh();
            _server = server;
            var serving = server.RunAsync(ct);
            var mode = forwardTo is null
                ? $"Listening on {bind}:{actual} as a proxy. HTTPS is DECRYPTED with CA \"{CertificateAuthority.CommonName}\"."
                : $"Listening on {bind}:{actual} as a MITM in front of {forwardTo.GetLeftPart(UriPartial.Authority)}" +
                  (forwardTo.Scheme == Uri.UriSchemeHttps
                      ? $". TLS is DECRYPTED with CA \"{CertificateAuthority.CommonName}\"; point the client at this address instead of the server."
                      : ". Point the client at this address instead of the server.");
            var exposed = bind.Equals(System.Net.IPAddress.Loopback) ? string.Empty
                : "\nWARNING: listening beyond loopback; anyone who can reach this port can send traffic through it. Restrict it with a firewall.";
            AppendOutput($"\n{mode}{exposed}\n{rulesNote}\n");

            var seen = -1;
            using var timer = new PeriodicTimer(TimeSpan.FromMilliseconds(500));
            try
            {
                while (await timer.WaitForNextTickAsync(ct))
                {
                    if (_store.Version != seen)
                    {
                        seen = _store.Version;
                        Refresh();
                    }
                }
            }
            finally
            {
                _server = null;
                await serving;
            }
        });
        AddStopButton();
        AddQuickButton("Apply filter", ApplyFilter);
        AddQuickButton("Show flow", () =>
        {
            if (!int.TryParse(flow.Text, out var id) || _store.Get(id) is not { } f)
            {
                SetOutput("No such flow number.");
                return;
            }

            _detailId = id;
            SetOutput(FlowFormatter.FormatDetail(f));
        });
        AddQuickButton("Flow list", () =>
        {
            _detailId = null;
            Refresh();
        }, sameRow: false);
        AddQuickButton("Clear", () =>
        {
            _store.Clear();
            _detailId = null;
            Refresh();
        });
        AddQuickButton("CA info / install help", () =>
        {
            var ca = CertificateAuthority.LoadOrCreate(CertificateAuthority.DefaultDirectory);
            SetOutput(CertificateAuthority.InstallInstructions(ca.CertificatePath));
        });
        AddQuickButton("Delete CA files", () =>
        {
            CertificateAuthority.DeleteFiles(CertificateAuthority.DefaultDirectory);
            SetOutput($"CA files deleted. Also remove \"{CertificateAuthority.CommonName}\" from any trust store you installed it in.");
        });
        AddQuickButton("Rules file", () =>
        {
            if (!File.Exists(RewriteRuleSet.DefaultPath))
            {
                Directory.CreateDirectory(Path.GetDirectoryName(RewriteRuleSet.DefaultPath)!);
                File.WriteAllText(RewriteRuleSet.DefaultPath, RewriteRuleSet.SampleJson);
            }

            SetOutput(RulesHelp + "\n" + RewriteRuleSet.DefaultPath);
        }, sameRow: false);
        AddQuickButton("Reload rules", () =>
        {
            var set = LoadRules(out var note);
            _server?.SetRewrites(set);
            SetOutput(note + (_server is null ? "\n(applied when the proxy starts)" : "\n(applied to new requests)"));
        });
        Build();
        SetOutput("PROXY MODE (Forward to empty): point your client at 127.0.0.1:<port> (e.g. HTTPS_PROXY=http://127.0.0.1:8888).\n" +
                  "MITM MODE (Forward to = https://server:port or http://server:port): the client connects to this tool\n" +
                  "  instead of the server; the tool forwards to the real server and records every request. Use Listen address\n" +
                  "  0.0.0.0 to accept clients from other machines. Set Trust server cert to yes for self-signed server certs.\n" +
                  "  Only HTTP/1.1 is decoded; other protocols are reported as RAW.\n" +
                  "For HTTPS, first install the CA on the client: press \"CA info / install help\".\n\n"+
                  "CAPTURE (applied on Start): Only hosts / Ignore hosts, e.g. api.corp.com, *.corp.com.\n" +
                  "  Non-matching HTTPS hosts are tunnelled untouched (not decrypted, not recorded).\n" +
                  "VIEW (press Apply filter): Search text, Status (e.g. 4xx,5xx,404,err), Content type (e.g. json,xml).");
    }

    /// <inheritdoc />
    public override string FeatureName => "Intercepting proxy";

    private const string RulesHelp = """
        REWRITE RULES (JSON file; edit it, then press Reload rules). Applied only to captured hosts.
        Each rule: name, enabled, match {host, path, method, status}, actions [...].
        match: host/path use '*' wildcards (path example /api/*); method and status take lists (POST,PUT / 4xx,503).
        Request actions:  setRequestHeader{name,value} removeRequestHeader{name} replaceRequestBody{find,replace}
                          redirectHost{host[:port]} mockResponse{status,body,contentType} delay{ms} drop
        Response actions: setResponseHeader{name,value} removeResponseHeader{name} replaceResponseBody{find,replace}
                          setStatus{status} delayResponse{ms}
        Any phase:        tag{value}
        Rules with a status match may only use response actions and tag. Flows changed by rules are marked '*'.
        """;

    private static RewriteRuleSet LoadRules(out string note)
    {
        var set = RewriteRuleSet.Load(RewriteRuleSet.DefaultPath, out var errors);
        note = $"Rewrite rules: {set.Count} active ({RewriteRuleSet.DefaultPath})" +
               string.Concat(errors.Select(e => "\n  ! " + e));
        return set;
    }

    private void Refresh()
    {
        if (_detailId is null)
        {
            var filter = _filter;
            var all = _store.Snapshot();
            var shown = all.Where(filter.Matches).ToList();
            SetOutput(FlowFormatter.FormatList(shown) +
                      (shown.Count == all.Count ? string.Empty : $"\n[{shown.Count} of {all.Count} flows shown - filter active]"));
        }
    }
}
