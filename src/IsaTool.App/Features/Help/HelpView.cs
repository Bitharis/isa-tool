using IsaTool.App.Shell;

namespace IsaTool.App.Features.Help;

/// <summary>Displays application navigation and feature help.</summary>
public sealed class HelpView : FeatureView
{
    private const string HelpText = """
        ISATOOL HELP

        NAVIGATION
          Up/Down       Choose a tool in the left list
          Tab           From the left list, move into the right pane
          Shift+Tab     From the right pane, return to the left list
          F6            Switch directly between left and right panes
          Enter/Space   Press the focused button
          Ctrl+Q        Quit
          Mouse         Clicking works too

        TOOLS
          HTTP client       Send a request; shows redirect chain, per-hop timing,
                            headers and body. Headers are "Name: value" separated
                            by ';'. The ignore-TLS button accepts bad certificates
                            (use only on systems you are authorised to test).
          DNS lookup        Types: A AAAA CNAME MX NS TXT SOA PTR. For PTR enter an
                            IP address. DNS server is optional (e.g. 1.1.1.1).
          TLS certificate   Host[:port] or URL. Shows protocol, cipher, chain,
                            expiry and SANs; chain problems are reported, not fatal.
          Port scan         Ports like "22,80,443,8000-8100". TCP connect scan.
          Ping / traceroute ICMP ping (4 probes) and TTL-based traceroute.
          Log viewer        Show tail of a file; Follow keeps reading new lines.
                            Filter is text, or regex when Regex is "y".
          Processes         Live process list every 2s. Sort: "cpu" or "mem".
          Health monitor    URLs separated by ';' checked every N seconds.
                            Healthy = HTTP 2xx/3xx. Shows uptime over last 100 checks.
          Decoders          Paste text into Input: format JSON, decode a JWT
                            (signature is NOT verified), Base64 encode/decode.
          Intercepting proxy  Listens on 127.0.0.1 only. Point a client at it
                            (HTTPS_PROXY=http://127.0.0.1:8888). For HTTPS, install the
                            generated CA ("CA info / install help" shows commands); its
                            name is "IsaTool Debug Proxy CA - REMOVE WHEN DONE". Enter a
                            flow number and press "Show flow" for headers and decoded
                            body. HTTP/1.1 only; no WebSocket or streaming. Pinned apps
                            reject the certificate. Remove the CA when done.
                            Capture filters (on Start): Only hosts / Ignore hosts
                            ("api.corp.com, *.corp.com"); others are tunnelled, not
                            decrypted. View filters (Apply filter): Search, Status
                            ("4xx,5xx,404,err"), Content type ("json,xml").
                            Rewrite rules: "Rules file" creates a JSON file with examples
                            (set headers, mock/redirect/delay/drop requests, edit response
                            bodies, tag flows); "Reload rules" applies edits. Flows changed
                            by rules show '*' in the list.
          Plugins           Lists DLL plugins in the plugin folder. Nothing loads until
                            you review it and press Allow (stores a SHA-256 of the folder;
                            changed files are refused). Plugins can modify/mock/drop proxy
                            requests, modify responses and decode bodies. NOT sandboxed:
                            they run with your full rights, so only allow code you trust.
          Assessment        Save exact hosts or URLs, check DNS, HTTPS certificates,
                            website security headers/cookies and only the TCP ports you
                            choose. Type I AM AUTHORIZED before running. Load saved scopes,
                            compare runs or export JSON/HTML reports.

        Long-running tools (scan, ping, follow, monitors, assessment) stop with the Stop
        button or when you switch to another tool.
        """;

    public HelpView()
    {
        Build();
        SetOutput(HelpText);
    }

    /// <inheritdoc />
    public override string FeatureName => "Help";
}
