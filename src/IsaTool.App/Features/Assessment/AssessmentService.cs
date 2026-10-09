using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using IsaTool.App.Features.Http;
using IsaTool.App.Features.PortScan;
using IsaTool.App.Features.Tls;
using IsaTool.Core.Hosts;

namespace IsaTool.App.Features.Assessment;

/// <summary>Represents a validated host or URL assessment target.</summary>
public sealed record AssessmentTarget(string Original, string Host, Uri? WebUri, int TlsPort);

/// <summary>Validates assessment scope and runs its network checks.</summary>
public static class AssessmentService
{
    private const int MaxTargets = 50;
    private const int MaxPorts = 64;
    private static readonly (string Header, string Advice, string Severity)[] SecurityHeaders =
    [
        ("Strict-Transport-Security", "HTTPS site does not set HSTS; browsers may accept a later downgrade to HTTP.", "Medium"),
        ("Content-Security-Policy", "No Content-Security-Policy header was found.", "Low"),
        ("X-Content-Type-Options", "No X-Content-Type-Options header was found.", "Low"),
        ("Referrer-Policy", "No Referrer-Policy header was found.", "Info"),
    ];

    /// <summary>Builds a bounded assessment definition from user input.</summary>
    public static bool TryBuildDefinition(string name, string targetsText, string portsText,
        out AssessmentDefinition definition, out string error)
    {
        definition = new AssessmentDefinition();
        error = "";
        name = name.Trim();
        if (name.Length is < 1 or > 80)
        {
            error = "Give the assessment a name (1 to 80 characters).";
            return false;
        }

        var rawTargets = targetsText.Split([';', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        if (rawTargets.Count == 0 || rawTargets.Count > MaxTargets)
        {
            error = $"Enter between 1 and {MaxTargets} exact hosts or URLs, separated by semicolons. No wildcards or network ranges.";
            return false;
        }

        foreach (var target in rawTargets)
        {
            if (!TryParseTarget(target, out _, out error))
            {
                return false;
            }
        }

        var ports = new SortedSet<int>();
        try
        {
            if (!string.IsNullOrWhiteSpace(portsText))
            {
                foreach (var part in portsText.Split([',', ';', ' '], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                {
                    var dash = part.IndexOf('-', StringComparison.Ordinal);
                    if (dash > 0 && int.TryParse(part[..dash], out var first) && int.TryParse(part[(dash + 1)..], out var last))
                    {
                        if (first < 1 || last > 65535 || first > last || last - first >= MaxPorts)
                        {
                            throw new FormatException("Each port range must be valid and contain no more than 64 ports.");
                        }

                        for (var p = first; p <= last; p++) ports.Add(p);
                    }
                    else if (int.TryParse(part, out var port) && port is >= 1 and <= 65535)
                    {
                        ports.Add(port);
                    }
                    else
                    {
                        throw new FormatException($"Invalid port: {part}");
                    }

                    if (ports.Count > MaxPorts)
                    {
                        throw new FormatException("Choose no more than 64 ports.");
                    }
                }
            }
        }
        catch (FormatException ex)
        {
            error = ex.Message;
            return false;
        }

        definition = new AssessmentDefinition { Name = name, Targets = rawTargets, Ports = [.. ports] };
        return true;
    }

    /// <summary>Validates and parses one exact host or HTTP(S) URL target.</summary>
    public static bool TryParseTarget(string input, out AssessmentTarget target, out string error)
    {
        target = new AssessmentTarget(input, "", null, 443);
        error = "";
        input = input.Trim();
        if (input.Length == 0 || input.Contains('*') || input.Contains('/') && !input.Contains("://", StringComparison.Ordinal))
        {
            error = $"'{input}' is not an exact host or URL. Wildcards, CIDR ranges and paths without a URL are not accepted.";
            return false;
        }

        if (input.Contains("://", StringComparison.Ordinal))
        {
            if (!Uri.TryCreate(input, UriKind.Absolute, out var uri) || uri.Scheme is not ("http" or "https") ||
                string.IsNullOrEmpty(uri.Host) || !string.IsNullOrEmpty(uri.UserInfo))
            {
                error = $"'{input}' must be an http:// or https:// URL without embedded user credentials.";
                return false;
            }

            target = new AssessmentTarget(input, uri.IdnHost, uri, uri.Port);
            return true;
        }

        if (!HostTarget.TryParse(input, 443, out var host, out var port) || Uri.CheckHostName(host) == UriHostNameType.Unknown)
        {
            error = $"'{input}' is not a valid host name or IP address.";
            return false;
        }

        target = new AssessmentTarget(input, host, null, port);
        return true;
    }

    /// <summary>Runs DNS, TLS, HTTP, and selected TCP-port checks for an assessment definition.</summary>
    public static async Task<AssessmentRun> RunAsync(
        AssessmentDefinition definition,
        IProgress<string>? progress = null,
        CancellationToken ct = default)
    {
        var run = new AssessmentRun
        {
            AssessmentName = definition.Name,
            Scope = [.. definition.Targets],
            StartedAt = DateTimeOffset.UtcNow,
        };

        foreach (var input in definition.Targets)
        {
            ct.ThrowIfCancellationRequested();
            if (!TryParseTarget(input, out var target, out var error))
            {
                run.Findings.Add(Finding(input, "target", "Error", "Target was not checked", error));
                continue;
            }

            progress?.Report($"Checking {target.Original}");
            await CheckDnsAsync(target, run, ct).ConfigureAwait(false);
            if (target.WebUri is { } webUri)
            {
                if (webUri.Scheme == Uri.UriSchemeHttps)
                {
                    await CheckTlsAsync(target, run, ct).ConfigureAwait(false);
                }
                else
                {
                    run.Findings.Add(Finding(target.Original, "https", "Medium", "Website uses plain HTTP", "Traffic to this URL is not protected by HTTPS."));
                }

                await CheckWebAsync(target, run, ct).ConfigureAwait(false);
            }
            else
            {
                await CheckTlsAsync(target, run, ct).ConfigureAwait(false);
            }

            foreach (var port in definition.Ports)
            {
                ct.ThrowIfCancellationRequested();
                var result = await PortScanner.ProbeAsync(target.Host, port, TimeSpan.FromSeconds(2), ct).ConfigureAwait(false);
                if (result.Open)
                {
                    run.Findings.Add(Finding(target.Original, $"port:{port}", "Info", $"TCP port {port} is open",
                        $"Connected in {result.Elapsed.TotalMilliseconds:F0} ms. Open does not by itself mean unsafe."));
                }
            }
        }

        run.FinishedAt = DateTimeOffset.UtcNow;
        return run;
    }

    public static AssessmentDifference Compare(AssessmentRun previous, AssessmentRun current)
    {
        var old = previous.Findings.Select(Fingerprint).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var now = current.Findings.Select(Fingerprint).ToHashSet(StringComparer.OrdinalIgnoreCase);
        return new AssessmentDifference(
            current.Findings.Where(f => !old.Contains(Fingerprint(f))).ToList(),
            previous.Findings.Where(f => !now.Contains(Fingerprint(f))).ToList());
    }

    private static async Task CheckDnsAsync(AssessmentTarget target, AssessmentRun run, CancellationToken ct)
    {
        try
        {
            var addresses = await System.Net.Dns.GetHostAddressesAsync(target.Host, ct).ConfigureAwait(false);
            var text = string.Join(", ", addresses.Select(a => a.ToString()));
            run.Findings.Add(Finding(target.Original, "dns", "Info", "Host name resolved", text));
        }
        catch (Exception ex) when (ex is SocketException or ArgumentException)
        {
            run.Findings.Add(Finding(target.Original, "dns", "Error", "Host name did not resolve", ex.Message));
        }
    }

    private static async Task CheckTlsAsync(AssessmentTarget target, AssessmentRun run, CancellationToken ct)
    {
        var result = await TlsInspector.InspectAsync(target.Host, target.TlsPort, ct).ConfigureAwait(false);
        if (result.Error is not null)
        {
            run.Findings.Add(Finding(target.Original, "tls", "Warning", "Could not complete TLS check", result.Error));
            return;
        }

        foreach (var issue in result.PolicyErrors)
        {
            run.Findings.Add(Finding(target.Original, "tls:trust", "Warning", "Certificate trust problem", issue));
        }

        foreach (var cert in result.Chain)
        {
            var days = cert.DaysUntilExpiry(DateTime.UtcNow);
            if (days <= 30)
            {
                run.Findings.Add(Finding(target.Original, $"tls:expiry:{cert.Thumbprint}", days < 0 ? "Error" : "Warning",
                    days < 0 ? "Certificate has expired" : "Certificate expires soon",
                    $"{cert.Subject}; expires {cert.NotAfter:u}; {days} days remaining."));
            }
        }

        run.Findings.Add(Finding(target.Original, "tls:protocol", "Info", "TLS connection details",
            $"Protocol {result.Protocol}; cipher {result.CipherSuite}; certificate chain length {result.Chain.Count}."));
    }

    private static async Task CheckWebAsync(AssessmentTarget target, AssessmentRun run, CancellationToken ct)
    {
        var result = await HttpProbe.SendAsync(new HttpProbeRequest(target.WebUri!.ToString(), Timeout: TimeSpan.FromSeconds(10)), ct)
            .ConfigureAwait(false);
        if (result.Error is not null)
        {
            run.Findings.Add(Finding(target.Original, "http", "Warning", "Website request failed", result.Error));
            return;
        }

        var final = result.Final;
        if (final is not null)
        {
            run.Findings.Add(Finding(target.Original, "http:status", "Info", $"Website returned HTTP {final.StatusCode}",
                $"Final URL: {final.Url}; total time {result.Total.TotalMilliseconds:F0} ms."));
        }

        string? Header(string name) => result.Headers.FirstOrDefault(h => h.Key.Equals(name, StringComparison.OrdinalIgnoreCase)).Value;
        foreach (var (header, advice, severity) in SecurityHeaders)
        {
            if (Header(header) is null && (header != "Strict-Transport-Security" || target.WebUri.Scheme == Uri.UriSchemeHttps))
            {
                run.Findings.Add(Finding(target.Original, $"http:header:{header}", severity, advice, $"Missing response header: {header}"));
            }
        }

        foreach (var cookie in result.Headers.Where(h => h.Key.Equals("Set-Cookie", StringComparison.OrdinalIgnoreCase)))
        {
            var name = cookie.Value.Split('=', 2)[0];
            var flags = $"Secure: {HasCookieAttribute(cookie.Value, "Secure")}; " +
                        $"HttpOnly: {HasCookieAttribute(cookie.Value, "HttpOnly")}; " +
                        $"SameSite: {CookieSameSite(cookie.Value) ?? "missing"}";
            if (!cookie.Value.Contains("; Secure", StringComparison.OrdinalIgnoreCase) && target.WebUri.Scheme == Uri.UriSchemeHttps)
            {
                run.Findings.Add(Finding(target.Original, $"cookie:{name}:secure", "Medium", $"Cookie '{name}' is missing Secure", flags));
            }

            if (!cookie.Value.Contains("; HttpOnly", StringComparison.OrdinalIgnoreCase))
            {
                run.Findings.Add(Finding(target.Original, $"cookie:{name}:httponly", "Low", $"Cookie '{name}' is missing HttpOnly", flags));
            }

            if (!Regex.IsMatch(cookie.Value, @";\s*SameSite\s*=", RegexOptions.IgnoreCase, TimeSpan.FromMilliseconds(50)))
            {
                run.Findings.Add(Finding(target.Original, $"cookie:{name}:samesite", "Low", $"Cookie '{name}' has no SameSite setting", flags));
            }
        }
    }

    private static AssessmentFinding Finding(string target, string key, string severity, string summary, string evidence) =>
        new() { Target = target, Key = key, Check = key.Split(':')[0], Severity = severity, Summary = summary, Evidence = evidence };

    private static bool HasCookieAttribute(string cookie, string attribute) =>
        Regex.IsMatch(cookie, $@";\s*{Regex.Escape(attribute)}(?:\s*;|\s*$)", RegexOptions.IgnoreCase, TimeSpan.FromMilliseconds(50));

    private static string? CookieSameSite(string cookie)
    {
        var match = Regex.Match(cookie, @";\s*SameSite\s*=\s*([^;\s]+)", RegexOptions.IgnoreCase, TimeSpan.FromMilliseconds(50));
        return match.Success ? match.Groups[1].Value : null;
    }

    private static string Fingerprint(AssessmentFinding finding) =>
        $"{finding.Target.ToLowerInvariant()}|{finding.Key.ToLowerInvariant()}";
}
