using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using IsaTool.Core.Hosts;
using IsaTool.Core.Settings;
using IsaTool.Plugins;

namespace IsaTool.App.Features.Proxy;

/// <summary>Defines one named proxy rewrite rule.</summary>
public sealed class ProxyRule
{
    public string Name { get; set; } = string.Empty;

    public bool Enabled { get; set; } = true;

    public RuleMatch Match { get; set; } = new();

    public List<RuleAction> Actions { get; set; } = [];
}

/// <summary>All set fields must match; comma-separated lists mean "any of". Status only exists in the response phase.</summary>
public sealed class RuleMatch
{
    public string? Host { get; set; }

    public string? Path { get; set; }

    public string? Method { get; set; }

    public string? Status { get; set; }
}

/// <summary>Defines one action performed by a matching rewrite rule.</summary>
public sealed class RuleAction
{
    public string Type { get; set; } = string.Empty;

    public string? Name { get; set; }

    public string? Value { get; set; }

    public string? Find { get; set; }

    public string? Replace { get; set; }

    public int? Status { get; set; }

    public string? Body { get; set; }

    public string? ContentType { get; set; }

    public int? Ms { get; set; }

    public string? Host { get; set; }
}

/// <summary>Contains the request-phase effects produced by rewrite rules.</summary>
public sealed class RequestRuleResult
{
    public MutableResponse? Mock { get; set; }

    public bool Drop { get; set; }

    public TimeSpan Delay { get; set; }
}

/// <summary>Declarative request/response rewrite rules loaded from a JSON file.</summary>
public sealed class RewriteRuleSet
{
    private static readonly HashSet<string> RequestActions = new(StringComparer.OrdinalIgnoreCase)
    {
        "setRequestHeader", "removeRequestHeader", "replaceRequestBody", "redirectHost", "mockResponse", "delay", "drop",
    };

    private static readonly HashSet<string> ResponseActions = new(StringComparer.OrdinalIgnoreCase)
    {
        "setResponseHeader", "removeResponseHeader", "replaceResponseBody", "setStatus", "delayResponse",
    };

    private static readonly JsonSerializerOptions Json = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
        WriteIndented = true,
    };

    private readonly List<CompiledRule> _rules;

    private RewriteRuleSet(List<CompiledRule> rules) => _rules = rules;

    public static RewriteRuleSet Empty { get; } = new([]);

    public static string DefaultPath => Path.Combine(SettingsStore.DefaultDirectory, "proxy-rules.json");

    public int Count => _rules.Count;

    /// <summary>Sample rules file; every rule is commented out so loading it changes nothing.</summary>
    public const string SampleJson = """
        // IsaTool proxy rewrite rules.
        //
        // Everything below is commented out. To use a rule, remove the leading "//" from
        // its lines and paste it inside the "rules" list (rules are separated by commas).
        // Then press "Reload rules" in the proxy screen. Comments and trailing commas are allowed.
        //
        // match (all optional; all given fields must match):
        //   host    "api.corp.com", "*.corp.com" (comma-separated list, '*' wildcard)
        //   path    "/v1/*" (path only, no query string)
        //   method  "GET,POST"
        //   status  "5xx,404" (response phase only; then only response actions and "tag" are allowed)
        //
        // Request actions:  setRequestHeader{name,value}  removeRequestHeader{name}
        //                   replaceRequestBody{find,replace}  redirectHost{host[:port]}
        //                   mockResponse{status,body,contentType}  delay{ms}  drop
        // Response actions: setResponseHeader{name,value}  removeResponseHeader{name}
        //                   replaceResponseBody{find,replace}  setStatus{status}  delayResponse{ms}
        // Any phase:        tag{value}
        //
        // Rules only apply to hosts the proxy captures (see "Only hosts" / "Ignore hosts").
        // Set "enabled": false on a rule to keep it in the file without applying it.
        {
          "rules": [

            // Add a test token to every call to one API.
            // {
            //   "name": "Add test auth header",
            //   "match": { "host": "api.example.com" },
            //   "actions": [
            //     { "type": "setRequestHeader", "name": "Authorization", "value": "Bearer TEST-TOKEN" }
            //   ]
            // },

            // Answer a URL locally without contacting the server.
            // {
            //   "name": "Mock health endpoint",
            //   "match": { "host": "api.example.com", "path": "/health" },
            //   "actions": [
            //     { "type": "mockResponse", "status": 200, "contentType": "application/json", "body": "{\"status\":\"ok\"}" }
            //   ]
            // },

            // Send traffic for one host to another (the Host header follows the new target).
            // {
            //   "name": "Send API calls to staging",
            //   "match": { "host": "api.example.com" },
            //   "actions": [ { "type": "redirectHost", "host": "staging.example.com" } ]
            // },

            // Simulate a slow upload path.
            // {
            //   "name": "Slow down uploads",
            //   "match": { "method": "POST,PUT", "path": "/upload/*" },
            //   "actions": [ { "type": "delay", "ms": 2000 } ]
            // },

            // Hide a value in responses (gzip/deflate/br bodies are decoded first).
            // {
            //   "name": "Redact tokens in responses",
            //   "match": { "host": "api.example.com" },
            //   "actions": [ { "type": "replaceResponseBody", "find": "secret-value", "replace": "REDACTED" } ]
            // },

            // Mark failing calls so they stand out (shown with '*' in the flow list).
            // {
            //   "name": "Flag server errors",
            //   "match": { "status": "5xx" },
            //   "actions": [ { "type": "tag", "value": "server error" } ]
            // },

            // Simulate a broken connection.
            // {
            //   "name": "Drop telemetry",
            //   "match": { "host": "telemetry.example.com" },
            //   "actions": [ { "type": "drop" } ]
            // }

          ]
        }
        """;
    public static RewriteRuleSet Load(string path, out List<string> errors)
    {
        errors = [];
        if (!File.Exists(path))
        {
            return Empty;
        }

        List<ProxyRule>? parsed;
        try
        {
            parsed = JsonSerializer.Deserialize<RuleFile>(File.ReadAllText(path), Json)?.Rules;
        }
        catch (JsonException ex)
        {
            errors.Add($"Rules file is not valid JSON: {ex.Message}");
            return Empty;
        }

        return Compile(parsed ?? [], errors);
    }

    public static RewriteRuleSet Compile(IEnumerable<ProxyRule> rules, List<string> errors)
    {
        var compiled = new List<CompiledRule>();
        var index = 0;
        foreach (var rule in rules)
        {
            index++;
            var label = string.IsNullOrWhiteSpace(rule.Name) ? $"rule #{index}" : $"'{rule.Name}'";
            if (!rule.Enabled)
            {
                continue;
            }

            var problems = Validate(rule).ToList();
            if (problems.Count > 0)
            {
                errors.AddRange(problems.Select(p => $"Rule {label} skipped: {p}"));
                continue;
            }

            compiled.Add(new CompiledRule(rule, label.Trim('\'')));
        }

        return new RewriteRuleSet(compiled);
    }

    /// <summary>Applies request-phase actions; <paramref name="applied"/> receives a note per effective action.</summary>
    public RequestRuleResult ApplyRequest(MutableRequest request, List<string> applied)
    {
        var result = new RequestRuleResult();
        foreach (var rule in _rules.Where(r => !r.HasStatus && r.Matches(request, null)))
        {
            foreach (var action in rule.Rule.Actions)
            {
                var type = action.Type;
                if (ResponseActions.Contains(type))
                {
                    continue;
                }

                switch (type.ToLowerInvariant())
                {
                    case "setrequestheader":
                        SetHeader(request.Headers, action.Name!, action.Value ?? string.Empty);
                        Note(applied, rule, action, action.Name);
                        break;
                    case "removerequestheader":
                        if (RemoveHeader(request.Headers, action.Name!))
                        {
                            Note(applied, rule, action, action.Name);
                        }

                        break;
                    case "replacerequestbody":
                        if (ReplaceInBody(request.Headers, request.Body, action.Find!, action.Replace ?? string.Empty) is { } changed)
                        {
                            request.Body = changed;
                            Note(applied, rule, action, null);
                        }

                        break;
                    case "redirecthost":
                        request.Uri = Redirect(request.Uri, action.Host!);
                        Note(applied, rule, action, action.Host);
                        break;
                    case "delay":
                        result.Delay += TimeSpan.FromMilliseconds(Math.Clamp(action.Ms ?? 0, 0, 60_000));
                        Note(applied, rule, action, $"{action.Ms} ms");
                        break;
                    case "mockresponse":
                        result.Mock = BuildMock(action, rule.Label);
                        Note(applied, rule, action, null);
                        return result;
                    case "drop":
                        result.Drop = true;
                        Note(applied, rule, action, null);
                        return result;
                    case "tag":
                        applied.Add($"{rule.Label}: tag '{action.Value}'");
                        break;
                }
            }
        }

        return result;
    }

    /// <summary>Applies response-phase actions and returns an extra delay to wait before replying.</summary>
    public TimeSpan ApplyResponse(MutableRequest request, MutableResponse response, List<string> applied)
    {
        var delay = TimeSpan.Zero;
        foreach (var rule in _rules.Where(r => r.Matches(request, response.Status)))
        {
            foreach (var action in rule.Rule.Actions)
            {
                switch (action.Type.ToLowerInvariant())
                {
                    case "setresponseheader":
                        SetHeader(response.Headers, action.Name!, action.Value ?? string.Empty);
                        Note(applied, rule, action, action.Name);
                        break;
                    case "removeresponseheader":
                        if (RemoveHeader(response.Headers, action.Name!))
                        {
                            Note(applied, rule, action, action.Name);
                        }

                        break;
                    case "replaceresponsebody":
                        if (ReplaceInBody(response.Headers, response.Body, action.Find!, action.Replace ?? string.Empty) is { } changed)
                        {
                            response.Body = changed;
                            if (!string.Equals(Header(response.Headers, "Content-Encoding"), "identity", StringComparison.OrdinalIgnoreCase))
                            {
                                RemoveHeader(response.Headers, "Content-Encoding");
                            }

                            Note(applied, rule, action, null);
                        }

                        break;
                    case "setstatus":
                        response.Status = action.Status!.Value;
                        response.Reason = ReasonFor(response.Status);
                        Note(applied, rule, action, action.Status.ToString());
                        break;
                    case "delayresponse":
                        delay += TimeSpan.FromMilliseconds(Math.Clamp(action.Ms ?? 0, 0, 60_000));
                        Note(applied, rule, action, $"{action.Ms} ms");
                        break;
                    case "tag" when rule.HasStatus:
                        applied.Add($"{rule.Label}: tag '{action.Value}'");
                        break;
                }
            }
        }

        return delay;
    }

    private static IEnumerable<string> Validate(ProxyRule rule)
    {
        if (rule.Actions.Count == 0)
        {
            yield return "no actions";
        }

        foreach (var a in rule.Actions)
        {
            var type = a.Type;
            if (!RequestActions.Contains(type) && !ResponseActions.Contains(type) &&
                !type.Equals("tag", StringComparison.OrdinalIgnoreCase))
            {
                yield return $"unknown action type '{type}'";
                continue;
            }

            var missing = type.ToLowerInvariant() switch
            {
                "setrequestheader" or "setresponseheader" => string.IsNullOrEmpty(a.Name) ? "name" : null,
                "removerequestheader" or "removeresponseheader" => string.IsNullOrEmpty(a.Name) ? "name" : null,
                "replacerequestbody" or "replaceresponsebody" => string.IsNullOrEmpty(a.Find) ? "find" : null,
                "redirecthost" => string.IsNullOrEmpty(a.Host) ? "host" : null,
                "setstatus" => a.Status is null ? "status" : null,
                "delay" or "delayresponse" => a.Ms is null ? "ms" : null,
                "tag" => string.IsNullOrEmpty(a.Value) ? "value" : null,
                _ => null,
            };
            if (missing is not null)
            {
                yield return $"action '{type}' needs '{missing}'";
            }
        }

        if (!string.IsNullOrEmpty(rule.Match.Status) &&
            rule.Actions.Any(a => RequestActions.Contains(a.Type)))
        {
            yield return "'status' can only be matched by response actions (request actions run before a status exists)";
        }
    }

    private static void Note(List<string> applied, CompiledRule rule, RuleAction action, string? detail) =>
        applied.Add($"{rule.Label}: {action.Type}{(string.IsNullOrEmpty(detail) ? string.Empty : " " + detail)}");

    private static MutableResponse BuildMock(RuleAction action, string ruleName)
    {
        var status = action.Status ?? 200;
        var body = Encoding.UTF8.GetBytes(action.Body ?? string.Empty);
        List<KeyValuePair<string, string>> headers =
        [
            new("Content-Type", action.ContentType ?? "text/plain; charset=utf-8"),
            new("X-IsaTool-Mock", ruleName),
        ];
        return new MutableResponse(status, ReasonFor(status), headers, body);
    }

    private static string ReasonFor(int status) =>
        Regex.Replace(((HttpStatusCode)status).ToString(), "(?<=[a-z])(?=[A-Z])", " ") is { } name && !int.TryParse(name, out _)
            ? name
            : "Status";

    private static Uri Redirect(Uri uri, string host)
    {
        var builder = new UriBuilder(uri);
        if (HostPort(host, out var h, out var port))
        {
            builder.Host = h;
            if (port is { } p)
            {
                builder.Port = p;
            }
        }

        return builder.Uri;
    }

    private static bool HostPort(string text, out string host, out int? port)
    {
        var parsed = HostTarget.TryParse(text, 0, out host, out var p);
        port = p == 0 ? null : p;
        return parsed;
    }

    public static string? Header(List<KeyValuePair<string, string>> headers, string name) =>
        headers.FirstOrDefault(h => h.Key.Equals(name, StringComparison.OrdinalIgnoreCase)).Value;

    private static void SetHeader(List<KeyValuePair<string, string>> headers, string name, string value)
    {
        RemoveHeader(headers, name);
        headers.Add(new(name, value));
    }

    private static bool RemoveHeader(List<KeyValuePair<string, string>> headers, string name) =>
        headers.RemoveAll(h => h.Key.Equals(name, StringComparison.OrdinalIgnoreCase)) > 0;

    /// <summary>Plain-text replace on a UTF-8 body (decompressing first); null when nothing changed.</summary>
    private static byte[]? ReplaceInBody(List<KeyValuePair<string, string>> headers, byte[] body, string find, string replace)
    {
        var encoding = Header(headers, "Content-Encoding");
        var bytes = body;
        if (encoding is not null)
        {
            bytes = FlowFormatter.Decode(encoding, body, out var note);
            if (note.Length > 0)
            {
                return null;
            }
        }

        string text;
        try
        {
            text = new UTF8Encoding(false, true).GetString(bytes);
        }
        catch (ArgumentException)
        {
            return null;
        }

        return text.Contains(find, StringComparison.Ordinal)
            ? Encoding.UTF8.GetBytes(text.Replace(find, replace, StringComparison.Ordinal))
            : null;
    }

    private sealed class RuleFile
    {
        public List<ProxyRule> Rules { get; set; } = [];
    }

    private sealed class CompiledRule
    {
        private readonly HostMatcher _host;
        private readonly Regex? _path;
        private readonly HashSet<string> _methods;
        private readonly string[] _status;

        public CompiledRule(ProxyRule rule, string label)
        {
            Rule = rule;
            Label = label;
            _host = new HostMatcher(rule.Match.Host);
            _path = string.IsNullOrWhiteSpace(rule.Match.Path)
                ? null
                : new Regex("^" + Regex.Escape(rule.Match.Path.Trim()).Replace("\\*", ".*", StringComparison.Ordinal) + "$",
                    RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(50));
            _methods = new HashSet<string>(Split(rule.Match.Method), StringComparer.OrdinalIgnoreCase);
            _status = Split(rule.Match.Status);
        }

        public ProxyRule Rule { get; }

        public string Label { get; }

        public bool HasStatus => _status.Length > 0;

        public bool Matches(MutableRequest request, int? status)
        {
            if (!_host.IsEmpty && !_host.IsMatch(request.Uri.Host))
            {
                return false;
            }

            if (_path is not null && !_path.IsMatch(request.Uri.AbsolutePath))
            {
                return false;
            }

            if (_methods.Count > 0 && !_methods.Contains(request.Method))
            {
                return false;
            }

            return !HasStatus || (status is { } s && FlowFilter.StatusMatches(_status, s));
        }

        private static string[] Split(string? v) =>
            (v ?? string.Empty).Split([',', ';', ' '], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    }
}
