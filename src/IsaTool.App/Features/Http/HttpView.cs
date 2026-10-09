using System.Text;
using IsaTool.App.Shell;

namespace IsaTool.App.Features.Http;

/// <summary>Provides the interactive interface for sending HTTP requests.</summary>
public sealed class HttpView : FeatureView
{
    public HttpView()
    {
        var url = AddField("URL", "https://");
        var method = AddField("Method", "GET");
        var headers = AddField("Headers", "Accept: */*");
        var body = AddField("Body");
        AddButton("Send", async ct =>
        {
            SetOutput("Sending...");
            var request = new HttpProbeRequest(url.Text, method.Text.Trim(),
                HttpProbe.ParseHeaders(headers.Text.Replace(';', '\n')), body.Text);
            SetOutput(Format(await HttpProbe.SendAsync(request, ct)));
        });
        AddButtonSameRow("Send (ignore TLS errors)", async ct =>
        {
            SetOutput("Sending...");
            var request = new HttpProbeRequest(url.Text, method.Text.Trim(),
                HttpProbe.ParseHeaders(headers.Text.Replace(';', '\n')), body.Text, IgnoreCertificateErrors: true);
            SetOutput(Format(await HttpProbe.SendAsync(request, ct)));
        });
        Build();
    }

    /// <inheritdoc />
    public override string FeatureName => "HTTP client";

    private static string Format(HttpProbeResult r)
    {
        var sb = new StringBuilder();
        foreach (var hop in r.Hops)
        {
            sb.AppendLine($"{hop.StatusCode} {hop.ReasonPhrase,-20} {hop.TimeToHeaders.TotalMilliseconds,7:F0} ms  {hop.Url}");
        }

        if (r.Error is not null)
        {
            sb.AppendLine($"ERROR: {r.Error}");
        }

        sb.AppendLine($"Total: {r.Total.TotalMilliseconds:F0} ms").AppendLine();
        foreach (var (name, value) in r.Headers)
        {
            sb.AppendLine($"{name}: {value}");
        }

        sb.AppendLine().Append(r.Body);
        if (r.BodyTruncated)
        {
            sb.AppendLine().Append("[body truncated]");
        }

        return sb.ToString();
    }
}
