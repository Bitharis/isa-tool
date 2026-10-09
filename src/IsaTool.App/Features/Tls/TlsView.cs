using System.Text;
using IsaTool.App.Shell;
using IsaTool.Core.Hosts;

namespace IsaTool.App.Features.Tls;

/// <summary>Provides the interactive interface for inspecting TLS certificates.</summary>
public sealed class TlsView : FeatureView
{
    public TlsView()
    {
        var target = AddField("Host[:port]", "example.com:443");
        AddButton("Inspect", async ct =>
        {
            if (!HostTarget.TryParse(target.Text, 443, out var host, out var port))
            {
                SetOutput("Invalid target.");
                return;
            }

            SetOutput("Connecting...");
            var r = await TlsInspector.InspectAsync(host, port, ct);
            var sb = new StringBuilder();
            if (r.Error is not null)
            {
                sb.AppendLine($"ERROR: {r.Error}");
            }
            else
            {
                sb.AppendLine($"Protocol: {r.Protocol}   Cipher: {r.CipherSuite}");
            }

            foreach (var e in r.PolicyErrors)
            {
                sb.AppendLine($"WARNING: {e}");
            }

            for (var i = 0; i < r.Chain.Count; i++)
            {
                var c = r.Chain[i];
                var days = c.DaysUntilExpiry(DateTime.UtcNow);
                sb.AppendLine().AppendLine($"[{i}] {c.Subject}")
                    .AppendLine($"    Issuer:  {c.Issuer}")
                    .AppendLine($"    Valid:   {c.NotBefore:u} -> {c.NotAfter:u} ({(days < 0 ? "EXPIRED" : days + " days left")})")
                    .AppendLine($"    SHA1:    {c.Thumbprint}   Sig: {c.SignatureAlgorithm}");
                if (c.SubjectAltNames.Count > 0)
                {
                    sb.AppendLine($"    SANs:    {string.Join(", ", c.SubjectAltNames)}");
                }
            }

            SetOutput(sb.ToString());
        });
        Build();
    }

    /// <inheritdoc />
    public override string FeatureName => "TLS certificate";
}
