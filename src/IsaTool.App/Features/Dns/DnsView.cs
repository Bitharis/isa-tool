using System.Text;
using DnsClient;
using IsaTool.App.Shell;

namespace IsaTool.App.Features.Dns;

/// <summary>Provides the interactive interface for DNS lookups.</summary>
public sealed class DnsView : FeatureView
{
    public DnsView()
    {
        var name = AddField("Name / IP", "example.com");
        var type = AddField("Type", "A", 14);
        var server = AddField("DNS server", string.Empty);
        AddButton("Lookup", async ct =>
        {
            if (!Enum.TryParse<QueryType>(type.Text.Trim(), true, out var qt))
            {
                SetOutput($"Unknown type. Use: {string.Join(", ", DnsLookup.SupportedTypes)}");
                return;
            }

            SetOutput("Querying...");
            var result = await DnsLookup.QueryAsync(name.Text, qt, server.Text, ct);
            var sb = new StringBuilder($"Server: {result.Server}\n");
            if (result.Error is not null)
            {
                sb.AppendLine($"ERROR: {result.Error}");
            }

            foreach (var r in result.Records)
            {
                sb.AppendLine($"{r.Name,-35} {r.Ttl,6} {r.Type,-6} {r.Data}");
            }

            if (result.Records.Count == 0 && result.Error is null)
            {
                sb.AppendLine("No records.");
            }

            SetOutput(sb.ToString());
        });
        Build();
    }

    /// <inheritdoc />
    public override string FeatureName => "DNS lookup";
}
