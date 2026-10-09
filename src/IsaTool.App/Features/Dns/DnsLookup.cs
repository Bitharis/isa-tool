using DnsClient;
using DnsClient.Protocol;

namespace IsaTool.App.Features.Dns;

/// <summary>Represents a DNS resource record formatted for display.</summary>
public sealed record DnsRecordRow(string Name, string Type, int Ttl, string Data);

/// <summary>Represents the records and server information returned by a DNS query.</summary>
public sealed record DnsLookupResult(IReadOnlyList<DnsRecordRow> Records, string? Error, string Server);

/// <summary>Queries DNS records and formats answers for display.</summary>
public static class DnsLookup
{
    /// <summary>Gets the record types supported by the lookup interface.</summary>
    public static readonly IReadOnlyList<QueryType> SupportedTypes =
        [QueryType.A, QueryType.AAAA, QueryType.CNAME, QueryType.MX, QueryType.NS, QueryType.TXT, QueryType.SOA, QueryType.PTR];

    /// <summary>Queries a DNS name or reverse-lookup address using the selected server.</summary>
    public static async Task<DnsLookupResult> QueryAsync(
        string name, QueryType type, string? server = null, CancellationToken ct = default)
    {
        name = name.Trim();
        if (name.Length == 0)
        {
            return new DnsLookupResult([], "Name is required.", string.Empty);
        }

        LookupClient client;
        try
        {
            var options = string.IsNullOrWhiteSpace(server)
                ? new LookupClientOptions { Timeout = TimeSpan.FromSeconds(5), Retries = 1 }
                : new LookupClientOptions(System.Net.IPAddress.Parse(server.Trim()))
                { Timeout = TimeSpan.FromSeconds(5), Retries = 1 };
            client = new LookupClient(options);
        }
        catch (FormatException)
        {
            return new DnsLookupResult([], "Invalid DNS server address.", string.Empty);
        }

        try
        {
            var response = type == QueryType.PTR && System.Net.IPAddress.TryParse(name, out var ip)
                ? await client.QueryReverseAsync(ip, ct).ConfigureAwait(false)
                : await client.QueryAsync(name, type, cancellationToken: ct).ConfigureAwait(false);

            var rows = response.Answers.Select(Describe).ToList();
            var error = response.HasError ? response.ErrorMessage : null;
            return new DnsLookupResult(rows, error, response.NameServer.ToString());
        }
        catch (DnsResponseException ex)
        {
            return new DnsLookupResult([], ex.Message, string.Empty);
        }
    }

    private static DnsRecordRow Describe(DnsResourceRecord record)
    {
        var data = record switch
        {
            AddressRecord a => a.Address.ToString(),
            CNameRecord c => c.CanonicalName.Value,
            MxRecord m => $"{m.Preference} {m.Exchange.Value}",
            NsRecord n => n.NSDName.Value,
            PtrRecord p => p.PtrDomainName.Value,
            TxtRecord t => string.Join(' ', t.Text),
            SoaRecord s => $"{s.MName.Value} {s.RName.Value} serial={s.Serial} refresh={s.Refresh} retry={s.Retry} expire={s.Expire} min={s.Minimum}",
            _ => record.ToString() ?? string.Empty,
        };
        return new DnsRecordRow(record.DomainName.Value, record.RecordType.ToString(), (int)record.TimeToLive, data);
    }
}
