using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

namespace IsaTool.App.Features.Tls;

/// <summary>Contains displayed TLS certificate information.</summary>
public sealed record TlsCertInfo(
    string Subject, string Issuer, DateTime NotBefore, DateTime NotAfter, string Thumbprint,
    string SignatureAlgorithm, IReadOnlyList<string> SubjectAltNames)
{
    /// <summary>Calculates whole days remaining before certificate expiry.</summary>
    public int DaysUntilExpiry(DateTime utcNow) => (int)Math.Floor((NotAfter.ToUniversalTime() - utcNow).TotalDays);
}

/// <summary>Contains the negotiated TLS details and reported certificate policy errors.</summary>
public sealed record TlsInspection(
    string Protocol,
    string? CipherSuite,
    IReadOnlyList<TlsCertInfo> Chain,
    IReadOnlyList<string> PolicyErrors,
    string? Error);

/// <summary>Connects to TLS endpoints and collects protocol and certificate details.</summary>
public static class TlsInspector
{
    /// <summary>Inspects the TLS connection to a host and port.</summary>
    public static async Task<TlsInspection> InspectAsync(string host, int port, CancellationToken ct = default)
    {
        var policyErrors = new List<string>();
        var chain = new List<TlsCertInfo>();
        try
        {
            using var tcp = new TcpClient();
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(TimeSpan.FromSeconds(10));
            await tcp.ConnectAsync(host, port, timeout.Token).ConfigureAwait(false);

            // Always accept so the chain can be inspected; problems are reported, not enforced.
            await using var ssl = new SslStream(tcp.GetStream(), false, (_, _, x509Chain, errors) =>
            {
                if (errors != SslPolicyErrors.None)
                {
                    policyErrors.Add(errors.ToString());
                }

                if (x509Chain is not null)
                {
                    foreach (var status in x509Chain.ChainStatus)
                    {
                        policyErrors.Add($"{status.Status}: {status.StatusInformation.Trim()}");
                    }

                    chain.AddRange(x509Chain.ChainElements.Select(e => Describe(e.Certificate)));
                }

                return true;
            });

            await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = host,
                EnabledSslProtocols = SslProtocols.None,
            }, timeout.Token).ConfigureAwait(false);

            return new TlsInspection(ssl.SslProtocol.ToString(), ssl.NegotiatedCipherSuite.ToString(),
                chain, policyErrors.Distinct().ToList(), null);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex) when (ex is SocketException or IOException or AuthenticationException or OperationCanceledException)
        {
            return new TlsInspection(string.Empty, null, chain, policyErrors, ex.InnerException?.Message ?? ex.Message);
        }
    }

    private static TlsCertInfo Describe(X509Certificate2 cert)
    {
        var sans = cert.Extensions.OfType<X509SubjectAlternativeNameExtension>()
            .SelectMany(e => e.EnumerateDnsNames())
            .ToList();
        return new TlsCertInfo(cert.Subject, cert.Issuer, cert.NotBefore, cert.NotAfter, cert.Thumbprint,
            cert.SignatureAlgorithm.FriendlyName ?? cert.SignatureAlgorithm.Value ?? "?", sans);
    }
}
