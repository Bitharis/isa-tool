using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using IsaTool.Core.Settings;

namespace IsaTool.App.Features.Proxy;

/// <summary>Local root CA used only by the debug proxy; names are deliberately obvious so it can be found and removed.</summary>
public sealed class CertificateAuthority
{
    public const string CommonName = "IsaTool Debug Proxy CA - REMOVE WHEN DONE";
    public const string FileBaseName = "isatool-debug-proxy-ca";

    private const string Subject = $"CN={CommonName}, OU=Local debug proxy - safe to delete, O=IsaTool";
    private static readonly TimeSpan CaLifetime = TimeSpan.FromDays(365);
    private static readonly TimeSpan LeafLifetime = TimeSpan.FromDays(7);

    private readonly ConcurrentDictionary<string, X509Certificate2> _leaves = new(StringComparer.OrdinalIgnoreCase);

    private CertificateAuthority(X509Certificate2 certificate, string directory)
    {
        Certificate = certificate;
        Directory = directory;
    }

    public static string DefaultDirectory => Path.Combine(SettingsStore.DefaultDirectory, "proxy-ca");

    public X509Certificate2 Certificate { get; }

    public string Directory { get; }

    public string CertificatePath => Path.Combine(Directory, FileBaseName + ".crt");

    private string KeyStorePath => Path.Combine(Directory, FileBaseName + ".pfx");

    public static bool Exists(string directory) => File.Exists(Path.Combine(directory, FileBaseName + ".pfx"));

    public static CertificateAuthority LoadOrCreate(string directory)
    {
        var pfx = Path.Combine(directory, FileBaseName + ".pfx");
        if (File.Exists(pfx))
        {
            var existing = X509CertificateLoader.LoadPkcs12FromFile(pfx, null);
            if (existing.HasPrivateKey && existing.NotAfter.ToUniversalTime() > DateTime.UtcNow + LeafLifetime)
            {
                var loaded = new CertificateAuthority(existing, directory);
                loaded.WriteCertificate();
                return loaded;
            }

            existing.Dispose();
        }

        return Create(directory);
    }

    /// <summary>Deletes the CA files; the OS trust store entry must be removed separately.</summary>
    public static void DeleteFiles(string directory)
    {
        foreach (var ext in new[] { ".pfx", ".crt" })
        {
            var path = Path.Combine(directory, FileBaseName + ext);
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
    }

    public X509Certificate2 GetLeaf(string host) => _leaves.GetOrAdd(host, IssueLeaf);

    public static string InstallInstructions(string certPath) =>
        $"""
        CA certificate: {certPath}
        Name in trust stores: "{CommonName}"

        INSTALL (needs your trust decision; only do this on machines you test with)
          Windows (current user):  certutil -addstore -user Root "{certPath}"
          Debian/Ubuntu:           sudo cp "{certPath}" /usr/local/share/ca-certificates/{FileBaseName}.crt
                                   sudo update-ca-certificates
          RHEL/Fedora:             sudo cp "{certPath}" /etc/pki/ca-trust/source/anchors/
                                   sudo update-ca-trust
          Single process only:     curl --cacert <file>, NODE_EXTRA_CA_CERTS=<file>
          Firefox/Java keep their own stores; import it there.

        REMOVE
          Windows:                 certutil -delstore -user Root "{CommonName}"
          Debian/Ubuntu:           sudo rm /usr/local/share/ca-certificates/{FileBaseName}.crt
                                   sudo update-ca-certificates --fresh
          RHEL/Fedora:             sudo rm /etc/pki/ca-trust/source/anchors/{FileBaseName}.crt
                                   sudo update-ca-trust
          Then use "Delete CA files" in IsaTool to remove the private key.
        """;

    private static CertificateAuthority Create(string directory)
    {
        CreateSecureDirectory(directory);

        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest(Subject, key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));

        var now = DateTimeOffset.UtcNow;
        using var created = request.CreateSelfSigned(now.AddDays(-1), now + CaLifetime);
        var pfxBytes = created.Export(X509ContentType.Pkcs12);

        var options = new FileStreamOptions { Mode = FileMode.Create, Access = FileAccess.Write };
        if (!OperatingSystem.IsWindows())
        {
            options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        }
        using (var stream = new FileStream(Path.Combine(directory, FileBaseName + ".pfx"), options))
        {
            stream.Write(pfxBytes);
        }

        var ca = new CertificateAuthority(X509CertificateLoader.LoadPkcs12(pfxBytes, null), directory);
        ca.WriteCertificate();
        return ca;
    }

    private static void CreateSecureDirectory(string directory)
    {
        if (OperatingSystem.IsWindows())
        {
            System.IO.Directory.CreateDirectory(directory);
        }
        else
        {
            System.IO.Directory.CreateDirectory(directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }
    }

    private void WriteCertificate() => File.WriteAllText(CertificatePath, Certificate.ExportCertificatePem());

    private X509Certificate2 IssueLeaf(string host)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var cn = host.Length <= 60 ? host : host[..60];
        var request = new CertificateRequest($"CN={cn}, O=IsaTool Debug Proxy (generated)", key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            [new Oid("1.3.6.1.5.5.7.3.1")], false));

        var san = new SubjectAlternativeNameBuilder();
        if (IPAddress.TryParse(host, out var ip))
        {
            san.AddIpAddress(ip);
        }
        else
        {
            san.AddDnsName(host);
        }

        request.CertificateExtensions.Add(san.Build());

        var now = DateTimeOffset.UtcNow;
        var notAfter = now + LeafLifetime;
        var caNotAfter = new DateTimeOffset(Certificate.NotAfter.ToUniversalTime());
        if (notAfter > caNotAfter)
        {
            notAfter = caNotAfter;
        }

        var serial = RandomNumberGenerator.GetBytes(16);
        serial[0] &= 0x7F;
        using var signed = request.Create(Certificate, now.AddDays(-1), notAfter, serial);
        using var withKey = signed.CopyWithPrivateKey(key);

        // Re-import so the key is usable by SslStream on Windows.
        return X509CertificateLoader.LoadPkcs12(withKey.Export(X509ContentType.Pkcs12), null);
    }
}
