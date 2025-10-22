using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using SCEP.Net.Services.Abstractions;
using SCEP.Net.Services.Options;

namespace SCEP.Net.Tests.Utils;
public static class DataGenerator
{
    public static CaCertificatesOptions CreateCaCertificatesOptions(int years, string org, string country)
    {
        var privateKey = RSA.Create(2048);
        var certificate = CreateX509Certificat2(privateKey, years, org, country);

        return new CaCertificatesOptions
        {
            CertificatePem = certificate.ExportCertificatePem(),
            PrivateKeyPem = ToPemConverter.ConvertPrivateKeyToPem(privateKey),
        };
    }

    public static async Task<RSA> CreateOrLoadKeyAsync(
        this IDbAdapter adapter,
        int bits,
        CancellationToken cancellationToken)
    {
        var keyBytes = await adapter.GetValueAsync("ca_key", cancellationToken);

        if (keyBytes != null && keyBytes.Length > 0)
        {
            var key = RSA.Create();
            key.ImportPkcs8PrivateKey(keyBytes, out _);
            return key;
        }

        var newKey = RSA.Create(bits);
        var pkcs8 = newKey.ExportPkcs8PrivateKey();

        await adapter.SetValueAsync("ca_key", pkcs8, cancellationToken);

        return newKey;
    }

    public static async Task<X509Certificate2> CreateOrLoadCAAsync(
        this IDbAdapter adapter,
        RSA key,
        int years,
        string org,
        string country,
        CancellationToken cancellationToken)
    {
        var certBytes = await adapter.GetValueAsync("ca_certificate", cancellationToken);

        if (certBytes != null && certBytes.Length > 0)
        {
            return new X509Certificate2(certBytes);
        }

        // Create new CA certificate
        var certRawData = CreateCertificateRawData(key, years, org, country);

        await adapter.SetValueAsync("ca_certificate", certRawData, cancellationToken);

        return new X509Certificate2(certRawData);
    }

    private static byte[] CreateCertificateRawData(RSA key, int years, string org, string country)
    {
        var caCert = CreateX509Certificat2(key, years, org, country);
        var rawData = caCert.Export(X509ContentType.Cert);

        return rawData;
    }

    private static X509Certificate2 CreateX509Certificat2(RSA key, int years, string org, string country)
    {
        // Create new CA certificate
        var subject = new X500DistinguishedName(
            $"CN=SCEP CA, O={org}, OU=MICROMDM SCEP CA, C={country}");

        var request = new CertificateRequest(
            subject,
            key,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        request.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(true, false, 0, true));

        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign,
                true));

        var notBefore = DateTimeOffset.UtcNow;
        var notAfter = notBefore.AddYears(years);

        var serial = new byte[16];
        RandomNumberGenerator.Fill(serial);

        var caCert = request.CreateSelfSigned(notBefore, notAfter);

        return caCert;
    }
}
