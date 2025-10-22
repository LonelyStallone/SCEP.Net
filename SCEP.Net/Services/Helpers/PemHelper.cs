using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace SCEP.Net.Services.Options;

public static class PemHelper
{
    public static X509Certificate2 ConvertPemToX509Certificate2(string pemCertificate)
    {
        if (string.IsNullOrWhiteSpace(pemCertificate))
            throw new ArgumentException("PEM Certificate string cannot be null or empty", nameof(pemCertificate));

        var base64 = pemCertificate
            .Replace("-----BEGIN CERTIFICATE-----", "")
            .Replace("-----END CERTIFICATE-----", "")
            .Replace("\n", "")
            .Replace("\r", "")
            .Trim();

        var certData = Convert.FromBase64String(base64);
        return new X509Certificate2(certData);
    }

    public static RSA ConvertPemToRSA(string pemPrivateKey)
    {
        var rsa = RSA.Create();
        rsa.ImportFromPem(pemPrivateKey);

        return rsa;
    }
}
