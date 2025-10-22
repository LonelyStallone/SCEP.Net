using System.Security.Cryptography;

namespace SCEP.Net.Tests.Utils;

public static class ToPemConverter
{
    public static string ConvertPrivateKeyToPem(RSA rsa)
    {
        // Export private key in PKCS#8 format
        byte[] privateKeyBytes = rsa.ExportPkcs8PrivateKey();

        // Convert to base64 with PEM formatting
        string base64 = Convert.ToBase64String(privateKeyBytes, Base64FormattingOptions.InsertLineBreaks);

        return $"-----BEGIN PRIVATE KEY-----\n{base64}\n-----END PRIVATE KEY-----";
    }
}