using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using Org.BouncyCastle.Pkcs;

namespace SCEP.Net.Tests.Utils;

public static class X509Certificate2Builder
{
    public static X509Certificate2 SelfSign(RSA priv, Pkcs10CertificationRequest csr)
    {
        // Генерация серийного номера
        byte[] serialNumber = new byte[16];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(serialNumber);
            serialNumber[0] &= 0x7F;
        }

        var notBefore = DateTimeOffset.Now;
        var notAfter = notBefore.AddHours(1);

        var subjectBuilder = new X500DistinguishedNameBuilder();
        subjectBuilder.AddCommonName("SCEP SIGNER");

        // Извлекаем организацию из CSR
        if (csr != null)
        {
            // Получаем Subject из CSR
            var subject = csr.GetCertificationRequestInfo().Subject;
            if (subject != null)
            {
                var subjectName = subject.ToString();
                var parts = subjectName.Split(',');
                foreach (var part in parts)
                {
                    var trimmed = part.Trim();
                    if (trimmed.StartsWith("O="))
                    {
                        subjectBuilder.AddOrganizationName(trimmed.Substring(2));
                        break;
                    }
                }
            }
        }

        var subjectNameObj = subjectBuilder.Build();

        var certificate = new CertificateRequest(
            subjectNameObj,
            priv,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        // Добавляем расширения
        certificate.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                X509KeyUsageFlags.KeyEncipherment | X509KeyUsageFlags.DigitalSignature,
                true));

        certificate.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension(
                new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, // serverAuth
                true));

        certificate.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(true, false, 0, true));

        var generator = X509SignatureGenerator.CreateForRSA(priv, RSASignaturePadding.Pkcs1);

        // Исправленный вызов Create - issuer тот же что и subject
        var signedCert = certificate.Create(
            subjectNameObj,
            generator, // issuer = subject для самоподписанного
            notBefore,
            notAfter,
            serialNumber);

        return new X509Certificate2(signedCert.CopyWithPrivateKey(priv));
    }
}
