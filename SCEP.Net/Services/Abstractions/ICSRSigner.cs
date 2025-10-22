using Org.BouncyCastle.Pkcs;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace SCEP.Net.Services.Abstractions;

public interface ICsrSigner
{
    Task<X509Certificate2> SignCsrAsync(
        X509Certificate2 caCertificate,
        RSA caKey,
        Pkcs10CertificationRequest csr,
        BigInteger serialNumber,
        CancellationToken cancellationToken);
}
