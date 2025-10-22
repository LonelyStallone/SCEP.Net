using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;

namespace SCEP.Net.Services.Abstractions;

public interface ICaCertificatesStorage
{
    public X509Certificate2 Certificate { get; }

    public RSA PrivateKey { get; }

    public IReadOnlyCollection<X509Certificate2> AdditionalCertificates { get; }

    byte[] DegenerateCertificates();

    int TotalCertificatesCount { get; }
}
