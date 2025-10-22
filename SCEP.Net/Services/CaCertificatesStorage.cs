using Microsoft.Extensions.Options;
using SCEP.Net.Services.Abstractions;
using SCEP.Net.Services.Helpers;
using SCEP.Net.Services.Options;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace SCEP.Net.Services;

public class CaCertificatesStorage : ICaCertificatesStorage
{
    public CaCertificatesStorage(IOptions<CaCertificatesOptions> options)
    {
        Certificate = PemHelper.ConvertPemToX509Certificate2(options.Value.CertificatePem);
        PrivateKey = PemHelper.ConvertPemToRSA(options.Value.PrivateKeyPem);
        AdditionalCertificates = options.Value.AdditionalCertificatesPem?
            .Select(PemHelper.ConvertPemToX509Certificate2)
            .ToList() ?? new List<X509Certificate2>();
    }

    public X509Certificate2 Certificate { get; }

    public RSA PrivateKey { get; }

    public IReadOnlyCollection<X509Certificate2> AdditionalCertificates { get; }

    public byte[] DegenerateCertificates()
    {

        if (AdditionalCertificates.Count < 1)
        {
            return Certificate.RawData;
        }

        var certs = new List<X509Certificate2> { Certificate };
        certs.AddRange(AdditionalCertificates);

        var degenerateCerts = PkcsHelper.DegenerateCertificates(certs);
        return degenerateCerts;
    }

    public int TotalCertificatesCount => AdditionalCertificates.Count + 1;
}
