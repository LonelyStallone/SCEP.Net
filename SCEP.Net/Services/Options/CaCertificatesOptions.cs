namespace SCEP.Net.Services.Options;

public class CaCertificatesOptions
{
    public string CertificatePem { get; init; }

    public string PrivateKeyPem { get; init; }

    public IReadOnlyCollection<string> AdditionalCertificatesPem { get; init; }
}
