using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using Org.BouncyCastle.Pkcs;
using SCEP.Net.Services.Enums;

namespace SCEP.Net.Services.PKI;

public class CsrReqMessage
{
    public Pkcs10CertificationRequest Csr { get; set; }

    public string ChallengePassword { get; set; }

    public X509Certificate2 SignerCert { get; set; }

    public RSA SignerKey { get; set; }

    public byte[] RawDecrypted { get; set; }

    public PkiStatus Status { get; set; }
}
