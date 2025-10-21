using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using Org.BouncyCastle.Pkcs;
using SCEP.Net.Services.Enums;

namespace SCEP.Net.Models;

public class CSRReqMessage
{
    public Pkcs10CertificationRequest CSR { get; set; }
    public string ChallengePassword { get; set; }
    public X509Certificate2 SignerCert { get; set; }
    public RSA SignerKey { get; set; }
    public byte[] RawDecrypted { get; set; }
    public PKIStatus Status { get; set; }
}
