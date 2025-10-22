using SCEP.Net.Services.Enums;
using System.Security.Cryptography.X509Certificates;

namespace SCEP.Net.Services.PKI;

public class CertRepMessage
{
    public PkiStatus PKIStatus { get; set; }

    public byte[] RecipientNonce { get; set; }

    public PkiFailInfo FailInfo { get; set; }

    public X509Certificate2 Certificate { get; set; }

    public byte[] Degenerate { get; set; }
}
