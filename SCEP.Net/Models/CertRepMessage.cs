using SCEP.Net.Services.PKI.Enums;
using System.Security.Cryptography.X509Certificates;

namespace SCEP.Net.Models;

public class CertRepMessage
{
    public PKIStatus PKIStatus { get; set; }
    public byte[] RecipientNonce { get; set; }
    public PKIFailInfo FailInfo { get; set; }
    public X509Certificate2 Certificate { get; set; }
    public byte[] Degenerate { get; set; }
}
