using SCEP.Net.Models;
using System.Security.Cryptography.X509Certificates;

namespace SCEP.Net.Services.Singer;

public interface ICSRSigner
{
    Task<X509Certificate2> SignCSRAsync(CSRReqMessage csrReq, CancellationToken cancellationToken);
}
