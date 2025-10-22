using Org.BouncyCastle.Crypto.Signers;
using SCEP.Net.Services.Enums;

namespace SCEP.Net.Services.Abstractions;

public interface IScepService
{
    byte[] GetCaCaps();

    (byte[] Data, int CertificatesCount) GetCaCert(string message);

    Task<byte[]> PkiOperationAsync(byte[] data, CancellationToken cancellationToken);

    Task<byte[]> GetNextCaCertAsync(CancellationToken cancellationToken);
}
