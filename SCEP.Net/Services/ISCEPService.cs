namespace SCEP.Net.Services;

public interface ISCEPService
{
    Task<byte[]> GetCACapsAsync(CancellationToken cancellationToken);

    Task<(byte[] data, int certNum)> GetCACertAsync(string message, CancellationToken cancellationToken);

    Task<byte[]> PKIOperationAsync(byte[] msg, CancellationToken cancellationToken);

    Task<byte[]> GetNextCACertAsync(CancellationToken cancellationToken);
}
