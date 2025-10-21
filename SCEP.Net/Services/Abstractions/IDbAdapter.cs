using System.Security.Cryptography.X509Certificates;

namespace SCEP.Net.Services.Abstractions;

public interface IDbAdapter
{
    Task<byte[]?> GetValueAsync(string key, CancellationToken cancellationToken);

    Task SetValueAsync(string key, byte[] value, CancellationToken cancellationToken);

    Task<bool> HasCnAsync(string commonName, X509Certificate2 certificate, CancellationToken cancellationToken);
}
