using System.Numerics;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;

namespace SCEP.Net.Services;

public interface IDepot
{
    /// <summary>
    /// Retrieves the CA certificate and private key
    /// </summary>
    /// <param name="password">Password to access the CA</param>
    /// <returns>Tuple containing CA certificates, private key</returns>
    Task<(X509Certificate2[], RSA)> GetCAAsync(string password, CancellationToken cancellationToken);

    /// <summary>
    /// Stores a certificate in the depot
    /// </summary>
    /// <param name="name">Name identifier for the certificate</param>
    /// <param name="certificate">Certificate to store</param>
    Task PutAsync(string name, X509Certificate2 certificate, CancellationToken cancellationToken);

    /// <summary>
    /// Gets the next available serial number
    /// </summary>
    /// <returns>Tuple containing serial number</returns>
    Task<BigInteger> GetSerialAsync(CancellationToken cancellationToken);

    /// <summary>
    /// Checks if a common name exists and optionally revokes old certificates
    /// </summary>
    /// <param name="commonName">Common name to check</param>
    /// <param name="allowTime">Time window allowance in seconds</param>
    /// <param name="certificate">Certificate to compare/validate</param>
    /// <param name="revokeOldCertificate">Whether to revoke old certificates</param>
    /// <returns>Containing existence flag</returns>
    Task<bool> HasCNAsync(
        string
        commonName,
        int allowTime,
        X509Certificate2 certificate,
        bool revokeOldCertificate,
        CancellationToken cancellationToken);


    // Init ca_key
    Task<RSA> CreateOrLoadKeyAsync(int bits, CancellationToken cancellationToken);

    Task SaveKeyAsync(RSA key, CancellationToken cancellationToken);

}
