using Microsoft.Extensions.Options;
using SCEP.Net.Services.Abstractions;
using SCEP.Net.Services.Options;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace SCEP.Net.Services;

public class BoltDepot : IDepot
{
    private readonly ISerialNumberGenerator _serialNumberGenerator;
    private readonly IDbAdapter _dbAdapter;

    public BoltDepot(ISerialNumberGenerator serialNumberGenerator, IDbAdapter dbAdapter)
    {
        _serialNumberGenerator = serialNumberGenerator;
        _dbAdapter = dbAdapter;
    }

    public async Task<(X509Certificate2[], RSA)> GetCAAsync(string password, CancellationToken cancellationToken)
    {
        var chain = new List<X509Certificate2>();
        RSA? key = null;

        var caCertBytes = await _dbAdapter.GetValueAsync("ca_certificate", cancellationToken);

        if (caCertBytes == null || caCertBytes.Length == 0)
        {
            throw new InvalidOperationException("No ca_certificate in bucket");
        }

        chain.Add(new X509Certificate2(caCertBytes));

        // Get CA key
        var caKeyBytes = await _dbAdapter.GetValueAsync("ca_key", cancellationToken);

        if (caKeyBytes == null || caKeyBytes.Length == 0)
        {
            throw new InvalidOperationException("No ca_key in bucket");
        }

        key = RSA.Create();
        key.ImportPkcs8PrivateKey(caKeyBytes, out _);

        return (chain.ToArray(), key);
    }

    public async Task PutAsync(string name, X509Certificate2 certificate, CancellationToken cancellationToken)
    {
        if (certificate == null || certificate.RawData == null)
        {
            throw new ArgumentException($"{name} does not specify a valid certificate for storage");
        }

        var fullName = $"{name}.{certificate.SerialNumber}";

        await _dbAdapter.SetValueAsync(fullName, certificate.RawData, cancellationToken);
    }

    public async Task<BigInteger> GetSerialAsync(CancellationToken cancellationToken)
    {
        return await _serialNumberGenerator.GetNextSerialNumberAsync(cancellationToken);
    }

    public async Task<bool> HasCNAsync(
        string commonName,
        int allowTime,
        X509Certificate2 certificate,
        bool revokeOldCertificate,
        CancellationToken cancellationToken)
    {
        return await _dbAdapter.HasCnAsync(commonName, certificate, cancellationToken);
    }

    public async Task InitilizeCaAsync(IOptions<BoltDepotOptions> options, CancellationToken cancellationToken)
    {
        var boltOptions = options.Value;
        using var rsa = RSA.Create();
        rsa.ImportFromPem(boltOptions.CertKey);

        var certificate = GetCertificateFromPem(boltOptions.CertPem);

        await InitilizeCaAsync(rsa, certificate, cancellationToken);
    }

    private async Task InitilizeCaAsync(RSA key, X509Certificate2 certificate2, CancellationToken cancellationToken)
    {
        await _dbAdapter.SetValueAsync("ca_key", key.ExportPkcs8PrivateKey(), cancellationToken);
        await _dbAdapter.SetValueAsync("ca_certificate", certificate2.RawData, cancellationToken);
    }

    private static X509Certificate2 GetCertificateFromPem(string pemString)
    {
        // Удаляем заголовки и подвалы PEM
        string base64 = pemString
            .Replace("-----BEGIN CERTIFICATE-----", "")
            .Replace("-----END CERTIFICATE-----", "")
            .Replace("\n", "")
            .Replace("\r", "")
            .Trim();

        byte[] certData = Convert.FromBase64String(base64);
        return new X509Certificate2(certData);
    }
}