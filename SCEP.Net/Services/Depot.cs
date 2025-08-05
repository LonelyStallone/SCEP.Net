using Microsoft.Data.Sqlite;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace SCEP.Net.Services;

public class BoltDepot : IDepot, IDisposable
{
    private readonly SqliteConnection _db;
    private readonly SemaphoreSlim _serialLock = new(1, 1);
    private const string CertBucket = "scep_certificates";

    public BoltDepot(string dbPath)
    {
        _db = new SqliteConnection($"Data Source={dbPath}");
        _db.Open();

        InitializeDatabase();
    }

    private void InitializeDatabase()
    {
        using var command = _db.CreateCommand();
        command.CommandText = $@"
            CREATE TABLE IF NOT EXISTS {CertBucket} (
                key TEXT PRIMARY KEY,
                value BLOB
            )";
        command.ExecuteNonQuery();
    }

    public async Task<(X509Certificate2[], RSA)> GetCAAsync(string password, CancellationToken cancellationToken)
    {
        var chain = new List<X509Certificate2>();
        RSA? key = null;

        using var command = _db.CreateCommand();
        command.CommandText = $"SELECT value FROM {CertBucket} WHERE key = @key";

        // Get CA certificate
        command.Parameters.AddWithValue("@key", "ca_certificate");
        var caCertBytes = (byte[]?)await command.ExecuteScalarAsync(cancellationToken);

        if (caCertBytes == null || caCertBytes.Length == 0)
        {
            throw new InvalidOperationException("No ca_certificate in bucket");
        }

        chain.Add(new X509Certificate2(caCertBytes));

        // Get CA key
        command.Parameters.Clear();
        command.Parameters.AddWithValue("@key", "ca_key");
        var caKeyBytes = (byte[]?)await command.ExecuteScalarAsync(cancellationToken);

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

        using var command = _db.CreateCommand();
        command.CommandText = $@"
            INSERT OR REPLACE INTO {CertBucket} (key, value)
            VALUES (@key, @value)";

        command.Parameters.AddWithValue("@key", fullName);
        command.Parameters.AddWithValue("@value", certificate.RawData);

        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task<BigInteger> GetSerialAsync(CancellationToken cancellationToken)
    {
        await _serialLock.WaitAsync(cancellationToken);
        try
        {
            var serial = await ReadSerialAsync(cancellationToken);
            await IncrementSerialAsync(serial, cancellationToken);
            return serial;
        }
        finally
        {
            _serialLock.Release();
        }
    }

    private async Task<BigInteger> ReadSerialAsync(CancellationToken cancellationToken)
    {
        if (!await HasKeyAsync("serial", cancellationToken))
        {
            var initialSerial = new BigInteger(2);
            await WriteSerialAsync(initialSerial, cancellationToken);
            return initialSerial;
        }

        using var command = _db.CreateCommand();
        command.CommandText = $"SELECT value FROM {CertBucket} WHERE key = @key";
        command.Parameters.AddWithValue("@key", "serial");

        var serialBytes = (byte[]?)await command.ExecuteScalarAsync(cancellationToken);
        if (serialBytes == null || serialBytes.Length == 0)
        {
            throw new InvalidOperationException("Serial key not found");
        }

        return new BigInteger(serialBytes);
    }

    private async Task<bool> HasKeyAsync(string key, CancellationToken cancellationToken)
    {
        using var command = _db.CreateCommand();
        command.CommandText = $"SELECT 1 FROM {CertBucket} WHERE key = @key LIMIT 1";
        command.Parameters.AddWithValue("@key", key);

        var result = await command.ExecuteScalarAsync(cancellationToken);
        return result != null;
    }

    private async Task WriteSerialAsync(BigInteger serial, CancellationToken cancellationToken)
    {
        using var command = _db.CreateCommand();
        command.CommandText = $@"
            INSERT OR REPLACE INTO {CertBucket} (key, value)
            VALUES (@key, @value)";

        command.Parameters.AddWithValue("@key", "serial");
        command.Parameters.AddWithValue("@value", serial.ToByteArray());

        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private async Task IncrementSerialAsync(BigInteger current, CancellationToken cancellationToken)
    {
        var newSerial = current + BigInteger.One;
        await WriteSerialAsync(newSerial, cancellationToken);
    }

    public async Task<bool> HasCNAsync(
        string commonName,
        int allowTime,
        X509Certificate2 certificate,
        bool revokeOldCertificate,
        CancellationToken cancellationToken)
    {
        if (certificate == null)
        {
            throw new ArgumentNullException(nameof(certificate));
        }

        bool hasCN = false;

        using var command = _db.CreateCommand();
        command.CommandText = $@"
            SELECT value FROM {CertBucket} 
            WHERE key LIKE @prefix || '%'";

        command.Parameters.AddWithValue("@prefix", commonName);

        using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            var certBytes = (byte[])reader["value"];
            if (certBytes.SequenceEqual(certificate.RawData))
            {
                hasCN = true;
                break;
            }
        }

        return hasCN;
    }

    public async Task<RSA> CreateOrLoadKeyAsync(int bits, CancellationToken cancellationToken)
    {
        using var command = _db.CreateCommand();
        command.CommandText = $"SELECT value FROM {CertBucket} WHERE key = @key";
        command.Parameters.AddWithValue("@key", "ca_key");

        var keyBytes = (byte[]?)await command.ExecuteScalarAsync(cancellationToken);

        if (keyBytes != null && keyBytes.Length > 0)
        {
            var key = RSA.Create();
            key.ImportPkcs8PrivateKey(keyBytes, out _);
            return key;
        }

        var newKey = RSA.Create(bits);
        var pkcs8 = newKey.ExportPkcs8PrivateKey();

        using var insertCommand = _db.CreateCommand();
        insertCommand.CommandText = $@"
            INSERT INTO {CertBucket} (key, value)
            VALUES (@key, @value)";

        insertCommand.Parameters.AddWithValue("@key", "ca_key");
        insertCommand.Parameters.AddWithValue("@value", pkcs8);

        await insertCommand.ExecuteNonQueryAsync(cancellationToken);

        return newKey;
    }

    public async Task<X509Certificate2> CreateOrLoadCAAsync(
        RSA key,
        int years,
        string org,
        string country,
        CancellationToken cancellationToken)
    {
        using var command = _db.CreateCommand();
        command.CommandText = $"SELECT value FROM {CertBucket} WHERE key = @key";
        command.Parameters.AddWithValue("@key", "ca_certificate");

        var certBytes = (byte[]?)await command.ExecuteScalarAsync(cancellationToken);

        if (certBytes != null && certBytes.Length > 0)
        {
            return new X509Certificate2(certBytes);
        }

        // Create new CA certificate
        var subject = new X500DistinguishedName(
            $"CN=SCEP CA, O={org}, OU=MICROMDM SCEP CA, C={country}");

        var request = new CertificateRequest(
            subject,
            key,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        request.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(true, false, 0, true));

        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign,
                true));

        var notBefore = DateTimeOffset.UtcNow;
        var notAfter = notBefore.AddYears(years);

        var serial = new byte[16];
        RandomNumberGenerator.Fill(serial);

        using var caCert = request.CreateSelfSigned(notBefore, notAfter);
        var rawData = caCert.Export(X509ContentType.Cert);

        using var insertCommand = _db.CreateCommand();
        insertCommand.CommandText = $@"
            INSERT INTO {CertBucket} (key, value)
            VALUES (@key, @value)";

        insertCommand.Parameters.AddWithValue("@key", "ca_certificate");
        insertCommand.Parameters.AddWithValue("@value", rawData);

        await insertCommand.ExecuteNonQueryAsync(cancellationToken);

        return new X509Certificate2(rawData);
    }

    public void Dispose()
    {
        _serialLock.Dispose();
        _db.Dispose();
    }
}