using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using Microsoft.Data.Sqlite;

namespace SCEP.Net.Tests.Utils;
internal class DepotHelper
{
    public async Task<X509Certificate2> CreateOrLoadCAAsync(
        SqliteConnection sqliteConnection,
        RSA key,
        int years,
        string org,
        string country,
        CancellationToken cancellationToken)
    {
        using var command = sqliteConnection.CreateCommand();
        command.CommandText = $"SELECT value FROM scep_certificates WHERE key = @key";
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

        using var insertCommand = sqliteConnection.CreateCommand();
        insertCommand.CommandText = $@"
            INSERT INTO scep_certificates (key, value)
            VALUES (@key, @value)";

        insertCommand.Parameters.AddWithValue("@key", "ca_certificate");
        insertCommand.Parameters.AddWithValue("@value", rawData);

        await insertCommand.ExecuteNonQueryAsync(cancellationToken);

        return new X509Certificate2(rawData);
    }
}
