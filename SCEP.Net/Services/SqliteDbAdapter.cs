using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Options;
using SCEP.Net.Services.Abstractions;
using SCEP.Net.Services.Options;
using System.Security.Cryptography.X509Certificates;

namespace SCEP.Net.Services;

public class SqliteDbAdapter : IDbAdapter
{
    private readonly string _connectionString;

    public SqliteDbAdapter(IOptions<SqliteDbAdapterOptions> sqliteDbAdapterOptions)
    {
        SQLitePCL.Batteries.Init();

        _connectionString = sqliteDbAdapterOptions.Value.ConnectionString;
        InitializeDatabase();
    }

    private void InitializeDatabase()
    {
        using var connection = new SqliteConnection(_connectionString);
        connection.Open();

        var command = connection.CreateCommand();
        command.CommandText = @"
            CREATE TABLE IF NOT EXISTS scep_certificates (
                key TEXT PRIMARY KEY,
                value BLOB
            )";

        command.ExecuteNonQuery();
    }

    public async Task<byte[]?> GetValueAsync(string key, CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(key))
            throw new ArgumentException("Key cannot be null or empty", nameof(key));

        using var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync(cancellationToken);

        var command = connection.CreateCommand();
        command.CommandText = "SELECT value FROM scep_certificates WHERE key = @key";
        command.Parameters.AddWithValue("@key", key);

        using var reader = await command.ExecuteReaderAsync(cancellationToken);

        if (await reader.ReadAsync(cancellationToken))
        {
            if (!reader.IsDBNull(0))
            {
                return (byte[])reader["value"];
            }
        }

        return null;
    }

    public async Task SetValueAsync(string key, byte[] value, CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(key))
            throw new ArgumentException("Key cannot be null or empty", nameof(key));

        using var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync(cancellationToken);

        var command = connection.CreateCommand();
        command.CommandText = @"
            INSERT OR REPLACE INTO scep_certificates (key, value) 
            VALUES (@key, @value)";

        command.Parameters.AddWithValue("@key", key);
        command.Parameters.AddWithValue("@value", value ?? (object)DBNull.Value);

        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task<bool> HasCnAsync(
        string commonName,
        X509Certificate2 certificate,
        CancellationToken cancellationToken)
    {
        if (certificate == null)
        {
            throw new ArgumentNullException(nameof(certificate));
        }

        bool hasCN = false;
        using var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync(cancellationToken);
        var command = connection.CreateCommand();
        command.CommandText = $@"
            SELECT value FROM scep_certificates 
            WHERE key LIKE @prefix || '%'
        ";
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
}
