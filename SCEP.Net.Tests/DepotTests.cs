using AutoFixture;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using Org.BouncyCastle.Pkcs;
using SCEP.Net.Services;
using SCEP.Net.Services.Enums;
using SCEP.Net.Services.Options;
using SCEP.Net.Tests.Utils;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

namespace SCEP.Net.Tests;

public class DebugTests
{
    private readonly Fixture _fixture = new();

    private readonly SqliteDbAdapterOptions _sqliteDbAdapterOptions;
    private readonly SqliteDbAdapter _adapter;

    private readonly SerialNumberGenerator _serialNumberGenerator;

    private readonly BoltDepot _boltDepot;

    private readonly CsrSignerOptions _csrSignerOptions;
    private readonly CsrSigner _csrSigner;

    private readonly CaCertificatesOptions _caCertificatesOptions;
    private readonly CaCertificatesStorage _caCertificatesStorage;

    private readonly ScepService _scepService;

    public DebugTests()
    {
        var path = _fixture.Create<string>() + "_test.db";

        _sqliteDbAdapterOptions = new SqliteDbAdapterOptions
        {
            ConnectionString = $"Data Source={path}.db"
        };

        _adapter = new SqliteDbAdapter(new OptionsWrapper<SqliteDbAdapterOptions>(_sqliteDbAdapterOptions));

        _serialNumberGenerator = new SerialNumberGenerator(_adapter);

        _boltDepot = new BoltDepot(_serialNumberGenerator, _adapter);

        _csrSignerOptions = new CsrSignerOptions
        {
            AllowRenewalDays = 14,
            ValidityDays = 365
        };

        _csrSigner = new CsrSigner(_boltDepot, (new OptionsWrapper<CsrSignerOptions>(_csrSignerOptions)));

        _caCertificatesOptions = DataGenerator.CreateCaCertificatesOptions(5, "MicroMDM", "US");
        _caCertificatesStorage = new CaCertificatesStorage(new OptionsWrapper<CaCertificatesOptions>(_caCertificatesOptions));

        _scepService = new ScepService(
           _serialNumberGenerator,
           _caCertificatesStorage,
           _csrSigner,
            new Mock<ILogger<ScepService>>().Object);
    }

    [Fact]
    public async Task GetCACertAsync_ShouldReturnCa_WhenCalled()
    {
        // Arrange     
        var options = new JsonSerializerOptions
        {
            WriteIndented = true, // Включение отступов
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase // Опционально: camelCase для свойств
        };

        var json = JsonSerializer.Serialize(_caCertificatesOptions, options);
        File.WriteAllText("ca.json", json);

        var selfKey = RSA.Create(2048);
        var csr = CsrBuilder.GenerateCSR(selfKey, "ou", "loc", "province", "RU", "cname", "org");
        var signerCert = X509Certificate2Builder.SelfSign(selfKey, csr);
        
        var rootStore = new X509Certificate2Collection();
        rootStore.Add(_caCertificatesStorage.Certificate);
        
        var serCollector = new List<byte[]>();
        
        for (int i = 0; i < 5; i++)
        {
            // check CA
            var (caBytes, num) = _scepService.GetCaCert(_fixture.Create<string>());
        
            // create scep "client" request
            var tmpl = new PKIMessage
            {
                MessageType = PkiMessageType.PKCSReq,
                Recipients = new[] { _caCertificatesStorage.Certificate }.ToList(),
                SignerKey = selfKey,
                SignerCert = signerCert,
            };
        
        
            var message = PKIMessage.NewCSRRequest(csr, tmpl);
        
            // submit to service
            var respMsgBytes = await _scepService.PkiOperationAsync(message.Raw, CancellationToken.None);
        
            // read and decrypt reply
            var respMsg = PKIMessage.Parse(respMsgBytes);
            respMsg.DecryptPKIEnvelope(signerCert, selfKey);
        
            // verify issued certificate is from the CA
            VerifyCertificateResponse(
                respMsg.CertRepMessage.Certificate,
                rootStore,
                csr,
                ref serCollector);
        }
    }

    private void VerifyCertificateResponse(
        X509Certificate2 respCert,
        X509Certificate2Collection roots,
        Pkcs10CertificationRequest csr,
        ref List<byte[]> serialCollector)
    {
        if (respCert == null)
            throw new ArgumentNullException(nameof(respCert));
        if (roots == null)
            throw new ArgumentNullException(nameof(roots));
        if (csr == null)
            throw new ArgumentNullException(nameof(csr));
        if (serialCollector == null)
            throw new ArgumentNullException(nameof(serialCollector));

        // Verify certificate chain
        var chain = new X509Chain
        {
            ChainPolicy = new X509ChainPolicy
            {
                RevocationMode = X509RevocationMode.NoCheck,
                VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority,
            }
        };

        // Add roots to the chain policy
        foreach (X509Certificate2 root in roots)
        {
            chain.ChainPolicy.ExtraStore.Add(root);
        }

        bool chainValid = chain.Build(respCert);

        if (!chainValid)
        {
            throw new Exception($"Certificate chain verification failed: {GetChainErrors(chain)}");
        }

        if (chain.ChainElements.Count < 1)
        {
            throw new Exception("No established chain between issued cert and CA");
        }

        // Verify signature algorithm matches CSR
        string csrAlgOid = csr.SignatureAlgorithm.Algorithm.Id;
        string certAlgOid = respCert.SignatureAlgorithm.Value;

        if (csrAlgOid != certAlgOid)
        {
            throw new Exception($"Cert signature algo {certAlgOid} ({GetAlgorithmName(certAlgOid)}) " +
                               $"different from csr signature algo {csrAlgOid} ({GetAlgorithmName(csrAlgOid)})");
        }

        // Verify unique certificate serials
        byte[] respSerial = respCert.GetSerialNumber();
        Array.Reverse(respSerial); // Convert from little-endian to big-endian for comparison

        foreach (byte[] serial in serialCollector)
        {
            if (SerialNumbersEqual(serial, respSerial))
            {
                throw new Exception("Seen serial number before!");
            }
        }

        serialCollector.Add(respSerial);
    }

    // Helper method to get chain errors
    private string GetChainErrors(X509Chain chain)
    {
        var errors = new List<string>();
        foreach (X509ChainStatus status in chain.ChainStatus)
        {
            if (status.Status != X509ChainStatusFlags.NoError)
            {
                errors.Add($"{status.Status}: {status.StatusInformation}");
            }
        }
        return string.Join("; ", errors);
    }

    // Helper method to compare serial numbers
    private bool SerialNumbersEqual(byte[] serial1, byte[] serial2)
    {
        if (serial1 == null || serial2 == null)
            return false;
        if (serial1.Length != serial2.Length)
            return false;

        for (int i = 0; i < serial1.Length; i++)
        {
            if (serial1[i] != serial2[i])
                return false;
        }
        return true;
    }

    // Helper method to get algorithm name from OID
    private string GetAlgorithmName(string oid)
    {
        return oid switch
        {
            "1.2.840.113549.1.1.11" => "sha256WithRSAEncryption",
            "1.2.840.113549.1.1.12" => "sha384WithRSAEncryption",
            "1.2.840.113549.1.1.13" => "sha512WithRSAEncryption",
            "1.2.840.113549.1.1.5" => "sha1WithRSAEncryption",
            "1.2.840.10045.4.3.2" => "ecdsa-with-SHA256",
            "1.2.840.10045.4.3.3" => "ecdsa-with-SHA384",
            "1.2.840.10045.4.3.4" => "ecdsa-with-SHA512",
            "1.2.840.10040.4.3" => "dsaWithSHA1",
            _ => oid
        };
    }
}