using AutoFixture;
using Microsoft.AspNetCore.Mvc.ModelBinding.Validation;
using Microsoft.Extensions.Logging;
using Moq;
using Org.BouncyCastle.Pkcs;
using SCEP.Net.Services;
using SCEP.Net.Services.PKI.Enums;
using SCEP.Net.Services.Singer;
using SCEP.Net.Tests.Utils;
using Shouldly;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace SCEP.Net.Tests;

public class DebugTests
{
    private readonly Fixture _fixture = new();

    private readonly BoltDepot _boltDepot;

    private readonly CSRSignerOptions _cSRSignerOptions;

    public DebugTests()
    {
        var path = _fixture.Create<string>() + "_test.db";
        _boltDepot = new BoltDepot(path);

        _cSRSignerOptions = new CSRSignerOptions
        {
            AllowRenewalDays = 14,
            ValidityDays = 365
        };

    }

    [Fact]
    public async Task GetCACertAsync5_ShouldReturnCa_WhenCalled()
    {
        // Arrange
        var keySize = 2048;
        var key = await _boltDepot.CreateOrLoadKeyAsync(keySize, CancellationToken.None);
        var ca = await _boltDepot.CreateOrLoadCAAsync(key, 5, "MicroMDM", "US", CancellationToken.None);
        var (certsFromDepot, keyFromDepot) = await _boltDepot.GetCAAsync(_fixture.Create<string>(), CancellationToken.None);

        var caCertificat = certsFromDepot.Single();
        var privateKey = keyFromDepot;
        var csrSigner = new CSRSigner(_boltDepot, _cSRSignerOptions);
        var logger = new Mock<ILogger<SCEPService>>().Object;

        var scepService = new SCEPService(
           caCertificat,
           privateKey,
           csrSigner,
           logger,
           Array.Empty<X509Certificate2>().ToList());

        var selfKey = RSA.Create(keySize);
        var csr = CsrBuilder.GenerateCSR(selfKey, "ou", "loc", "province", "RU", "cname", "org");
        var signerCert = X509Certificate2Builder.SelfSign(selfKey, csr);

        var rootStore = new X509Certificate2Collection();
        rootStore.Add(ca);

        var serCollector = new List<byte[]>();

        for (int i = 0; i < 5; i++)
        {
            // check CA
            var (caBytes, num) = await scepService.GetCACertAsync(_fixture.Create<string>(), CancellationToken.None);

            // create scep "client" request
            var tmpl = new PKIMessage
            {
                MessageType = PKIMessageType.PKCSReq,
                Recipients = new[] { caCertificat }.ToList(),
                SignerKey = selfKey,
                SignerCert = signerCert,
            };


            var message = PKIMessage.NewCSRRequest(csr, tmpl);

            // submit to service
            var respMsgBytes = await scepService.PKIOperationAsync(message.Raw, CancellationToken.None);

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