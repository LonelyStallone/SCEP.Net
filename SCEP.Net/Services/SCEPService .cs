using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SCEP.Net.Services.Abstractions;
using SCEP.Net.Services.Enums;

public class SCEPService : ISCEPService
{
    private readonly X509Certificate2 _caCertificate;
    private readonly RSA _privateKey;
    private readonly List<X509Certificate2> _additionalCaCerts;
    private readonly ICSRSigner _csrSigner;
    private readonly ILogger _logger;
     
    public SCEPService(
        X509Certificate2 caCertificate,
        RSA privateKey,
        ICSRSigner csrSigner,
        ILogger<SCEPService> logger,
        List<X509Certificate2> additionalCaCerts)
    {
        _caCertificate = caCertificate;
        _privateKey = privateKey;
        _csrSigner = csrSigner;
        _logger = logger;
        _additionalCaCerts = additionalCaCerts;
    }

    public Task<byte[]> GetCACapsAsync(CancellationToken cancellationToken)
    {
        var defaultCaps = "Renewal\nSHA-1\nSHA-256\nAES\nDES3\nSCEPStandard\nPOSTPKIOperation";
        return Task.FromResult(System.Text.Encoding.UTF8.GetBytes(defaultCaps));
    }

    public Task<(byte[] data, int certNum)> GetCACertAsync(string message, CancellationToken cancellationToken)
    {
        if (_caCertificate == null)
        {
            throw new InvalidOperationException("Missing CA certificate");
        }

        if (_additionalCaCerts.Count < 1)
        {
            return Task.FromResult((_caCertificate.RawData, 1));
        }

        var certs = new List<X509Certificate2> { _caCertificate };
        certs.AddRange(_additionalCaCerts);

        var degenerateCerts = PKIMessage.DegenerateCertificates(certs);
        return Task.FromResult((degenerateCerts, certs.Count));
    }

    public async Task<byte[]> PKIOperationAsync(byte[] data, CancellationToken cancellationToken)
    {
        var msg = PKIMessage.Parse(data);
        try
        {
            msg.DecryptPKIEnvelope(_caCertificate, _privateKey);

            var signedCertificate = await _csrSigner.SignCSRAsync(msg.CSRReqMessage, cancellationToken);
            if (signedCertificate == null)
            {
                throw new InvalidOperationException("No signed certificate");
            }

            // Здесь должна быть реализация Success метода для создания CertRep
            // Это упрощенная версия - в реальности нужно создать соответствующий PKIMessage
            var certRep = msg.CreateSuccessResponse(_caCertificate, _privateKey, signedCertificate);
            return certRep.Raw;
        }
        catch (Exception ex)
        {
            _logger.LogError($"Failed to sign CSR: {ex}");

            // Здесь должна быть реализация Fail метода для создания CertRep с ошибкой
            // Это упрощенная версия - в реальности нужно создать соответствующий PKIMessage
            var certRep = msg.CreateFailResponse(PKIFailInfo.BadRequest);

            return certRep.Raw;
        }
    }

    public Task<byte[]> GetNextCACertAsync(CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }
}