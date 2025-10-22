using System.Security.Cryptography.X509Certificates;
using SCEP.Net.Services.Abstractions;
using SCEP.Net.Services.Enums;
using SCEP.Net.Services.Helpers;

public class ScepService : IScepService
{
    private readonly ISerialNumberGenerator _serialNumberGenerator;
    private readonly ICaCertificatesStorage _caCertificatesStorage;
    private readonly ICsrSigner _csrSigner;
    private readonly ILogger _logger;
     
    public ScepService(
        ISerialNumberGenerator serialNumberGenerator,
        ICaCertificatesStorage caCertificatesStorage,
        ICsrSigner csrSigner,
        ILogger<ScepService> logger)
    {
        _serialNumberGenerator = serialNumberGenerator;
        _caCertificatesStorage = caCertificatesStorage;
        _csrSigner = csrSigner;
        _logger = logger;
    }

    public byte[] GetCaCaps()
    {
        _logger.LogInformation($"GetCaCert.");

        var defaultCaps = "Renewal\nSHA-1\nSHA-256\nAES\nDES3\nSCEPStandard\nPOSTPKIOperation";
        return System.Text.Encoding.UTF8.GetBytes(defaultCaps);
    }

    public (byte[] Data, int CertificatesCount) GetCaCert(string message)
    {
        _logger.LogInformation($"GetCaCert: {message}");

        var degenerateCerts = GetDegenerateCertificates();

        return (degenerateCerts, _caCertificatesStorage.AdditionalCertificates.Count + 1);
    }

    public async Task<byte[]> PkiOperationAsync(byte[] data, CancellationToken cancellationToken)
    {
        _logger.LogInformation($"PkiOperation: {Convert.ToBase64String(data)}");
        var msg = PKIMessage.Parse(data);
        try
        {
            msg.DecryptPKIEnvelope(_caCertificatesStorage.Certificate, _caCertificatesStorage.PrivateKey);
            var serial = await _serialNumberGenerator.GetNextSerialNumberAsync(cancellationToken);


            var signedCertificate = await _csrSigner.SignCsrAsync(
                _caCertificatesStorage.Certificate,
                _caCertificatesStorage.PrivateKey,
                msg.CsrReqMessage.Csr,
                serial,
                cancellationToken);


            if (signedCertificate == null)
            {
                throw new InvalidOperationException("No signed certificate");
            }

            var certRep = msg.CreateSuccessResponse(
                _caCertificatesStorage.Certificate,
                _caCertificatesStorage.PrivateKey,
                signedCertificate);

            return certRep.Raw;
        }
        catch (Exception ex)
        {
            _logger.LogError($"Failed to sign CSR: {ex}");

            var certRep = msg.CreateFailResponse(PkiFailInfo.BadRequest);

            return certRep.Raw;
        }
    }

    private byte[] GetDegenerateCertificates()
    {
        if (_caCertificatesStorage.AdditionalCertificates.Count < 1)
        {
            return _caCertificatesStorage.Certificate.RawData;
        }

        var certificates = new List<X509Certificate2> { _caCertificatesStorage.Certificate };
        certificates.AddRange(_caCertificatesStorage.AdditionalCertificates);

        return PkcsHelper.DegenerateCertificates(certificates);
    }

    public Task<byte[]> GetNextCaCertAsync(CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }
}