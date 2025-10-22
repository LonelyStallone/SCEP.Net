using Microsoft.Extensions.Options;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using SCEP.Net.Services.Abstractions;
using SCEP.Net.Services.Enums;
using SCEP.Net.Services.Options;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace SCEP.Net.Services;

public class CsrSigner : ICsrSigner
{
    private readonly IDepot _depot;
    private readonly int _allowRenewalDays;
    private readonly int _validityDays;
    private readonly bool _serverAttrs;
    private readonly SignatureAlgorithm _signatureAlgorithm;

    public CsrSigner(IDepot depot, IOptions<CsrSignerOptions> options)
    {
        _depot = depot;
        _allowRenewalDays = options.Value.AllowRenewalDays;
        _validityDays = options.Value.ValidityDays;
        _serverAttrs = options.Value.ServerAttrs;
        _signatureAlgorithm = options.Value.SignatureAlgorithm;
    }

    public async Task<X509Certificate2> SignCsrAsync(
        X509Certificate2 caCertificate,
        RSA caKey,
        Pkcs10CertificationRequest csr,
        System.Numerics.BigInteger serialNumber,
        CancellationToken cancellationToken)
    {
        // Generate subject key ID
        var subjectKeyId = GenerateSubjectKeyId(csr.GetPublicKey());

        // Get CA cert and key
        var caBouncyCert = DotNetUtilities.FromX509Certificate(caCertificate);
        var caPrivateKey = DotNetUtilities.GetRsaKeyPair(caKey).Private;

        // Create certificate generator
        var certificateGenerator = new X509V3CertificateGenerator();

        // Set certificate fields
        certificateGenerator.SetSerialNumber(new BigInteger(serialNumber.ToByteArray()));
        certificateGenerator.SetIssuerDN(caBouncyCert.SubjectDN);
        certificateGenerator.SetSubjectDN(csr.GetCertificationRequestInfo().Subject);
        certificateGenerator.SetPublicKey(csr.GetPublicKey());

        // Set validity period
        var now = DateTime.UtcNow;
        var notBefore = now.AddMinutes(-10); // Allow 10 minutes clock skew
        var notAfter = now.AddDays(_validityDays);
        certificateGenerator.SetNotBefore(notBefore);
        certificateGenerator.SetNotAfter(notAfter);

        // Add extensions
        certificateGenerator.AddExtension(
            X509Extensions.SubjectKeyIdentifier,
            false,
            new SubjectKeyIdentifier(subjectKeyId));

        certificateGenerator.AddExtension(
            X509Extensions.BasicConstraints,
            true,
            new BasicConstraints(false));

        // Set key usage
        var keyUsage = KeyUsage.DigitalSignature;
        if (_serverAttrs)
        {
            keyUsage |= KeyUsage.KeyEncipherment | KeyUsage.DataEncipherment;
        }
        certificateGenerator.AddExtension(
            X509Extensions.KeyUsage,
            true,
            new KeyUsage(keyUsage));

        // Set extended key usage
        var extKeyUsages = new List<DerObjectIdentifier>
        {
            X509Extensions.ExtendedKeyUsage,
            new DerObjectIdentifier("1.3.6.1.5.5.7.3.2") // Client Auth
        };
        if (_serverAttrs)
        {
            extKeyUsages.Add(new DerObjectIdentifier("1.3.6.1.5.5.7.3.1")); // Server Auth
        }
        certificateGenerator.AddExtension(
            X509Extensions.ExtendedKeyUsage,
            false,
            new ExtendedKeyUsage(extKeyUsages));

        // Create signature factory
        var signatureFactory = CreateSignatureFactory(caBouncyCert, caPrivateKey);

        // Generate certificate
        var bouncyCert = certificateGenerator.Generate(signatureFactory);

        // Convert to X509Certificate2
        var signedCert = new X509Certificate2(DotNetUtilities.ToX509Certificate(bouncyCert));

        // Check if certificate already exists and needs revocation
        var certName = GetCertName(signedCert);
        var existingCert = await _depot.HasCNAsync(
            certName,
            _allowRenewalDays,
            signedCert,
            false,
            cancellationToken);

        if (existingCert)
        {
            // TODO: Optionally handle revocation here
        }

        // Store the new certificate
        await _depot.PutAsync(certName, signedCert, cancellationToken);

        return signedCert;
    }

    private byte[] GenerateSubjectKeyId(AsymmetricKeyParameter publicKey)
    {
        var subjectPublicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(publicKey);
        var sha1 = DigestUtilities.CalculateDigest("SHA-1", subjectPublicKeyInfo.GetEncoded());
        return sha1;
    }

    private string GetCertName(X509Certificate2 cert)
    {
        if (!string.IsNullOrEmpty(cert.SubjectName.Name))
        {
            return cert.SubjectName.Name;
        }

        return Convert.ToBase64String(cert.GetCertHash());
    }

    private ISignatureFactory CreateSignatureFactory(X509Certificate caBouncyCert, AsymmetricKeyParameter caPrivateKey)
    {

        // Create signature factory
        if (_signatureAlgorithm != SignatureAlgorithm.Unknown)
        {
            return new Asn1SignatureFactory(
                _signatureAlgorithm.ToString(),
                caPrivateKey);
        }
        else
        {
            return new Asn1SignatureFactory(
                caBouncyCert.SigAlgName,
                caPrivateKey);
        }
    }
}