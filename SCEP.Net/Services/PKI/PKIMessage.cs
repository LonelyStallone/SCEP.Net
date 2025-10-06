using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.X509;
using SCEP.Net.Models;
using SCEP.Net.Services.Helpers;
using SCEP.Net.Services.PKI;
using SCEP.Net.Services.PKI.Enums;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;

public class PKIMessage
{
    public string TransactionID { get; set; }
    public PKIMessageType MessageType { get; set; }
    public byte[] SenderNonce { get; set; }
    public CertRepMessage CertRepMessage { get; set; }
    public CSRReqMessage CSRReqMessage { get; set; }
    public byte[] Raw { get; set; }
    public SignedCms P7 { get; set; }
    public byte[] PkiEnvelope { get; set; }
    public List<X509Certificate2> Recipients { get; set; }
    public RSA SignerKey { get; set; }
    public X509Certificate2 SignerCert { get; set; }

    // SCEP OIDs
    private static readonly string oidSCEPmessageType = "2.16.840.1.113733.1.9.2";
    private static readonly string oidSCEPpkiStatus = "2.16.840.1.113733.1.9.3";
    private static readonly string oidSCEPfailInfo = "2.16.840.1.113733.1.9.4";
    private static readonly string oidSCEPsenderNonce = "2.16.840.1.113733.1.9.5";
    private static readonly string oidSCEPrecipientNonce = "2.16.840.1.113733.1.9.6";
    private static readonly string oidSCEPtransactionID = "2.16.840.1.113733.1.9.7";

    public static PKIMessage Parse(byte[] data, List<X509Certificate2> caCerts = null)
    {
        var p7 = new SignedCms();
        p7.Decode(data);

        if (caCerts != null && caCerts.Count > 0)
        {
            // In .NET, certificate verification is typically done separately
            // We would need to implement proper verification here
        }

        var msg = new PKIMessage
        {
            Raw = data,
            P7 = p7,
            Recipients = new List<X509Certificate2>()
        };

        // Extract attributes from the SignedCms
        foreach (var signer in p7.SignerInfos)
        {
            foreach (var attribute in signer.SignedAttributes)
            {
                switch (attribute.Oid.Value)
                {
                    case var oid when oid == oidSCEPtransactionID:
                        msg.TransactionID = Asn1Helper.DecodePrintableString(attribute.Values[0].RawData);
                        break;
                    case var oid when oid == oidSCEPmessageType:
                        var type = (PKIMessageType)Asn1Helper.DecodeInteger(attribute.Values[0].RawData);
                        msg.MessageType = type;
                        break;
                    case var oid when oid == oidSCEPsenderNonce:
                        msg.SenderNonce = Asn1Helper.DecodeOctetString(attribute.Values[0].RawData);
                        break;
                }
            }
        }

        msg.ParseMessageType();
        return msg;
    }

    private void ParseMessageType()
    {
        switch (MessageType)
        {
            case PKIMessageType.CertRep:
                var status = PKIStatus.Success; // Would extract from attributes
                var rn = new byte[0]; // Would extract recipient nonce

                CertRepMessage = new CertRepMessage
                {
                    PKIStatus = status,
                    RecipientNonce = rn
                };

                if (status == PKIStatus.Failure)
                {
                    // Extract failInfo
                    CertRepMessage.FailInfo = PKIFailInfo.BadRequest;
                }
                break;

            case PKIMessageType.PKCSReq:
            case PKIMessageType.UpdateReq:
            case PKIMessageType.RenewalReq:
                if (SenderNonce == null || SenderNonce.Length == 0)
                {
                    throw new Exception("scep: pkiMessage must include senderNonce attribute");
                }
                break;

            default:
                throw new NotImplementedException("Message type not implemented");
        }
    }

    public void DecryptPKIEnvelope(X509Certificate2 cert, RSA key)
    {
        if (cert == null) throw new ArgumentNullException(nameof(cert));
        if (key == null) throw new ArgumentNullException(nameof(key));
        if (P7 == null) throw new InvalidOperationException("PKCS#7 message not initialized");

        try
        {
            // Decode the enveloped content
            var env = new EnvelopedCms();
            env.Decode(P7.ContentInfo.Content);

            // Find the recipient info that matches our certificate
            RecipientInfo recipientInfo = FindRecipientInfo(env.RecipientInfos, cert);

            if (recipientInfo == null)
            {
                throw new CryptographicException("No matching recipient found for the provided certificate");
            }

            // Decrypt the content
            env.Decrypt(recipientInfo, key);
            PkiEnvelope = env.ContentInfo.Content;

            // Process the decrypted content based on message type
            switch (MessageType)
            {
                case PKIMessageType.CertRep:
                    var certs = CACerts(PkiEnvelope);
                    if (certs == null || certs.Count == 0)
                    {
                        throw new CryptographicException("No certificates found in CertRep message");
                    }
                    CertRepMessage.Certificate = certs[0];
                    break;

                case PKIMessageType.PKCSReq:
                case PKIMessageType.UpdateReq:
                case PKIMessageType.RenewalReq:
                    try
                    {
                        var csr = new Pkcs10CertificationRequest(PkiEnvelope);
                        if (!csr.Verify())
                        {
                            throw new CryptographicException("Invalid CSR signature");
                        }

                        // Extract challenge password if present
                        var cp = ChallengePasswordExtractor.ExtractChallengePassword(PkiEnvelope);

                        CSRReqMessage = new CSRReqMessage
                        {
                            RawDecrypted = PkiEnvelope,
                            CSR = csr,
                            ChallengePassword = cp
                        };
                    }
                    catch (Exception ex)
                    {
                        throw new CryptographicException("Failed to parse CSR", ex);
                    }
                    break;

                default:
                    throw new NotSupportedException($"Message type {MessageType} not supported for decryption");
            }
        }
        catch (CryptographicException ex)
        {
            throw new CryptographicException("Failed to decrypt PKI envelope", ex);
        }
    }


    public static byte[] DegenerateCertificates(List<X509Certificate2> certs)
    {
        var collection = new X509Certificate2Collection();
        collection.AddRange(certs.ToArray());

        // Прямое создание PKCS#7 дегенерированной структуры
        return collection.Export(X509ContentType.Pkcs7);
    }

    public static List<X509Certificate2> CACerts(byte[] data)
    {
        var cms = new SignedCms();
        cms.Decode(data);
        return cms.Certificates.OfType<X509Certificate2>().ToList();
    }

    public static PKIMessage NewCSRRequest(Pkcs10CertificationRequest csr, PKIMessage tmpl, Func<List<X509Certificate2>, List<X509Certificate2>> certsSelector = null)
    {
        certsSelector ??= (certs) => certs;

        var recipients = certsSelector(tmpl.Recipients);
        if (recipients.Count < 1)
        {
            throw new Exception("scep: no CA/RA recipients");
        }

        var recipientInfos = new CmsRecipientCollection(
            SubjectIdentifierType.IssuerAndSerialNumber,
            new X509Certificate2Collection(recipients.ToArray()));

        var env = new EnvelopedCms(new ContentInfo(csr.GetEncoded()));

        env.Encrypt(recipientInfos);
        var e7 = env.Encode();
        var tID = NewTransactionID(csr.GetPublicKey());
        var sn = NewNonce();

        var signedData = new SignedCms(new ContentInfo(e7));
        var signer = new CmsSigner(SubjectIdentifierType.IssuerAndSerialNumber, tmpl.SignerCert, tmpl.SignerKey);
        signer.SignedAttributes.Add(
            new AsnEncodedData(
                new Oid(oidSCEPtransactionID),
                Asn1Helper.EncodePrintableString(tID)
            )
        );

        signer.SignedAttributes.Add(
            new AsnEncodedData(
                new Oid(oidSCEPmessageType),
                Asn1Helper.EncodeInteger((int)tmpl.MessageType)
            )
        );

        signer.SignedAttributes.Add(
            new AsnEncodedData(
                new Oid(oidSCEPsenderNonce),
                Asn1Helper.EncodeOctetString(sn)
            ));

        signedData.ComputeSignature(signer);
        var rawPKIMessage = signedData.Encode();

        return new PKIMessage
        {
            Raw = rawPKIMessage,
            MessageType = tmpl.MessageType,
            TransactionID = tID,
            SenderNonce = sn,
            CSRReqMessage = new CSRReqMessage { CSR = csr },
            Recipients = recipients
        };
    }

    public byte[] DecryptMessage(byte[] encryptedData, X509Certificate2 cert, RSA privateKey)
    {
        try
        {
            var env = new EnvelopedCms();
            env.Decode(encryptedData);

            // Находим соответствующую информацию о получателе
            var recipientInfo = FindRecipientInfo(env.RecipientInfos, cert);

            if (recipientInfo == null)
                throw new Exception("Не найдена информация о получателе для указанного сертификата");

            // Расшифровываем сообщение
            env.Decrypt(recipientInfo, privateKey);

            return env.ContentInfo.Content;
        }
        catch (Exception ex)
        {
            // Обработка ошибок
            throw;
        }
    }

    private RecipientInfo FindRecipientInfo(RecipientInfoCollection recipientInfos, X509Certificate2 cert)
    {
        foreach (RecipientInfo info in recipientInfos)
        {
            if (info.RecipientIdentifier.Type == SubjectIdentifierType.IssuerAndSerialNumber)
            {
                var identifier = (X509IssuerSerial)info.RecipientIdentifier.Value;
                if (string.Equals(identifier.SerialNumber, cert.SerialNumber, StringComparison.OrdinalIgnoreCase) &&
                    string.Equals(identifier.IssuerName, cert.IssuerName.Name, StringComparison.OrdinalIgnoreCase))
                {
                    return info;
                }
            }
        }
        return null;
    }

    private static byte[] NewNonce()
    {
        var rng = RandomNumberGenerator.Create();
        var nonce = new byte[16];
        rng.GetBytes(nonce);
        return nonce;
    }

    private static string NewTransactionID(AsymmetricKeyParameter publicKey)
    {
        if (publicKey == null)
            throw new ArgumentNullException(nameof(publicKey));

        try
        {
            var keyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(publicKey);
            var keyBytes = keyInfo.GetDerEncoded();

            using (var sha1 = SHA1.Create())
            {
                var hash = sha1.ComputeHash(keyBytes);
                // Убираем возможные символы = в конце Base64 строки для совместимости
                return Convert.ToBase64String(hash)
                    .TrimEnd('=')
                    .Replace('+', '-')
                    .Replace('/', '_');
            }
        }
        catch (Exception ex)
        {
            throw new CryptographicException("Failed to generate TransactionID", ex);
        }
    }

    public PKIMessage CreateSuccessResponse(X509Certificate2 caCertificate, RSA privateKey, X509Certificate2 signedCert)
    {
        if (signedCert == null)
            throw new ArgumentNullException(nameof(signedCert));
        if (caCertificate == null)
            throw new ArgumentNullException(nameof(caCertificate));
        if (privateKey == null)
            throw new ArgumentNullException(nameof(privateKey));

        // Create degenerate certificate structure
        var degenerateCertData = DegenerateCertificates(new List<X509Certificate2> { signedCert });

        // Encrypt degenerate data using the original message recipients
        var recipients = new CmsRecipientCollection(
            SubjectIdentifierType.IssuerAndSerialNumber,
            new X509Certificate2Collection(P7.Certificates.ToArray()));

        var env = new EnvelopedCms(new ContentInfo(degenerateCertData));
        env.Encrypt(recipients);
        var encryptedData = env.Encode();

        // Create signed response
        var signedData = new SignedCms(new ContentInfo(encryptedData), detached: false);
        var signer = new CmsSigner(SubjectIdentifierType.IssuerAndSerialNumber, caCertificate, privateKey);

        // Add the certificate to signed data (must be first in collection)
        signedData.Certificates.Add(signedCert);

        // Add SCEP attributes - через метод Add, так как SignedAttributes только для чтения
        signer.SignedAttributes.Add(new AsnEncodedData(
            new Oid(oidSCEPtransactionID),
            Asn1Helper.EncodePrintableString(TransactionID))
        );

        signer.SignedAttributes.Add(new AsnEncodedData(
            new Oid(oidSCEPpkiStatus),
            Asn1Helper.EncodeInteger((int)PKIStatus.Success))
        );

        signer.SignedAttributes.Add(new AsnEncodedData(
            new Oid(oidSCEPmessageType),
            Asn1Helper.EncodeInteger((int)PKIMessageType.CertRep))
        );

        signer.SignedAttributes.Add(new AsnEncodedData(
            new Oid(oidSCEPsenderNonce),
            Asn1Helper.EncodeOctetString(SenderNonce)) // Используем существующий nonce, а не создаем новый
        );

        signer.SignedAttributes.Add(new AsnEncodedData(
            new Oid(oidSCEPrecipientNonce),
            Asn1Helper.EncodeOctetString(SenderNonce)) // Используем SenderNonce как RecipientNonce
        );

        signedData.ComputeSignature(signer);
        var rawResponse = signedData.Encode();

        return new PKIMessage
        {
            Raw = rawResponse,
            MessageType = PKIMessageType.CertRep,
            TransactionID = TransactionID,
            SenderNonce = SenderNonce, // Используем существующий, а не создаем новый
            CertRepMessage = new CertRepMessage
            {
                PKIStatus = PKIStatus.Success,
                RecipientNonce = SenderNonce, // Используем SenderNonce
                Certificate = signedCert
            },
            Recipients = Recipients,
            SignerCert = caCertificate, // Используем переданный CA сертификат
            SignerKey = privateKey // Используем переданный приватный ключ
        };
    }

    public PKIMessage CreateFailResponse(PKIFailInfo failInfo)
    {
        // Create signed response (no encrypted content needed for failure)
        var signedData = new SignedCms(new ContentInfo(new byte[0]));
        var signer = new CmsSigner(SubjectIdentifierType.IssuerAndSerialNumber, SignerCert, SignerKey);

        // Add SCEP attributes
        signer.SignedAttributes.Add(new AsnEncodedData(
            new Oid(oidSCEPtransactionID),
            Encoding.ASCII.GetBytes(TransactionID))
        );

        signer.SignedAttributes.Add(new AsnEncodedData(
            new Oid(oidSCEPmessageType),
            BitConverter.GetBytes((int)PKIMessageType.CertRep))
        );

        signer.SignedAttributes.Add(new AsnEncodedData(
            new Oid(oidSCEPsenderNonce),
            NewNonce())
        );

        signer.SignedAttributes.Add(new AsnEncodedData(
            new Oid(oidSCEPpkiStatus),
            BitConverter.GetBytes((int)PKIStatus.Failure))
        );

        signer.SignedAttributes.Add(new AsnEncodedData(
            new Oid(oidSCEPrecipientNonce),
            SenderNonce)
        );

        signer.SignedAttributes.Add(new AsnEncodedData(
            new Oid(oidSCEPfailInfo),
            BitConverter.GetBytes((int)failInfo))
        );

        signedData.ComputeSignature(signer);
        var rawResponse = signedData.Encode();

        return new PKIMessage
        {
            Raw = rawResponse,
            MessageType = PKIMessageType.CertRep,
            TransactionID = TransactionID,
            SenderNonce = NewNonce(),
            CertRepMessage = new CertRepMessage
            {
                PKIStatus = PKIStatus.Failure,
                RecipientNonce = SenderNonce,
                FailInfo = failInfo
            },
            Recipients = Recipients,
            SignerCert = SignerCert,
            SignerKey = SignerKey
        };
    }
}