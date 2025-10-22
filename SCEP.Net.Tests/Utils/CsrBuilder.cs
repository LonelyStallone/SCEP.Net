using System.Security.Cryptography;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkcs;

namespace SCEP.Net.Tests.Utils;

public static class CsrBuilder
{
    public static Pkcs10CertificationRequest GenerateCSR(
        RSA rsaPrivateKey,
        string ou,
        string location,
        string province,
        string country,
        string commonName,
        string organization)
    {
        // Создание subject DN
        var subject = new X509Name($"C={country}, ST={province}, L={location}, O={organization}, OU={ou}, CN={commonName}");
        var privateKey = ConvertRSAToKeyPair(rsaPrivateKey);

        // Создание CSR напрямую через конструктор Pkcs10CertificationRequest
        var signatureFactory = new Asn1SignatureFactory("SHA256WITHRSA", privateKey.Private);

        var csr = new Pkcs10CertificationRequest(
            signatureFactory,
            subject,
            privateKey.Public,
            null);

        return csr;
    }

    public static AsymmetricKeyParameter GetPublicKeyFromPrivate(AsymmetricKeyParameter privateKey)
    {
        if (privateKey is RsaPrivateCrtKeyParameters rsaPrivate)
        {
            return new RsaKeyParameters(
                false, // isPrivate
                rsaPrivate.Modulus,
                rsaPrivate.PublicExponent);
        }

        throw new NotSupportedException("Key type not supported");
    }

    private static AsymmetricCipherKeyPair ConvertRSAToKeyPair(RSA rsa)
    {
        var rsaParameters = rsa.ExportParameters(true);

        var modulus = new Org.BouncyCastle.Math.BigInteger(1, rsaParameters.Modulus);
        var exponent = new Org.BouncyCastle.Math.BigInteger(1, rsaParameters.Exponent);
        var d = new Org.BouncyCastle.Math.BigInteger(1, rsaParameters.D);

        var pubKey = new RsaKeyParameters(false, modulus, exponent);

        var privKey = new RsaPrivateCrtKeyParameters(
            modulus, exponent, d,
            new Org.BouncyCastle.Math.BigInteger(1, rsaParameters.P),
            new Org.BouncyCastle.Math.BigInteger(1, rsaParameters.Q),
            new Org.BouncyCastle.Math.BigInteger(1, rsaParameters.DP),
            new Org.BouncyCastle.Math.BigInteger(1, rsaParameters.DQ),
            new Org.BouncyCastle.Math.BigInteger(1, rsaParameters.InverseQ));

        return new AsymmetricCipherKeyPair(pubKey, privKey);
    }
}
