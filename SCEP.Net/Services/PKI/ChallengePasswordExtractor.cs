using System.Security.Cryptography.X509Certificates;
using System.Text;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Pkcs;

namespace SCEP.Net.Services.PKI;

public static class ChallengePasswordExtractor
{
    public static string ExtractChallengePassword(byte[] csrData)
    {
        try
        {
            // Parse the CSR structure
            var asn1Stream = new Asn1InputStream(csrData);
            var asn1Sequence = (Asn1Sequence)asn1Stream.ReadObject();

            // Get the attributes if present
            if (asn1Sequence.Count > 2)
            {
                var attributes = (Asn1Set)asn1Sequence[2];
                foreach (Asn1Sequence attribute in attributes)
                {
                    var oid = (DerObjectIdentifier)attribute[0];
                    if (oid.Id == PkcsObjectIdentifiers.Pkcs9AtChallengePassword.Id)
                    {
                        var attrValues = (Asn1Set)attribute[1];
                        var printableString = (DerPrintableString)attrValues[0];
                        return printableString.GetString();
                    }
                }
            }
        }
        catch
        {
            // Ignore parsing errors - challenge password is optional
        }
        return null;
    }
}