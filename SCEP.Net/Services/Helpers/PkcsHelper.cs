using System.Security.Cryptography.X509Certificates;

namespace SCEP.Net.Services.Helpers;

public static class PkcsHelper
{
    public static byte[] DegenerateCertificates(IReadOnlyCollection<X509Certificate2> certs)
    {
        var collection = new X509Certificate2Collection();
        collection.AddRange(certs.ToArray());

        // Прямое создание PKCS#7 дегенерированной структуры
        return collection.Export(X509ContentType.Pkcs7)!;
    }
}
