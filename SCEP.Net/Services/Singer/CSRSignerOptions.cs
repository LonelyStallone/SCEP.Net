using System.Security.Cryptography.X509Certificates;

namespace SCEP.Net.Services.Singer;

public class CSRSignerOptions
{
    public string CAPass { get; set; } = string.Empty;

    public int AllowRenewalDays { get; set; } = 14;

    public int ValidityDays { get; set; } = 365;

    public bool ServerAttrs { get; set; } = false;

    public SignatureAlgorithm SignatureAlgorithm { get; set; } = SignatureAlgorithm.Unknown;
}
