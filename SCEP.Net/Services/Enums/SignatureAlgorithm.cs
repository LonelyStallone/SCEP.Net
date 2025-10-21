namespace SCEP.Net.Services.Enums;

public enum SignatureAlgorithm
{
    Unknown,
    MD2WithRSA,  // Unsupported.
    MD5WithRSA,  // Only supported for signing, not verification.
    SHA1WithRSA, // Only supported for signing, and verification of CRLs, CSRs, and OCSP responses.
    SHA256WithRSA,
    SHA384WithRSA,
    SHA512WithRSA,
    DSAWithSHA1,   // Unsupported.
    DSAWithSHA256, // Unsupported.
    ECDSAWithSHA1, // Only supported for signing, and verification of CRLs, CSRs, and OCSP responses.
    ECDSAWithSHA256,
    ECDSAWithSHA384,
    ECDSAWithSHA512,
    SHA256WithRSAPSS,
    SHA384WithRSAPSS,
    SHA512WithRSAPSS,
    PureEd25519,
}
