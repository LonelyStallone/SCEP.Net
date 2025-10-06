using System.Formats.Asn1;

namespace SCEP.Net.Services.Helpers;

public static class Asn1Helper
{
    public static byte[] EncodeInteger(int value)
    {
        var asnWriter = new AsnWriter(AsnEncodingRules.BER);
        asnWriter.WriteInteger(value);

        return asnWriter.Encode();
    }

    public static byte[] EncodePrintableString(string value)
    {
        var asnWriter = new AsnWriter(AsnEncodingRules.BER);

        asnWriter.WriteCharacterString(UniversalTagNumber.PrintableString, value);
        return asnWriter.Encode();
    }

    public static byte[] EncodeOctetString(byte[] data)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);

        writer.WriteOctetString(data);
        return writer.Encode();
    }

    public static byte[] DecodeOctetString(byte[] asn1Data)
    {
        var reader = new AsnReader(asn1Data, AsnEncodingRules.DER);
        var octetString = reader.ReadOctetString();
        reader.ThrowIfNotEmpty();

        return octetString;
    }

    public static string DecodePrintableString(byte[] asn1Data)
    {
        var reader = new AsnReader(asn1Data, AsnEncodingRules.DER);

        return reader.ReadCharacterString(UniversalTagNumber.PrintableString);
    }

    public static int DecodeInteger(byte[] asn1Data)
    {
        var reader = new AsnReader(asn1Data, AsnEncodingRules.DER);
        var bigInt = reader.ReadInteger();

        if (bigInt < int.MinValue || bigInt > int.MaxValue)
            throw new ArgumentException("Integer value too large for int32");

        return (int)bigInt;
    }
}

