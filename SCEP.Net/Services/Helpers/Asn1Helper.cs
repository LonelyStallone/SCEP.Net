using System.Formats.Asn1;

namespace SCEP.Net.Services.Helpers;

public static class Asn1Helper
{
    public static byte[] EncodeInteger(int value)
    {
        // Конвертируем число в строку
        string stringValue = value.ToString();

        // Кодируем как PrintableString
        var writer = new AsnWriter(AsnEncodingRules.BER);
        writer.WriteCharacterString(
            UniversalTagNumber.PrintableString,
            stringValue);

        return writer.Encode();
    }

    public static byte[] EncodePrintableString(string value)
    {
        var asnWriter = new AsnWriter(AsnEncodingRules.DER);

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
        var reader = new AsnReader(asn1Data, AsnEncodingRules.BER);

        // Тег 19 = PrintableString (Universal tag 19)
        string printableString = reader.ReadCharacterString(
            UniversalTagNumber.PrintableString);

        // Парсим строку как число
        int result = int.Parse(printableString);

        return result;
    }
}

