namespace SCEP.Net.Controllers.Models;

public class SCEPResponse
{
    public string Operation { get; set; }

    public int CACertNum { get; set; }

    public byte[] Data { get; set; }

    public Exception Error { get; set; }
}