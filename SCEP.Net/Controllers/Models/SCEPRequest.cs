namespace SCEP.Net.Controllers.Models;

public class SCEPRequest
{
    public string Operation { get; set; }

    public byte[] Message { get; set; }
}
