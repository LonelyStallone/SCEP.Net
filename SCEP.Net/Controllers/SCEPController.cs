using System.Text;
using Microsoft.AspNetCore.Mvc;
using SCEP.Net.Services.Abstractions;
using SCEP.Net.Controllers.Models;

namespace SCEP.Net;

// SCEPController.cs
[ApiController]
[Route("scep")]
public class SCEPController : ControllerBase
{
    private readonly IScepService _service;

    public SCEPController(IScepService service)
    {
        _service = service;
    }

    [HttpGet]
    public async Task<IActionResult> Get([FromQuery] string operation, [FromQuery] string message)
    {
        try
        {
            var request = new SCEPRequest
            {
                Operation = operation,
                Message = operation == "PKIOperation"
                    ? Base64UrlDecode(message)
                    : Encoding.UTF8.GetBytes(message ?? string.Empty)
            };

            var response = await ProcessRequest(request);

            return File(response.Data, GetContentType(response.Operation, response.CACertNum));
        }
        catch (Exception ex)
        {
            return StatusCode(StatusCodes.Status500InternalServerError, ex.Message);
        }
    }

    [HttpPost]
    public async Task<IActionResult> Post([FromQuery] string operation)
    {
        try
        {
            using var ms = new MemoryStream();
            await Request.Body.CopyToAsync(ms);

            var request = new SCEPRequest
            {
                Operation = operation,
                Message = ms.ToArray()
            };

            var response = await ProcessRequest(request);

            return File(response.Data, GetContentType(response.Operation, response.CACertNum));
        }
        catch (Exception ex)
        {
            return StatusCode(StatusCodes.Status500InternalServerError, ex.Message);
        }
    }

    private async Task<SCEPResponse> ProcessRequest(SCEPRequest request)
    {
        return request.Operation switch
        {
            "GetCACaps" => CreateGetCACaps(request),
            "GetCACert" => await CreatGetCACertAsync(request, Request.HttpContext.RequestAborted),
            "PKIOperation" => await CreatPkiOperationAsync(request, Request.HttpContext.RequestAborted),
            _ => throw new NotSupportedException($"Operation {request.Operation} not supported")
        };
    }

    private SCEPResponse CreateGetCACaps(SCEPRequest request)
    {
        return new SCEPResponse
        {
            Data = _service.GetCaCaps(),
            Operation = request.Operation
        };
    }

    private async Task<SCEPResponse> CreatGetCACertAsync(SCEPRequest request, CancellationToken cancellation)
    {
        var message = Encoding.UTF8.GetString(request.Message);
        var (data, certificatesCount) = _service.GetCaCert(message);

        return new SCEPResponse
        {
            Data = data,
            CACertNum = certificatesCount,
            Operation = request.Operation
        };
    }

    private async Task<SCEPResponse> CreatPkiOperationAsync(SCEPRequest request, CancellationToken cancellation)
    {
        return new SCEPResponse
        {
            Data = await _service.PkiOperationAsync(request.Message, cancellation),
            Operation = request.Operation
        };
    }

    private string GetContentType(string operation, int certNum)
    {
        return operation switch
        {
            "GetCACert" => certNum > 1
                ? "application/x-x509-ca-ra-cert"
                : "application/x-x509-ca-cert",
            "PKIOperation" => "application/x-pki-message",
            _ => "text/plain"
        };
    }

    private byte[] Base64UrlDecode(string input)
    {
        string base64 = input.Replace('-', '+').Replace('_', '/');
        switch (base64.Length % 4)
        {
            case 2: base64 += "=="; break;
            case 3: base64 += "="; break;
        }
        return Convert.FromBase64String(base64);
    }
}