using System.Numerics;

namespace SCEP.Net.Services.Abstractions;

public interface ISerialNumberGenerator
{
    Task<BigInteger> GetNextSerialNumberAsync(CancellationToken cancellationToken);
}
