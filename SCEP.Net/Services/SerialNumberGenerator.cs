namespace SCEP.Net.Services;

using SCEP.Net.Services.Abstractions;
using System.Numerics;

public class DbSerialNumberGenerator : ISerialNumberGenerator
{
    private const string StorageKey = "serial";

    private readonly IDbAdapter _dbAdapter;

    private readonly SemaphoreSlim _semaphore = new SemaphoreSlim(1, 1);

    public DbSerialNumberGenerator(IDbAdapter dbAdapter)
    {
        _dbAdapter = dbAdapter;
    }

    public async Task<BigInteger> GetNextSerialNumberAsync(CancellationToken cancellationToken)
    {
        await _semaphore.WaitAsync(cancellationToken);
        try
        {
            var currentValue = new BigInteger(1);
            // Получаем текущее значение из базы данных
            var currentValueBytes = await _dbAdapter.GetValueAsync(StorageKey, cancellationToken);

            if (currentValueBytes != null && currentValueBytes.Length > 0)
            {
                // Конвертируем байты обратно в BigInteger
                currentValue = new BigInteger(currentValueBytes, isUnsigned: true);
            }

            // Инкрементируем значение
            var nextValue = currentValue + 1;

            // Сохраняем новое значение в базу данных
            byte[] nextValueBytes = nextValue.ToByteArray(isUnsigned: true);
            await _dbAdapter.SetValueAsync(StorageKey, nextValueBytes, cancellationToken);

            return nextValue;
        }
        finally
        {
            _semaphore.Release();
        }
    }
}
