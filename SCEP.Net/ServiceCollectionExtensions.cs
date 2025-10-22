using SCEP.Net.Services;
using SCEP.Net.Services.Abstractions;
using SCEP.Net.Services.Options;

namespace SCEP.Net;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddScepServices(this IServiceCollection services, IConfiguration configuration)
    {
        services.Configure<CaCertificatesOptions>(configuration.GetSection("Scep:CaCertificates"));
        services.Configure<CsrSignerOptions>(configuration.GetSection("Scep:CsrSigners"));
        services.Configure<SqliteDbAdapterOptions>(configuration.GetSection("Scep:SqliteDbAdapter"));

        services
            .AddSingleton<IDepot, BoltDepot>()
            .AddSingleton<ICaCertificatesStorage, CaCertificatesStorage>()
            .AddSingleton<ICsrSigner, CsrSigner>()
            .AddScoped<IScepService, ScepService>()
            .AddSingleton<ISerialNumberGenerator, SerialNumberGenerator>()
            .AddSingleton<IDbAdapter, SqliteDbAdapter>();

        return services;
    }
}
