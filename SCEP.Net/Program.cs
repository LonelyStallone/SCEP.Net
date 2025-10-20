using SCEP.Net.Services;
using SCEP.Net.Services.Singer;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var keySize = 2048;
var boltDepot = new BoltDepot("test.db");
var key = await boltDepot.CreateOrLoadKeyAsync(keySize, CancellationToken.None);
var ca = await boltDepot.CreateOrLoadCAAsync(key, 5, "MicroMDM", "US", CancellationToken.None);


builder.Services.AddSingleton((_) =>
{
    return new CSRSignerOptions
    {
        AllowRenewalDays = 14,
        ValidityDays = 365
    };
});

builder.Services.AddSingleton<IDepot, BoltDepot>((sp) =>
{
    return boltDepot;
});
builder.Services.AddScoped<ICSRSigner, CSRSigner>();
builder.Services.AddScoped<ISCEPService, SCEPService>(sp =>
{
    var signer = sp.GetRequiredService<ICSRSigner>();
    var logger = sp.GetRequiredService<ILogger<SCEPService>>();

    return new SCEPService(ca, key, signer, logger, new List<X509Certificate2>());
});


var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthorization();

app.MapControllers();

await app.RunAsync();
