using SCEP.Net.Services;
using SCEP.Net.Services.Abstractions;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();




//builder.Services.AddSingleton<IDepot, BoltDepot>((sp) =>
//{
//    return boltDepot;
//});
//builder.Services.AddScoped<ICSRSigner, CSRSigner>();
// builder.Services.AddScoped<ISCEPService, SCEPService>(sp =>
// {
//     var depot = sp.GetRequiredService<IDepot>();
//     var signer = sp.GetRequiredService<ICSRSigner>();
//     var logger = sp.GetRequiredService<ILogger<SCEPService>>();
// 
//     depot.GetCA
// 
//     return new SCEPService(ca, key, signer, logger, new List<X509Certificate2>());
// });


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
