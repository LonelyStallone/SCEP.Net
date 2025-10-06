using AutoFixture;
using Microsoft.AspNetCore.Mvc.ModelBinding.Validation;
using Microsoft.Extensions.Logging;
using Moq;
using SCEP.Net.Services;
using SCEP.Net.Services.PKI.Enums;
using SCEP.Net.Services.Singer;
using SCEP.Net.Tests.Utils;
using Shouldly;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace SCEP.Net.Tests;

public class DebugTests
{
    private readonly Fixture _fixture = new();

    private readonly BoltDepot _boltDepot;

    private readonly CSRSignerOptions _cSRSignerOptions;

    public DebugTests()
    {
        var path = _fixture.Create<string>() + "_test.db";
        _boltDepot = new BoltDepot(path);

        _cSRSignerOptions = new CSRSignerOptions
        {
            AllowRenewalDays = 14,
            ValidityDays = 365
        };

    }

    [Fact]
    public async Task CreateOrLoadKeyAsync_ShouldReturnKey_WhenCalled()
    {
        // Arrange
        var keySize = 2048;

        // Act 
        var key = await _boltDepot.CreateOrLoadKeyAsync(keySize, CancellationToken.None);

        // Assert
        key.ShouldNotBeNull();
    }

    [Fact]
    public async Task CreateOrLoadCAAsync_ShouldReturnCa_WhenCalled()
    {
        // Arrange
        var keySize = 2048;
        var key = await _boltDepot.CreateOrLoadKeyAsync(keySize, CancellationToken.None);

        // Act
        var ca = await _boltDepot.CreateOrLoadCAAsync(key, 5, "MicroMDM", "US", CancellationToken.None);

        // Assert
        key.ShouldNotBeNull();
    }

    [Fact]
    public async Task GetCAAsync_ShouldReturnCa_WhenCalled()
    {
        // Arrange
        var keySize = 2048;
        var key = await _boltDepot.CreateOrLoadKeyAsync(keySize, CancellationToken.None);
        var ca = await _boltDepot.CreateOrLoadCAAsync(key, 5, "MicroMDM", "US", CancellationToken.None);

        // Act
        var (certsFromDepot, keyFromDepot) = await _boltDepot.GetCAAsync(_fixture.Create<string>(), CancellationToken.None);

        // Assert
        certsFromDepot.Length.ShouldBe(1);
    }

    [Fact]
    public async Task GetCACertAsync_ShouldReturnCa_WhenCalled()
    {
        // Arrange
        var keySize = 2048;
        var key = await _boltDepot.CreateOrLoadKeyAsync(keySize, CancellationToken.None);
        var ca = await _boltDepot.CreateOrLoadCAAsync(key, 5, "MicroMDM", "US", CancellationToken.None);
        var (certsFromDepot, keyFromDepot) = await _boltDepot.GetCAAsync(_fixture.Create<string>(), CancellationToken.None);

        var caCertificat = certsFromDepot.Single();
        var privateKey = keyFromDepot;
        var csrSigner = new CSRSigner(_boltDepot, _cSRSignerOptions);
        var logger = new Mock<ILogger<SCEPService>>().Object;

        var scepService = new SCEPService(
           caCertificat,
           privateKey,
           csrSigner,
           logger,
           Array.Empty<X509Certificate2>().ToList());

        // Act
        var (caCert, num) = await scepService.GetCACertAsync(_fixture.Create<string>(), CancellationToken.None);

        // Assert
        caCert.ShouldNotBeNull();
    }

    [Fact]
    public async Task GetCACertAsync2_ShouldReturnCa_WhenCalled()
    {
        // Arrange
        var keySize = 2048;
        var key = await _boltDepot.CreateOrLoadKeyAsync(keySize, CancellationToken.None);
        var ca = await _boltDepot.CreateOrLoadCAAsync(key, 5, "MicroMDM", "US", CancellationToken.None);
        var (certsFromDepot, keyFromDepot) = await _boltDepot.GetCAAsync(_fixture.Create<string>(), CancellationToken.None);

        var caCertificat = certsFromDepot.Single();
        var privateKey = keyFromDepot;
        var csrSigner = new CSRSigner(_boltDepot, _cSRSignerOptions);
        var logger = new Mock<ILogger<SCEPService>>().Object;

        var scepService = new SCEPService(
           caCertificat,
           privateKey,
           csrSigner,
           logger,
           Array.Empty<X509Certificate2>().ToList());

        var newKey = RSA.Create(keySize);
        var csr = CsrBuilder.GenerateCSR(newKey, "ou", "loc", "province", "RU", "cname", "org");
        var signerCert = X509Certificate2Builder.SelfSign(newKey, csr);

        var rootStore = new X509Certificate2Collection();
        rootStore.Add(ca);

        // Act
        var (caCert, num) = await scepService.GetCACertAsync(_fixture.Create<string>(), CancellationToken.None);

        // Assert
        caCert.ShouldNotBeNull();
    }

    [Fact]
    public async Task GetCACertAsync3_ShouldReturnCa_WhenCalled()
    {
        // Arrange
        var keySize = 2048;
        var key = await _boltDepot.CreateOrLoadKeyAsync(keySize, CancellationToken.None);
        var ca = await _boltDepot.CreateOrLoadCAAsync(key, 5, "MicroMDM", "US", CancellationToken.None);
        var (certsFromDepot, keyFromDepot) = await _boltDepot.GetCAAsync(_fixture.Create<string>(), CancellationToken.None);

        var caCertificat = certsFromDepot.Single();
        var privateKey = keyFromDepot;
        var csrSigner = new CSRSigner(_boltDepot, _cSRSignerOptions);
        var logger = new Mock<ILogger<SCEPService>>().Object;

        var scepService = new SCEPService(
           caCertificat,
           privateKey,
           csrSigner,
           logger,
           Array.Empty<X509Certificate2>().ToList());

        var selfKey = RSA.Create(keySize);
        var csr = CsrBuilder.GenerateCSR(selfKey, "ou", "loc", "province", "RU", "cname", "org");
        var signerCert = X509Certificate2Builder.SelfSign(selfKey, csr);

        var rootStore = new X509Certificate2Collection();
        rootStore.Add(ca);

        var (caBytes, num) = await scepService.GetCACertAsync(_fixture.Create<string>(), CancellationToken.None);


        var tmpl = new PKIMessage
        {
            MessageType = PKIMessageType.PKCSReq,
            Recipients = new[] { caCertificat }.ToList(),
            SignerKey = selfKey,
            SignerCert = signerCert,
        };
        // Act

        var message = PKIMessage.NewCSRRequest(csr, tmpl);

        // Assert
        message.ShouldNotBeNull();
    }

    [Fact]
    public async Task GetCACertAsync4_ShouldReturnCa_WhenCalled()
    {
        // Arrange
        var keySize = 2048;
        var key = await _boltDepot.CreateOrLoadKeyAsync(keySize, CancellationToken.None);
        var ca = await _boltDepot.CreateOrLoadCAAsync(key, 5, "MicroMDM", "US", CancellationToken.None);
        var (certsFromDepot, keyFromDepot) = await _boltDepot.GetCAAsync(_fixture.Create<string>(), CancellationToken.None);

        var caCertificat = certsFromDepot.Single();
        var privateKey = keyFromDepot;
        var csrSigner = new CSRSigner(_boltDepot, _cSRSignerOptions);
        var logger = new Mock<ILogger<SCEPService>>().Object;

        var scepService = new SCEPService(
           caCertificat,
           privateKey,
           csrSigner,
           logger,
           Array.Empty<X509Certificate2>().ToList());

        var selfKey = RSA.Create(keySize);
        var csr = CsrBuilder.GenerateCSR(selfKey, "ou", "loc", "province", "RU", "cname", "org");
        var signerCert = X509Certificate2Builder.SelfSign(selfKey, csr);

        var rootStore = new X509Certificate2Collection();
        rootStore.Add(ca);

        var (caBytes, num) = await scepService.GetCACertAsync(_fixture.Create<string>(), CancellationToken.None);

        var tmpl = new PKIMessage
        {
            MessageType = PKIMessageType.PKCSReq,
            Recipients = new[] { caCertificat }.ToList(),
            SignerKey = selfKey,
            SignerCert = signerCert,
        };


        var message = PKIMessage.NewCSRRequest(csr, tmpl);

        // Act
        var respMsgBytes = await scepService.PKIOperationAsync(message.Raw, CancellationToken.None);

        // Assert
        message.ShouldNotBeNull();
    }
}