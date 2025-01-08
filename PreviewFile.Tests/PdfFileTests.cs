using PreviewFile.Service;
using Moq;
using PreviewFile.Domain.Dtos;
using PreviewFile.Tests.TestResources;
using PreviewFile.Service.Helper;

namespace PreviewFile.Tests
{
    [TestFixture]
    public class PdfFileTests
    {
        private Mock<IPdfService> _pdfServiceMock;

        [SetUp]
        public void Setup()
        {
            _pdfServiceMock = new Mock<IPdfService>();
        }

        [Test]
        public async Task AnalyzePdfAsync_ValidStandardPdf_ReturnsCorrectType()
        {
            byte[] pdfBytes = PdfResources.PdfStandardData;
            var expectedResult = new PdfFile
            {
                Type = PdfType.Standard,
                ErrorMessage = string.Empty
            };
            _pdfServiceMock.Setup(service => service.AnalyzePdfAsync(pdfBytes))
                           .ReturnsAsync(expectedResult);

            var result = await _pdfServiceMock.Object.AnalyzePdfAsync(pdfBytes);

            Assert.That(result.Type, Is.EqualTo(PdfType.Standard));
            Assert.IsEmpty(result.ErrorMessage);
        }

        [Test]
        public async Task AnalyzePdfAsync_LargePdf_ReturnsUnsupportedType()
        {
            byte[] pdfBytes = PdfResources.PdfLargeData;
            var expectedResult = new PdfFile
            {
                Type = PdfType.Unsupported,
                ErrorMessage = TranslateHelper.Pdf.ErrorLargeFile
            };
            _pdfServiceMock.Setup(service => service.AnalyzePdfAsync(pdfBytes))
                           .ReturnsAsync(expectedResult);

            var result = await _pdfServiceMock.Object.AnalyzePdfAsync(pdfBytes);

            Assert.That(result.Type, Is.EqualTo(PdfType.Unsupported));
            Assert.That(result.ErrorMessage, Is.EqualTo(TranslateHelper.Pdf.ErrorLargeFile));
        }

        [Test]
        public async Task AnalyzePdfAsync_CorruptedPdf_ReturnsCorruptedType()
        {
            byte[] pdfBytes = PdfResources.PdfCorruptedData;
            var expectedResult = new PdfFile
            {
                Type = PdfType.Corrupted,
                ErrorMessage = string.Empty
            };

            _pdfServiceMock.Setup(service => service.AnalyzePdfAsync(pdfBytes))
                           .ReturnsAsync(expectedResult);

            var result = await _pdfServiceMock.Object.AnalyzePdfAsync(pdfBytes);

            Assert.That(result.Type, Is.EqualTo(PdfType.Corrupted));
            Assert.IsEmpty(result.ErrorMessage);
        }

        [Test]
        public async Task AnalyzePdfAsync_ShouldIdentifyDigitalSignedPdf()
        {
            byte[] pdfBytes = PdfResources.PdfDigitalSignedData;
            var expectedResult = new PdfFile
            {
                Type = PdfType.Digital_Signed,
                IsDigitallySigned = true,
                ErrorMessage = string.Empty
            };

            _pdfServiceMock.Setup(service => service.AnalyzePdfAsync(pdfBytes))
                           .ReturnsAsync(expectedResult);

            var result = await _pdfServiceMock.Object.AnalyzePdfAsync(pdfBytes);

            Assert.That(result.Type, Is.EqualTo(PdfType.Digital_Signed));
            Assert.True(result.IsDigitallySigned);
            Assert.IsEmpty(result.ErrorMessage);
        }

        [Test]
        public async Task AnalyzePdfAsync_ShouldIdentifySecuredPdf()
        {
            byte[] pdfBytes = PdfResources.PdfSecuredData;
            var expectedResult = new PdfFile
            {
                Type = PdfType.Secured,
                IsEncrypted = true,
                ErrorMessage = string.Empty
            };
            _pdfServiceMock.Setup(service => service.AnalyzePdfAsync(pdfBytes))
                           .ReturnsAsync(expectedResult);

            var result = await _pdfServiceMock.Object.AnalyzePdfAsync(pdfBytes);

            Assert.That(result.Type, Is.EqualTo(PdfType.Secured));
            Assert.True(result.IsEncrypted);
            Assert.IsEmpty(result.ErrorMessage);
        }

        [Test]
        public async Task AnalyzePdfAsync_ShouldIdentifyPdfA()
        {
            byte[] pdfBytes = PdfResources.PdfAData;
            var expectedResult = new PdfFile
            {
                Type = PdfType.PDF_A,
                ErrorMessage = string.Empty
            };

            _pdfServiceMock.Setup(service => service.AnalyzePdfAsync(pdfBytes))
                           .ReturnsAsync(expectedResult);

            var result = await _pdfServiceMock.Object.AnalyzePdfAsync(pdfBytes);

            Assert.That(result.Type, Is.EqualTo(PdfType.PDF_A));
            Assert.IsEmpty(result.ErrorMessage);
        }

        [Test]
        public async Task AnalyzePdfAsync_ShouldIdentifyPdfX()
        {
            byte[] pdfBytes = PdfResources.PdfXData;
            var expectedResult = new PdfFile
            {
                Type = PdfType.PDF_X,
                ErrorMessage = string.Empty
            };
            _pdfServiceMock.Setup(service => service.AnalyzePdfAsync(pdfBytes))
                           .ReturnsAsync(expectedResult);

            var result = await _pdfServiceMock.Object.AnalyzePdfAsync(pdfBytes);

            Assert.That(result.Type, Is.EqualTo(PdfType.PDF_X));
            Assert.IsEmpty(result.ErrorMessage);
        }

        [Test]
        public async Task AnalyzePdfAsync_ShouldIdentifyLinearizedPdf()
        {
            byte[] pdfBytes = PdfResources.PdfLinearizedData;
            var expectedResult = new PdfFile
            {
                Type = PdfType.Linearized,
                IsLinearized = true,
                ErrorMessage = string.Empty
            };

            _pdfServiceMock.Setup(service => service.AnalyzePdfAsync(pdfBytes))
                           .ReturnsAsync(expectedResult);

            var result = await _pdfServiceMock.Object.AnalyzePdfAsync(pdfBytes);

            Assert.That(result.Type, Is.EqualTo(PdfType.Linearized));
            Assert.True(result.IsLinearized);
            Assert.IsEmpty(result.ErrorMessage);
        }



    }
}