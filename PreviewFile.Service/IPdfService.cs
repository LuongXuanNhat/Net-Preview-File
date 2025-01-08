using PreviewFile.Domain.Dtos;
using PreviewFile.Service.Helper;
using System.Text.RegularExpressions;

namespace PreviewFile.Service
{
    public interface IPdfService
    {
        Task<PdfFile> AnalyzePdfAsync(byte[] pdfBytes);
        Task<byte[]> UnlockPdf(byte[] pdfBytes, string password);
    }
    public sealed class PdfService : IPdfService
    {
        public PdfService() { }

        public async Task<PdfFile> AnalyzePdfAsync(byte[] pdfBytes)
        {
            var result = new PdfFile
            {
                FileSize = pdfBytes.Length
            };

            try
            {
                Console.WriteLine("FileSize: " + pdfBytes.Length / (1024 * 1024));
                if (pdfBytes.Length > 100 * 1024 * 1024) 
                {
                    result.Type = PdfType.Unsupported;
                    result.ErrorMessage = TranslateHelper.Pdf.ErrorLargeFile;
                    return result;
                }
                if (!IsValidPdfSignature(pdfBytes))
                {
                    result.Type = PdfType.Corrupted;
                    return result;
                }

                result.Version = ExtractPdfVersion(pdfBytes);

                result.IsLinearized = CheckIfLinearized(pdfBytes);

                result.IsEncrypted = CheckIfEncrypted(pdfBytes);

                result.IsDigitallySigned = CheckForDigitalSignature(pdfBytes);

                result.HasForms = CheckForAcroForms(pdfBytes);

                Console.WriteLine("FileType: " + result.Type);
   
                if (result.IsEncrypted)
                {
                    result.Type = PdfType.Secured;
                }
                else if (result.IsDigitallySigned)
                {
                    result.Type = PdfType.Digital_Signed;
                }
                else if (IsPdfA(pdfBytes))
                {
                    result.Type = PdfType.PDF_A;
                }
                else if (IsPdfX(pdfBytes))
                {
                    result.Type = PdfType.PDF_X;
                }
                else if (result.IsLinearized)
                {
                    result.Type = PdfType.Linearized;
                }
                else
                {
                    result.Type = PdfType.Standard;
                }
            }
            catch (Exception ex)
            {
                result.Type = PdfType.Corrupted;
                result.ErrorMessage = ex.Message;
            }

            return result;
        }




        //------------------------------------------------

        private bool IsValidPdfSignature(byte[] pdfBytes)
        {
            if (pdfBytes == null || pdfBytes.Length < 5)
                return false;

            // Check header PDF
            return pdfBytes[0] == '%' &&
                   pdfBytes[1] == 'P' &&
                   pdfBytes[2] == 'D' &&
                   pdfBytes[3] == 'F' &&
                   pdfBytes[4] == '-';
        }
        private string ExtractPdfVersion(byte[] pdfBytes)
        {
            // Find version in header PDF
            var header = System.Text.Encoding.ASCII.GetString(pdfBytes, 0, Math.Min(32, pdfBytes.Length));
            var versionMatch = Regex.Match(header, @"%PDF-(\d+\.\d+)");
            return versionMatch.Success ? versionMatch.Groups[1].Value : "Unknown";
        }

        private bool CheckIfLinearized(byte[] pdfBytes)
        {
            // Find Linearized in 1024 first bytes 
            var header = System.Text.Encoding.ASCII.GetString(pdfBytes, 0, Math.Min(1024, pdfBytes.Length));
            return header.Contains("/Linearized");
        }

        private bool CheckIfEncrypted(byte[] pdfBytes)
        {
            // Find key: /Encrypt in file
            // var content = System.Text.Encoding.ASCII.GetString(pdfBytes);
            // return content.Contains("/Encrypt");

            int bytesToCheck = Math.Min(1024 * 1024, pdfBytes.Length);
            var content = System.Text.Encoding.ASCII.GetString(pdfBytes, 0, bytesToCheck);
            return content.Contains("/Encrypt");
        }

        private bool CheckForDigitalSignature(byte[] pdfBytes)
        {
            // Find key: /ByteRange và /Contents (often appears printed with a digital signature)
            // var content = System.Text.Encoding.ASCII.GetString(pdfBytes);
            // return content.Contains("/ByteRange") && content.Contains("/Contents");

            int bytesToCheck = Math.Min(1024 * 1024, pdfBytes.Length);
            var startContent = System.Text.Encoding.ASCII.GetString(pdfBytes, 0, bytesToCheck);

            if (pdfBytes.Length > bytesToCheck * 2)
            {
                var endContent = System.Text.Encoding.ASCII.GetString(
                    pdfBytes,
                    pdfBytes.Length - bytesToCheck,
                    bytesToCheck
                );
                return (startContent.Contains("/ByteRange") && startContent.Contains("/Contents")) ||
                       (endContent.Contains("/ByteRange") && endContent.Contains("/Contents"));
            }

            return startContent.Contains("/ByteRange") && startContent.Contains("/Contents");
        }

        private bool CheckForAcroForms(byte[] pdfBytes)
        {
            // Find key: /AcroForm
            var content = System.Text.Encoding.ASCII.GetString(pdfBytes);
            return content.Contains("/AcroForm");
        }

        private bool IsPdfA(byte[] pdfBytes)
        {
            // Tìm metadata cho PDF/A
            var content = System.Text.Encoding.ASCII.GetString(pdfBytes);
            return content.Contains("pdfaid:conformance");
        }

        private bool IsPdfX(byte[] pdfBytes)
        {
            // Tìm metadata cho PDF/X
            var content = System.Text.Encoding.ASCII.GetString(pdfBytes);
            return content.Contains("GTS_PDFXVersion");
        }

        public Task<byte[]> UnlockPdf(byte[] pdfBytes, string password)
        {
            try
            {
                var decryption = new PdfDecryption();
                return Task.FromResult(decryption.UnlockPdf(pdfBytes, password));
            }
            catch (Exception ex)
            {
                Console.WriteLine("Mở khóa thất bại");
                throw;
            }
        }
    }
}