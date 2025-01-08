using PreviewFile.Service.Helper;

namespace PreviewFile.Service
{
    public interface IPreviewFileService
    {
        public IPdfService PdfService { get; }

    }
    public class PreviewFileService : IPreviewFileService
    {
        public readonly Lazy<IPdfService> _pdfService;
        public static readonly Lazy<PreviewFileService> _instance = new(() => new PreviewFileService());


        public PreviewFileService(string language = TranslateHelper.EN)
        {
            TranslateHelper.CurrentLanguage = language;
            _pdfService = new Lazy<IPdfService>(() => new PdfService());
        }

        public static PreviewFileService Instance => _instance.Value;
        public IPdfService PdfService => _pdfService.Value;
    }
}
