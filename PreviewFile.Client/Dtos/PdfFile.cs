namespace PreviewFile.Client.Dtos
{
    internal class PdfFile
    {
        public PdfType Type { get; set; }
        public string Version { get; set; }
        public bool IsEncrypted { get; set; }
        public bool IsLinearized { get; set; }
        public bool IsDigitallySigned { get; set; }
        public bool HasForms { get; set; }
        public long FileSize { get; set; }
        public string ErrorMessage { get; set; }
    }
    internal enum PdfType
    {
        Standard,           // PDF thông thường
        Secured,           // PDF có mật khẩu
        Linearized,        // PDF được tối ưu cho web (Fast Web View)
        Digital_Signed,    // PDF có chữ ký số
        PDF_A,             // PDF/A (Archive)
        PDF_X,             // PDF/X (Exchange)
        Corrupted,         // PDF bị hỏng
        Unsupported        // Định dạng không được hỗ trợ
    }
}
