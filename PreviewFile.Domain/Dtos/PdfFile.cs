namespace PreviewFile.Domain.Dtos;

public class PdfFile
{
    public PdfType Type { get; set; }
    public string Version { get; set; } = string.Empty;
    public bool IsEncrypted { get; set; }
    public bool IsLinearized { get; set; }
    public bool IsDigitallySigned { get; set; }
    public bool HasForms { get; set; }
    public long FileSize { get; set; }
    public string ErrorMessage { get; set; } = string.Empty;
}
public enum PdfType
{
    Standard,
    Secured,          
    Linearized,        
    Digital_Signed,   
    PDF_A,            
    PDF_X,          
    Corrupted,         
    Unsupported        
}
