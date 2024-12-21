namespace PreviewFile.Client.Dtos
{
    internal class Helper
    {
    }

    internal enum LoadingStatus
    {
        NotLoaded,
        Loading,
        Loaded,
        Error
    }
    internal enum FileType
    {
        Image,
        Video,
        Pdf,
        Unsupported
    }
}
