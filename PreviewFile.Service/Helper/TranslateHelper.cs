using System.Globalization;
using System.Resources;

namespace PreviewFile.Service.Helper
{
    /// <summary>
    /// Helper for translations - Allows inheritance
    /// </summary>
    public static class TranslateHelper
    {
        public const string VI = "vi";
        public const string EN = "en";

        public static string CurrentLanguage { get; set; } = EN;

        /// <summary>
        /// Represents PDF-related translations
        /// </summary>
        public static class Pdf
        {
            private static ResourceManager resourceManager => GetResourceManager(typeof(Pdf), "pdf");

            public static string ErrorLargeFile => Get(resourceManager, "ErrorLargeFile");
            //public static string FileLarge => Get(resourceManager, "FileLarge");
            //public static string Corrupted => Get(resourceManager, "Corrupted");
        }


        private static ResourceManager GetResourceManager(Type type, string resourceName)
        {
            string resourcePath = $"PreviewFile.Service.Translator.{CurrentLanguage}.{resourceName}";
            return new ResourceManager(resourcePath, type.Assembly);
        }

        private static string Get(ResourceManager resourceManager, string key) 
            => resourceManager.GetString(key, new CultureInfo(CurrentLanguage)) ?? key;
        

    }


}
