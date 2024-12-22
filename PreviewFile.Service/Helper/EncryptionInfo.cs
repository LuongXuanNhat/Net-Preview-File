
    public class EncryptionInfo
    {
        // Basic encryption info
        public string EncryptionMethod { get; set; }  // RC4, AES128, AES256
        public int Version { get; set; }              // PDF encryption version (1-5)
        public int KeyLength { get; set; }            // Length of encryption key in bits
        public byte[] FileId { get; set; }            // Document's unique file ID

        // Permission flags
        public bool AllowPrinting { get; set; }
        public bool AllowModifying { get; set; }
        public bool AllowCopying { get; set; }
        public bool AllowAnnotating { get; set; }
        public bool AllowFillingForms { get; set; }
        public bool AllowAccessibility { get; set; }
        public bool AllowDocumentAssembly { get; set; }
        public bool AllowHighQualityPrinting { get; set; }

        // Security handler info
        public int RevisionNumber { get; set; }       // Security handler revision number
        public string Handler { get; set; }           // Security handler name (usually Standard)
        public string OwnerKey { get; set; }
        public string UserKey { get; set; }         // U entry in encryption dictionary
        public byte[] EncryptionKey { get; set; }    // Computed encryption key
        public int[] PermissionFlags { get; set; }    // Raw permission flags

        // Additional encryption parameters
        public Dictionary<string, object> CryptFilters { get; set; }  // Crypt filters dictionary
        public string CryptFilter { get; set; }                // Default filter to use
        public bool EncryptMetadata { get; set; }                     // Whether metadata is encrypted
        public byte[] PermsValue { get; set; }                       // Perms entry (V5 only)

        public EncryptionInfo()
        {
            // Initialize default values
            CryptFilters = new Dictionary<string, object>();
            EncryptMetadata = true;
            AllowPrinting = true;
            AllowModifying = false;
            AllowCopying = false;
            AllowAnnotating = false;
            AllowFillingForms = true;
            AllowAccessibility = true;
            AllowDocumentAssembly = false;
            AllowHighQualityPrinting = true;
        }

        public bool IsEncrypted()
        {
            return !string.IsNullOrEmpty(EncryptionMethod) && Version > 0;
        }

        private byte[] ComputeOwnerKey(string password)
        {
            // Implement owner key computation based on version
            using (var md5 = System.Security.Cryptography.MD5.Create())
            {
                byte[] passwordBytes = PadPassword(password);
                byte[] key = md5.ComputeHash(passwordBytes);

                if (RevisionNumber >= 3)
                {
                    // Additional hashing for newer revisions
                    for (int i = 0; i < 50; i++)
                    {
                        key = md5.ComputeHash(key);
                    }
                }

                return key;
            }
        }

        private byte[] ComputeUserKey(string password)
        {
            // Implement user key computation based on version
            using (var md5 = System.Security.Cryptography.MD5.Create())
            {
                byte[] passwordBytes = PadPassword(password);
                byte[] input = new byte[passwordBytes.Length + FileId.Length];
                Array.Copy(passwordBytes, input, passwordBytes.Length);
                Array.Copy(FileId, 0, input, passwordBytes.Length, FileId.Length);

                byte[] key = md5.ComputeHash(input);

                if (RevisionNumber >= 3)
                {
                    // Additional hashing for newer revisions
                    for (int i = 0; i < 20; i++)
                    {
                        key = md5.ComputeHash(key);
                    }
                }

                return key;
            }
        }

        private byte[] PadPassword(string password)
        {
            byte[] passwordBytes = System.Text.Encoding.UTF8.GetBytes(password);
            byte[] paddedBytes = new byte[32];

            if (passwordBytes.Length < 32)
            {
                Array.Copy(passwordBytes, paddedBytes, passwordBytes.Length);
                // Pad with predefined padding if needed
                for (int i = passwordBytes.Length; i < 32; i++)
                {
                    paddedBytes[i] = (byte)(i + 1);
                }
            }
            else
            {
                Array.Copy(passwordBytes, paddedBytes, 32);
            }

            return paddedBytes;
        }

        private bool CompareBytes(byte[] array1, byte[] array2, int length = -1)
        {
            if (length == -1)
                length = Math.Min(array1.Length, array2.Length);

            if (array1 == null || array2 == null || length > array1.Length || length > array2.Length)
                return false;

            for (int i = 0; i < length; i++)
            {
                if (array1[i] != array2[i])
                    return false;
            }
            return true;
        }

        public override string ToString()
        {
            return $"PDF Encryption Info:\n" +
                   $"Method: {EncryptionMethod}\n" +
                   $"Version: {Version}\n" +
                   $"Key Length: {KeyLength} bits\n" +
                   $"Revision: {RevisionNumber}\n" +
                   $"Handler: {Handler}\n" +
                   $"Encrypt Metadata: {EncryptMetadata}";
        }
    }
