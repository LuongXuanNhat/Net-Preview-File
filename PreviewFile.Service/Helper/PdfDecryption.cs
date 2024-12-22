using System.Text;

public partial class PdfDecryption
{
    private const int PADDING_SIZE = 32;
    private const int AES_BLOCK_SIZE = 16;
    private readonly byte[] S_BOX = new byte[256] {
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};


    private readonly byte[] INV_S_BOX = new byte[256] {
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
};

    public byte[] UnlockPdf(byte[] pdfBytes, string password)
    {
        try
        {
            // Đọc PDF header và xác định loại mã hóa
            var encryptionInfo = ReadEncryptionInfo(pdfBytes);

            if (encryptionInfo.EncryptionMethod == "RC4")
            {
                Console.WriteLine("1: ");
                return DecryptRC4(pdfBytes, password, encryptionInfo);
            }
            else if (encryptionInfo.EncryptionMethod == "AES")
            {
                Console.WriteLine("2: ");
                return DecryptAES(pdfBytes, password, encryptionInfo);
            }
            else
            {
                Console.WriteLine("3: ");
                throw new Exception("Không hỗ trợ phương thức mã hóa này");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("UnlockPdf: "+ ex.Message);
            throw new Exception($"Lỗi khi mở khóa PDF: {ex.Message}");
        }
    }

    private Dictionary<string, object> ParseDictionaryEntries(string dictContent)
    {
        var entries = new Dictionary<string, object>();
        int pos = 0;

        // Tìm vị trí bắt đầu của dictionary
        pos = dictContent.IndexOf("<<") + 2;
        if (pos == -1) return entries;

        // Tìm vị trí kết thúc của dictionary
        int endPos = dictContent.LastIndexOf(">>");
        if (endPos == -1) return entries;

        while (pos < endPos)
        {
            // Bỏ qua khoảng trắng
            while (pos < endPos && char.IsWhiteSpace(dictContent[pos]))
                pos++;

            if (pos >= endPos || dictContent[pos] != '/')
                break;

            // Đọc key
            pos++; // bỏ qua '/'
            int keyEnd = pos;
            while (keyEnd < endPos && !char.IsWhiteSpace(dictContent[keyEnd]) && dictContent[keyEnd] != '/' && dictContent[keyEnd] != '<')
                keyEnd++;

            string key = dictContent.Substring(pos, keyEnd - pos);
            pos = keyEnd;

            // Bỏ qua khoảng trắng sau key
            while (pos < endPos && char.IsWhiteSpace(dictContent[pos]))
                pos++;

            // Đọc value
            object value;
            if (pos + 1 < dictContent.Length && dictContent[pos] == '<' && dictContent[pos + 1] == '<')
            {
                // Nested dictionary
                int nestedDictEnd = FindMatchingEndBracket(dictContent, pos);
                string nestedDict = dictContent.Substring(pos, nestedDictEnd - pos + 2);
                value = ParseDictionaryEntries(nestedDict);
                pos = nestedDictEnd + 2;
            }
            else if (dictContent[pos] == '[')
            {
                // Array
                int arrayEnd = dictContent.IndexOf(']', pos);
                string arrayContent = dictContent.Substring(pos + 1, arrayEnd - pos - 1);
                value = arrayContent.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                pos = arrayEnd + 1;
            }
            else if (dictContent[pos] == '<')
            {
                // Hex string
                int hexEnd = dictContent.IndexOf('>', pos);
                string hexString = dictContent.Substring(pos + 1, hexEnd - pos - 1);
                value = hexString;
                pos = hexEnd + 1;
            }
            else if (dictContent[pos] == '(')
            {
                // Literal string
                int strEnd = dictContent.IndexOf(')', pos);
                string literalString = dictContent.Substring(pos + 1, strEnd - pos - 1);
                value = literalString;
                pos = strEnd + 1;
            }
            else if (char.IsDigit(dictContent[pos]) || dictContent[pos] == '-' || dictContent[pos] == '+')
            {
                // Number
                int numEnd = pos;
                while (numEnd < endPos && (char.IsDigit(dictContent[numEnd]) || dictContent[numEnd] == '.' ||
                      dictContent[numEnd] == '-' || dictContent[numEnd] == '+'))
                    numEnd++;

                string numStr = dictContent.Substring(pos, numEnd - pos);
                if (int.TryParse(numStr, out int intValue))
                    value = intValue;
                else if (double.TryParse(numStr, out double doubleValue))
                    value = doubleValue;
                else
                    value = numStr;

                pos = numEnd;
            }
            else
            {
                // Name or other value
                int valueEnd = pos;
                while (valueEnd < endPos && !char.IsWhiteSpace(dictContent[valueEnd]) &&
                      dictContent[valueEnd] != '/' && dictContent[valueEnd] != '<' &&
                      dictContent[valueEnd] != '>')
                    valueEnd++;

                value = dictContent.Substring(pos, valueEnd - pos);
                pos = valueEnd;
            }

            // Lưu entry vào dictionary
            entries[key] = value;
        }

        return entries;
    }

    private int GetEncryptionVersion(Dictionary<string, object> encrypt)
    {
        // Look for V field (not Version)
        if (encrypt == null) return 0;

        if (encrypt.ContainsKey("V"))
        {
            var vValue = encrypt["V"];
            if (vValue is int version) return version;
            if (int.TryParse(vValue.ToString(), out int parsedVersion))
                return parsedVersion;
        }

        return 0;
    }

    private EncryptionInfo ReadEncryptionInfo(byte[] pdfBytes)
    {
        try
        {
            string pdfContent = System.Text.Encoding.ASCII.GetString(pdfBytes);
            var trailer = ParseTrailer(pdfContent);
            var encrypt = ParseEncryptObject(pdfContent, trailer);
            LogEncryptDictionary(encrypt);

            // Get encryption version from V field (not Version)
            int version = GetEncryptionVersion(encrypt);

            string[] idArray1 = (string[])trailer["ID"]; // Giả sử ID là mảng chuỗi
            byte[] fileId = idArray1.SelectMany(s => Encoding.ASCII.GetBytes(s)).ToArray();

            var encryptInfo = new EncryptionInfo
            {
                Version = version,
                KeyLength = encrypt.ContainsKey("Length") ? Convert.ToInt32(encrypt["Length"]) : 40,
                FileId = fileId,
                RevisionNumber = encrypt.ContainsKey("R") ? Convert.ToInt32(encrypt["R"]) : 0,
                Handler = encrypt.ContainsKey("Filter") ? encrypt["Filter"].ToString() : "Standard",
                OwnerKey = encrypt.ContainsKey("O") ? encrypt["O"].ToString() : null,
                UserKey = encrypt.ContainsKey("U") ? encrypt["U"].ToString() : null,
                EncryptMetadata = !encrypt.ContainsKey("EncryptMetadata") || Convert.ToBoolean(encrypt["EncryptMetadata"])
            };

            // Determine encryption method based on V and CF dictionary
            encryptInfo.EncryptionMethod = DetermineEncryptionMethod(encrypt);

            return encryptInfo;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error reading encryption info: {ex.Message}");
            throw;
        }
    }
    private Dictionary<string, object> ParseTrailer(string pdfContent)
    {
        var trailer = new Dictionary<string, object>();

        // Find the last trailer in the file
        int startxrefPos = pdfContent.LastIndexOf("startxref");
        if (startxrefPos == -1)
        {
            throw new Exception("Invalid PDF: Missing startxref");
        }

        int trailerPos = pdfContent.LastIndexOf("trailer", startxrefPos);
        if (trailerPos == -1)
        {
            throw new Exception("Invalid PDF: Missing trailer");
        }

        // Extract trailer dictionary
        int trailerDictStart = pdfContent.IndexOf("<<", trailerPos);
        if (trailerDictStart == -1)
        {
            throw new Exception("Invalid PDF: Malformed trailer dictionary");
        }

        // Find matching end bracket
        int trailerDictEnd = FindMatchingEndBracket(pdfContent, trailerDictStart);
        if (trailerDictEnd == -1)
        {
            throw new Exception("Invalid PDF: Unclosed trailer dictionary");
        }

        string trailerDict = pdfContent.Substring(trailerDictStart, trailerDictEnd - trailerDictStart + 2);
        Console.WriteLine($"Raw trailer dictionary: {trailerDict}");

        // Parse ID array
        int idPos = trailerDict.IndexOf("/ID");
        if (idPos != -1)
        {
            int idStart = trailerDict.IndexOf("[", idPos);
            int idEnd = trailerDict.IndexOf("]", idPos);
            if (idStart != -1 && idEnd != -1)
            {
                string idContent = trailerDict.Substring(idStart + 1, idEnd - idStart - 1).Trim();
                trailer["ID"] = idContent.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
            }
        }

        // Parse Encrypt reference
        int encryptPos = trailerDict.IndexOf("/Encrypt");
        if (encryptPos != -1)
        {
            int valueStart = encryptPos + 8; // Skip "/Encrypt "
            while (valueStart < trailerDict.Length && char.IsWhiteSpace(trailerDict[valueStart]))
                valueStart++;

            int valueEnd = valueStart;
            while (valueEnd < trailerDict.Length && !char.IsWhiteSpace(trailerDict[valueEnd]) && trailerDict[valueEnd] != '/')
                valueEnd++;

            string encryptRef = trailerDict.Substring(valueStart, valueEnd - valueStart);
            trailer["Encrypt"] = encryptRef;
            Console.WriteLine($"Found Encrypt reference: {encryptRef}");
        }
        else
        {
            Console.WriteLine("No encryption found in trailer");
        }

        return trailer;
    }

    private Dictionary<string, object> ParseEncryptObject(string pdfContent, Dictionary<string, object> trailer)
    {
        if (!trailer.ContainsKey("Encrypt"))
        {
            throw new Exception("PDF is not encrypted");
        }

        string encryptRef = trailer["Encrypt"].ToString();
        Console.WriteLine($"Processing Encrypt reference: {encryptRef}");

        // Handle both "obj_num gen_num" and simple "obj_num" formats
        string[] refParts = encryptRef.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);

        int objNum;
        if (!int.TryParse(refParts[0], out objNum))
        {
            throw new Exception($"Invalid object number in encryption reference: {refParts[0]}");
        }

        // Find encryption object, trying both formats
        string[] objPatterns = {
        $"{objNum} 0 obj",  // Standard format
        $"{objNum} obj"     // Alternative format
    };

        int objPos = -1;
        foreach (var pattern in objPatterns)
        {
            objPos = pdfContent.IndexOf(pattern);
            if (objPos != -1) break;
        }

        if (objPos == -1)
        {
            throw new Exception($"Encryption object {objNum} not found in PDF");
        }

        Console.WriteLine($"Found encryption object at position: {objPos}");

        // Extract encryption dictionary
        int dictStart = pdfContent.IndexOf("<<", objPos);
        if (dictStart == -1)
        {
            throw new Exception("Invalid encryption object format: dictionary start not found");
        }

        int dictEnd = FindMatchingEndBracket(pdfContent, dictStart);
        if (dictEnd == -1)
        {
            throw new Exception("Invalid encryption object format: dictionary end not found");
        }

        string encryptDict = pdfContent.Substring(dictStart, dictEnd - dictStart + 2);
        Console.WriteLine($"Found encryption dictionary: {encryptDict}");

        // Add some context logging
        Console.WriteLine($"Dictionary context: {pdfContent.Substring(Math.Max(0, dictStart - 50),
            Math.Min(pdfContent.Length - dictStart + 50, 100))}");

        var dictEntries = ParseDictionaryEntries(encryptDict);

        // Log the parsed entries
        foreach (var entry in dictEntries)
        {
            Console.WriteLine($"Parsed entry: {entry.Key} = {entry.Value}");
        }

        return dictEntries;
    }

    private int FindMatchingEndBracket(string content, int startPos)
    {
        int nesting = 0;
        for (int i = startPos; i < content.Length - 1; i++)
        {
            if (content[i] == '<' && content[i + 1] == '<')
            {
                nesting++;
                i++;
            }
            else if (content[i] == '>' && content[i + 1] == '>')
            {
                nesting--;
                if (nesting == 0)
                    return i;
                i++;
            }
        }
        return -1;
    }

    private string GetHandler(Dictionary<string, object> encrypt)
    {
        if (encrypt == null) return null;
        if (encrypt.TryGetValue("Filter", out object filter))
        {
            return filter.ToString();
        }
        return "Standard"; // Default handler
    }

    private int GetRevisionNumber(Dictionary<string, object> encrypt)
    {
        if (encrypt == null) return 0;
        if (encrypt.TryGetValue("R", out object revision))
        {
            if (revision is int rev) return rev;
            if (int.TryParse(revision.ToString(), out int parsedRev))
            {
                return parsedRev;
            }
        }
        return 0;
    }

    private byte[] GetOwnerKey(Dictionary<string, object> encrypt)
    {
        if (encrypt == null) return null;
        if (encrypt.TryGetValue("O", out object ownerKey))
        {
            return System.Text.Encoding.ASCII.GetBytes(ownerKey.ToString());
        }
        return null;
    }

    private byte[] GetUserKey(Dictionary<string, object> encrypt)
    {
        if (encrypt == null) return null;
        if (encrypt.TryGetValue("U", out object userKey))
        {
            return System.Text.Encoding.ASCII.GetBytes(userKey.ToString());
        }
        return null;
    }

    private bool GetEncryptMetadata(Dictionary<string, object> encrypt)
    {
        if (encrypt == null) return true;
        if (encrypt.TryGetValue("EncryptMetadata", out object encryptMetadata))
        {
            if (bool.TryParse(encryptMetadata.ToString(), out bool result))
            {
                return result;
            }
        }
        return true; // Default value
    }

    private void LogEncryptDictionary(Dictionary<string, object> encryptDict)
    {
        if (encryptDict == null)
        {
            Console.WriteLine("Encryption dictionary is null.");
            return;
        }

        Console.WriteLine("Encryption dictionary content:");
        foreach (var kvp in encryptDict)
        {
            Console.WriteLine($"Key: {kvp.Key}, Value: {kvp.Value} (Type: {kvp.Value?.GetType().Name})");
        }
    }
    private byte[] DecryptRC4(byte[] pdfBytes, string password, EncryptionInfo info)
    {
        // Generate encryption key từ password
        byte[] encryptionKey = GenerateEncryptionKey(password, info);

        // Tìm và decrypt từng stream được mã hóa
        var ms = new MemoryStream();
        var reader = new BinaryReader(new MemoryStream(pdfBytes));

        while (reader.BaseStream.Position < reader.BaseStream.Length)
        {
            var chunk = ReadNextChunk(reader);
            if (IsEncryptedStream(chunk))
            {
                var decryptedChunk = RC4Decrypt(chunk, encryptionKey);
                ms.Write(decryptedChunk);
            }
            else
            {
                ms.Write(chunk);
            }
        }

        return ms.ToArray();
    }

    private byte[] DecryptAES(byte[] pdfBytes, string password, EncryptionInfo info)
    {
        // Generate AES key từ password
        byte[] aesKey = GenerateAESKey(password, info);
        byte[] iv = new byte[AES_BLOCK_SIZE];

        // Tìm và decrypt từng stream được mã hóa
        var ms = new MemoryStream();
        var reader = new BinaryReader(new MemoryStream(pdfBytes));

        while (reader.BaseStream.Position < reader.BaseStream.Length)
        {
            var chunk = ReadNextChunk(reader);
            if (IsEncryptedStream(chunk))
            {
                // Extract IV từ stream header
                Array.Copy(chunk, 0, iv, 0, AES_BLOCK_SIZE);
                var encryptedData = new byte[chunk.Length - AES_BLOCK_SIZE];
                Array.Copy(chunk, AES_BLOCK_SIZE, encryptedData, 0, encryptedData.Length);

                var decryptedChunk = AESDecrypt(encryptedData, aesKey, iv);
                ms.Write(decryptedChunk);
            }
            else
            {
                ms.Write(chunk);
            }
        }

        return ms.ToArray();
    }

    private byte[] RC4Decrypt(byte[] data, byte[] key)
    {
        int[] s = new int[256];
        byte[] result = new byte[data.Length];

        // RC4 key scheduling
        for (int i = 0; i < 256; i++)
        {
            s[i] = i;
        }

        int j = 0;
        for (int i = 0; i < 256; i++)
        {
            j = (j + s[i] + key[i % key.Length]) % 256;
            int temp = s[i];
            s[i] = s[j];
            s[j] = temp;
        }

        // RC4 stream generation and XOR
        int x = 0, y = 0;
        for (int i = 0; i < data.Length; i++)
        {
            x = (x + 1) % 256;
            y = (y + s[x]) % 256;

            int temp = s[x];
            s[x] = s[y];
            s[y] = temp;

            int t = (s[x] + s[y]) % 256;
            result[i] = (byte)(data[i] ^ s[t]);
        }

        return result;
    }

    private byte[] AESDecrypt(byte[] data, byte[] key, byte[] iv)
    {
        byte[] result = new byte[data.Length];
        int blockCount = data.Length / AES_BLOCK_SIZE;

        // AES in CBC mode
        byte[] previousBlock = iv;

        for (int i = 0; i < blockCount; i++)
        {
            byte[] block = new byte[AES_BLOCK_SIZE];
            Array.Copy(data, i * AES_BLOCK_SIZE, block, 0, AES_BLOCK_SIZE);

            // Decrypt block
            byte[] decryptedBlock = AESDecryptBlock(block, key);

            // XOR với previous block (CBC mode)
            for (int j = 0; j < AES_BLOCK_SIZE; j++)
            {
                result[i * AES_BLOCK_SIZE + j] = (byte)(decryptedBlock[j] ^ previousBlock[j]);
            }

            previousBlock = block;
        }

        // Remove PKCS7 padding
        int paddingLength = result[result.Length - 1];
        byte[] finalResult = new byte[result.Length - paddingLength];
        Array.Copy(result, 0, finalResult, 0, finalResult.Length);

        return finalResult;
    }

    private byte[] AESDecryptBlock(byte[] block, byte[] key)
    {
        // AES block decryption implementation
        // Key expansion
        byte[,] expandedKey = KeyExpansion(key);

        // Initial state
        byte[,] state = new byte[4, 4];
        for (int i = 0; i < 4; i++)
        {
            for (int j = 0; j < 4; j++)
            {
                state[j, i] = block[i * 4 + j];
            }
        }

        // Add round key
        state = AddRoundKey(state, expandedKey, 10);

        // Decryption rounds
        for (int round = 9; round >= 1; round--)
        {
            state = InvShiftRows(state);
            state = InvSubBytes(state);
            state = AddRoundKey(state, expandedKey, round);
            state = InvMixColumns(state);
        }

        // Final round
        state = InvShiftRows(state);
        state = InvSubBytes(state);
        state = AddRoundKey(state, expandedKey, 0);

        // Convert state back to bytes
        byte[] result = new byte[16];
        for (int i = 0; i < 4; i++)
        {
            for (int j = 0; j < 4; j++)
            {
                result[i * 4 + j] = state[j, i];
            }
        }

        return result;
    }
    private int FindTrailer(byte[] pdfBytes)
    {
        // Tìm từ cuối file lên để tìm "startxref"
        string content = System.Text.Encoding.ASCII.GetString(pdfBytes);
        int startxrefPos = content.LastIndexOf("startxref");
        if (startxrefPos == -1)
            throw new Exception("Invalid PDF structure: Missing startxref");

        // Đọc offset của xref table
        int trailerPos = content.LastIndexOf("trailer", startxrefPos);
        if (trailerPos == -1)
            throw new Exception("Invalid PDF structure: Missing trailer");

        return trailerPos;
    }

    private Dictionary<string, object> FindEncryptDictionary(byte[] pdfBytes, int trailerPos)
    {
        string content = System.Text.Encoding.ASCII.GetString(pdfBytes);

        // Tìm encrypt dictionary trong trailer
        int encryptDictStart = content.IndexOf("/Encrypt", trailerPos);
        if (encryptDictStart == -1)
            return null; // PDF không được mã hóa

        // Tìm kết thúc của dictionary
        int dictEnd = content.IndexOf(">>", encryptDictStart);
        if (dictEnd == -1)
            throw new Exception("Không tìm thấy kết thúc của dictionary /Encrypt.");

        // Đọc nội dung dictionary
        string dictContent = content.Substring(encryptDictStart, dictEnd - encryptDictStart + 2);

        // Log nội dung để kiểm tra
        Console.WriteLine($"Encrypt dictionary content: {dictContent}");

        // Parse các entry cơ bản
        var dict = new Dictionary<string, object>();

        if (dictContent.Contains("/Filter"))
            dict["Filter"] = GetDictionaryValue(dictContent, "Filter");
        if (dictContent.Contains("/V"))
            dict["Version"] = int.Parse(GetDictionaryValue(dictContent, "V"));
        if (dictContent.Contains("/Length"))
            dict["Length"] = int.Parse(GetDictionaryValue(dictContent, "Length"));
        if (dictContent.Contains("/CF"))
            dict["CryptFilter"] = ParseCryptFilters(dictContent);

        return dict;
    }



    private string GetDictionaryValue(string content, string key)
    {
        int keyIndex = content.IndexOf($"/{key}");
        if (keyIndex == -1)
            return null;

        int valueStart = keyIndex + key.Length + 1; // +1 for the '/'
        while (valueStart < content.Length && char.IsWhiteSpace(content[valueStart]))
            valueStart++;

        // Handle different value types
        if (content[valueStart] == '/')
        {
            // Name object
            int valueEnd = valueStart + 1;
            while (valueEnd < content.Length && !char.IsWhiteSpace(content[valueEnd]) && content[valueEnd] != '/')
                valueEnd++;
            return content.Substring(valueStart + 1, valueEnd - valueStart - 1);
        }
        else if (content[valueStart] == '(')
        {
            // String object
            int valueEnd = content.IndexOf(')', valueStart);
            return content.Substring(valueStart + 1, valueEnd - valueStart - 1);
        }
        else
        {
            // Number or other simple value
            int valueEnd = valueStart;
            while (valueEnd < content.Length && !char.IsWhiteSpace(content[valueEnd]) && content[valueEnd] != '/')
                valueEnd++;
            return content.Substring(valueStart, valueEnd - valueStart);
        }
    }
    private Dictionary<string, object> ParseCryptFilters(string dictContent)
    {
        var filters = new Dictionary<string, object>();
        int cfStart = dictContent.IndexOf("/CF");
        if (cfStart == -1) return filters;

        // Parse each crypt filter in the CF dictionary
        int cfDictStart = dictContent.IndexOf("<<", cfStart);
        int cfDictEnd = dictContent.IndexOf(">>", cfDictStart);
        string cfContent = dictContent.Substring(cfDictStart, cfDictEnd - cfDictStart);

        // Parse individual filters
        // Example: /StdCF << /AuthEvent /DocOpen /CFM /AESV2 /Length 128 >>
        string[] filterEntries = cfContent.Split(new[] { '/' }, StringSplitOptions.RemoveEmptyEntries);
        foreach (var entry in filterEntries)
        {
            if (entry.StartsWith("StdCF") || entry.StartsWith("DefaultCryptFilter"))
            {
                filters[entry.Split(' ')[0]] = ParseFilterDetails(entry);
            }
        }

        return filters;
    }


    private string DetermineEncryptionMethod(Dictionary<string, object> encrypt)
    {
        int version = GetEncryptionVersion(encrypt);

        if (version <= 1) return "RC4";
        if (version == 2) return "RC4";
        if (version == 4 || version == 5)
        {
            // Check CF dictionary for encryption method
            if (encrypt.ContainsKey("CF") && encrypt["CF"] is Dictionary<string, object> cf)
            {
                if (cf.ContainsKey("StdCF") && cf["StdCF"] is Dictionary<string, object> stdCf)
                {
                    if (stdCf.ContainsKey("CFM"))
                    {
                        string cfm = stdCf["CFM"].ToString();
                        if (cfm == "AESV2") return "AES-128";
                        if (cfm == "AESV3") return "AES-256";
                    }
                }
            }
        }

        return "Unknown";
    }


    private int GetKeyLength(Dictionary<string, object> encryptDict)
    {
        return encryptDict != null && encryptDict.ContainsKey("Length")
            ? (int)encryptDict["Length"]
            : 40; // Default key length
    }

    private byte[] GetFileID(Dictionary<string, object> trailer)
    {
        // Kiểm tra trailer có chứa thông tin FileID hay không
        if (trailer.ContainsKey("/ID"))
        {
            var fileId = trailer["/ID"];

            if (fileId is byte[] fileIdBytes)
            {
                // Trả về FileID nếu nó là một mảng byte
                return fileIdBytes;
            }
            else if (fileId is string fileIdString)
            {
                // Nếu FileID là chuỗi, chuyển nó thành mảng byte
                return System.Text.Encoding.ASCII.GetBytes(fileIdString);
            }
        }

        // Nếu không có FileID, trả về giá trị mặc định (chẳng hạn mảng byte rỗng)
        return new byte[16]; // Placeholder nếu không tìm thấy FileID
    }


    private byte[] GenerateEncryptionKey(string password, EncryptionInfo info)
    {
        // Padding password
        byte[] paddedPassword = new byte[32];
        byte[] passwordBytes = System.Text.Encoding.UTF8.GetBytes(password);
        Array.Copy(passwordBytes, paddedPassword, Math.Min(passwordBytes.Length, 32));

        // Initial key = padding || O || P || FileID
        using (var md5 = System.Security.Cryptography.MD5.Create())
        {
            byte[] initialKey = new byte[paddedPassword.Length + 4 + info.FileId.Length];
            Array.Copy(paddedPassword, initialKey, paddedPassword.Length);
            Array.Copy(info.FileId, 0, initialKey, paddedPassword.Length + 4, info.FileId.Length);

            // MD5 hash
            byte[] key = md5.ComputeHash(initialKey);

            // Truncate to key length
            if (info.KeyLength < 128)
            {
                Array.Resize(ref key, info.KeyLength / 8);
            }

            return key;
        }
    }

    private byte[] ReadNextChunk(BinaryReader reader)
    {
        const int CHUNK_SIZE = 4096;
        return reader.ReadBytes(CHUNK_SIZE);
    }

    private bool IsEncryptedStream(byte[] chunk)
    {
        // Check for stream marker
        string content = System.Text.Encoding.ASCII.GetString(chunk);
        return content.Contains("stream\n") || content.Contains("stream\r\n");
    }

    private byte[] GenerateAESKey(string password, EncryptionInfo info)
    {
        // Similar to GenerateEncryptionKey but with AES-specific modifications
        byte[] key = GenerateEncryptionKey(password, info);

        // Additional AES key preparation steps
        if (info.Version >= 5)
        {
            // For AES-256, apply additional SHA-256 hashing
            using (var sha256 = System.Security.Cryptography.SHA256.Create())
            {
                key = sha256.ComputeHash(key);
            }
        }

        return key;
    }

    private byte[,] KeyExpansion(byte[] key)
    {
        const int Nb = 4;  // block size
        const int Nk = 4;  // key length
        const int Nr = 10; // number of rounds

        byte[,] w = new byte[Nb * (Nr + 1), 4];

        // Copy the key into the first Nk words
        for (int i = 0; i < Nk; i++)
        {
            for (int j = 0; j < 4; j++)
            {
                w[i, j] = key[4 * i + j];
            }
        }

        // Generate the remaining words
        for (int i = Nk; i < Nb * (Nr + 1); i++)
        {
            byte[] temp = new byte[4];
            for (int j = 0; j < 4; j++)
                temp[j] = w[i - 1, j];

            if (i % Nk == 0)
            {
                temp = SubWord(RotWord(temp));
                temp[0] ^= Rcon(i / Nk);
            }

            for (int j = 0; j < 4; j++)
            {
                w[i, j] = (byte)(w[i - Nk, j] ^ temp[j]);
            }
        }

        return w;
    }

    private byte[,] AddRoundKey(byte[,] state, byte[,] roundKey, int round)
    {
        byte[,] result = new byte[4, 4];
        for (int i = 0; i < 4; i++)
        {
            for (int j = 0; j < 4; j++)
            {
                result[i, j] = (byte)(state[i, j] ^ roundKey[round * 4 + j, i]);
            }
        }
        return result;
    }

    private byte[,] InvShiftRows(byte[,] state)
    {
        byte[,] result = new byte[4, 4];

        // Row 0: no shift
        for (int j = 0; j < 4; j++)
            result[0, j] = state[0, j];

        // Row 1: shift right by 1
        for (int j = 0; j < 4; j++)
            result[1, j] = state[1, (j + 3) % 4];

        // Row 2: shift right by 2
        for (int j = 0; j < 4; j++)
            result[2, j] = state[2, (j + 2) % 4];

        // Row 3: shift right by 3
        for (int j = 0; j < 4; j++)
            result[3, j] = state[3, (j + 1) % 4];

        return result;
    }

    private byte[,] InvSubBytes(byte[,] state)
    {
        byte[,] result = new byte[4, 4];
        for (int i = 0; i < 4; i++)
        {
            for (int j = 0; j < 4; j++)
            {
                result[i, j] = INV_S_BOX[state[i, j]];
            }
        }
        return result;
    }

    private byte[,] InvMixColumns(byte[,] state)
    {
        byte[,] result = new byte[4, 4];
        for (int i = 0; i < 4; i++)
        {
            byte s0 = state[0, i];
            byte s1 = state[1, i];
            byte s2 = state[2, i];
            byte s3 = state[3, i];

            result[0, i] = (byte)(Multiply(0x0e, s0) ^ Multiply(0x0b, s1) ^
                                 Multiply(0x0d, s2) ^ Multiply(0x09, s3));
            result[1, i] = (byte)(Multiply(0x09, s0) ^ Multiply(0x0e, s1) ^
                                 Multiply(0x0b, s2) ^ Multiply(0x0d, s3));
            result[2, i] = (byte)(Multiply(0x0d, s0) ^ Multiply(0x09, s1) ^
                                 Multiply(0x0e, s2) ^ Multiply(0x0b, s3));
            result[3, i] = (byte)(Multiply(0x0b, s0) ^ Multiply(0x0d, s1) ^
                                 Multiply(0x09, s2) ^ Multiply(0x0e, s3));
        }
        return result;
    }

    // Helper methods cho AES
    private byte[] SubWord(byte[] word)
    {
        byte[] result = new byte[4];
        for (int i = 0; i < 4; i++)
        {
            result[i] = S_BOX[word[i]];
        }
        return result;
    }

    private byte[] RotWord(byte[] word)
    {
        byte[] result = new byte[4];
        result[0] = word[1];
        result[1] = word[2];
        result[2] = word[3];
        result[3] = word[0];
        return result;
    }

    private byte Rcon(int i)
    {
        byte[] rcon = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };
        return rcon[i - 1];
    }

    private byte Multiply(byte a, byte b)
    {
        byte result = 0;
        byte temp = b;
        while (a != 0)
        {
            if ((a & 1) != 0)
                result = (byte)(result ^ temp);
            temp = (byte)(temp << 1);
            if ((temp & 0x80) != 0)
                temp = (byte)(temp ^ 0x1b);
            a = (byte)(a >> 1);
        }
        return result;
    }

    private Dictionary<string, string> ParseFilterDetails(string filterEntry)
    {
        var details = new Dictionary<string, string>();
        int dictStart = filterEntry.IndexOf("<<");
        int dictEnd = filterEntry.IndexOf(">>");
        if (dictStart == -1 || dictEnd == -1) return details;

        string dictContent = filterEntry.Substring(dictStart + 2, dictEnd - dictStart - 2);
        string[] entries = dictContent.Split(new[] { '/' }, StringSplitOptions.RemoveEmptyEntries);

        foreach (string entry in entries)
        {
            string[] parts = entry.Trim().Split(new[] { ' ' }, 2, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length == 2)
            {
                details[parts[0]] = parts[1].Trim();
            }
        }

        return details;
    }

    private class PDFObject
    {
        public int ObjectNumber { get; set; }
        public int GenerationNumber { get; set; }
        public string Type { get; set; }
        public byte[] Data { get; set; }
        public Dictionary<string, string> Dictionary { get; set; }
    }

    private List<PDFObject> ParsePDFObjects(byte[] pdfBytes)
    {
        var objects = new List<PDFObject>();
        string content = System.Text.Encoding.ASCII.GetString(pdfBytes);

        // Regex để tìm object definitions
        var regex = new System.Text.RegularExpressions.Regex(@"(\d+)\s+(\d+)\s+obj[\r\n\s]");
        var matches = regex.Matches(content);

        foreach (System.Text.RegularExpressions.Match match in matches)
        {
            int objStart = match.Index;
            int objNum = int.Parse(match.Groups[1].Value);
            int genNum = int.Parse(match.Groups[2].Value);

            // Tìm end của object
            int endObjIndex = content.IndexOf("endobj", objStart);
            if (endObjIndex == -1) continue;

            // Extract object content
            string objContent = content.Substring(objStart, endObjIndex - objStart + 6);

            var pdfObj = new PDFObject
            {
                ObjectNumber = objNum,
                GenerationNumber = genNum,
                Dictionary = ParseObjectDictionary(objContent),
                Data = ExtractStreamData(objContent)
            };

            objects.Add(pdfObj);
        }

        return objects;
    }

    private Dictionary<string, string> ParseObjectDictionary(string objContent)
    {
        var dict = new Dictionary<string, string>();

        // Tìm dictionary trong object
        int dictStart = objContent.IndexOf("<<");
        if (dictStart == -1) return dict;

        int dictEnd = objContent.IndexOf(">>", dictStart);
        if (dictEnd == -1) return dict;

        string dictContent = objContent.Substring(dictStart + 2, dictEnd - dictStart - 2);

        // Parse từng entry trong dictionary
        var entries = dictContent.Split(new[] { '/' }, StringSplitOptions.RemoveEmptyEntries);
        foreach (var entry in entries)
        {
            var parts = entry.Trim().Split(new[] { ' ' }, 2, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length == 2)
            {
                dict[parts[0]] = parts[1].Trim();
            }
        }

        return dict;
    }

    private byte[] ExtractStreamData(string objContent)
    {
        int streamStart = objContent.IndexOf("stream\n");
        if (streamStart == -1) streamStart = objContent.IndexOf("stream\r\n");
        if (streamStart == -1) return null;

        int streamEnd = objContent.IndexOf("endstream", streamStart);
        if (streamEnd == -1) return null;

        // Điều chỉnh vị trí bắt đầu stream để bỏ qua marker
        streamStart = streamStart + "stream\n".Length;
        if (objContent[streamStart - 2] == '\r')
            streamStart++;

        // Extract stream data
        string streamContent = objContent.Substring(streamStart, streamEnd - streamStart);
        return System.Text.Encoding.ASCII.GetBytes(streamContent);
    }

    private class SecurityHandler
    {
        private byte[] _encryptionKey;
        private EncryptionInfo _encryptInfo;

        public SecurityHandler(byte[] encryptionKey, EncryptionInfo encryptInfo)
        {
            _encryptionKey = encryptionKey;
            _encryptInfo = encryptInfo;
        }

        public byte[] DecryptStream(byte[] streamData, int objNumber, int genNumber)
        {
            // Generate key for specific object
            byte[] objKey = GenerateObjectKey(objNumber, genNumber);

            if (_encryptInfo.EncryptionMethod == "RC4")
            {
                return RC4DecryptStream(streamData, objKey);
            }
            else if (_encryptInfo.EncryptionMethod == "AES")
            {
                return AESDecryptStream(streamData, objKey);
            }

            throw new Exception("Unsupported encryption method");
        }

        private byte[] GenerateObjectKey(int objNumber, int genNumber)
        {
            using (var md5 = System.Security.Cryptography.MD5.Create())
            {
                byte[] input = new byte[_encryptionKey.Length + 5];
                Array.Copy(_encryptionKey, input, _encryptionKey.Length);

                // Add object and generation numbers
                input[_encryptionKey.Length] = (byte)objNumber;
                input[_encryptionKey.Length + 1] = (byte)(objNumber >> 8);
                input[_encryptionKey.Length + 2] = (byte)(objNumber >> 16);
                input[_encryptionKey.Length + 3] = (byte)genNumber;
                input[_encryptionKey.Length + 4] = (byte)(genNumber >> 8);

                return md5.ComputeHash(input);
            }
        }

        private byte[] RC4DecryptStream(byte[] streamData, byte[] key)
        {
            // RC4 implementation từ trước
            return new RC4(key).ProcessBytes(streamData);
        }

        private byte[] AESDecryptStream(byte[] streamData, byte[] key)
        {
            if (streamData.Length < 16) // IV size
                throw new Exception("Invalid AES stream data");

            byte[] iv = new byte[16];
            Array.Copy(streamData, 0, iv, 0, 16);

            byte[] encryptedData = new byte[streamData.Length - 16];
            Array.Copy(streamData, 16, encryptedData, 0, encryptedData.Length);

            using (var aes = System.Security.Cryptography.Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;
                aes.Mode = System.Security.Cryptography.CipherMode.CBC;
                aes.Padding = System.Security.Cryptography.PaddingMode.PKCS7;

                using (var decryptor = aes.CreateDecryptor())
                {
                    return decryptor.TransformFinalBlock(encryptedData, 0, encryptedData.Length);
                }
            }
        }
    }

    private class RC4
    {
        private byte[] _state;
        private int _i, _j;

        public RC4(byte[] key)
        {
            _state = new byte[256];
            for (int i = 0; i < 256; i++)
                _state[i] = (byte)i;

            _i = _j = 0;
            int j = 0;
            for (int i = 0; i < 256; i++)
            {
                j = (j + _state[i] + key[i % key.Length]) % 256;
                Swap(i, j);
            }
        }

        private void Swap(int i, int j)
        {
            byte temp = _state[i];
            _state[i] = _state[j];
            _state[j] = temp;
        }

        public byte[] ProcessBytes(byte[] data)
        {
            byte[] output = new byte[data.Length];
            for (int k = 0; k < data.Length; k++)
            {
                _i = (_i + 1) % 256;
                _j = (_j + _state[_i]) % 256;
                Swap(_i, _j);
                int t = (_state[_i] + _state[_j]) % 256;
                output[k] = (byte)(data[k] ^ _state[t]);
            }
            return output;
        }
    }
}