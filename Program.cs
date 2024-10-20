/*
 * Cat's Claw Encrypt/Decrypt Security Helper 
 * C.Winters / US / Arizona / Thinkpad T15g
 * 20-Oct-2024
 * 
 * Remember: If it doesn't work, I didn't write it.
 *
 * Purpose: To work with data and give encryption/decryption solutions.
 *
 * Origin: A project I worked on (Repeater) needs to decrypt values in a config file, but is not supported in 
 * its alpha stages. 
 * The need is to have this as a library to decrypt the values from the config files and later through memory
 * or authentication redirection such as Vault, secrets, or environment variables.
 * System.Security.Cryptography was an interesting thing to learn.
 * 
 * EXAMPLES:
 * To see functionality, take a gander at main(). There's examples step by step and expected output from the 
 * mock examples. 
 * 
 * TODO/FUTURE:
 * - Change functions that have "salt" and use "secret key" instead. These seem to confuse during design-time.
 * - Change function that have "encrypted key" to use "passwords" instead. These seem to confuse during design-time.
 */
using System;
using System.Security.Cryptography;
using System.Text;
using System.IO;
using System.Runtime.CompilerServices;
using System.ComponentModel;
using System.Reflection.Metadata.Ecma335;
using System.Diagnostics.CodeAnalysis;
using System.Reflection;
using System.Data.SqlTypes;

namespace com.winters.securityhelper
{
    public interface ISecurityHelperLogger
    {
        void LogError(string message);
        void LogWarning(string message);
        void LogInfo(string message);
    }

    public class SecurityHelper
    {
        //logger member
        private static ISecurityHelperLogger? _logger;

        // Property to set the logger - internal or external
        public static ISecurityHelperLogger? Logger
        {
            get => _logger;
            set => _logger = value;
        }
        //Initing the class:
        //SecurityHelper.Logger = new CustomLogger();

        //Internal info to keep track of the encryption key and salt. 
        [EditorBrowsable(EditorBrowsableState.Never)]
        private static string? _combinedKeySalt = "";

        //Internal info to keep track of the encryption key and salt
        //if we do an override encryption/decryption without
        //ecapsulation. This relies on flag _manualOverride
        [EditorBrowsable(EditorBrowsableState.Never)]
        private static string? _combinedKeySaltOverride = "";

        [EditorBrowsable(EditorBrowsableState.Never)]
        private static bool _manualOverride = false;


        //The encryption passcode to be used for encryption.
        [EditorBrowsable(EditorBrowsableState.Never)]
        private static string? _EncryptionKey = "";
        
        //Stringable salt for non-randomized encryption. This also makes it more difficult to 
        //decrypt an encrypted secret. 
        [EditorBrowsable(EditorBrowsableState.Never)]
        private static string? _Salt = "";
        
        //Length of salt can be specified if random generating salt
        [EditorBrowsable(EditorBrowsableState.Never)]
        private static int _SaltLength = 0;

        //Internal: Security storage for encrypted password key and secure key.
        [EditorBrowsable(EditorBrowsableState.Never)]
        private static string CombinedKeySalt
        {
            set => _combinedKeySalt = value;
            get => _combinedKeySalt ?? string.Empty;
        }

        //Internal: Security storage for overrride encrypted password key and secure key.
        [EditorBrowsable(EditorBrowsableState.Never)]   
        private static string CombinedKeySaltOverride
        {
            set => _combinedKeySaltOverride = value;
            get => _combinedKeySaltOverride ?? string.Empty;
        }

        public static string EncryptionKey
        {
            set => _EncryptionKey = value; 
            get => _EncryptionKey ?? string.Empty;
        }

        public static string Salt
        {
            set => _Salt = value;
            get => (_Salt ?? string.Empty);
        }

        public static int SaltLength
        {
            set => _SaltLength = value;
            get => (_SaltLength );
        }

        public static string GetCombinedKeySalt()
        {
            return (CombinedKeySalt);

        }

        /// <summary>
        /// Encrypts string with the ability to isolate and override parameters.
        /// </summary>
        /// <param name="clearText">clear text to pass in and encrypt</param>
        /// <param name="encryptionKey">a password string to derive encryption from</param>
        /// <param name="saltString">key salt value to make unauthorized decrypting of a message more difficult</param>
        /// <param name="saltLength">Set salt length if encryptionKey and saltString are null, generate random key and salt </param>
        /// Example:
        /// string customKey = "MyCustomEncryptionKey";
        /// string saltString = "Chris Winters";
        /// string encryptedText = SecurityHelper.Encrypt("NO more secrets!", customKey, saltString);
        /// <returns>Encrypted string, but use GetEncryptionKey(),GetSalt(), or GetSaltEncryption() to obtain the encryption key and salt value </returns>
        /// Complete - 18-10-2024
        public static string Encrypt(string? clearText, string? encryptionKey = null, string? saltString = null, int saltLength = 40)
        {
            //Manual override for manual - when calling CombineKeySalt() the internal pointer will hold
            //the secure keys encrypted separately from the intended setup (init'ed preference or encapsulated)
            _manualOverride = true;

            //Record/udpate the combination of encryption key and salt string
            if (!string.IsNullOrEmpty(saltString))
                CombineKeySalt(encryptionKey, Convert.FromBase64String(saltString));

            //null-coalescing assignment operator (??=) checks if the variable is null, and only then does it assign a value.
            encryptionKey ??= GenerateRandomString(16);

            //Convert provided salt string to byte array or generate random salt (40 bytes)
            //Ternary - if saltBytes not null, then encode bytes into saltBytes array, or generate a random set.
            byte[] saltBytes = !string.IsNullOrEmpty(saltString)
                ? Encoding.Unicode.GetBytes(saltString)
                : GenerateRandomBytes(saltLength);

            //Encodes characters in string to bytes
            byte[] clearBytes = Encoding.Unicode.GetBytes(clearText);

            using (System.Security.Cryptography.Aes crypto = System.Security.Cryptography.Aes.Create())
            {
                //TODO -pass in iteration num rather than magic-number
                Rfc2898DeriveBytes pbkdf2 = new Rfc2898DeriveBytes(encryptionKey, saltBytes, 1000, HashAlgorithmName.SHA256);
                // AES-256 key
                crypto.Key = pbkdf2.GetBytes(32);
                // 128-bit initialization vector (IV)
                crypto.IV = pbkdf2.GetBytes(16);

                using (System.IO.MemoryStream memStream = new System.IO.MemoryStream())
                {
                    using (System.Security.Cryptography.CryptoStream cryptoStream =
                        new System.Security.Cryptography.CryptoStream(memStream, crypto.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(clearBytes, 0, clearBytes.Length);
                        cryptoStream.Close();
                    }
                    clearText = Convert.ToBase64String(memStream.ToArray());
                }
            }
            return (clearText);
        }

        /// <summary>
        /// Encrypts string 
        /// </summary>
        /// <param name="clearText">clear text to pass in and encrypt. The secure key (salt) and encryption keys are setup by class properties </param>
        /// Example:
        /// SecurityHelper.EncryptionKey = "My Custom Encryption Key";
        /// SecurityHelper.Salt = "ChrisWinters";
        /// SecurityHelper.Init();
        /// string encryptedText = SecurityHelper.Encrypt("NO more secrets!");
        /// <returns>Encrypted string</returns>
        /// Complete - 18-10-2024
        public static string Encrypt(string clearText)
        {
            //Record/udpate the combination of encryption key and salt string
            //if (!string.IsNullOrEmpty(SecurityHelper.Salt))
            //    CombineKeySalt(SecurityHelper.EncryptionKey, Convert.FromBase64String(SecurityHelper.Salt));

            // null-coalescing assignment operator (??=) checks if SecurityHelper.EncryptionKey is null
            // and only then does it assign a value.
            SecurityHelper.EncryptionKey ??= GenerateRandomString(16);

            //Convert provided salt string to byte array or generate random salt (40 bytes)
            //Ternary - if saltBytes not null, then encode bytes into saltBytes array, or generate a random set.
            byte[] saltBytes = !string.IsNullOrEmpty(SecurityHelper.Salt)
                ? Encoding.Unicode.GetBytes(SecurityHelper.Salt)
                : GenerateRandomBytes(SecurityHelper.SaltLength);

            //Encodes characters in string to bytes
            byte[] clearBytes = Encoding.Unicode.GetBytes(clearText);

            using (System.Security.Cryptography.Aes crypto = System.Security.Cryptography.Aes.Create())
            {
                //TODO -pass in iteration num rather than magic-number
                Rfc2898DeriveBytes pbkdf2 = new Rfc2898DeriveBytes(SecurityHelper.EncryptionKey, saltBytes, 1000, HashAlgorithmName.SHA256);
                // AES-256 key
                crypto.Key = pbkdf2.GetBytes(32);
                // 128-bit initialization vector (IV)
                crypto.IV = pbkdf2.GetBytes(16);

                using (System.IO.MemoryStream memStream = new System.IO.MemoryStream())
                {
                    using (System.Security.Cryptography.CryptoStream cryptoStream =
                        new System.Security.Cryptography.CryptoStream(memStream, crypto.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(clearBytes, 0, clearBytes.Length);
                        cryptoStream.Close();
                    }
                    clearText = Convert.ToBase64String(memStream.ToArray());
                }
            }
            return (clearText);
        }

        /// <summary>
        /// Decrypts a string with the ability to isolate and override parameters.
        /// </summary>
        /// <param name="cipherText">Encrypted string to decrypt</param>
        /// <returns>Decrypted string from original encryption key and salt</returns>
        /// <exception cref="ArgumentException">Encryption key and salt /must/ be provided for decryption</exception>
        /// Completed 19-10-2024
        public static string Decrypt(string cipherText)
        {
            if (string.IsNullOrEmpty(SecurityHelper.EncryptionKey) || string.IsNullOrEmpty(SecurityHelper.Salt))
                throw new ArgumentException("Encryption key and salt /must/ be provided for decryption.");

            // Use the original salt for decryption by converting the string to its original byte arr
            byte[] saltBytes = Encoding.Unicode.GetBytes(SecurityHelper.Salt);
            cipherText = cipherText.Replace(" ", "+");
            byte[] cipherBytes = Convert.FromBase64String(cipherText);

            using (System.Security.Cryptography.Aes crypto = System.Security.Cryptography.Aes.Create())
            {
                Rfc2898DeriveBytes pbkdf2 = new Rfc2898DeriveBytes(SecurityHelper.EncryptionKey, saltBytes, 1000, HashAlgorithmName.SHA256);
                // 256-bit key
                crypto.Key = pbkdf2.GetBytes(32);
                // 128-bit initialization vector (IV)
                crypto.IV = pbkdf2.GetBytes(16);
                crypto.Padding = PaddingMode.PKCS7;

                using (System.IO.MemoryStream memStream = new System.IO.MemoryStream())
                {
                    using (System.Security.Cryptography.CryptoStream cryptoStream =
                        new System.Security.Cryptography.CryptoStream(memStream, crypto.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        try
                        {
                            cryptoStream.Write(cipherBytes, 0, cipherBytes.Length);
                            cryptoStream.Close();
                        }
                        catch (System.Security.Cryptography.CryptographicException)
                        {
                            return ("Error: Decryption failed.");
                        }
                    }
                    cipherText = Encoding.Unicode.GetString(memStream.ToArray());
                }
            }
            return (cipherText);
        }


        /// <summary>
        /// Decrypts a string with the ability to isolate and override parameters.
        /// </summary>
        /// <param name="cipherText">Encrypted string to decrypt</param>
        /// <param name="encryptionKey">a password string to decrypt originally generated from an encrypted string</param>
        /// <param name="saltString">key salt value to make unauthorized decrypting of a message more difficult</param>
        /// <returns>Decrypted string from original encryption key and salt</returns>
        /// <exception cref="ArgumentException">Encryption key and salt /must/ be provided for decryption</exception>
        /// Completed 18-10-2024
        public static string Decrypt(string cipherText, string encryptionKey, string saltString)
        {
                if (string.IsNullOrEmpty(encryptionKey) || string.IsNullOrEmpty(saltString))
                    throw new ArgumentException("Encryption key and salt /must/ be provided for decryption.");

            // Use the original salt for decryption by converting the string to its original byte arr
            byte[] saltBytes = Encoding.Unicode.GetBytes(saltString);
            cipherText = cipherText.Replace(" ", "+");
            byte[] cipherBytes = Convert.FromBase64String(cipherText);

            using (System.Security.Cryptography.Aes crypto = System.Security.Cryptography.Aes.Create())
            {
                Rfc2898DeriveBytes pbkdf2 = new Rfc2898DeriveBytes(encryptionKey, saltBytes, 1000, HashAlgorithmName.SHA256);
                // 256-bit key
                crypto.Key = pbkdf2.GetBytes(32);
                // 128-bit initialization vector (IV)
                crypto.IV = pbkdf2.GetBytes(16);
                crypto.Padding = PaddingMode.PKCS7;

                /*
                 * note:
                 * Error: Padding is invalid and cannot be removed
                 * Make sure that the keys you use to encrypt and decrypt are the same. 
                 * The padding method even if not explicitly set should still allow for 
                 * proper decryption/encryption (if not set they will be the same). However 
                 * if you for some reason are using a different set of keys for decryption 
                 * than used for encryption you will get this error.
                 * See additional info under CombineKeySalt()
                 */

                using (System.IO.MemoryStream memStream = new System.IO.MemoryStream())
                {
                    using (System.Security.Cryptography.CryptoStream cryptoStream =
                        new System.Security.Cryptography.CryptoStream(memStream, crypto.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        try
                        {
                            cryptoStream.Write(cipherBytes, 0, cipherBytes.Length);
                            cryptoStream.Close();
                        }
                        catch (System.Security.Cryptography.CryptographicException)
                        {
                            return ("Error: Decryption failed.");
                        }
                    }
                    cipherText = Encoding.Unicode.GetString(memStream.ToArray());
                }
            }
            return (cipherText);
        }


        /// <summary>
        /// Generates a random string from a specified length (default =25)
        /// </summary>
        /// <param name="stringLength">Specify the length of randomized string</param>
        /// <returns>A randomized string</returns>
        /// Completed 18-10-2024
        public static string GenerateRandomString(int length =25)
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            Random random = new Random();
            char[] stringChars = new char[length];

            for (int i = 0; i < length; i++)
            {
                stringChars[i] = chars[random.Next(chars.Length)];
            }
            return (new string(stringChars));
        }

        /// <summary>
        /// Generates random byte array from a specified length (default =25)
        /// </summary>
        /// <param name="length">Specify the length of randomized byte array</param>
        /// <returns>a byte array with random bytes</returns>
        /// Completed 18-10-2024
        public static byte[] GenerateRandomBytes(int length = 25)
        {
            byte[] randomBytes = new byte[length];
            RandomNumberGenerator.Fill(randomBytes);
            return (randomBytes);
        }


        /// <summary>
        /// Convert string to a byte array
        /// </summary>
        /// <param name="input">string to convert to byte arrary</param>
        /// <returns>Returns a byte array</returns>
        /// Example:
        /// byte[] arRes = ConvertStringToByteArray("Test me!");
        /// Completed 18-10-2024
        public static byte[] ConvertStringToByteArray(string input)
        {
            return (System.Text.Encoding.UTF8.GetBytes(input));
        }


        /// <summary>
        /// Convert a byte array to string
        /// </summary>
        /// <param name="sourceArray">source byte array to convert to string</param>
        /// <returns>string of sourced byte array</returns>
        /// //Completed: 19-10-2024
        public static string ConvertByteArrayToString(byte [] sourceArray)
        {
            return (Convert.ToBase64String((sourceArray)));
        }


        /// <summary>
        /// Converts a string from hexidecial format to a readable string
        /// </summary>
        /// <param name="hexString">The source string to convert</param>
        /// <returns>readable strings from hexidecimal values</returns>
        /// Example:
        /// // Hex representation of string "test"
        /// string hexString = "74657374";
        /// string result = ConvertHexToString(hexString);
        /// // Expected output: "test"
        /// Console.WriteLine(result);  
        public static string ConvertHexToString(string hexString)
        {
            // Add leading zero if string has an odd number of characters
            if (hexString.Length % 2 != 0)
                hexString = "0" + hexString;

            System.Text.StringBuilder sb = new System.Text.StringBuilder();

            for (int i = 0; i < hexString.Length; i += 2)
            {
                string hs = hexString.Substring(i, 2);
                try
                {
                    sb.Append(Convert.ToString(Convert.ToChar(Int32.Parse(hs, System.Globalization.NumberStyles.HexNumber))));
                }
                catch (System.FormatException)
                {
                    return string.Empty; // Handle invalid hex format
                }
            }
            return (sb.ToString());
        }

        /// <summary>
        /// Converts a string to hex format
        /// </summary>
        /// <param name="clearText">source string to convert</param>
        /// <returns>Returns a hex formatted string</returns>
        /// Example:
        /// Convert a string "test" to hex and back again:
        /// string hexString = ConvertStringToHex("test");
        ///  // Expected output: "74657374"
        /// string result = ConvertHexToString(hexString);
        /// // Expected output: "test"
        /// Console.WriteLine(result); 
        /// Completed 18-10-2024
        public static string ConvertStringToHex(string clearText)
        {
            //Create stringbuilder for mutable text string
            System.Text.StringBuilder sb = new System.Text.StringBuilder();

            byte[] arByteRes = ConvertStringToByteArray(clearText);

            for (int iArrayIter = 0; iArrayIter < arByteRes.Length; iArrayIter++)
            {
                byte bTmpByte = arByteRes[iArrayIter];
                sb.Append(bTmpByte.ToString("X2"));
            }
            return (sb.ToString());

            //todo: cleaner way:
            //byte[] byteArray = Encoding.UTF8.GetBytes(input);
            //return BitConverter.ToString(byteArray).Replace("-", "");
        }


        /// <summary>
        /// Combines the encryption key and salt
        /// </summary>
        /// <param name="encryptionKey">Source generated encryption key</param>
        /// <param name="saltBytes">Source generated salt</param>
        /// <returns>Returns a combined value of encryption key and salt with a colon (:) separation the values</returns>
        /// Completed 19-10-2024
        private static void CombineKeySalt(string encryptionKey, byte[] saltBytes)
        {
            //ToBase64String WILL remove space since it's an invalid character when converting.
            //Debugging why DecryptByCombinedKeySalt() would not work at the time, I realised the salt
            //string value was changed. After CLOSELY examining the strings with this line, I was
            //able to find this out:
            //if ((SecurityHelper.EncryptionKey == encryptedKey) && (SecurityHelper.Salt == uncombinedSalt))
            //    Console.WriteLine("Both match with current");
            // THAT slipped me. "My Salt" was different from "MySalt", thus corrupting the cipherText. 
            //The the following error under Decrypt(string cipherText, string encryptionKey, string saltString)
            //"Error: Padding is invalid and cannot be removed"
            string saltBytesToString = Convert.ToBase64String(saltBytes);
            String sTmpTest = encryptionKey + ":" + Convert.ToBase64String(saltBytes);

            if (_manualOverride)
                CombinedKeySaltOverride = ConvertStringToHex(encryptionKey + ":" + Convert.ToBase64String(saltBytes));
            else
                CombinedKeySalt = ConvertStringToHex(encryptionKey + ":" + Convert.ToBase64String(saltBytes));
                
            _manualOverride = false;
            //return $"{encryptionKey}:{Convert.ToBase64String(saltBytes)}";
        }

        /// <summary>
        /// Decrypts a secret message by passing in a combined encrypted key and salt.
        /// </summary>
        /// <param name="cipherText">The string containing encrypted message/secret</param>
        /// <param name="combinedKeySalt">source string from a previous encrypted key/salt from a combined secure storage</param>
        /// <returns>string to a decrypted message/secret</returns>
        /// Completed 19-10-2024
        public static string DecryptByCombinedKeySalt(string? cipherText, string? combinedKeySalt)
        {
            if (string.IsNullOrEmpty(cipherText) || string.IsNullOrEmpty(combinedKeySalt))
                //throw new ArgumentException("Cipher text must be provided for decryption.");
                return (string.Empty);

            (string encryptedKey, _) = UnCombineKeySalt(combinedKeySalt);
            string uncombinedSalt = GetSaltBytesStr(combinedKeySalt);

            string? deciphered = null;
            deciphered ??= Decrypt(cipherText, encryptedKey, uncombinedSalt);
            //string deciphered = Decrypt(cipherText, encryptedKey, saltBytes);
            return (deciphered);
        }


        /// <summary>
        /// Decrypt the combined encryption key (password) and secure key (salt)
        /// </summary>
        /// <param name="encryptedKeyAndSalt">string to the encrypted combined security storage of the password and secure key</param>
        /// <returns></returns>
        /// <exception cref="FormatException"></exception>
        /// NOTE: This is a private function, helper mostly. 
        /// The CombinedKeySalt is an encrypted combination security storage of the encryption key (password)
        /// and secure key (salt). Both are combined with a colon (:) during encryption. That format apepars like this:
        /// "encryptionkey:securekey"
        /// After the format is constructed, it is then encrypted for use. That format is then turned into alpha-numeric
        /// upper-cased characters. See example below.
        /// 
        /// Examples:
        /// encryptedPassAndKey = "4D7920437573746F6D20456E6372797074696F6E204B65793A436872697357696E74657273"
        /// 
        /// (string password, byte [] securekey) = UnCombineKeySalt(encryptedPassAndKey);
        /// During this function, "encryptedPassAndKey" will translate into this: "My Custom Encryption Key:ChrisWinters"
        /// Then it is separated art the colon and returned separately into a string and byte array. 
        /// Completed 19-10-2024
        private static (string? encryptionKey, byte[]? saltBytes) UnCombineKeySalt(string encryptedKeyAndSalt)
        {
            // Decrypt the combined key and salt string
            //string decryptedKeyAndSalt = DecryptString(encryptedKeyAndSalt);
            string decryptedKeyAndSalt = ConvertHexToString(encryptedKeyAndSalt);

            // Split the decrypted string into key and salt based on the delimiter ":"
            string[] parts = decryptedKeyAndSalt.Split(':');
            if (parts.Length == 2)
            {
                string encryptionKey = parts[0];
                byte[] saltBytes = Convert.FromBase64String(parts[1]);

                // Return the encryption key and salt as a tuple
                return (encryptionKey, saltBytes);
            }

            Logger?.LogError("Invalid format of combined password and secure key.");
            //throw new FormatException("Invalid format of combined encryption key and salt.");
            return (encryptionKey: null, saltBytes: null);
        }



        /// <summary>
        /// Return the encryption key (password) used in the encryption
        /// </summary>
        /// <param name="encryptedKeyAndSalt">source string that points to a predetermined encrypted password and secure key</param>
        /// <returns>string of the encrypted password</returns>
        /// Completed 19-10-2024
        public static string GetEncryptionKey(string encryptedKeyAndSalt)
        {
            (string encryptionKey, _) = UnCombineKeySalt(encryptedKeyAndSalt);
            return encryptionKey;
        }


        /// <summary>
        /// Return the secure key (salt) used in the encryption
        /// </summary>
        /// <param name="encryptedKeyAndSalt">source string that points to a predetermined encrypted password and secure key (salt)</param>
        /// <returns>byte array of the secure key (salt)</returns>
        /// Completed 19-10-2024
        public static byte[] GetSalt(string encryptedKeyAndSalt)
        {
            (_, byte[] saltBytes) = UnCombineKeySalt(encryptedKeyAndSalt);
            return saltBytes;
        }

        /// <summary>
        /// Get secure key (salt) in a byte representation
        /// </summary>
        /// <param name="encryptedKeyAndSalt"></param>
        /// <returns>string containing the byte array representation of the encrypted secure key (salt)</returns>
        /// Completed: 19-10-2024
        public static string GetSaltBytesStr(string encryptedKeyAndSalt)
        {
            (_, byte[] saltBytes) = UnCombineKeySalt(encryptedKeyAndSalt);
            return (Convert.ToBase64String(saltBytes));
        }

        /// <summary>
        /// Checks for validation of a salt string
        /// </summary>
        /// <param name="salt">source string to a salt value</param>
        /// <exception cref="ArgumentException"></exception>
        /// Completed: 19-10-2024
        private static void ValidateSalt(string salt)
        {
            if ( (string.IsNullOrWhiteSpace(salt)) || (salt.Contains(" ")) )
            {
                Logger?.LogError("Invalid salt! No null or whitespaces.");
                //throw new ArgumentException("Invalid salt! No null or whitespaces.");
            }
            Logger?.LogInfo("Init validated");
        }

        /// <summary>
        /// Initializes the encryption/decryption process checking for validation and encapsulate encryption info
        /// </summary>
        /// Completed 19-10-2024 
        public static void Init()
        {
            ValidateSalt(SecurityHelper.Salt);

            if (!string.IsNullOrEmpty(SecurityHelper.Salt))
                CombineKeySalt(SecurityHelper.EncryptionKey, Convert.FromBase64String(SecurityHelper.Salt));
        }


        // / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / 
        //Example "external" logging to capture logging in SecurityHelper class
        // / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / 
        public class CustomLogger : ISecurityHelperLogger
        {
            //Log errors....
            public void LogError(string message)
            {
                Console.ForegroundColor = ConsoleColor.Red; 
                Console.WriteLine($"[ERROR] {DateTime.Now}: {message}");
                Console.ResetColor();
            }

            // Log warnings...
            public void LogWarning(string message)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine($"[WARNING] {DateTime.Now}: {message}");
                Console.ResetColor();
            }

            // Log informational...
            public void LogInfo(string message)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"[INFO] {DateTime.Now}: {message}");
                Console.ResetColor();
            }
        }

        // / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / 
        //Example "external" logging to capture logging in SecurityHelper class
        // / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / 
        internal class Program
        {
            static void Main(string[] args)
            {
                // Create logger instance
                CustomLogger customLogger = new CustomLogger();

                // Initialize the logger in SecurityHelper
                SecurityHelper.Logger = customLogger;

                customLogger.LogInfo("Starting...");

                ///////////////////////////////////////////////////////////////////////////////                
                // Example 1: Using custom encryption key (password) and secure key (salt)
                ///////////////////////////////////////////////////////////////////////////////

                //Set up encryption key (password) and secure key (salt)
                SecurityHelper.EncryptionKey = "My Custom Encryption Key";
                SecurityHelper.Salt = "ChrisWinters";
                
                //Initialize security validation
                SecurityHelper.Init();
                
                //Encapsulation encrypt and decrypt
                string encryptedText = SecurityHelper.Encrypt("NO more secrets!");
                string decryptedText = SecurityHelper.Decrypt(encryptedText);

                //-----That's it! But, wait! There's more!

                //Overriding encryption/decryption -not ecapsulated, but new/isolated password and secure keys
                string encryptedTextB = SecurityHelper.Encrypt("No more OTHER secrets", "NewPassword", "NewSecretKey");
                string decryptedTextB = SecurityHelper.Decrypt(encryptedTextB, "NewPassword", "NewSecretKey");

                //Another encryption/decryption under same ecapsulation
                string encryptedText2 = SecurityHelper.Encrypt("Another message");
                string decryptedText2 = SecurityHelper.Decrypt(encryptedText2);

                //With the two last calls, you can see the encapulated setup retains previous setup when
                //a manual encryp/decrypt calls are made with overrides. This way later on you can still use 
                //the same setup to encrypt or decrypt additional data. 

                //Now, a few utility functions...

                //Gets the encryption key, or the password, set earlier.
                string uncombinedencryptionkey = SecurityHelper.GetEncryptionKey(SecurityHelper.CombinedKeySalt);

                //Gets the secure key and displays it as a string
                string uncombinedsaltbytesstr = SecurityHelper.GetSaltBytesStr(SecurityHelper.CombinedKeySalt);

                //Gets the secure key and displays it as a byte array
                byte[] uncombinedsaltbytes = SecurityHelper.GetSalt(SecurityHelper.CombinedKeySalt);

                //Decrypt secret with a predetermined secret key
                string decryptByCombinedKeySalt = DecryptByCombinedKeySalt(encryptedText, SecurityHelper.CombinedKeySalt);

                Console.WriteLine($"customKey: {SecurityHelper.EncryptionKey}");
                Console.WriteLine($"saltString: {SecurityHelper.Salt}");
                Console.WriteLine($"combinedSecurityStorage: {SecurityHelper.CombinedKeySalt}");
                Console.WriteLine($"encryptedText: {encryptedText}");
                Console.WriteLine($"decryptedText: {decryptedText}");

                Console.WriteLine($"encryptedTextB: {encryptedTextB}");
                Console.WriteLine($"decryptedTextB: {decryptedTextB}");

                Console.WriteLine($"encryptedText2: {encryptedText2}");
                Console.WriteLine($"decryptedText2: {decryptedText2}");

                Console.WriteLine("DECRYPTIONED:");
                Console.WriteLine($"uncombinedencryptionkey: {uncombinedencryptionkey}");
                Console.WriteLine($"uncombinedsaltbytesStr: {uncombinedsaltbytesstr}");
                Console.Write("uncombinedsaltBytes: ");

                foreach (byte b in uncombinedsaltbytes)
                {
                    Console.Write($"{b:X2} ");
                }
                Console.WriteLine();

                Console.WriteLine($"decryptByCombinedKeySalt: {decryptByCombinedKeySalt}\n");

                /*
                    Expected output:
                    customKey: My Custom Encryption Key
                    saltString: ChrisWinters
                    combinedSecurityStorage: 4D7920437573746F6D20456E6372797074696F6E204B65793A436872697357696E74657273
                    encryptedText: 4SjxZJmcp4lhxsGn8SAxEPkdi81gKY0WkRYwPmKEAibRL/bj//nGpvHX1BzEJt2Q
                    decryptedText: NO more secrets!
                    encryptedTextB: GOUiT0XYp20MZpdny9vIAZRLRdoWT4OsxD79ETx88+33Dhjz099LWc5mv6U1lYaR
                    decryptedTextB: No more OTHER secrets
                    encryptedText2: /bSeuQUVN76LIJ7iwpz/h1DM+9TWpyi4jsxeBn68vMY=
                    decryptedText2: Another message
                    DECRYPTIONED:
                    uncombinedencryptionkey: My Custom Encryption Key
                    uncombinedsaltbytesStr: ChrisWinters
                    uncombinedsaltBytes: 0A 1A E2 B1 68 A7 B5 EA EC
                    decryptByCombinedKeySalt: NO more secrets!
                */


                ///////////////////////////////////////////////////////////////////////////////
                // Example 2: Random encryption using a random encryption key (password)
                // and secure key (salt)
                ///////////////////////////////////////////////////////////////////////////////

                //Set up random encryption key (password) and secure key (salt) with a length of 32.
                SecurityHelper.EncryptionKey = SecurityHelper.GenerateRandomString(32);
                SecurityHelper.Salt = SecurityHelper.ConvertByteArrayToString(SecurityHelper.GenerateRandomBytes(32));

                //Initialize security validation
                SecurityHelper.Init();

                //Encapsulation encrypt and decrypt
                string encryptedTextRnd = SecurityHelper.Encrypt("Secrets are NO more!");
                string decryptedTextRnd = SecurityHelper.Decrypt(encryptedTextRnd);

                Console.WriteLine($"combinedSecurityStorage: {SecurityHelper.CombinedKeySalt}");
                Console.WriteLine($"encryptedTextRnd: {encryptedTextRnd}");
                Console.WriteLine($"decryptedTextRnd: {decryptedTextRnd}");

                /*
                    Expected output:
                    combinedSecurityStorage: 7835375959657A5355744957447939316D5357654E515732556959656748395A3A6467446D47674A4B4B79455649774A3272544965554B483848666B4173624F70346C7A6E43724F35324C553D
                    encryptedTextRnd: 5yrKJJs64CC8xyvKwFqsj5YG4VZfyp8azGngtqTl7bSzvaBtA0taFqAqb9VOnwk2
                    decryptedTextRnd: Secrets are NO more!
                 */

            }
        }
    }
}
