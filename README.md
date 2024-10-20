<h3>Purpose: </h3>
To work with data and give encryption/decryption solutions.

This project is ongoing work. However, it does supply the basics. *_*

<h3>Build:</h3>
Simply copy the SecurityClass() code over your your copy and implement the functions. There are examples with comments:

```
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

                Console.WriteLine("DECRYPTION:");
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

```
