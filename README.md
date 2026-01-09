**Project:** Cat's Claw Security Helper<BR>
**Codename:** function_3<BR>
**Method:** This project uses AES-256 symmetric encryption, deriving keys from passwords and salts for secure string encryption and decryption. All cryptographic operations are provided through a simple static helper class.<BR>
**Lang/Dev Env:** C#, .NET 8 - Library/Tooling - Visual Studio 2022.

# Cat's Claw Security Helper

## Summary
Cat's Claw Security Helper is a C# library and tool for encrypting and decrypting data using AES-256. It is designed to help secure sensitive configuration values or secrets, with support for custom or randomly generated keys and salts (secret keys). The library is flexible for use in other projects or as a standalone tool.

## Introduction
This project provides a simple, extensible, and well-documented set of encryption/decryption helpers for .NET projects. It is ideal for scenarios where you need to secure configuration values, secrets, or any sensitive data, and can be used as a library or as a reference implementation.

## Project Architecture

### Function Flow

```mermaid
flowchart TD
    A[Start: Set Encryption Key & Salt] --> B[Init SecurityHelper]
    B --> C[Encrypt Data]
    C --> D[Store/Transmit Encrypted Data]
    D --> E[Decrypt Data]
    E --> F[Retrieve Original Data]
    B --> G[Override Key/Salt (Optional)]
    G --> C
    C --> H[Utility Functions]
    H --> I[Get Key/Salt]
    H --> J[Convert Formats]
    H --> K[Combine/Extract Key & Salt]
    E --> L[Error Handling]
    L --> F
```

This chart shows the typical flow: setting up keys and salts, initializing the helper, encrypting and decrypting data, and using utility functions for key/salt management and conversion. Error handling is integrated during decryption.




- **Program.cs**: Contains the `SecurityHelper` class, which provides all encryption, decryption, and utility methods. Also includes example usage in `Main()`. Plenty of comments will help guide you.
- **CatsClawSecurityKey.csproj**: Project file targeting .NET 8.0.
- **README.md**: Documentation and usage examples.

### Technical Details
- **Encryption Algorithm:** Uses AES-256 (Advanced Encryption Standard) in CBC mode for symmetric encryption and decryption of strings.
- **Key Derivation:** Keys and initialization vectors (IVs) are derived using PBKDF2 (`Rfc2898DeriveBytes`) with SHA-256, based on user-provided or randomly generated passwords and salts.
- **Salt Management:** Supports custom or randomly generated salts for enhanced security. Salt length is configurable.
- **Encoding:** All encrypted data is output as Base64 strings for easy storage and transmission.
- **Utility Functions:** Includes helpers for converting between strings, byte arrays, and hexadecimal formats, as well as combining and extracting keys and salts.
- **Logging:** Optional logger interface for error/info/warning reporting.

The core logic is encapsulated in the static `SecurityHelper` class, which exposes methods for:
- Encrypting and decrypting strings
- Managing encryption keys and salts (custom or random)
- Utility functions for key/salt extraction and conversion
- Logging support via an optional logger interface. Typically, logging should not be included in the same code, but for simplicity, it's included here.

## How to Build
1. **Requirements:** .NET 8.0 SDK or later.
2. **Build:**
    Open a terminal in the project directory and run:
    ```
    dotnet build
    ```
    This will compile the project and output the executable to the `bin/Debug/net8.0/` directory.

    Note: I will add scripts to build exactg for .NET platform  for cross-platform use later. I'd also like to target this as a library (or assembly) that can be imported into other projects.

## How to Use
You can use the `SecurityHelper` class directly in your code. Below are some common usage patterns:

### Example 1: Using custom encryption key (password) and secure key (salt)

```csharp
SecurityHelper.EncryptionKey = "My Custom Encryption Key";
SecurityHelper.Salt = "ChrisWinters";
SecurityHelper.Init();

string encryptedText = SecurityHelper.Encrypt("NO more secrets!");
string decryptedText = SecurityHelper.Decrypt(encryptedText);
```

### Example 2: Overriding encryption/decryption with new password and salt

```csharp
string encryptedTextB = SecurityHelper.Encrypt("No more OTHER secrets", "NewPassword", "NewSecretKey");
string decryptedTextB = SecurityHelper.Decrypt(encryptedTextB, "NewPassword", "NewSecretKey");
```

### Example 3: Random encryption using a random encryption key (password) and secure key (salt)

```csharp
SecurityHelper.EncryptionKey = SecurityHelper.GenerateRandomString(32);
SecurityHelper.Salt = SecurityHelper.ConvertByteArrayToString(SecurityHelper.GenerateRandomBytes(32));
SecurityHelper.Init();

string encryptedTextRnd = SecurityHelper.Encrypt("Secrets are NO more!");
string decryptedTextRnd = SecurityHelper.Decrypt(encryptedTextRnd);
```


### TODOs / Challenges

- Refactor function names: Change functions that use "salt" to use "secret key" for clarity during design-time.
- Refactor naming: Change functions that use "encrypted key" to use "password" for clarity during design-time.
- Make salt length configurable and ensure random salt generation is robust.
- Pass iteration count for PBKDF2 as a parameter instead of using a magic number (currently 1000).
- Improve error handling for cryptographic exceptions, especially padding errors (e.g., "Padding is invalid and cannot be removed"). This often occurs if encryption and decryption keys do not match.
- Consider separating logging from core cryptographic logic for better modularity.
- Add cross-platform build scripts and support for packaging as a library/assembly for easier integration into other projects.
- Validate salt values to avoid whitespace and other invalid characters.
- Add more utility functions for key/salt management and conversion.
- Document edge cases and provide more example outputs for troubleshooting.

#### Practical Findings / Experience
- Padding errors are common if the encryption key and salt used for decryption do not exactly match those used for encryption. Always ensure keys and salts are consistent.
- Base64 encoding is used for output, but spaces in encrypted strings can cause issues; always replace spaces with "+" before decoding.
- When combining keys and salts, ensure the format is consistent (e.g., "encryptionkey:securekey") and properly encoded.
- Logging is helpful for debugging cryptographic operations, but should be optional and decoupled from main logic.
---

## Detailed Examples

Below are detailed code examples and expected output:

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
