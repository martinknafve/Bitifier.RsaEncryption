# Bitifier.RsaEncryption

Bitifier.RsaEncryption is a .NET library (written in C#) which simplifies encryption of secrets using RSA and X509 certificates. Bitifier.RsaEncryption is useful for encrypting short secrets (less than 500 bytes).

It uses the .NET-built-in `RSACryptoServiceProvider`, but provides the following benefits over it:

* It allows for encryption of longer secrets than `RSACryptoServiceProvider`. For longer secrets (depending on key size), the secret will be split up and each part will be encrypted on its own.
* It can load a X509 from a certificate store using the certificates thumbprint.
* During encryption, it can generate a string containing both the cipher text and information needed to locate the certificate. On decryption, this string contains all info needed to decrypt the string, and the certificate can be loaded automatically.

##When to use##

* Encrypting credentials the application need to run, such as a connection string to a database.
* Allowing a server to store encrypted secret data without being able to decrypt it. Useful if you want a web server to store data which should only be readable by a backend server ("write-only" from the web servers perspective).

##When not to use##

* Encrypting longer secrets (several kilobytes). Use symmetric encryption for this. Assymmetric encryption will most likely be too slow for you.
* Encrypting passwords users use to log on your application. Never store user passwords encrypted - use hashing for this.

## Example ##

```cs
  X509Certificate certificate = ...
  var encryption = new X509Certificate2Crypto();
  var cipherText = encryption.Encrypt(certificate, "plaintext")
```

