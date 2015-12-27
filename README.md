# Bitifier.RsaEncryption

Bitifier.RsaEncryption is a .NET library (written in C#) which simplifies encryption of secrets using RSA and X509 certificates.

It uses the .NET-built-in `RSACryptoServiceProvider`, but provides the following benefits over it:

* It allows for encryption of longer secrets than `RSACryptoServiceProvider`. For longer secrets (depending on key size), the secret will be split up and each part will be encrypted on its own.
* It can load a X509 from a certificate store using the certificates thumbprint.
* During encryption, it can generate a string containing both the cipher text and information needed to locate the certificate. On decryption, this string contains all info needed to decrypt the string, and the certificate can be loaded automatically.

## Example ##

```cs
  X509Certificate certificate = ...
  var encryption = new X509Certificate2Crypto();
  var cipherText = encryption.Encrypt(certificate, "plaintext")
```

