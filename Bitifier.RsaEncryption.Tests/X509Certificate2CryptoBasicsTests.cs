using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using NUnit.Framework;

namespace Bitifier.RsaEncryption.Tests
{
   [TestFixture]
   public class X509Certificate2CryptoBasicsTests
   {
      [Test]
      public void EncryptingWithNullCertificateShouldThrow()
      {
         var encryption = new X509Certificate2Crypto();

         var exception = Assert.Throws<ArgumentNullException>(() => encryption.Encrypt(null, "A"));

         Assert.AreEqual("certificate", exception.ParamName);
      }

      [Test]
      public void EncryptingWithCertificateWithoutPublicKeyShouldThrowArgumentException()
      {
         var certificate = new X509Certificate2();
         var encryption = new X509Certificate2Crypto();

         var exception = Assert.Throws<ArgumentException>(() => encryption.Encrypt(certificate, "A"));
         Assert.AreEqual("certificate", exception.ParamName);
      }

      [Test]
      public void EncryptingWithCertificateWithoutPublicKeyShouldThrowWithMessage()
      {
         var certificate = new X509Certificate2();
         var encryption = new X509Certificate2Crypto();

         var exception = Assert.Throws<ArgumentException>(() => encryption.Encrypt(certificate, "A"));
         Assert.AreEqual("certificate", exception.ParamName);
         Assert.That(exception.Message, Does.StartWith("Certificate does not have a public key."));
      }

      [Test]
      public void EncryptingNullPlainTextShouldThrow()
      {
         var certificate = X509Certificate2Loader.Test2048AWithPrivateKey();
         var encryption = new X509Certificate2Crypto();

         var exception = Assert.Throws<ArgumentNullException>(() => encryption.Encrypt(certificate, null));

         Assert.AreEqual("plainText", exception.ParamName);
      }


      [Test]
      public void EncryptingShouldReturnData()
      {
         var certificate = X509Certificate2Loader.Test2048AWithPrivateKey();

         var encryption = new X509Certificate2Crypto();
         var data = encryption.Encrypt(certificate, "A");

         Assert.IsFalse(string.IsNullOrEmpty(data));
      }
      
      [Test]
      public void EncryptingEmptyStringShouldReturnData()
      {
         var certificate = X509Certificate2Loader.Test2048AWithPrivateKey();

         var encryption = new X509Certificate2Crypto();
         var data = encryption.Encrypt(certificate, "");

         Assert.IsFalse(string.IsNullOrEmpty(data));
      }

      [Test]
      public void EncryptionAndDecryptingWithSameCertificateShouldSucceed()
      {
         var certificate = X509Certificate2Loader.Test2048AWithPrivateKey();
         
         var encryption = new X509Certificate2Crypto();
         var cipherText = encryption.Encrypt(certificate, "A");
         var plainText = encryption.Decrypt(certificate, cipherText);

         Assert.AreEqual("A", plainText);
      }

      [Test]
      public void DecryptingWithWrongCertShouldThrow()
      {
         var certificate = X509Certificate2Loader.Test2048AWithPrivateKey();
         var anotherCertificate = X509Certificate2Loader.Test2048BWithPrivateKey();

         var encryption = new X509Certificate2Crypto();
         var cipherText = encryption.Encrypt(certificate, "A");

         Assert.Throws<CryptographicException>(() => encryption.Decrypt(anotherCertificate, cipherText));
      }

      [Test]
      public void DecryptingWithNullCertificateShouldThrow()
      {
         var encryption = new X509Certificate2Crypto();

         var exception = Assert.Throws<ArgumentNullException>(() => encryption.Decrypt(null, "A"));

         Assert.AreEqual("certificate", exception.ParamName);
      }

      [Test]
      public void DecryptingWithCertificateWithoutPrivateKeyShouldFail()
      {
         var certificate = X509Certificate2Loader.Test2048AWithoutPrivateKey();

         var encryption = new X509Certificate2Crypto();
         var cipherText = encryption.Encrypt(certificate, "A");

         var exception = Assert.Throws<ArgumentException>(() => encryption.Decrypt(certificate, cipherText));

         Assert.AreEqual("certificate", exception.ParamName);
         Assert.That(exception.Message, Does.StartWith("Certificate does not have a private key."));
      }

      [Test]
      public void DecryptingNullCipherTextShouldFail()
      {
         var certificate = X509Certificate2Loader.Test2048AWithPrivateKey();

         var encryption = new X509Certificate2Crypto();

         Assert.Throws<ArgumentNullException>(() => encryption.Decrypt(certificate, null));

      }

      [Test]
      public void EncryptionShouldHandleDifferentPlainTextLengths()
      {
         var certificate = X509Certificate2Loader.Test2048AWithPrivateKey();

         var encryption = new X509Certificate2Crypto();

         var plainTextBuilder = new StringBuilder();

         for (int i = 0; i < 1000; i++)
         {
            var currentCharacter = i%10;
            plainTextBuilder.Append(currentCharacter);

            var plainText = plainTextBuilder.ToString();

            var cipherText = encryption.Encrypt(certificate, plainText);
            var decryptedPlainText = encryption.Decrypt(certificate, cipherText);

            Assert.AreEqual(plainText, decryptedPlainText);
         }

         
      }
   }
}
