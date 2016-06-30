using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Remoting;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using NUnit.Framework;
using NUnit.Framework.Compatibility;

namespace Bitifier.RsaEncryption.Tests
{
   [TestFixture]
   public class X509Certificate2CryptoLongStringTests
   {

      [Test]
      public void Encrypting1KBStringShouldSucceed()
      {
         var certificate = X509Certificate2Loader.Test2048AWithPrivateKey();

         var builder = new StringBuilder();
         builder.Append('a', 1024);

         var plainText = builder.ToString();

         var encryption = new X509Certificate2Crypto();
         var cipherText = encryption.Encrypt(certificate, plainText);
         var plainTextAfterDecryption = encryption.Decrypt(certificate, cipherText);

         Assert.AreEqual(plainText, plainTextAfterDecryption);
      }

      [Test]
      public void Encrypting1KBStringWtih2048BitCertShouldProduce5Chunks()
      {
         var certificate = X509Certificate2Loader.Test2048AWithPrivateKey();

         var builder = new StringBuilder();
         builder.Append('a', 1024);

         var plainText = builder.ToString();

         var encryption = new X509Certificate2Crypto();
         var cipherText = encryption.Encrypt(certificate, plainText);

         var chunkCount = cipherText.Count(f => f == '|') + 1;

         Assert.AreEqual(5, chunkCount);
      }

      [Test]
      public void Encrypting1KBStringWtih4096BitCertShouldProduce2Chunks()
      {
         var certificate = X509Certificate2Loader.Test4096AWithPrivateKey();

         var builder = new StringBuilder();
         builder.Append('a', 1024);

         var plainText = builder.ToString();

         var encryption = new X509Certificate2Crypto();
         var cipherText = encryption.Encrypt(certificate, plainText);

         var chunkCount = cipherText.Count(f => f == '|') + 1;

         Assert.AreEqual(3, chunkCount);
      }


      [Test]
      public void Encrypting1MBStringShouldSucceed()
      {
         var certificate = X509Certificate2Loader.Test2048AWithPrivateKey();

         var guidRequired = (1024*1024)/Guid.NewGuid().ToString().Length;
         var messageBuilder = new StringBuilder();
         for (int i = 0; i < guidRequired; i++)
            messageBuilder.Append(Guid.NewGuid());

         var plainText = messageBuilder.ToString();

         var encryption = new X509Certificate2Crypto();
         var cipherText = encryption.Encrypt(certificate, plainText);
         var plainTextAfterDecryption = encryption.Decrypt(certificate, cipherText);

         Assert.AreEqual(plainText, plainTextAfterDecryption);
      }
   }
}
