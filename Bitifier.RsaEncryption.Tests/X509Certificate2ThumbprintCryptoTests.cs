using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Remoting;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Moq;
using NUnit.Framework;

namespace Bitifier.RsaEncryption.Tests
{
   [TestFixture]
   public class X509Certificate2ThumbprintCryptoTests
   {
      [Test]
      public void DefaultConstructorCreatesItsOwnStore()
      {
         var crypto = new X509Certificate2ThumbprintCrypto();
      }

      [Test]
      public void EncryptingWithNonexistantCertShouldThrowArgumentException()
      {
         var certificateStore = new Mock<ICertificateStoreRepository>();

         certificateStore.Setup(f => f.Find(It.IsAny<StoreLocation>(), It.IsAny<StoreName>(), It.IsAny<string>()))
            .Returns(new List<X509Certificate2>());

         var crypto = new X509Certificate2ThumbprintCrypto(certificateStore.Object);

         var exception = Assert.Throws<ArgumentException>(() => crypto.Encrypt(StoreLocation.CurrentUser, StoreName.My, "A", "A"));

         Assert.That(exception.Message, Does.StartWith("Unable to find requested certificate."));
      }

      [Test]
      public void EncryptingWithMultipleMatchingThumbprintsShouldThrowArgumentException()
      {
         var certificateStore = new Mock<ICertificateStoreRepository>();

         certificateStore.Setup(f => f.Find(It.IsAny<StoreLocation>(), It.IsAny<StoreName>(), It.IsAny<string>()))
            .Returns(new List<X509Certificate2>()
            {
               new X509Certificate2(),
               new X509Certificate2(),
            });

         var crypto = new X509Certificate2ThumbprintCrypto(certificateStore.Object);


         var exception = Assert.Throws<ArgumentException>(() => crypto.Encrypt(StoreLocation.CurrentUser, StoreName.My, "A", "A"));

         Assert.That(exception.Message, Does.StartWith("Found multiple matching certificates."));
      }

      [Test]
      public void EncryptingShouldReturnCertificateInfo()
      {
         var certificateStore = new Mock<ICertificateStoreRepository>();

         certificateStore.Setup(f => f.Find(It.IsAny<StoreLocation>(), It.IsAny<StoreName>(), It.IsAny<string>()))
            .Returns(new List<X509Certificate2>()
            {
               X509Certificate2Loader.Test2048AWithoutPrivateKey()
            });

         var crypto = new X509Certificate2ThumbprintCrypto(certificateStore.Object);

         var cipherTextWithCertificateInfo = crypto.Encrypt(StoreLocation.CurrentUser, StoreName.My, "A", "A");

         Assert.IsNotNull(cipherTextWithCertificateInfo);
      }

      [Test]
      public void DecryptingUsingCipherTextWithCertificateInfoShouldLoadSpecificKey()
      {
         var certificateStore = new Mock<ICertificateStoreRepository>();

         certificateStore.Setup(f => f.Find(StoreLocation.CurrentUser, StoreName.AddressBook, "Thumbprint"))
            .Returns(new List<X509Certificate2>()
            {
               X509Certificate2Loader.Test2048AWithPrivateKey()
            });
         
         var crypto = new X509Certificate2ThumbprintCrypto(certificateStore.Object);

         var cipherTextWithCertificateInfo = crypto.Encrypt(StoreLocation.CurrentUser, StoreName.AddressBook, "Thumbprint", "A");

         crypto.Decrypt(cipherTextWithCertificateInfo);

         certificateStore.Verify(f => f.Find(StoreLocation.CurrentUser, StoreName.AddressBook, "Thumbprint"), Times.Exactly(2));
      }

      [Test]
      public void DecryptingUsingCipherTextWithCertificateInfoShouldSucceed()
      {
         var certificateStore = new Mock<ICertificateStoreRepository>();

         certificateStore.Setup(f => f.Find(It.IsAny<StoreLocation>(), It.IsAny<StoreName>(), It.IsAny<string>()))
            .Returns(new List<X509Certificate2>()
            {
               X509Certificate2Loader.Test2048AWithPrivateKey()
            });

         var crypto = new X509Certificate2ThumbprintCrypto(certificateStore.Object);

         var cipherTextWithCertificateInfo = crypto.Encrypt(StoreLocation.CurrentUser, StoreName.My, "A", "A");

         var plaintext = crypto.Decrypt(cipherTextWithCertificateInfo);

         Assert.AreEqual("A", plaintext);
      }

      [Test]
      public void DecryptingWithNonexistantCertShouldThrowArgumentException()
      {
         var certificateStore = new Mock<ICertificateStoreRepository>();

         certificateStore.Setup(f => f.Find(It.IsAny<StoreLocation>(), It.IsAny<StoreName>(), It.IsAny<string>()))
            .Returns(new List<X509Certificate2>());

         var crypto = new X509Certificate2ThumbprintCrypto(certificateStore.Object);
         var cipherTextWithCertificateInfo = new CipherTextWithCertificateInfo();
         var exception = Assert.Throws<ArgumentException>(() => crypto.Decrypt(cipherTextWithCertificateInfo));

         Assert.That(exception.Message, Does.StartWith("Unable to find requested certificate."));
      }

      [Test]
      public void DecryptingWithMultipleMatchingThumbprintsShouldThrowArgumentException()
      {
         var certificateStore = new Mock<ICertificateStoreRepository>();

         certificateStore.Setup(f => f.Find(It.IsAny<StoreLocation>(), It.IsAny<StoreName>(), It.IsAny<string>()))
            .Returns(new List<X509Certificate2>()
            {
               new X509Certificate2(),
               new X509Certificate2(),
            });

         var crypto = new X509Certificate2ThumbprintCrypto(certificateStore.Object);
         var cipherTextWithCertificateInfo = new CipherTextWithCertificateInfo();
         var exception = Assert.Throws<ArgumentException>(() => crypto.Decrypt(cipherTextWithCertificateInfo));

         Assert.That(exception.Message, Does.StartWith("Found multiple matching certificates."));
      }

      [Test]
      public void DecryptingSerializedDataShouldSucceed()
      {
         var certificateStore = new Mock<ICertificateStoreRepository>();

         certificateStore.Setup(f => f.Find(StoreLocation.CurrentUser, StoreName.My, "TestThumbprint"))
            .Returns(new List<X509Certificate2>()
            {
               X509Certificate2Loader.Test2048AWithPrivateKey()
            });

         var crypto = new X509Certificate2ThumbprintCrypto(certificateStore.Object);

         var cipherTextWithCertificateInfo = crypto.Encrypt(StoreLocation.CurrentUser, StoreName.My, "TestThumbprint", "TestPlaintext");

         var serializer = new CipherTextWithCertificateInfoSerializer();
         var serializedCipherTextWithCertInfo = serializer.Serialize(cipherTextWithCertificateInfo);

         var deserializedCipherTextWithCertInfo = serializer.Deserialize(serializedCipherTextWithCertInfo);

         var decryptedCipherTextWithCertificateInfo = crypto.Decrypt(deserializedCipherTextWithCertInfo);

         Assert.AreEqual("TestPlaintext", decryptedCipherTextWithCertificateInfo);
      }

      [Test]
      public void CertificateStoreReturningNullListShouldThrowWhenEncrypting()
      {
         var certificateStore = new Mock<ICertificateStoreRepository>();

         certificateStore.Setup(f => f.Find(StoreLocation.CurrentUser, StoreName.My, "SomeOtherThumbprint"))
            .Returns(new List<X509Certificate2>()
            {
               X509Certificate2Loader.Test2048AWithPrivateKey()
            });

         var crypto = new X509Certificate2ThumbprintCrypto(certificateStore.Object);

         var exception = Assert.Throws<InvalidOperationException>(() =>crypto.Encrypt(StoreLocation.CurrentUser, StoreName.My, "TestThumbprint", "TestPlaintext"));

         Assert.That(exception.Message, Does.StartWith("The certificate store failed to return a list of certificates"));
      }

      [Test]
      public void CertificateStoreReturningNullListShouldThrowWhenDecrypting()
      {
         var certificateStore = new Mock<ICertificateStoreRepository>();

         certificateStore.Setup(f => f.Find(StoreLocation.CurrentUser, StoreName.My, "TestThumbprint"))
            .Returns(new List<X509Certificate2>()
            {
               X509Certificate2Loader.Test2048AWithPrivateKey()
            });

         var crypto = new X509Certificate2ThumbprintCrypto(certificateStore.Object);

         var cipherTextWithCertificateInfo = crypto.Encrypt(StoreLocation.CurrentUser, StoreName.My, "TestThumbprint", "TestPlaintext");

         cipherTextWithCertificateInfo.Thumbprint = "SomeOtherThumbprint";

         var exception = Assert.Throws<InvalidOperationException>(() => crypto.Decrypt(cipherTextWithCertificateInfo));

         Assert.That(exception.Message, Does.StartWith("The certificate store failed to return a list of certificates"));
      }
   }
}
