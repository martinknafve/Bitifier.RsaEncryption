using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using NUnit.Framework;

namespace Bitifier.RsaEncryption.Tests
{
   [TestFixture]
   public class CipherTextWithCertificateInfoSerializerTests
   {
      [Test]
      public void SerializingNullInstanceShouldThrow()
      {
         var serializer = new CipherTextWithCertificateInfoSerializer();

         var exception = Assert.Throws<ArgumentNullException>(() => serializer.Serialize(null));
         Assert.AreEqual("cipherTextWithCertificateInfo", exception.ParamName);
      }

      [Test]
      public void SerializingNonNullInstanceShouldReturnSerializedData()
      {
         var serializer = new CipherTextWithCertificateInfoSerializer();

         string serialized = serializer.Serialize(new CipherTextWithCertificateInfo());

         Assert.IsFalse(string.IsNullOrWhiteSpace(serialized));
      }

      [Test]
      public void DeserializingNullStringShouldThrow()
      {
         var serializer = new CipherTextWithCertificateInfoSerializer();

         var exception = Assert.Throws<ArgumentNullException>(() => serializer.Deserialize(null));
         Assert.AreEqual("serializedCipherTextWithCertificateInfo", exception.ParamName);
      }

      [Test]
      public void DeserializingEmptyStringShouldThrow()
      {
         var serializer = new CipherTextWithCertificateInfoSerializer();

         var exception = Assert.Throws<ArgumentException>(() => serializer.Deserialize(""));
         Assert.AreEqual("serializedCipherTextWithCertificateInfo", exception.ParamName);
         Assert.That(exception.Message, Does.StartWith("String cannot be parsed."));
      }

      [Test]
      public void DeserializingMalformedStringShoudlThrow()
      {
         var serializer = new CipherTextWithCertificateInfoSerializer();

         var exception = Assert.Throws<ArgumentException>(() => serializer.Deserialize("A"));
         Assert.AreEqual("serializedCipherTextWithCertificateInfo", exception.ParamName);
         Assert.That(exception.Message, Does.StartWith("String cannot be parsed."));
      }

      [Test]
      public void DeserializingUnsupportedVersionShouldThrow()
      {
         var serializer = new CipherTextWithCertificateInfoSerializer();

         var exception = Assert.Throws<ArgumentException>(() => serializer.Deserialize("0::::"));
         Assert.AreEqual("serializedCipherTextWithCertificateInfo", exception.ParamName);
         Assert.That(exception.Message, Does.StartWith("The version 0 is not supported."));
      }

      [Test]
      public void DeserializingUnknownStoreLocationShouldThrow()
      {
         var serializer = new CipherTextWithCertificateInfoSerializer();

         var exception = Assert.Throws<ArgumentException>(() => serializer.Deserialize("1:InvalidStoreLocation:Root:ThumbPrint:Ciphertext"));
         Assert.AreEqual("serializedCipherTextWithCertificateInfo", exception.ParamName);
         Assert.That(exception.Message, Does.StartWith("The store location InvalidStoreLocation is unknown."));
      }

      [Test]
      public void DeserializingUnknownStoreNameShouldThrow()
      {
         var serializer = new CipherTextWithCertificateInfoSerializer();
         var exception = Assert.Throws<ArgumentException>(() => serializer.Deserialize("1:CurrentUser:InvalidStoreName:ThumbPrint:Ciphertext"));
         Assert.AreEqual("serializedCipherTextWithCertificateInfo", exception.ParamName);
         Assert.That(exception.Message, Does.StartWith("The store name InvalidStoreName is unknown"));
      }

      [Test]
      public void DeserializingCorrectlyFormedVersion1ShouldSucceed()
      {
         var serializer = new CipherTextWithCertificateInfoSerializer();
         var result = serializer.Deserialize("1:CurrentUser:Root:MyThumbprint:MyCiphertext");
         
         Assert.AreEqual(StoreLocation.CurrentUser, result.StoreLocation);
         Assert.AreEqual(StoreName.Root, result.StoreName);
         Assert.AreEqual("MyThumbprint", result.Thumbprint);
         Assert.AreEqual("MyCiphertext", result.CipherText);
      }
   }

}
