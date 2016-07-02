using System;
using System.Collections.Generic;
using System.Data.Common;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace Bitifier.RsaEncryption
{
   public class CipherTextWithCertificateInfoSerializer
   {
      private const string EncryptionIndicator = "Bitifier.RsaEncryption";

      public string Serialize(CipherTextWithCertificateInfo cipherTextWithCertificateInfo)
      {
         if (cipherTextWithCertificateInfo == null)
            throw new ArgumentNullException(nameof(cipherTextWithCertificateInfo));

         const string version = "1";

         return
            $"{EncryptionIndicator}:{version}:{cipherTextWithCertificateInfo.StoreLocation}:{cipherTextWithCertificateInfo.StoreName}:{cipherTextWithCertificateInfo.Thumbprint}:{cipherTextWithCertificateInfo.CipherText}";
      }

      public CipherTextWithCertificateInfo Deserialize(string serializedCipherTextWithCertificateInfo)
      {
         if (serializedCipherTextWithCertificateInfo == null)
            throw new ArgumentNullException(nameof(serializedCipherTextWithCertificateInfo));
         
         var values = serializedCipherTextWithCertificateInfo.Split(':');

         if (values.Length != 6)
         {
            int segmentsFound = values.Length;
            throw new ArgumentException($"String cannot be parsed. Expected 6 segments, found {segmentsFound}",
               nameof(serializedCipherTextWithCertificateInfo));
         }

         var indicator = values[0];
         if (indicator != EncryptionIndicator)
            throw new ArgumentException("No indicator found.");

         var version = values[1];

         if (version != "1")
            throw new ArgumentException($"The version {version} is not supported.", nameof(serializedCipherTextWithCertificateInfo));

         StoreLocation storeLocation;
         if (!Enum.TryParse<StoreLocation>(values[2], out storeLocation))
            throw new ArgumentException($"The store location {values[2]} is unknown.", nameof(serializedCipherTextWithCertificateInfo));

         StoreName storeName;
         if (!Enum.TryParse<StoreName>(values[3], out storeName))
            throw new ArgumentException($"The store name {values[3]} is unknown", nameof(serializedCipherTextWithCertificateInfo));

         return new CipherTextWithCertificateInfo()
            {
               StoreLocation = storeLocation,
               StoreName = storeName,
               Thumbprint = values[4],
               CipherText = values[5]
            };
      }

      public bool IsSerializedCipherText(string serializedCipherTextWithCertificateInfo)
      {
         var values = serializedCipherTextWithCertificateInfo.Split(':');

         if (values.Length != 6)
            return false;

         var indicator = values[0];
         if (indicator != EncryptionIndicator)
            return false;

         return true;
      }

   }
}
