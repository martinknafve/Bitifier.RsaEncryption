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
      public string Serialize(CipherTextWithCertificateInfo cipherTextWithCertificateInfo)
      {
         if (cipherTextWithCertificateInfo == null)
            throw new ArgumentNullException(nameof(cipherTextWithCertificateInfo));

         const string version = "1";

         return
            $"{version}:{cipherTextWithCertificateInfo.StoreLocation}:{cipherTextWithCertificateInfo.StoreName}:{cipherTextWithCertificateInfo.Thumbprint}:{cipherTextWithCertificateInfo.CipherText}";
      }

      public CipherTextWithCertificateInfo Deserialize(string serializedCipherTextWithCertificateInfo)
      {
         if (serializedCipherTextWithCertificateInfo == null)
            throw new ArgumentNullException(nameof(serializedCipherTextWithCertificateInfo));
         
         var values = serializedCipherTextWithCertificateInfo.Split(':');

         if (values.Length != 5)
            throw new ArgumentException("String cannot be parsed.", nameof(serializedCipherTextWithCertificateInfo));

         var version = values[0];

         if (version != "1")
            throw new ArgumentException($"The version {version} is not supported.", nameof(serializedCipherTextWithCertificateInfo));

         StoreLocation storeLocation;
         if (!Enum.TryParse<StoreLocation>(values[1], out storeLocation))
            throw new ArgumentException($"The store location {values[1]} is unknown.", nameof(serializedCipherTextWithCertificateInfo));

         StoreName storeName;
         if (!Enum.TryParse<StoreName>(values[2], out storeName))
            throw new ArgumentException($"The store name {values[2]} is unknown", nameof(serializedCipherTextWithCertificateInfo));

         return new CipherTextWithCertificateInfo()
            {
               StoreLocation = storeLocation,
               StoreName = storeName,
               Thumbprint = values[3],
               CipherText = values[4]
            };
      }

   }
}
