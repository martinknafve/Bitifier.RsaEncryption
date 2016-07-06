using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace Bitifier.RsaEncryption
{
   public class X509Certificate2ThumbprintCrypto
   {
      private readonly ICertificateStoreRepository _certificateStoreRepository;

      private const string InvalidStoreBehaviorMessage = "The certificate store failed to return a list of certificates";

      public X509Certificate2ThumbprintCrypto()
      {
         _certificateStoreRepository = new WindowsCertificateStoreRepository();
      }

      public X509Certificate2ThumbprintCrypto(ICertificateStoreRepository certificateStoreRepository)
      {
         if (certificateStoreRepository == null)
            throw new ArgumentNullException(nameof(certificateStoreRepository));

         _certificateStoreRepository = certificateStoreRepository;
      }

      public CipherTextWithCertificateInfo Encrypt(StoreLocation location, StoreName storeName, string thumbprint, string plainText)
      {
         var certificates = _certificateStoreRepository.Find(location, storeName, thumbprint);

         if (certificates == null)
            throw new InvalidOperationException(InvalidStoreBehaviorMessage);

         if (certificates.Count == 0)
            throw new ArgumentException("Unable to find requested certificate.", "thumbprint");
         if (certificates.Count > 1)
            throw new ArgumentException("Found multiple matching certificates.", "thumbprint");

         // Now we have a single cert to use for encryption
         var certificate = certificates.Single();

         var x509Certificate2Crypto = new X509Certificate2Crypto();
         var cipherText = x509Certificate2Crypto.Encrypt(certificate, plainText);

         return new CipherTextWithCertificateInfo()
            {
               StoreLocation = location,
               StoreName = storeName,
               Thumbprint = thumbprint,
               CipherText = cipherText
            };
      }

      public string Decrypt(CipherTextWithCertificateInfo cipherTextWithCertificateInfo)
      {
         var certificates = _certificateStoreRepository.Find(cipherTextWithCertificateInfo.StoreLocation, cipherTextWithCertificateInfo.StoreName, cipherTextWithCertificateInfo.Thumbprint);

         if (certificates == null)
            throw new InvalidOperationException(InvalidStoreBehaviorMessage);

         if (certificates.Count == 0)
            throw new ArgumentException("Unable to find requested certificate.", "thumbprint");
         if (certificates.Count > 1)
            throw new ArgumentException("Found multiple matching certificates.", "thumbprint");
         
         // Now we have a single cert to use for encryption
         var certificate = certificates.Single();

         var x509Certificate2Crypto = new X509Certificate2Crypto();
         var plainText = x509Certificate2Crypto.Decrypt(certificate, cipherTextWithCertificateInfo.CipherText);

         return plainText;
      }
   }
}
