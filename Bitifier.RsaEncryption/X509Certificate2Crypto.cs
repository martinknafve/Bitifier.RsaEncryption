using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace Bitifier.RsaEncryption
{
   public class X509Certificate2Crypto
   {
      public string Encrypt(X509Certificate2 certificate, string plainText)
      {
         if (certificate == null)
            throw new ArgumentNullException(nameof(certificate));
         if (plainText == null)
            throw new ArgumentNullException(nameof(plainText));

         try
         {
            var publicKey = certificate.PublicKey;
         }
         catch (CryptographicException ex)
         {
            throw new ArgumentException("Certificate does not have a public key.", nameof(certificate), ex);
         }

         using (RSACryptoServiceProvider publicKeyProvider =
               (RSACryptoServiceProvider) certificate.PublicKey.Key)
         {
            var plainTextBytes = Encoding.UTF8.GetBytes(plainText);

            var maxDataLength = CalculateMaxDataLength(certificate);

            var cipherText = new StringBuilder();

            var chunks = plainTextBytes.Split(maxDataLength);

            // Encrypting an empty string should still return ciphertext
            if (chunks.Count == 0)
               chunks.Add(new byte[0]);

            for (int i = 0; i < chunks.Count; i++)
            {
               if (i > 0)
                  cipherText.Append("|");

               var chunk = chunks[i];

               var cipherTextBytes = publicKeyProvider.Encrypt(chunk, true);
               cipherText.Append(Convert.ToBase64String(cipherTextBytes, Base64FormattingOptions.None));
            }

            return cipherText.ToString();
         }
      }

      public string Decrypt(X509Certificate2 certificate, string cipherText)
      {
         if (certificate == null)
            throw new ArgumentNullException(nameof(certificate));
         if (cipherText == null)
            throw new ArgumentNullException(nameof(cipherText));

         if (!certificate.HasPrivateKey)
            throw new ArgumentException("Certificate does not have a private key.", "certificate");

         var chunks = cipherText.Split('|');

         var plainText = new StringBuilder();

         using (RSACryptoServiceProvider privateKeyProvider =
            (RSACryptoServiceProvider) certificate.PrivateKey)
         {
            foreach (var chunk in chunks)
            {
               var cipherTextBytes = Convert.FromBase64String(chunk);
               
               var plainTextBytes = privateKeyProvider.Decrypt(cipherTextBytes, true);

               plainText.Append(Encoding.UTF8.GetString(plainTextBytes));
            }
         }

         return plainText.ToString();
      }

      private int CalculateMaxDataLength(X509Certificate2 certificate)
      {
         var keySize = certificate.PublicKey.Key.KeySize;

         return ((keySize - 384)/8) + 7 - 1;
      }

   }
}
