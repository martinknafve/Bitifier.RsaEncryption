using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using NDesk.Options;

namespace Bitifier.RsaEncryption.Console
{
   class Program
   {
      static int Main(string[] args)
      {
         string thumbprint = null;
         string inputFile = null;
         string outputFile = null;
         string certificateFile = null;

         bool encrypt = false;
         bool decrypt = false;
         bool overwrite = false;

         var optionSet = new OptionSet
            {
               { "inputFile=",       v => inputFile = v },
               { "outputFile=",      v => outputFile = v },
               { "thumbprint=",      v => thumbprint = v },
               { "certificateFile=", v => certificateFile = v },
               { "encrypt",          v => encrypt = true  },
               { "decrypt",          v => decrypt = true  },
               { "overwrite",        v => overwrite = true  },
            };

         try
         {
            optionSet.Parse(args);

            var errors = new StringBuilder();

            if (encrypt)
            {
               if (string.IsNullOrWhiteSpace(thumbprint) && string.IsNullOrWhiteSpace(certificateFile))
                  errors.AppendLine("Either /thumbprint or /certificateFile must be used.");
               if (!string.IsNullOrWhiteSpace(thumbprint) && !string.IsNullOrWhiteSpace(certificateFile))
                  errors.AppendLine("Both /thumbprint or /certificateFile were used. Only one may be used at a time.");
            }
            else
            {
               if (!string.IsNullOrWhiteSpace(thumbprint) && !string.IsNullOrWhiteSpace(certificateFile))
                  errors.AppendLine("When decrypting, a certificate must not be specified. It will be looked up from the thumbprint info in encrypted file.");
            }

            if (string.IsNullOrWhiteSpace(inputFile))
               errors.AppendLine("Input file must be specified.");
            if (string.IsNullOrWhiteSpace(outputFile))
               errors.AppendLine("Output file must be specified.");
            
            if (!encrypt && !decrypt)
               errors.AppendLine("Either /encrypt or /decrypt must be used.");

            if (encrypt && decrypt)
               errors.AppendLine("Both /encrypt and /decrypt were used. Only one may be used at a time.");

            if (errors.Length > 0)
            {
               throw new ArgumentException(errors.ToString());
            }
         }
         catch (Exception e)
         {
            System.Console.WriteLine("Missing command line parameters:");
            System.Console.WriteLine(e.Message);
            return -1;
         }

         if (!File.Exists(inputFile))
         {
            System.Console.WriteLine("The input file {0} does not exist.", inputFile);
         }

         if (File.Exists(outputFile) && !overwrite)
         {
            System.Console.WriteLine("The output file {0} already exists, and the /overwrite flag has not been supplied.", outputFile);
            return -1;
         }

         X509Certificate2 encryptionCertificate = null;
         StoreLocation encryptionCertificateStoreLocation = StoreLocation.CurrentUser;
         StoreName encryptionCertificateStoreName = StoreName.My;

         if (encrypt)
         {
            if (!string.IsNullOrWhiteSpace(certificateFile))
            {
               if (!File.Exists(certificateFile))
               {
                  System.Console.WriteLine("The certificate file {0} was not found.", certificateFile);
                  return -1;
               }

               encryptionCertificate = new X509Certificate2(certificateFile);
            }



            if (encryptionCertificate == null)
            {
               System.Console.WriteLine(@"Attempting to find certificate in <CurrentUser>\Personal\Certificates...");

               var certificateStore = new WindowsCertificateStoreRepository();
               var matchingCertificates = certificateStore.Find(encryptionCertificateStoreLocation, encryptionCertificateStoreName, thumbprint);
               encryptionCertificate = matchingCertificates.FirstOrDefault();

               if (encryptionCertificate == null)
               {
                  System.Console.WriteLine(@"Attempting to find certificate in <LocalMachine>\Personal\Certificates...");

                  encryptionCertificateStoreLocation = StoreLocation.LocalMachine;
                  encryptionCertificateStoreName = StoreName.My;

                  matchingCertificates = certificateStore.Find(encryptionCertificateStoreLocation, encryptionCertificateStoreName, thumbprint);
                  encryptionCertificate = matchingCertificates.FirstOrDefault();
               }
            }

            if (encryptionCertificate == null)
            {
               System.Console.WriteLine(
                  "Unable to find certificate with thumbprint {0}. Make sure it's imported into the Windows Certificate Store.",
                  thumbprint);
               return -1;
            }

            System.Console.WriteLine("Certificate found.");
         }

         if (File.Exists(outputFile) && overwrite)
         {
            File.Delete(outputFile);
         }

         var inputFileContent = File.ReadAllText(inputFile, Encoding.UTF8);
         
         var serializer = new CipherTextWithCertificateInfoSerializer();

         if (encrypt)
         {
            var crypto = new X509Certificate2Crypto();
            var cipherText = crypto.Encrypt(encryptionCertificate, inputFileContent);

            var cipherTextWithCertInfo = new CipherTextWithCertificateInfo()
               {
                  CipherText = cipherText,
                  StoreLocation = encryptionCertificateStoreLocation,
                  StoreName = encryptionCertificateStoreName,
                  Thumbprint = encryptionCertificate.Thumbprint
               };

            var serializedInfo = serializer.Serialize(cipherTextWithCertInfo);
            File.WriteAllText(outputFile, serializedInfo, Encoding.UTF8);

            System.Console.WriteLine("Encryption completed.");
         }
         else
         {
            var cipherTextWithCertInfo = serializer.Deserialize(inputFileContent);
            
            var crypto = new X509Certificate2ThumbprintCrypto();
            var plainText = crypto.Decrypt(cipherTextWithCertInfo);

            File.WriteAllText(outputFile, plainText, Encoding.UTF8);

            System.Console.WriteLine("Decryption completed.");
         }

         return 0;
      }
   }
}
