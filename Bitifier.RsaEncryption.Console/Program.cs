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

         bool encrypt = false;
         bool decrypt = false;
         bool overwrite = false;

         var optionSet = new OptionSet
            {
               { "inputFile=",       v => inputFile = v },
               { "outputFile=",      v => outputFile = v },
               { "thumbprint=",      v => thumbprint = v },
               { "encrypt",          v => encrypt = true  },
               { "decrypt",          v => decrypt = true  },
               { "overwrite",        v => overwrite = true  },
            };

         try
         {
            optionSet.Parse(args);

            var errors = new StringBuilder();

            if (string.IsNullOrWhiteSpace(thumbprint))
               errors.AppendLine("Thumbprint must be specified.");
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

         StoreLocation storeLocation = StoreLocation.CurrentUser;
         StoreName storeName = StoreName.My;

         System.Console.WriteLine(@"Attempting to find certificate in <CurrentUser>\Personal\Certificates");
         var certificateStore = new WindowsCertificateStoreRepository();
         var matchingCertificates = certificateStore.Find(storeLocation, storeName, thumbprint);
         var matchingCertificate = matchingCertificates.FirstOrDefault();

         if (matchingCertificate == null)
         {
            System.Console.WriteLine(@"Attempting to find certificate in <LocalMachine>\Personal\Certificates");

            storeLocation = StoreLocation.LocalMachine;
            storeName = StoreName.My;

            matchingCertificates = certificateStore.Find(storeLocation, storeName, thumbprint);
            matchingCertificate = matchingCertificates.FirstOrDefault();
         }

         if (matchingCertificate == null)
         {
            System.Console.WriteLine("Unable to find certificate with thumbprint {0}. Make sure it's imported into the Windows Certificate Store.", thumbprint);
            return -1;
         }

      
         if (File.Exists(outputFile) && !overwrite)
         {
            File.Delete(outputFile);
         }

         var inputFileContent = File.ReadAllText(inputFile, Encoding.UTF8);

         var crypto = new X509Certificate2ThumbprintCrypto();
         var serializer = new CipherTextWithCertificateInfoSerializer();

         if (encrypt)
         {
            var cipherTextWithCertInfo = crypto.Encrypt(storeLocation, storeName, thumbprint, inputFileContent);

            var serializedInfo = serializer.Serialize(cipherTextWithCertInfo);
            File.WriteAllText(outputFile, serializedInfo, Encoding.UTF8);
         }
         else
         {
            var cipherTextWithCertInfo = serializer.Deserialize(inputFileContent);

            var plainText = crypto.Decrypt(cipherTextWithCertInfo);

            File.WriteAllText(outputFile, plainText, Encoding.UTF8);
         }

         return 0;
      }
   }
}
