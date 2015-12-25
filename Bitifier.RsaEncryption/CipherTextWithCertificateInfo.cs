using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace Bitifier.RsaEncryption
{
   public class CipherTextWithCertificateInfo
   {
      public StoreLocation StoreLocation { get; set; }

      public StoreName StoreName { get; set;}

      public string Thumbprint { get; set; }

      public string CipherText { get; set; }
   }
}
