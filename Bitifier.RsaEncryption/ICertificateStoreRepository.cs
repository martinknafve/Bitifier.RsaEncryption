using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace Bitifier.RsaEncryption
{
   public interface ICertificateStoreRepository
   {
      IList<X509Certificate2> Find(StoreLocation location, StoreName name, string thumbprint);
   }
}
