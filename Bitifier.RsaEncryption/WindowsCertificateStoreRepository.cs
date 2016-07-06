using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace Bitifier.RsaEncryption
{
   public class WindowsCertificateStoreRepository : ICertificateStoreRepository
   {
      public IList<X509Certificate2> Find(StoreLocation location, StoreName name, string thumbprint)
      {
         var store = new X509Store(name, location);

         store.Open(OpenFlags.ReadOnly);

         try
         {
            var items = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false);

            return items.Cast<X509Certificate2>().ToList();
         }
         finally
         {
            store.Close();
         }
      }
   }
}
