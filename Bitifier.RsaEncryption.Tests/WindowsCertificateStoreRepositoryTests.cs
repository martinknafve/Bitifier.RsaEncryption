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
   public class WindowsCertificateStoreRepositoryTests
   {
      [Test]
      public void TestFindCertificate()
      {
         var windowsCertificateStoreRepo = new WindowsCertificateStoreRepository();

         windowsCertificateStoreRepo.Find(StoreLocation.CurrentUser, StoreName.My, "");
      }
   }
}
