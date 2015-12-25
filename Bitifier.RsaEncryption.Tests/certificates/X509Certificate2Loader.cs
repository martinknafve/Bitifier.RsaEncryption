using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace Bitifier.RsaEncryption.Tests
{
   static class X509Certificate2Loader
   {
      public static X509Certificate2 Test2048AWithPrivateKey()
      {
         return new X509Certificate2(Resources.Test2048A_pfx, "secret");
      }

      public static X509Certificate2 Test2048AWithoutPrivateKey()
      {
         return new X509Certificate2(Resources.Test2048A_cer);
      }

      public static X509Certificate2 Test2048BWithPrivateKey()
      {
         return new X509Certificate2(Resources.Test2048B_pfx, "secret");
      }

      public static X509Certificate2 Test4096AWithPrivateKey()
      {
         return new X509Certificate2(Resources.Test4096A_pfx, "secret");
      }
   }
}
