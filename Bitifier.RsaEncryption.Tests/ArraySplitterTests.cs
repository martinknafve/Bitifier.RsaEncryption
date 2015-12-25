using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using NUnit.Framework;
using NUnit.Framework.Compatibility;

namespace Bitifier.RsaEncryption.Tests
{
   [TestFixture]
   public class ArraySplitterTests
   {
      [Test]
      public void TestSplitLargeArray()
      {
         var messageBuilder = new StringBuilder();
         for (int i = 0; i < 50000; i++)
            messageBuilder.Append(Guid.NewGuid());

         var message = messageBuilder.ToString();
         var bytes = Encoding.UTF8.GetBytes(message);

         var stopwatch = new Stopwatch();
         stopwatch.Start();
         var arrays = bytes.Split(200);
         stopwatch.Stop();

         // Join it again
         var joinedBytes = new List<byte>();

         foreach (var arr in arrays)
            joinedBytes.AddRange(arr);

         var data = Encoding.UTF8.GetString(joinedBytes.ToArray());

         Assert.AreEqual(data, message);

         Console.WriteLine("Data split in {0}", stopwatch.Elapsed);
      }

      [Test]
      public void SplittingNullArrayShouldThrow()
      {
         byte[] bytes = null;

         var exception = Assert.Throws<ArgumentNullException>( () => bytes.Split(1));
         Assert.AreEqual("source", exception.ParamName);
      }

      [Test]
      public void SplittingIntoZeroByteChunksShouldThrow()
      {
         byte[] bytes = new byte[10];

         var exception = Assert.Throws<ArgumentException>(() => bytes.Split(0));
         Assert.AreEqual("maxSize", exception.ParamName);
         Assert.That(exception.Message, Does.StartWith("Max size must be greater than 0"));
      }
   }
}
