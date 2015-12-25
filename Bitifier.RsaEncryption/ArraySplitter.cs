using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Bitifier.RsaEncryption
{
   internal static class ArraySplitter
   { 
      public static List<T[]> Split<T>(this T[] source, int maxSize)
      {
         if (source == null)
            throw new ArgumentNullException(nameof(source));
         if (maxSize <= 0)
            throw new ArgumentException("Max size must be greater than 0.", nameof(maxSize));

         var result = new List<T[]>();

         for (int i = 0; i < source.Length; i += maxSize)
         {
            int remaining = source.Length - i;

            var chunKSize = Math.Min(maxSize, remaining);

            T[] chunk = new T[chunKSize];
            Array.Copy(source, i, chunk, 0, chunKSize);

            result.Add(chunk);
         }

         return result;
      }
   }
}
