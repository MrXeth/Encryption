using System;
using System.Collections.Generic;
using System.Text;

namespace Encryption.GaloisField
{
    /// <summary>
    /// Class to perform the Itoh Tsujii to find the multiplicative inverse over the Rjindael Field.
    /// </summary>
    public static class ItohTsujii
    {
        /// <summary>
        /// Performs the Itoh Tsujii algorithm to find the multiplicative inverse of a number over the Rjindael Field.
        /// </summary>
        /// <param name="a">Number to invert.</param>
        /// <returns>the result</returns>
        public static byte Apply(byte a)
        {
            // r = 255 => (2^8-1)-(2-1)
            byte ar1 = a;
            // a^(r-1) in GF(2^8)
            for(byte i = 1; i < 254; i++)
            {
                ar1 = LookupTables.GMul(ar1, a);
            }
            // a^r
            byte ar = LookupTables.GMul(ar1, a);
            // ar & 1: inversion of a^r in GF(2)
            // (a^r)^(-1) * a^(r-1) = a^(-1)
            return (byte)((ar & 1) * ar1);
        }
    }
}
 