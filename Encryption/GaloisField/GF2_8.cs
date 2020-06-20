using System;
using System.Collections.Generic;
using System.Net;
using System.Text;

namespace Encryption.GaloisField
{
    /// <summary>
    /// Class providing operations for the GF(2^8) Galois Field.
    /// </summary>
    static class GF2_8
    {
        /// <summary>
        /// Performs an addition/subtraction.
        /// </summary>
        /// <param name="a">first value</param>
        /// <param name="b">second value</param>
        /// <returns>the result</returns>
        public static byte AddSub(byte a, byte b)
        {
            return (byte)(a ^ b);
        }

        /// <summary>
        /// Performs a multiplication.
        /// </summary>
        /// <param name="a">first value</param>
        /// <param name="b">second value</param>
        /// <returns>the result</returns>
        public static byte Mul(byte a, byte b)
        {
            byte p = 0;
            for (byte counter = 0; counter < 8; counter++)
            {
                if ((b & 1) == 1)
                    p ^= a;
                byte hiBitSet = (byte)(a & 0x80);
                a <<= 1;
                if (hiBitSet != 0)
                    // add 27 to a, because the generator polynom of the Rijndael field is 0x11b and 256 is already cutted out
                    a ^= 0x1b;
                b >>= 1;
            }
            return p;
        }

        /// <summary>
        /// Multiplicates a number by 2.
        /// </summary>
        /// <param name="num">number</param>
        /// <returns>result</returns>
        public static byte XTime(byte num)
        {
            return (byte)((num << 1) ^ ((num & 0x80) != 0 ? 0x1b : 0x00));
        }
    }
}
