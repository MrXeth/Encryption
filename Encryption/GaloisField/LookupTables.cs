
using System;

namespace Encryption.GaloisField
{
    /// <summary>
    /// Operations over the 2^8 Galois Field.
    /// </summary>
    static class LookupTables
    {
        /// <summary>
        /// Generator number for logarithm tables to get results for every antilogarithm result.
        /// </summary>
        private static readonly byte g = 3;
     
        /// <summary>
        /// logarithm table
        /// </summary>
        private static readonly byte[] log = new byte[256];

        /// <summary>
        /// antlogarithm table
        /// </summary>
        private static readonly byte[] antilog = new byte[255];

        static LookupTables()
        {
            InitTables();
        }

        #region init methods

        /// <summary>
        /// Inits the log and the antilog tables.
        /// </summary>
        private static void InitTables()
        {
            antilog[0] = 1;
            for(byte i = 1; i < antilog.Length; i++)
            {
                // next antilog is g*g^(i-1) = g^i
                antilog[i] = GF2_8.Mul(antilog[i - 1], g);
                log[antilog[i]] = i;
            }
        }

        #endregion

        /// <summary>
        /// Performs a multiplication.
        /// </summary>
        /// <param name="a">number</param>
        /// <param name="b">number</param>
        /// <returns>result</returns>
        public static byte GMul(byte a, byte b)
        {
            if (a == 0 || b == 0)
                return 0;
            int logMul = log[a] + log[b];
            if (logMul >= 255)
                logMul = (byte)(logMul + 1);
            return antilog[logMul];
        }

        /// <summary>
        /// Calculates the inverse of a number
        /// </summary>
        /// <param name="number">number</param>
        /// <returns>inverse</returns>
        public static byte GInv(byte number)
        {
            if (number == 0)
                return 0;
            else
                return antilog[255 - log[number]];
        }
    }
}
