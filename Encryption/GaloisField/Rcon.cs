using System;
using System.Collections.Generic;
using System.Text;

namespace Encryption.GaloisField
{
    /// <summary>
    /// Class providing operations for the rcon table.
    /// </summary>
    static class Rcon
    {
        /// <summary>
        /// the rcon table
        /// </summary>
        private static byte[] rconTable;

        /// <summary>
        /// static constructor
        /// </summary>
        static Rcon()
        {
            InitAesRcon();
        }

        /// <summary>
        /// Inits the rcon table with the necessary values for the Rjindael field (1-10).
        /// </summary>
        private static void InitAesRcon()
        {
            rconTable = new byte[10];
            rconTable[0] = 0x1;
            for(byte i = 1; i < rconTable.Length; i++)
            {
                rconTable[i] = GF2_8.XTime(rconTable[i - 1]);
            }
        }

        /// <summary>
        /// Inits the entire rcon table
        /// </summary>
        private static void InitRcon()
        {
            rconTable = new byte[255];
            rconTable[0] = 0x8d;
            for(byte i = 1; i < rconTable.Length; i++)
            {
                rconTable[i] = GF2_8.XTime(rconTable[i - 1]);
            }
        }

        /// <summary>
        /// Gets the rcon for a specific value
        /// </summary>
        /// <param name="val">the value</param>
        /// <returns>the rcon value</returns>
        public static byte GetRcon(byte val)
        {
            return rconTable[val];
        }

        /// <summary>
        /// calculates rcon values for 2er power values dynamically. 
        /// </summary>
        /// <param name="pow">the power</param>
        /// <returns>the 2er power value</returns>
        public static byte DynRcon(byte pow)
        {
            // 2 ^ (number - 1)
            byte res = (byte)(0x01 << --pow);
            return (byte)(res ^ ((0x80 & res) != 0 ? 0x1b : 0x0));
        }

    }
}
