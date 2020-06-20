using Encryption.GaloisField;
using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Linq;

namespace Encryption.AESCrypto
{
    /// <summary>
    /// Class providing methods for the AES key expansion.
    /// </summary>
    static class KeyExpansion
    {

        /// <summary>
        /// Performs the mathematic operation to expand a key
        /// </summary>
        /// <param name="word"></param>
        /// <param name="iteration">current iteration number</param>
        public static void KeyScheduleCore(byte[] word, byte iteration)
        {
            // rotate the word by one
            byte temp = word[0];
            for (byte i = 1; i < word.Length; i++)
                word[i - 1] = word[i];
            word[^1] = temp;

            for(int i = 0; i < 4; i++)
                word[i] = RijndaelSBox.Sub(word[i]);
            word[0] = (byte)(word[0] ^ Rcon.GetRcon(iteration));
        }

        /// <summary>
        /// Expands an AES key.
        /// </summary>
        /// <param name="key">AES key</param>
        /// <returns>the expanded key</returns>
        public static byte[] ExpandKey(byte[] key)
        {
            // set the size of the key to expand (128 Bit -> 176 Byte | 192 Bit -> 208 Byte | 256 Bit -> 240 Byte)
            byte[] expKey;
            if (key.Length == 16)
                expKey = new byte[176];
            else if (key.Length == 24)
                expKey = new byte[208];
            else if (key.Length == 32)
                expKey = new byte[240];
            else
                return null;

            // assign the key to the first bytes of the expanded key
            for(byte i = 0; i < key.Length; i++)
                expKey[i] = key[i];

            byte currSize = (byte)key.Length;
            byte rconIt = 0;
            byte[] prevBytes = new byte[4];

            while(currSize < expKey.Length)
            {
                for(int i = 0; i < prevBytes.Length; i++)
                    prevBytes[i] = expKey[currSize - 4 + i];

                if (currSize % key.Length == 0)
                    KeyScheduleCore(prevBytes, rconIt++);

                // for 256 Bit keys perform an extra substitution every 16 Bytes
                if (key.Length == 32 && currSize % key.Length == 16)
                    for (byte i = 0; i < 4; i++)
                        prevBytes[i] = RijndaelSBox.Sub(prevBytes[i]);

                for(int i = 0; i < 4; i++, currSize++)
                    expKey[currSize] = (byte)(expKey[currSize - key.Length] ^ prevBytes[i]);
            }
            return expKey;
        }
        
    }
}
