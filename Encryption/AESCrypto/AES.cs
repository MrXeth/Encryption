using Encryption.AESCrypto;
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Security.Cryptography;
using System.Text;

namespace Encryption.AESCrypto
{
    /// <summary>
    /// Class to perform the AES encryption.
    /// </summary>
    public class AES
    {
        /// <summary>
        /// Expands the key (128, 192, 256 Bits to 176, 208, 240 Bytes)
        /// </summary>
        /// <param name="key">key</param>
        /// <returns>expanded key</returns>
        private static byte[] InitExpKey(byte[] key)
        {
            int keyLen;
            if (key.Length < 16)
                keyLen = 16;
            else if (key.Length < 24)
                keyLen = 24;
            else if (key.Length < 32)
                keyLen = 32;
            else
                keyLen = 16;

            byte[] cipherKey;
            if (key.Length == keyLen)
                cipherKey = key;
            else
            {
                cipherKey = new byte[keyLen];
                for (byte i = 0; i < keyLen / 8; i++)
                {
                    if (i < keyLen)
                        cipherKey[i] = key[i];
                    else
                        // fixed algorithm to fill space if the key is not long enough
                        cipherKey[i] = i;
                }
            }
            return KeyExpansion.ExpandKey(cipherKey);
        }


        /// <summary>
        /// Extracts a round key from the expanded key.
        /// </summary>
        /// <param name="expKey">expanded key</param>
        /// <param name="rowLen">how long a row in the expanded key matrix is</param>
        /// <returns>a round key</returns>
        private static byte[] RoundKey(byte[] expKey, byte round, byte rowLen = 4)
        {
            byte[] roundKey = new byte[4 * rowLen];
            // columns
            for (byte i = 0; i < 4; i++)
                // rows
                for (byte j = 0; j < rowLen; j++)
                    roundKey[i + j * 4] = expKey[round * 16 + i * 4 + j];
            return roundKey;
        }

        #region encryption

        #nullable enable

        /// <summary>
        /// Encrypts data using the AES algorithm
        /// </summary>
        /// <param name="input">input data</param>
        /// <param name="key">key</param>
        /// <param name="expKey">expanded key</param>
        /// <returns>encrypted data</returns>
        public static byte[] Encrypt(byte[] input, byte[]? key, byte[]? expKey)
        {

            if (expKey == null)
            {
                if (key == null)
                    throw new ArgumentNullException(nameof(key));
                expKey = InitExpKey(key);
            }
            Cipher(input, expKey);
            return input;
        }

    #nullable disable

        /// <summary>
        /// Ciphers data using the expanded AES key.
        /// </summary>
        /// <param name="input">input data</param>
        /// <param name="expKey">expanded key</param>
        private static void Cipher(byte[] input, byte[] expKey)
        {
            byte[] state = new byte[16];
            
            byte rounds;
            if (expKey.Length == 176)
                rounds = 10;
            else if (expKey.Length == 208)
                rounds = 12;
            else if (expKey.Length == 240)
                rounds = 14;
            else
                return;

            // map to state mds format
            for (byte i = 0; i < 4; i++)
                for (byte j = 0; j < 4; j++)
                    state[i + j * 4] = input[i * 4 + j];
            
            EncryptState(state, expKey, rounds);

            // unmap
            for (byte i = 0; i < 4; i++)
                for (byte j = 0; j < 4; j++)
                    input[i * 4 + j] = state[i + j * 4];
        }

        /// <summary>
        /// Performs the AES opererations on a state block
        /// </summary>
        /// <param name="state">state block</param>
        /// <param name="expKey">expanded key</param>
        /// <param name="rounds">number of rounds</param>
        public static void EncryptState(byte[] state, byte[] expKey, byte rounds)
        {
            byte[] rk = RoundKey(expKey, 0);
            Rounds.AddRoundKey(state, rk);
            
            for(byte i = 1; i < rounds; i++)
            {
                rk = RoundKey(expKey, i);
                Rounds.Round(state, rk);
            }
            rk = RoundKey(expKey, rounds);
            Rounds.FinalRound(state, rk);
        }

        #endregion

        #region decryption

        #nullable enable

        /// <summary>
        /// Decrypts data using the AES algorithm.
        /// </summary>
        /// <param name="input">input data</param>
        /// <param name="key">key</param>
        /// <param name="expKey">expanded key</param>
        /// <returns>decrypted data</returns>
        public static byte[] Decrypt(byte[] input, byte[]? key, byte[]? expKey)
        {
            if (expKey == null)
            {
                if (key == null)
                    throw new ArgumentNullException(nameof(key));
                expKey = InitExpKey(key);
            }
            Decipher(input, expKey);
            return input;
        }

        #nullable disable

        /// <summary>
        /// Deciphers data using the expanded AES key.
        /// </summary>
        /// <param name="input">input data</param>
        /// <param name="expKey">expanded key</param>
        public static void Decipher(byte[] input, byte[] expKey)
        {
            byte[] state = new byte[16];

            byte rounds;
            if (expKey.Length == 176)
                rounds = 10;
            else if (expKey.Length == 208)
                rounds = 12;
            else if (expKey.Length == 240)
                rounds = 14;
            else
                return;

            // map to state mds format
            for (byte i = 0; i < 4; i++)
                for (byte j = 0; j < 4; j++)
                    state[i + j * 4] = input[i * 4 + j];

            DecryptState(state, expKey, rounds);

            // unmap
            for (byte i = 0; i < 4; i++)
                for (byte j = 0; j < 4; j++)
                    input[i * 4 + j] = state[i + j * 4];

        }

        /// <summary>
        /// Decrypts an AES stata block.
        /// </summary>
        /// <param name="state">state block</param>
        /// <param name="expKey">expanded key</param>
        /// <param name="rounds">number of rounds to perform</param>
        public static void DecryptState(byte[] state, byte[] expKey, byte rounds)
        {
            byte[] rk = RoundKey(expKey, rounds);
            Rounds.AddRoundKey(state, rk);

            for (byte i = (byte)(rounds - 1); i > 0; i--)
            {
                rk = RoundKey(expKey, i);
                Rounds.InvRound(state, rk);
            }
            rk = RoundKey(expKey, 0);
            Rounds.InvFinalRound(state, rk);
        }

        #endregion
    }
}
