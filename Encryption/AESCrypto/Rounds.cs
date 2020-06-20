using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations.Schema;
using System.Runtime.CompilerServices;
using System.Text;
using static Encryption.Utils.Math;
using static Encryption.GaloisField.LookupTables;

namespace Encryption.AESCrypto
{
    /// <summary>
    /// Class providing operations for the AES rounds.
    /// </summary>
    static class Rounds {

        /// <summary>
        /// mix columns MDS matrix
        /// </summary>
        private static readonly byte[] mds = new byte[] { 0x2, 0x3, 0x1, 0x1 };

        /// <summary>
        /// inverse mix columns MDS  matrix
        /// </summary>
        private static readonly byte[] invMds = new byte[] { 0x0E, 0x0B, 0x0D, 0x09};

        #region basic operations

        /// <summary>
        /// Adds the round key to the current state
        /// </summary>
        /// <param name="state">current state block</param>
        /// <param name="roundKey">current round key</param>
        public static void AddRoundKey(byte[] state, byte[] roundKey)
        {
            for (int i = 0; i < state.Length; i++)
                state[i] ^= roundKey[i];
        }

        /// <summary>
        /// Mixes the columns of an AES state block using a MDS matrix.
        /// </summary>
        /// <param name="state">state block</param>
        /// <param name="mds">MDS matrix</param>
        /// <param name="rowLen">row length</param>
        private static void MixCols(byte[] state, byte[] mds, byte rowLen = 4)
        {
            byte[] col = new byte[4];
            for (int i = 0; i < rowLen; i++)
            {
                for (int j = 0; j < rowLen; j++)
                    col[i] = state[rowLen * j + i];
                MixCol(col, mds);
                for (int j = 0; j < rowLen; j++)
                    state[rowLen * j + i] = col[i];
            }
        }

        /// <summary>
        /// Mixes one byte array using a MDS matrix.
        /// </summary>
        /// <param name="col">column</param>
        /// <param name="mds">MDS matrix</param>
        private static void MixCol(byte[] col, byte[] mds)
        {
            byte[] cpy = new byte[col.Length];
            col.CopyTo(cpy, 0);

            // apply MDS matrix
            for (int i = 0; i < 4; i++)
                col[i] = (byte)(GMul(cpy[0], mds[i]) ^ GMul(cpy[1], mds[(i + 1) % 4]) ^ GMul(cpy[2], mds[(i + 2) % 4]) ^ GMul(cpy[3], mds[(i + 3) % 4]));
        }

        /// <summary>
        /// Shifts the rows of a state block.
        /// Each row is shifted one block more leftwards than the previous row.
        /// </summary>
        /// <param name="state">state block</param>
        /// <param name="mul">multiplicator of shifts (1 for forward shift / -1 for inverse shift)</param>
        /// <param name="rowLen">length of one row</param>
        private static void ShiftRows(byte[] state, int mul, int rowLen = 4)
        {
            byte[] temp = new byte[rowLen];
            for (int i = 1; i < 4; i++)
            {
                int offset = 4 * rowLen;
                for (int j = 0; j < rowLen; j++)
                    temp[j] = state[offset + Mod(mul * (i + j), rowLen)];
                for (int j = 0; j < rowLen; j++)
                    state[j] = temp[j];
            }
        }

        #endregion

        #region cipher - forward

        /// <summary>
        /// Apply one round on an AES block.
        /// </summary>
        /// <param name="state">state block</param>
        /// <param name="rKey">round key</param>
        public static void Round(byte[] state, byte[] rKey)
        {
            Sub(state);
            ShiftRows(state, 1);
            MixCols(state, mds);
            AddRoundKey(state, rKey);
        }

        /// <summary>
        /// Apply the final round on an AES block.
        /// </summary>
        /// <param name="state">state block</param>
        /// <param name="rKey">round key</param>
        public static void FinalRound(byte[] state, byte[] rKey)
        {
            Sub(state);
            ShiftRows(state, 1);
            AddRoundKey(state, rKey);
        }

        /// <summary>
        /// Substitutes the state block.
        /// </summary>
        /// <param name="state">state block</param>
        private static void Sub(byte[] state)
        {
            for(byte i = 0; i < state.Length; i++)
                state[i] = RijndaelSBox.Sub(state[i]);
        }

        #endregion

        #region decipher - inverse

        /// <summary>
        /// Inverts an AES round.
        /// </summary>
        /// <param name="state">state matrix</param>
        /// <param name="rKey">round key</param>
        public static void InvRound(byte[] state, byte[] rKey)
        {
            ShiftRows(state, -1);
            InvSub(state);
            AddRoundKey(state, rKey);
            MixCols(state, invMds);
        }
        /// <summary>
        /// Performs the inverse final round on an AES block.
        /// </summary>
        /// <param name="state">state block</param>
        /// <param name="rKey">round key</param>
        public static void InvFinalRound(byte[] state, byte[] rKey)
        {
            ShiftRows(state, -1);
            InvSub(state);
            AddRoundKey(state, rKey);
        }

        /// <summary>
        /// Inversion of the substutition method.
        /// </summary>
        /// <param name="state">state block</param>
        private static void InvSub(byte[] state)
        {
            for (byte i = 0; i < state.Length; i++)
                state[i] = RijndaelSBox.InvSub(state[i]);
        }

        #endregion
    }
}