using Encryption.GaloisField;
using System.Data;

namespace Encryption.AESCrypto
{
    /// <summary>
    /// Class providing lookups on the Rijndael substitution box.
    /// </summary>
    static class RijndaelSBox
    {
        /// <summary>
        /// the substitution box
        /// </summary>
        private static readonly byte[] sBox = new byte[256];

        private static readonly byte[] invSBox = new byte[256];

        /// <summary>
        /// static constructor
        /// </summary>
        static RijndaelSBox()
        {
            InitSBox();
            InitInvSBox();
        }

        /// <summary>
        /// Performs a circular shift on a byte.
        /// </summary>
        /// <param name="x">number</param>
        /// <param name="shift">positions to shift</param>
        /// <returns>shifted number</returns>
        private static byte ROTL8(byte x, int shift)
        {
            return (byte)(x << shift | x >> 8 - shift);
        }

        #region init methods

        /// <summary>
        /// Initializes the Rijndael subsitition box.
        /// </summary>
        private static void InitSBox()
        {
            sBox[0] = 0x63;
            byte p = 1;
            byte q = 1;
            do
            {
                // multiply p with 3
                p = (byte)(p ^ (p << 1) ^ ((p & 0x80) != 0 ? 0x1b : 0));

                // divide q by 3
                q ^= (byte)(q << 1);
                q ^= (byte)(q << 2);
                q ^= (byte)(q << 4);

                if ((q & 0x80) != 0)
                    q ^= 0x09;

                // perform the rijndael matrix transformation
                byte xformed = (byte)(q ^ ROTL8(q, 1) ^ ROTL8(q, 2) ^ ROTL8(q, 3) ^ ROTL8(q, 4) ^ 0x63);
                sBox[p] = xformed;
            }
            while (p != 1);
        }

        /// <summary>
        /// Initializes the Rijndael inverse substitution box.
        /// </summary>
        private static void InitInvSBox()
        {
            for(uint i = 0; i < sBox.Length; i++)
            {
                invSBox[sBox[i]] = (byte)i;
            }
        }

        #endregion 

        /// <summary>
        /// Substitutes a value.
        /// </summary>
        /// <param name="val">value to substitute</param>
        /// <returns>the substituted value</returns>
        public static byte Sub(byte val)
        {
            return sBox[val];
        }

        /// <summary>
        /// Substitutes a value with the inverse SBox.
        /// </summary>
        /// <param name="val">value</param>
        /// <returns>substituted value</returns>
        public static byte InvSub(byte val)
        {
            return invSBox[val];
        }
    }
}
