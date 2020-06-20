using System;

namespace Encryption.GaloisField
{
    /// <summary>
    /// Class providing euclidean algorithms.
    /// </summary>
    static class Euler
    {
        /// <summary>
        /// Gets the greatest common divisor of two numbers using binary operations ("Steinscher Algorithmus").
        /// </summary>
        /// <param name="a">first number</param>
        /// <param name="b">second number</param>
        /// <returns>the greatest common divisor</returns>
        static public uint GCD(uint a, uint b)
        {
            // a == 0 or b == 0 is not allowed
            if (a == 0) return b;
            if (b == 0) return a;

            // if both values are even shift them
            var shift = 0;
            while(Convert.ToBoolean(~a & 1) && Convert.ToBoolean(~b & 1))
            {
                a >>= 1;
                b >>= 1;
                shift++;
            }
            // while rest exists
            while(a != 0)
            {
                //  a to odd
                while (Convert.ToBoolean(~a & 1)) a >>= 1;
                // b to odd
                while (Convert.ToBoolean(~b & 1)) b >>= 1;
                // remove the smaller from the greater and divide it by two, because it is even.
                if (a < b) b = (b - a) >> 2;
                else a = (a - b) >> 2;
            }
            return b << shift;
        }

        /// <summary>
        /// Processes an algorithm to solve equations in the following style: gcd(a, b) = ax + by.
        /// </summary>
        /// <param name="a">first number</param>
        /// <param name="b">second number</param>
        /// <returns> 
        /// An Array containing values in the following order: {gcd, x, y}.
        /// </returns>
        static public int[] XGCD(int a, int b)
        {
            // first equations coefficients
            int[] equation1 = { 1, 0 };
            // second equations coefficients
            int[] equation2 = { 0, 1 };
            
            var rest = a % b;
            // while there is a rest
            while(rest != 0)
            {
                var division = a / b;
                // calculate coefficients
                int[] newEquation =
                {
                    equation1[0] - division * equation2[0],
                    equation1[1] - division * equation2[1]
                };
                // add equation to the two stored equations
                equation1[0] = equation2[0];
                equation1[1] = equation2[1];
                equation2[0] = newEquation[0];
                equation2[1] = newEquation[1];

                // swap a and b 
                a = b;
                b = rest;
                rest = a % b;
            }

            return new int[] {b, equation2[0], equation2[1] };
        }

        /// <summary>
        /// Calculates the multiplicative inverse in the Rinjael Field (2^8 elements, generator polynom 0x11b) 
        /// by using the extended euclidean algorithm.
        /// </summary>
        /// <param name="a">number</param>
        /// <returns>multiplicative inverse</returns>
        public static byte RinInv(byte a)
        {
            ushort u1 = 0, u3 = 0x11b, v1 = 1, v3 = a;

            while (v3 != 0)
            {
                ushort t1 = u1, t3 = u3;
                byte q = (byte)(Math.Log2(u3) - Math.Log2(v3));

                if (q >= 0)
                {
                    t1 ^= (ushort)(v1 << q);
                    t3 ^= (ushort)(v3 << q);
                }
                u1 = v1;
                u3 = v3;
                v1 = t1;
                v3 = t3;
            }

            if (u1 >= 0x100)
                u1 ^= 0x11b;

            return (byte)u1;
        }
    }
}
