using System;

namespace Encryption.GaloisField
{
    /// <summary>
    /// Class providing Operations for the Binary Arithmetics.
    /// </summary>
    static class BinaryArithmetics
    {
        /// <summary>
        /// Performs a polynomial division in the binary arithmetic.
        /// </summary>
        /// <param name="term">term to use</param>
        /// <param name="polynom">polynom to divide by</param>
        /// <returns>An array conaining the following values: {result, rest}</returns>
        public static uint[] Div(uint term, uint polynom)
        {
            if(polynom > term)
            {
                return new uint[] { 0, term };
            }
            var polynomLength = (int)Math.Log2(polynom);
            var shift = (int)Math.Log2(term) - polynomLength;

            // shift term to get the first carry
            uint carryPolynom = polynom << shift;
            uint carry = (term >> shift) << shift;

            uint result = 0;
            while(carryPolynom >= polynom)
            {
                shift = (int)Math.Log2(carryPolynom);
                if(carry < 1 << shift)
                {
                    // add 0 to the result if the reverse multiplication is 0
                    result <<= 1;
                    carry |= ((uint)1 << shift - polynomLength - 1) & term;
                }
                else
                {
                    // else add 1 to the result
                    result = (result << 1) + 1;
                    // transform XOR (polynomial addition/substraction in the 2er arithmetic) and get the next carry
                    carry = carryPolynom ^ carry | ((uint)1 << shift - polynomLength - 1) & term;
                }
                carryPolynom >>= 1;
            }
            return new uint[] { result, carry };
        }

        /// <summary>
        /// performs a polynomial division on  two polynoms
        /// </summary>
        /// <param name="term">term</param>
        /// <param name="multiplicator">multiplicator</param>
        /// <returns>the multiplicated polynoms</returns>
        public static uint Mul(uint term, uint multiplicator)
        {
            int shift = 1;
            uint result = 0;
            while(shift <= multiplicator)
            {
                if((multiplicator & shift) != 0)
                {
                    // add the term shifted by shift to the result
                    result ^= term << (int)Math.Log2(shift);
                }
                shift <<= 1;
            }
            return result;
        }

        /// <summary>
        /// Performs a addition/substraction in the binary arithmetic
        /// </summary>
        /// <param name="a">first number</param>
        /// <param name="b">second number</param>
        /// <returns>result</returns>
        public static uint AddSub(uint a, uint b)
        {
            return a ^ b;
        }

    }
}
