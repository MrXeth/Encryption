using System;
using System.Collections.Generic;
using System.Text;

namespace Encryption.Utils
{
    static class Math
    {

        public static int Mod(int a, int b)
        {
            return (a % b + b) % b;
        }
    }
}
