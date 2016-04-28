// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System.Text;

namespace IdentityModel.OidcClient
{
    internal static class RNG
    {
        public static string CreateUniqueId(int length = 64)
        {
            var bytes = PCLCrypto.WinRTCrypto.CryptographicBuffer.GenerateRandom(length);
            return ByteArrayToString(bytes);
        }

        private static string ByteArrayToString(byte[] ba)
        {
            StringBuilder hex = new StringBuilder(ba.Length * 2);
            foreach (byte b in ba)
            {
                hex.AppendFormat("{0:x2}", b);
            }

            return hex.ToString();
        }
    }
}