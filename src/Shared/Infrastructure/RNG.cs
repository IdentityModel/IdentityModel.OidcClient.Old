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
            return PCLCrypto.WinRTCrypto.CryptographicBuffer.ConvertBinaryToString(Encoding.UTF8, bytes);
        }
    }
}