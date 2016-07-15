// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using Newtonsoft.Json.Linq;
using System.Collections.Generic;

namespace IdentityModel.OidcClient
{
    public static class ClaimsExtensions
    {
        public static Claims ToClaims(this IEnumerable<Claim> claims)
        {
            return new Claims(claims);
        }

        public static Claims ToClaims(this JObject jobject)
        {
            var claims = new Claims();

            foreach (var x in jobject)
            {
                var array = x.Value as JArray;

                if (array != null)
                {
                    foreach (var item in array)
                    {
                        claims.Add(new Claim(x.Key, item.ToString()));
                    }
                }
                else
                {
                    claims.Add(new Claim(x.Key, x.Value.ToString()));
                }
            }

            return claims;
        }
    }
}