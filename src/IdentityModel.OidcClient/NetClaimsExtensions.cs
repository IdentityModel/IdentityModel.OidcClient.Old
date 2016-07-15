// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System.Collections.Generic;
using System.Linq;

namespace IdentityModel.OidcClient
{
    public static class NetClaimsExtensions
    {
        public static IList<System.Security.Claims.Claim> ToClaimsList(this Claims claims)
        {
            return new List<System.Security.Claims.Claim>(claims.Select(c => new System.Security.Claims.Claim(c.Type, c.Value)));
        }

        public static System.Security.Claims.ClaimsIdentity ToClaimsIdentity(this Claims claims, string authenticationType = "internal")
        {
            return new System.Security.Claims.ClaimsIdentity(claims.ToClaimsList(), authenticationType);
        }

        public static System.Security.Claims.ClaimsPrincipal ToClaimsPrincipal(this Claims claims, string authenticationType = "internal")
        {
            return new System.Security.Claims.ClaimsPrincipal(claims.ToClaimsIdentity(authenticationType));
        }
    }
}