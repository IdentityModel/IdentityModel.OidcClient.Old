// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System.Collections.Generic;
using System.Linq;

namespace IdentityModel.OidcClient
{
    public class Claims : List<Claim>
    {
        public Claims()
        { }

        public Claims(IEnumerable<Claim> claims) : base(claims)
        { }

        public Claim FindFirst(string claimType)
        {
            return this.FirstOrDefault(c => c.Type == claimType);
        }

        public Claims FindAll(string claimType)
        {
            return this.Where(c => c.Type == claimType).ToClaims();
        }
    }
}