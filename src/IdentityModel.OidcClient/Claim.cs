// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


namespace IdentityModel.OidcClient
{
    public class Claim
    {
        public string Type { get; set; }
        public string Value { get; set; }

        public Claim(string type, string value)
        {
            Type = type;
            Value = value;
        }

        public Claim()
        { }
    }
}