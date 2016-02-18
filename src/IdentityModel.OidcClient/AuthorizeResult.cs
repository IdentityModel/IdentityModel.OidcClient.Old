// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


namespace IdentityModel.OidcClient
{
    public class AuthorizeResult
    {
        public bool IsError { get; set; }
        public string Error { get; set; }

        public string IdentityToken { get; set; }
        public string Code { get; set; }
        public string RedirectUri { get; set; }

        public string Nonce { get; set; }
        public string Verifier { get; set; }
    }
}