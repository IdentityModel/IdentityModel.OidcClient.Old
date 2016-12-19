// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityModel.Client;

namespace IdentityModel.OidcClient
{
    class ResponseValidationResult : Result
    {
        public AuthorizeResponse AuthorizeResponse { get; set; }
        public TokenResponse TokenResponse { get; set; }
        public Claims Claims { get; set; }
    }
}