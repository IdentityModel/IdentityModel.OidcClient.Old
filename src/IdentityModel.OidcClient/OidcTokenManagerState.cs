// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


namespace IdentityModel.OidcClient
{
    internal class OidcTokenManagerState
    {
        internal OidcClientOptions Options { get; set; }
        internal LoginResult LoginResult { get; set; }
    }
}
