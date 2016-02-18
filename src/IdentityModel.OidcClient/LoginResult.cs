// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using Newtonsoft.Json;
using System;

namespace IdentityModel.OidcClient
{
    public class LoginResult
    {
        public bool Success { get; set; }
        public string Error { get; set; }

        public Claims Claims { get; set; }
        public string AccessToken { get; set; }
        public string IdentityToken { get; set; }
        public string RefreshToken { get; set; }

        public DateTime AccessTokenExpiration { get; set; }
        public DateTime AuthenticationTime { get; set; }

        public int SecondsBeforeRenewRequired { get; set; } = 60;

        [JsonIgnore]
        public bool IsAccessTokenValid
        {
            get
            {
                return DateTime.Now < AccessTokenExpiration.AddSeconds(- SecondsBeforeRenewRequired);
            }
        }
    }
}