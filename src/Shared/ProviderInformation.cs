// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading.Tasks;

namespace IdentityModel.OidcClient
{
    public class ProviderInformation
    {
        public string IssuerName { get; set; }
        //public JObject KeySet { get; set; }

        public string Token { get; set; }
        public string Authorize { get; set; }
        public string EndSession { get; set; }
        public string UserInfo { get; set; }

        public void Validate()
        {
            if (string.IsNullOrEmpty(Token)) throw new InvalidOperationException("Missing token endpoint.");
            if (string.IsNullOrEmpty(Authorize)) throw new InvalidOperationException("Missing authorize endpoint.");
        }

        public static async Task<ProviderInformation> LoadFromMetadataAsync(string authority)
        {
            var client = new HttpClient();
            var url = authority.EnsureTrailingSlash() + ".well-known/openid-configuration";

            var json = await client.GetStringAsync(url);

            var doc = JsonConvert.DeserializeObject<Dictionary<string, object>>(json);

            var info = new ProviderInformation
            {
                IssuerName = doc["issuer"].ToString(),
                Authorize = doc["authorization_endpoint"].ToString(),
                Token = doc["token_endpoint"].ToString(),
                EndSession = doc["end_session_endpoint"].ToString(),
                UserInfo = doc["userinfo_endpoint"].ToString(),
            };

            // todo: load jwks endpoint

            return info;
        }
    }
}