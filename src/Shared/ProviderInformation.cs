// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityModel.Jwt;
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
        public JsonWebKeySet KeySet { get; set; }

        public string TokenEndpoint { get; set; }
        public string AuthorizeEndpoint { get; set; }
        public string EndSessionEndpoint { get; set; }
        public string UserInfoEndpoint { get; set; }

        public void Validate()
        {
            if (string.IsNullOrEmpty(TokenEndpoint)) throw new InvalidOperationException("Missing token endpoint.");
            if (string.IsNullOrEmpty(AuthorizeEndpoint)) throw new InvalidOperationException("Missing authorize endpoint.");
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
                AuthorizeEndpoint = doc["authorization_endpoint"].ToString(),
                TokenEndpoint = doc["token_endpoint"].ToString(),
                EndSessionEndpoint = doc["end_session_endpoint"].ToString(),
                UserInfoEndpoint = doc["userinfo_endpoint"].ToString(),
            };

            // parse web key set
            var jwksUri = doc["jwks_uri"].ToString();
            var jwks = await client.GetStringAsync(jwksUri);

            info.KeySet = new JsonWebKeySet(jwks);

            return info;
        }
    }
}