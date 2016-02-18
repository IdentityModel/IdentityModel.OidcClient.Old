// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading.Tasks;

namespace IdentityModel.OidcClient
{
    public class Endpoints
    {
        public string Token { get; set; }
        public string Authorize { get; set; }
        public string IdentityTokenValidation { get; set; }
        public string EndSession { get; set; }
        public string UserInfo { get; set; }

        public void Validate()
        {
            if (string.IsNullOrEmpty(Token)) throw new InvalidOperationException("Missing token endpoint.");
            if (string.IsNullOrEmpty(Authorize)) throw new InvalidOperationException("Missing authorize endpoint.");
        }

        public static async Task<Endpoints> LoadFromMetadataAsync(string authority)
        {
            var client = new HttpClient();
            var url = authority.EnsureTrailingSlash() + ".well-known/openid-configuration";

            var json = await client.GetStringAsync(url);

            var doc = JsonConvert.DeserializeObject<Dictionary<string, object>>(json);

            var endpoints = new Endpoints
            {
                Authorize = doc["authorization_endpoint"].ToString(),
                Token = doc["token_endpoint"].ToString(),
                EndSession = doc["end_session_endpoint"].ToString(),
                UserInfo = doc["userinfo_endpoint"].ToString(),
            };

            // todo: replace with local validation
            endpoints.IdentityTokenValidation = authority.EnsureTrailingSlash() + "connect/identitytokenvalidation";

            return endpoints;
        }
    }
}
