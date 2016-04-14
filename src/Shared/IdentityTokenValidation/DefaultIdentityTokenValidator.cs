// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System;
using System.Threading.Tasks;
using System.Linq;
using JosePCL.Keys.Rsa;
using Newtonsoft.Json.Linq;

namespace IdentityModel.OidcClient.IdentityTokenValidation
{
    public class DefaultIdentityTokenValidator : IIdentityTokenValidator
    {
        public TimeSpan ClockSkew { get; set; } = TimeSpan.FromMinutes(5);

        public Task<IdentityTokenValidationResult> ValidateAsync(string identityToken, string clientId, ProviderInformation providerInformation)
        {
            var fail = new IdentityTokenValidationResult
            {
                Success = false
            };

            var e = Base64Url.Decode(providerInformation.KeySet.Keys.First().E);
            var n = Base64Url.Decode(providerInformation.KeySet.Keys.First().N);
            var pubKey = PublicKey.New(e, n);

            var json = JosePCL.Jwt.Decode(identityToken, pubKey);
            var payload = JObject.Parse(json);

            var issuer = payload["iss"].ToString();
            var audience = payload["aud"].ToString();

            if (issuer != providerInformation.IssuerName)
            {
                fail.Error = "Invalid issuer name";
                return Task.FromResult(fail);
            }

            if (audience != clientId)
            {
                fail.Error = "Invalid audience";
                return Task.FromResult(fail);
            }

            var exp = payload["exp"].ToString();
            var nbf = payload["nbf"].ToString();

            var utcNow = DateTime.UtcNow;
            var notBefore = long.Parse(nbf).ToDateTimeFromEpoch();
            var expires = long.Parse(exp).ToDateTimeFromEpoch();

            if (notBefore > utcNow.Add(ClockSkew))
            {
                fail.Error = "Token not valid yet";
                return Task.FromResult(fail);
            }

            if (expires < utcNow.Add(ClockSkew.Negate()))
            {
                fail.Error = "Token expired";
                return Task.FromResult(fail);
            }

            return Task.FromResult(new IdentityTokenValidationResult
            {
                Success = true,
                Claims = payload.ToClaims(),
                SignatureAlgorithm = "RS256"
            });

        }
    }
}