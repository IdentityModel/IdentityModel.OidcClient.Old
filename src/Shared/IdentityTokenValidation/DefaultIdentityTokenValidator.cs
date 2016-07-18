// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System;
using System.Threading.Tasks;
using System.Linq;
using JosePCL.Keys.Rsa;
using Newtonsoft.Json.Linq;
using IdentityModel.OidcClient.Logging;

namespace IdentityModel.OidcClient.IdentityTokenValidation
{
    public class DefaultIdentityTokenValidator : IIdentityTokenValidator
    {
        private static readonly ILog Logger = LogProvider.For<DefaultIdentityTokenValidator>();

        public TimeSpan ClockSkew { get; set; } = TimeSpan.FromMinutes(5);

        public Task<IdentityTokenValidationResult> ValidateAsync(string identityToken, string clientId, ProviderInformation providerInformation)
        {
            Logger.Debug("starting identity token validation");
            Logger.Debug($"identity token: {identityToken}");

            var fail = new IdentityTokenValidationResult
            {
                Success = false
            };

            var e = Base64Url.Decode(providerInformation.KeySet.Keys.First().E);
            var n = Base64Url.Decode(providerInformation.KeySet.Keys.First().N);
            var pubKey = PublicKey.New(e, n);

            var json = JosePCL.Jwt.Decode(identityToken, pubKey);
            Logger.Debug("decoded JWT: " + json);

            var payload = JObject.Parse(json);

            var issuer = payload["iss"].ToString();
            Logger.Debug($"issuer: {issuer}");

            var audience = payload["aud"].ToString();
            Logger.Debug($"audience: {audience}");

            if (issuer != providerInformation.IssuerName)
            {
                fail.Error = "Invalid issuer name";
                Logger.Error(fail.Error);

                return Task.FromResult(fail);
            }

            if (audience != clientId)
            {
                fail.Error = "Invalid audience";
                Logger.Error(fail.Error);

                return Task.FromResult(fail);
            }

            var utcNow = DateTime.UtcNow;
            var exp = payload.Value<long>("exp");
            var nbf = payload.Value<long?>("nbf");

            Logger.Debug($"exp: {exp}");
            
            if (nbf != null)
            {
                Logger.Debug($"nbf: {nbf}");

                var notBefore = nbf.Value.ToDateTimeFromEpoch();
                if (notBefore > utcNow.Add(ClockSkew))
                {
                    fail.Error = "Token not valid yet";
                    Logger.Error(fail.Error);

                    return Task.FromResult(fail);
                }
            }

            var expires = exp.ToDateTimeFromEpoch();
            if (expires < utcNow.Add(ClockSkew.Negate()))
            {
                fail.Error = "Token expired";
                Logger.Error(fail.Error);

                return Task.FromResult(fail);
            }

            Logger.Info("identity token validation success");

            return Task.FromResult(new IdentityTokenValidationResult
            {
                Success = true,
                Claims = payload.ToClaims(),
                SignatureAlgorithm = "RS256"
            });

        }
    }
}