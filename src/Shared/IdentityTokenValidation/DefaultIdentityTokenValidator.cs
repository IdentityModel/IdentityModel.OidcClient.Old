// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System;
using System.Threading.Tasks;
using System.Linq;
using JosePCL.Keys.Rsa;
using Newtonsoft.Json.Linq;
using IdentityModel.OidcClient.Logging;
using IdentityModel.Jwt;
using JosePCL.Serialization;
using PCLCrypto;
using System.Collections;
using System.Collections.Generic;

namespace IdentityModel.OidcClient.IdentityTokenValidation
{
    public class DefaultIdentityTokenValidator : IIdentityTokenValidator
    {
        private IEnumerable<string> _supportedAlgorithms = new List<string>
        {
            OidcConstants.Algorithms.Asymmetric.RS256,
            OidcConstants.Algorithms.Asymmetric.RS384,
            OidcConstants.Algorithms.Asymmetric.RS512
        };

        private static readonly ILog Logger = LogProvider.For<DefaultIdentityTokenValidator>();

        public TimeSpan ClockSkew { get; set; } = TimeSpan.FromMinutes(5);

        public Task<IdentityTokenValidationResult> ValidateAsync(string identityToken, string clientId, ProviderInformation providerInformation)
        {
            Logger.Debug("starting identity token validation");
            Logger.Debug($"identity token: {identityToken}");

            var fail = new IdentityTokenValidationResult();

            ValidatedToken token;
            try
            {
                token = ValidateSignature(identityToken, providerInformation.KeySet);
            }
            catch (Exception ex)
            {
                fail.Error = ex.ToString();
                Logger.Error(fail.Error);

                return Task.FromResult(fail);
            }

            if (!token.Success)
            {
                fail.Error = token.Error;
                Logger.Error(fail.Error);

                return Task.FromResult(fail);
            }

            var issuer = token.Payload["iss"].ToString();
            Logger.Debug($"issuer: {issuer}");

            var audience = token.Payload["aud"].ToString();
            Logger.Debug($"audience: {audience}");

            if (!string.Equals(issuer, providerInformation.IssuerName, StringComparison.Ordinal))
            {
                fail.Error = "Invalid issuer name";
                Logger.Error(fail.Error);

                return Task.FromResult(fail);
            }

            if (!string.Equals(audience, clientId, StringComparison.Ordinal))
            {
                fail.Error = "Invalid audience";
                Logger.Error(fail.Error);

                return Task.FromResult(fail);
            }

            var utcNow = DateTime.UtcNow;
            var exp = token.Payload.Value<long>("exp");
            var nbf = token.Payload.Value<long?>("nbf");

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
                Claims = token.Payload.ToClaims(),
                SignatureAlgorithm = token.Algorithm
            });
        }

        ICryptographicKey LoadKey(JsonWebKeySet keySet, string kid)
        {
            Logger.Debug("Searching keyset for id: " + kid);

            foreach (var webkey in keySet.Keys)
            {
                if (webkey.Kid == kid)
                {
                    var e = Base64Url.Decode(webkey.E);
                    var n = Base64Url.Decode(webkey.N);

                    Logger.Debug("found");
                    return PublicKey.New(e, n);
                }
            }

            Logger.Debug("Key not found");
            return null;
        }

        ValidatedToken ValidateSignature(string token, JsonWebKeySet keySet)
        {
            var parts = Compact.Parse(token);
            var header = JObject.Parse(parts.First().Utf8);

            var kid = header["kid"].ToString();
            if (kid.IsMissing())
            {
                var error = "JWT has no kid";

                Logger.Error(error);
                return new ValidatedToken { Error = error };
            }
            
            var alg = header["alg"].ToString();

            if (!_supportedAlgorithms.Contains(alg))
            {
                var error = $"JWT uses an unsupported algorithm: {alg}";

                Logger.Error(error);
                return new ValidatedToken { Error = error };
            }

            Logger.Debug("Token signing algorithm: " + alg);

            var key = LoadKey(keySet, kid);
            if (key == null)
            {
                return new ValidatedToken
                {
                    Error = "No key found that matches the kid of the token"
                };
            }

            var json = JosePCL.Jwt.Decode(token, key);
            Logger.Debug("decoded JWT: " + json);

            var payload = JObject.Parse(json);

            return new ValidatedToken
            {
                KeyId = kid,
                Algorithm = alg,
                Payload = payload
            };
        }
    }
}