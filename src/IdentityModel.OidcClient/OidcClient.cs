// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityModel.Client;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using PCLCrypto;
using static PCLCrypto.WinRTCrypto;

namespace IdentityModel.OidcClient
{
    public class OidcClient
    {
        private readonly AuthorizeClient _authorizeClient;
        private readonly OidcClientOptions _options;

        public OidcClient(OidcClientOptions options)
        {
            _authorizeClient = new AuthorizeClient(options);
            _options = options;
        }

        public async Task<LoginResult> LoginAsync(bool trySilent = false, object extraParameters = null)
        {
            var authorizeResult = await _authorizeClient.AuthorizeAsync(trySilent, extraParameters);

            if (authorizeResult.IsError)
            {
                return new LoginResult
                {
                    Success = false,
                    Error = authorizeResult.Error
                };
            }

            return await ValidateAsync(authorizeResult);
        }

        public Task LogoutAsync(string identityToken = null, bool trySilent = true)
        {
            return _authorizeClient.EndSessionAsync(identityToken, trySilent);
        }

        private async Task<LoginResult> ValidateAsync(AuthorizeResult result)
        {
            // validate identity token
            var claims = await ValidateIdentityTokenAsync(result.IdentityToken);
            if (claims == null)
            {
                return new LoginResult
                {
                    Success = false,
                    Error = "identity token validation error"
                };
            }

            // validate nonce
            var tokenNonce = claims.FindFirst(JwtClaimTypes.Nonce)?.Value ?? "";
            if (!string.Equals(result.Nonce, tokenNonce))
            {
                return new LoginResult
                {
                    Success = false,
                    Error = "invalid nonce"
                };
            }

            // validate audience
            var audience = claims.FindFirst(JwtClaimTypes.Audience)?.Value ?? "";
            if (!string.Equals(_options.ClientId, audience))
            {
                return new LoginResult
                {
                    Success = false,
                    Error = "invalid audience"
                };
            }

            // validate c_hash
            var cHash = claims.FindFirst(JwtClaimTypes.AuthorizationCodeHash)?.Value ?? "";

            var sha256 = HashAlgorithmProvider.OpenAlgorithm(HashAlgorithm.Sha256);

            var codeHash = sha256.HashData(
                CryptographicBuffer.CreateFromByteArray(
                    Encoding.UTF8.GetBytes(result.Code)));

            byte[] codeHashArray;
            CryptographicBuffer.CopyToByteArray(codeHash, out codeHashArray);

            byte[] leftPart = new byte[16];
            Array.Copy(codeHashArray, leftPart, 16);

            var leftPartB64 = Base64Url.Encode(leftPart);

            if (!leftPartB64.Equals(cHash))
            {
                return new LoginResult
                {
                    Success = false,
                    Error = "invalid code"
                };
            }

            var endpoints = await _options.GetEndpointsAsync();

            // get access token
            var tokenClient = new TokenClient(endpoints.Token, _options.ClientId, _options.ClientSecret);
            var tokenResult = await tokenClient.RequestAuthorizationCodeAsync(
                result.Code, 
                result.RedirectUri, 
                codeVerifier: result.Verifier);

            if (tokenResult.IsError || tokenResult.IsHttpError)
            {
                return new LoginResult
                {
                    Success = false,
                    Error = tokenResult.Error
                };
            }

            // get profile if enabled
            if (_options.LoadProfile)
            {
                var userInfoClient = new UserInfoClient(new Uri(endpoints.UserInfo), tokenResult.AccessToken);
                var userInfoResponse = await userInfoClient.GetAsync();

                var primaryClaimTypes = claims.Select(c => c.Type).Distinct();

                foreach (var claim in userInfoResponse.Claims.Where(c => !primaryClaimTypes.Contains(c.Item1)))
                {
                    claims.Add(new Claim(claim.Item1, claim.Item2));
                }
            }

            // success
            return new LoginResult
            {
                Success = true,
                Claims = FilterProtocolClaims(claims),
                AccessToken = tokenResult.AccessToken,
                RefreshToken = tokenResult.RefreshToken,
                AccessTokenExpiration = DateTime.Now.AddSeconds(tokenResult.ExpiresIn),
                IdentityToken = result.IdentityToken,
                AuthenticationTime = DateTime.Now
            };
        }

        private async Task<Claims> ValidateIdentityTokenAsync(string identityToken)
        {
            var client = new HttpClient();

            var form = new Dictionary<string, string>
            {
                { "token", identityToken },
                { "client_id", _options.ClientId }
            };

            var response = await client.PostAsync(
                new Uri((await _options.GetEndpointsAsync()).IdentityTokenValidation),
                new FormUrlEncodedContent(form));

            if (!response.IsSuccessStatusCode)
            {
                return null;
            }

            var json = JObject.Parse(await response.Content.ReadAsStringAsync());

            var claims = new Claims();

            foreach (var x in json)
            {
                var array = x.Value as JArray;

                if (array != null)
                {
                    foreach (var item in array)
                    {
                        claims.Add(new Claim(x.Key, item.ToString()));
                    }
                }
                else
                {
                    claims.Add(new Claim(x.Key, x.Value.ToString()));
                }
            }

            return claims;
        }

        private Claims FilterProtocolClaims(Claims claims)
        {
            if (_options.FilterClaims)
            {
                return claims.Where(c => !_options.FilteredClaims.Contains(c.Type)).ToClaims();
            }

            return claims;
        }
    }
}