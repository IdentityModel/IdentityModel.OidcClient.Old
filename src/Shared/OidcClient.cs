// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityModel.Client;
using System;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using PCLCrypto;
using static PCLCrypto.WinRTCrypto;
using IdentityModel.OidcClient.Logging;

namespace IdentityModel.OidcClient
{
    public class OidcClient
    {
        private static readonly ILog Logger = LogProvider.For<OidcClient>();

        private readonly AuthorizeClient _authorizeClient;
        private readonly OidcClientOptions _options;

        public OidcClient(OidcClientOptions options)
        {
            _authorizeClient = new AuthorizeClient(options);
            _options = options;
        }

        public OidcClientOptions Options
        {
            get { return _options; }
        }

        public async Task<LoginResult> LoginAsync(bool trySilent = false, object extraParameters = null)
        {
            Logger.Debug("LoginAsync");

            var authorizeResult = await _authorizeClient.AuthorizeAsync(trySilent, extraParameters);

            if (!authorizeResult.Success)
            {
                return new LoginResult
                {
                    Success = false,
                    Error = authorizeResult.Error
                };
            }

            return await ValidateResponseAsync(authorizeResult.Data, authorizeResult.State);
        }

        public async Task<AuthorizeState> PrepareLoginAsync(object extraParameters = null)
        {
            Logger.Debug("PrepareLoginAsync");

            return await _authorizeClient.PrepareAuthorizeAsync(extraParameters);
        }

        public Task LogoutAsync(string identityToken = null, bool trySilent = true)
        {
            return _authorizeClient.EndSessionAsync(identityToken, trySilent);
        }

        public async Task<LoginResult> ValidateResponseAsync(string data, AuthorizeState state)
        {
            Logger.Debug("ValidateResponseAsync");

            var result = new LoginResult { Success = false };

            var response = new AuthorizeResponse(data);

            if (response.IsError)
            {
                result.Error = response.Error;
                Logger.Error(result.Error);

                return result;
            }

            if (string.IsNullOrEmpty(response.Code))
            {
                result.Error = "missing authorization code";
                Logger.Error(result.Error);

                return result;
            }

            if (string.IsNullOrEmpty(response.State))
            {
                result.Error = "missing state";
                Logger.Error(result.Error);

                return result;
            }

            if (!string.Equals(state.State, response.State, StringComparison.Ordinal))
            {
                result.Error = "invalids state";
                Logger.Error(result.Error);

                return result;
            }

            if (_options.Style == OidcClientOptions.AuthenticationStyle.AuthorizationCode)
            {
                return await ValidateCodeFlowResponseAsync(response, state);
            }
            else if (_options.Style == OidcClientOptions.AuthenticationStyle.Hybrid)
            {
                return await ValidateHybridFlowResponseAsync(response, state);
            }

            throw new InvalidOperationException("Invalid authentication style");
        }

        private async Task<LoginResult> ValidateHybridFlowResponseAsync(AuthorizeResponse authorizeResponse, AuthorizeState state)
        {
            Logger.Debug("ValidateHybridFlowResponse");

            var result = new LoginResult { Success = false };

            if (string.IsNullOrEmpty(authorizeResponse.IdentityToken))
            {
                result.Error = "missing identity token";
                Logger.Error(result.Error);

                return result;
            }

            var validationResult = await ValidateIdentityTokenAsync(authorizeResponse.IdentityToken);
            if (!validationResult.Success)
            {
                result.Error = validationResult.Error ?? "identity token validation error";
                Logger.Error(result.Error);

                return result;
            }

            if (!ValidateNonce(state.Nonce, validationResult.Claims))
            {
                result.Error = "invalid nonce";
                Logger.Error(result.Error);

                return result;
            }

            if (!ValidateAuthorizationCodeHash(authorizeResponse.Code, validationResult.Claims))
            {
                result.Error = "invalid c_hash";
                Logger.Error(result.Error);

                return result;
            }

            // redeem code for tokens
            var tokenResponse = await RedeemCodeAsync(authorizeResponse.Code, state);
            if (tokenResponse.IsError || tokenResponse.IsHttpError)
            {
                return new LoginResult
                {
                    Success = false,
                    Error = tokenResponse.Error
                };
            }

            return await ProcessClaimsAsync(authorizeResponse, tokenResponse, validationResult.Claims);
        }

        
        private async Task<LoginResult> ValidateCodeFlowResponseAsync(AuthorizeResponse authorizeResponse, AuthorizeState state)
        {
            Logger.Debug("ValidateCodeFlowResponse");

            var result = new LoginResult { Success = false };
            
            // redeem code for tokens
            var tokenResponse = await RedeemCodeAsync(authorizeResponse.Code, state);
            if (tokenResponse.IsError || tokenResponse.IsHttpError)
            {
                result.Error = tokenResponse.Error;
                return result;
            }

            if (tokenResponse.IdentityToken.IsMissing())
            {
                result.Error = "missing identity token";
                Logger.Error(result.Error);

                return result;
            }

            var validationResult = await ValidateIdentityTokenAsync(tokenResponse.IdentityToken);
            if (!validationResult.Success)
            {
                result.Error = validationResult.Error ?? "identity token validation error";
                Logger.Error(result.Error);

                return result;
            }

            if (!ValidateAccessTokenHash(tokenResponse.AccessToken, validationResult.Claims))
            {
                result.Error = "invalid access token hash";
                Logger.Error(result.Error);

                return result;
            }

            return await ProcessClaimsAsync(authorizeResponse, tokenResponse, validationResult.Claims);
        }

        private async Task<LoginResult> ProcessClaimsAsync(AuthorizeResponse response, TokenResponse tokenResult, Claims claims)
        {
            Logger.Debug("ProcessClaimsAsync");

            // get profile if enabled
            if (_options.LoadProfile)
            {
                Logger.Debug("load profile");

                var userInfoResult = await GetUserInfoAsync(tokenResult.AccessToken);

                if (!userInfoResult.Success)
                {
                    return new LoginResult
                    {
                        Success = false,
                        Error = userInfoResult.Error
                    };
                }

                Logger.Debug("profile claims:");
                Logger.LogClaims(userInfoResult.Claims);

                var primaryClaimTypes = claims.Select(c => c.Type).Distinct();
                foreach (var claim in userInfoResult.Claims.Where(c => !primaryClaimTypes.Contains(c.Type)))
                {
                    claims.Add(claim);
                }

                Logger.LogClaims(claims);
            }
            else
            {
                Logger.Debug("don't load profile");
                Logger.LogClaims(claims);
            }

            // success
            var loginResult = new LoginResult
            {
                Success = true,
                Claims = FilterClaims(claims),
                AccessToken = tokenResult.AccessToken,
                RefreshToken = tokenResult.RefreshToken,
                AccessTokenExpiration = DateTime.Now.AddSeconds(tokenResult.ExpiresIn),
                IdentityToken = tokenResult.IdentityToken,
                AuthenticationTime = DateTime.Now
            };

            if (!string.IsNullOrWhiteSpace(tokenResult.RefreshToken))
            {
                var providerInfo = await _options.GetProviderInformationAsync();

                loginResult.Handler = new RefeshTokenHandler(
                    providerInfo.TokenEndpoint,
                    _options.ClientId,
                    _options.ClientSecret,
                    tokenResult.RefreshToken,
                    tokenResult.AccessToken);
            }

            return loginResult;
        }


        private async Task<IdentityTokenValidationResult> ValidateIdentityTokenAsync(string idToken)
        {
            var providerInfo = await _options.GetProviderInformationAsync();

            Logger.Debug("Calling identity token validator: " + _options.IdentityTokenValidator.GetType().FullName);
            var validationResult = await _options.IdentityTokenValidator.ValidateAsync(idToken, _options.ClientId, providerInfo);

            if (validationResult.Success == false)
            {
                return validationResult;
            }

            var claims = validationResult.Claims;

            Logger.Debug("identity token validation claims:");
            Logger.LogClaims(claims);
            
            // validate audience
            var audience = claims.FindFirst(JwtClaimTypes.Audience)?.Value ?? "";
            if (!string.Equals(_options.ClientId, audience))
            {
                Logger.Error($"client id ({_options.ClientId}) does not match audience ({audience})");

                return new IdentityTokenValidationResult
                {
                    Success = false,
                    Error = "invalid audience"
                };
            }

            // validate issuer
            var issuer = claims.FindFirst(JwtClaimTypes.Issuer)?.Value ?? "";
            if (!string.Equals(providerInfo.IssuerName, issuer))
            {
                Logger.Error($"configured issuer ({providerInfo.IssuerName}) does not match token issuer ({issuer}");

                return new IdentityTokenValidationResult
                {
                    Success = false,
                    Error = "invalid issuer"
                };
            }

            return validationResult;
        }

        private bool ValidateNonce(string nonce, Claims claims)
        {
            Logger.Debug("validate nonce");

            var tokenNonce = claims.FindFirst(JwtClaimTypes.Nonce)?.Value ?? "";
            var match = string.Equals(nonce, tokenNonce, StringComparison.Ordinal);

            if (!match)
            {
                Logger.Error($"nonce ({nonce}) does not match nonce from token ({tokenNonce})");
            }

            return match;
        }

        private bool ValidateAuthorizationCodeHash(string code, Claims claims)
        {
            Logger.Debug("validate authorization code hash");

            var cHash = claims.FindFirst(JwtClaimTypes.AuthorizationCodeHash)?.Value ?? "";
            if (cHash.IsMissing())
            {
                return true;
            }

            var sha256 = HashAlgorithmProvider.OpenAlgorithm(HashAlgorithm.Sha256);

            var codeHash = sha256.HashData(
                CryptographicBuffer.CreateFromByteArray(
                    Encoding.UTF8.GetBytes(code)));

            byte[] codeHashArray;
            CryptographicBuffer.CopyToByteArray(codeHash, out codeHashArray);

            byte[] leftPart = new byte[16];
            Array.Copy(codeHashArray, leftPart, 16);

            var leftPartB64 = Base64Url.Encode(leftPart);
            var match = leftPartB64.Equals(cHash);

            if (!match)
            {
                Logger.Error($"code hash ({leftPartB64}) does not match c_hash from token ({cHash})");
            }

            return match;
        }

        private bool ValidateAccessTokenHash(string accessToken, Claims claims)
        {
            Logger.Debug("validate authorization code hash");

            var atHash = claims.FindFirst(JwtClaimTypes.AccessTokenHash)?.Value ?? "";
            if (atHash.IsMissing())
            {
                return true;
            }

            var sha256 = HashAlgorithmProvider.OpenAlgorithm(HashAlgorithm.Sha256);

            var codeHash = sha256.HashData(
                CryptographicBuffer.CreateFromByteArray(
                    Encoding.UTF8.GetBytes(accessToken)));

            byte[] atHashArray;
            CryptographicBuffer.CopyToByteArray(codeHash, out atHashArray);

            byte[] leftPart = new byte[16];
            Array.Copy(atHashArray, leftPart, 16);

            var leftPartB64 = Base64Url.Encode(leftPart);

            var match = leftPartB64.Equals(atHash);

            if (!match)
            {
                Logger.Error($"access token hash ({leftPartB64}) does not match at_hash from token ({atHash})");
            }

            return match;
        }

        private async Task<TokenResponse> RedeemCodeAsync(string code, AuthorizeState state)
        {
            var endpoint = (await _options.GetProviderInformationAsync()).TokenEndpoint;

            var tokenClient = new TokenClient(endpoint, _options.ClientId, _options.ClientSecret);
            var tokenResult = await tokenClient.RequestAuthorizationCodeAsync(
                code,
                state.RedirectUri,
                codeVerifier: state.CodeVerifier);

            return tokenResult;
        }

        public async Task<UserInfoResult> GetUserInfoAsync(string accessToken)
        {
            var providerInfo = await _options.GetProviderInformationAsync();

            var userInfoClient = new UserInfoClient(new Uri(providerInfo.UserInfoEndpoint), accessToken);
            var userInfoResponse = await userInfoClient.GetAsync();

            if (userInfoResponse.IsError)
            {
                return new UserInfoResult
                {
                    Success = false,
                    Error = userInfoResponse.ErrorMessage
                };
            }

            return new UserInfoResult
            {
                Success = true,
                Claims = userInfoResponse.Claims.Select(c => new Claim(c.Item1, c.Item2)).ToClaims()
            };
        }

        public async Task<RefreshTokenResult> RefreshTokenAsync(string refreshToken)
        {
            var providerInfo = await _options.GetProviderInformationAsync();

            var tokenClient = new TokenClient(
                providerInfo.TokenEndpoint,
                _options.ClientId,
                _options.ClientSecret);

            var response = await tokenClient.RequestRefreshTokenAsync(refreshToken);

            if (response.IsError)
            {
                return new RefreshTokenResult
                {
                    Success = false,
                    Error = response.Error
                };
            }
            else
            {
                return new RefreshTokenResult
                {
                    Success = true,
                    AccessToken = response.AccessToken,
                    RefreshToken = response.RefreshToken,
                    ExpiresIn = (int)response.ExpiresIn
                };
            }
        }

        private Claims FilterClaims(Claims claims)
        {
            Logger.Debug("filtering claims");

            if (_options.FilterClaims)
            {
                claims = claims.Where(c => !_options.FilteredClaims.Contains(c.Type)).ToClaims();
            }

            Logger.Debug("filtered claims:");
            Logger.LogClaims(claims);

            return claims;
        }
    }
}