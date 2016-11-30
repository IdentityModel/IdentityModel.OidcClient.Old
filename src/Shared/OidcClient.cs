// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityModel.Client;
using System;
using System.Linq;
using System.Threading.Tasks;
using IdentityModel.OidcClient.Logging;
using System.Net.Http;
using IdentityModel.OidcClient.Infrastructure;

namespace IdentityModel.OidcClient
{
    public class OidcClient
    {
        private static readonly ILog Logger = LogProvider.For<OidcClient>();

        private readonly AuthorizeClient _authorizeClient;
        private readonly OidcClientOptions _options;
        private readonly ResponseValidator _validator;

        public OidcClientOptions Options
        {
            get { return _options; }
        }

        public OidcClient(OidcClientOptions options)
        {
            _authorizeClient = new AuthorizeClient(options);
            _validator = new ResponseValidator(options);

            _options = options;
        }

        public async Task<LoginResult> LoginAsync(bool trySilent = false, object extraParameters = null)
        {
            Logger.Debug("LoginAsync");

            var authorizeResult = await _authorizeClient.AuthorizeAsync(trySilent, extraParameters);

            if (!authorizeResult.Success)
            {
                return new LoginResult(authorizeResult.Error);
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
            Logger.Debug("Validate authorize response");
            
            var response = new AuthorizeResponse(data);

            if (response.IsError)
            {
                Logger.Error(response.Error);

                return new LoginResult(response.Error);
            }

            if (string.IsNullOrEmpty(response.Code))
            {
                var error = "Missing authorization code";
                Logger.Error(error);

                return new LoginResult(error);
            }

            if (string.IsNullOrEmpty(response.State))
            {
                var error = "Missing state";
                Logger.Error(error);

                return new LoginResult(error);
            }

            if (!string.Equals(state.State, response.State, StringComparison.Ordinal))
            {
                var error = "Invalid state";
                Logger.Error(error);

                return new LoginResult(error);
            }

            ResponseValidationResult validationResult = null;
            if (_options.Style == OidcClientOptions.AuthenticationStyle.AuthorizationCode)
            {
                validationResult = await _validator.ValidateCodeFlowResponseAsync(response, state);
            }
            else if (_options.Style == OidcClientOptions.AuthenticationStyle.Hybrid)
            {
                validationResult = await _validator.ValidateHybridFlowResponseAsync(response, state);
            }
            else
            {
                throw new InvalidOperationException("Invalid authentication style");
            }

            if (!validationResult.Success)
            {
                return new LoginResult
                {
                    Error = validationResult.Error
                };
            }

            return await ProcessClaimsAsync(validationResult);
        }

        private async Task<LoginResult> ProcessClaimsAsync(ResponseValidationResult result)
        {
            Logger.Debug("ProcessClaimsAsync");

            // get profile if enabled
            if (_options.LoadProfile)
            {
                Logger.Debug("load profile");

                var userInfoResult = await GetUserInfoAsync(result.TokenResponse.AccessToken);

                if (!userInfoResult.Success)
                {
                    return new LoginResult(userInfoResult.Error);
                }

                Logger.Debug("profile claims:");
                Logger.LogClaims(userInfoResult.Claims);

                var primaryClaimTypes = result.Claims.Select(c => c.Type).Distinct();
                foreach (var claim in userInfoResult.Claims.Where(c => !primaryClaimTypes.Contains(c.Type)))
                {
                    result.Claims.Add(claim);
                }
            }
            else
            {
                Logger.Debug("don't load profile");
            }

            // success
            var loginResult = new LoginResult
            {
                Claims = FilterClaims(result.Claims),
                AccessToken = result.TokenResponse.AccessToken,
                RefreshToken = result.TokenResponse.RefreshToken,
                AccessTokenExpiration = DateTime.Now.AddSeconds(result.TokenResponse.ExpiresIn),
                IdentityToken = result.TokenResponse.IdentityToken,
                AuthenticationTime = DateTime.Now
            };

            if (!string.IsNullOrWhiteSpace(result.TokenResponse.RefreshToken))
            {
                var providerInfo = await _options.GetProviderInformationAsync();

                loginResult.Handler = new RefeshTokenHandler(
                    await TokenClientFactory.CreateAsync(_options),
                    result.TokenResponse.RefreshToken,
                    result.TokenResponse.AccessToken);
            }

            return loginResult;
        }

        public async Task<UserInfoResult> GetUserInfoAsync(string accessToken)
        {
            var providerInfo = await _options.GetProviderInformationAsync();
            var handler = _options.BackchannelHandler ?? new HttpClientHandler();

            var userInfoClient = new UserInfoClient(new Uri(providerInfo.UserInfoEndpoint), accessToken, handler);
            userInfoClient.Timeout = _options.BackchannelTimeout;

            var userInfoResponse = await userInfoClient.GetAsync();
            if (userInfoResponse.IsError)
            {
                return new UserInfoResult
                {
                    Error = userInfoResponse.ErrorMessage
                };
            }

            return new UserInfoResult
            {
                Claims = userInfoResponse.Claims.Select(c => new Claim(c.Item1, c.Item2)).ToClaims()
            };
        }

        public async Task<RefreshTokenResult> RefreshTokenAsync(string refreshToken)
        {
            var client = await TokenClientFactory.CreateAsync(_options);
            var response = await client.RequestRefreshTokenAsync(refreshToken);

            if (response.IsError)
            {
                return new RefreshTokenResult
                {
                    Error = response.Error
                };
            }
            else
            {
                return new RefreshTokenResult
                {
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