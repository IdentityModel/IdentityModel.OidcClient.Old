// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityModel.Client;
using IdentityModel.OidcClient.WebView;
using System;
using System.Text;
using System.Threading.Tasks;
using PCLCrypto;
using static PCLCrypto.WinRTCrypto;

namespace IdentityModel.OidcClient
{
    public class AuthorizeClient
    {
        private readonly OidcClientOptions _options;

        public AuthorizeClient(OidcClientOptions options)
        {
            _options = options;
        }

        public async Task<AuthorizeResult> AuthorizeAsync(bool trySilent = false, object extraParameters = null)
        {
            InvokeResult wviResult;
            AuthorizeResult result = new AuthorizeResult
            {
                IsError = true,
            };

            // todo: replace with CryptoRandom
            result.Nonce = Guid.NewGuid().ToString("N");
            result.RedirectUri = _options.RedirectUri;
            string codeChallenge = CreateCodeChallenge(result);
            var url = await CreateUrlAsync(result, codeChallenge, extraParameters);
            var webViewOptions = new InvokeOptions(url, _options.RedirectUri);
            if (trySilent)
            {
                webViewOptions.InitialDisplayMode = DisplayMode.Hidden;
            }
            if (_options.UseFormPost)
            {
                webViewOptions.ResponseMode = ResponseMode.FormPost;
            }

            // try silent mode if requested
            wviResult = await _options.WebView.InvokeAsync(webViewOptions);

            if (wviResult.ResultType == InvokeResultType.Success)
            {
                return await ParseResponse(wviResult.Response, result);
            }

            result.Error = wviResult.ResultType.ToString();
            return result;
        }

        public async Task EndSessionAsync(string identityToken = null, bool trySilent = true)
        {
            string url = (await _options.GetProviderInformationAsync()).EndSession;

            if (!string.IsNullOrWhiteSpace(identityToken))
            {
                url += $"?{OidcConstants.EndSessionRequest.IdTokenHint}={identityToken}" +
                       $"&{OidcConstants.EndSessionRequest.PostLogoutRedirectUri}={_options.RedirectUri}";
            }

            var webViewOptions = new InvokeOptions(url, _options.RedirectUri)
            {
                ResponseMode = ResponseMode.Redirect
            };

            if (trySilent)
            {
                webViewOptions.InitialDisplayMode = DisplayMode.Hidden;
            }

            var result = await _options.WebView.InvokeAsync(webViewOptions);
        }

        private string CreateCodeChallenge(AuthorizeResult result)
        {
            if (_options.UseProofKeys)
            {
                // todo: replace with CryptoRandom
                result.Verifier = Guid.NewGuid().ToString("N") + Guid.NewGuid().ToString("N");
                var sha256 = HashAlgorithmProvider.OpenAlgorithm(HashAlgorithm.Sha256);

                var challengeBuffer = sha256.HashData(
                    CryptographicBuffer.CreateFromByteArray(
                        Encoding.UTF8.GetBytes(result.Verifier)));
                byte[] challengeBytes;

                CryptographicBuffer.CopyToByteArray(challengeBuffer, out challengeBytes);
                return Base64Url.Encode(challengeBytes);
            }
            else
            {
                return null;
            }
        }

        private async Task<string> CreateUrlAsync(AuthorizeResult result, string codeChallenge, object extraParameters)
        {
            var request = new AuthorizeRequest((await _options.GetProviderInformationAsync()).Authorize);
            var url = request.CreateAuthorizeUrl(
                clientId: _options.ClientId,
                responseType: OidcConstants.ResponseTypes.CodeIdToken,
                scope: _options.Scope,
                redirectUri: result.RedirectUri,
                responseMode: _options.UseFormPost ? OidcConstants.ResponseModes.FormPost : null,
                nonce: result.Nonce,
                codeChallenge: codeChallenge,
                codeChallengeMethod: _options.UseProofKeys ? OidcConstants.CodeChallengeMethods.Sha256 : null,
                extra: extraParameters);

            return url;
        }

        private Task<AuthorizeResult> ParseResponse(string webViewResponse, AuthorizeResult result)
        {
            var response = new AuthorizeResponse(webViewResponse);

            if (response.IsError)
            {
                result.Error = response.Error;
                return Task.FromResult(result);
            }

            if (string.IsNullOrEmpty(response.Code))
            {
                result.Error = "Missing authorization code";
                return Task.FromResult(result);
            }

            if (string.IsNullOrEmpty(response.IdentityToken))
            {
                result.Error = "Missing identity token";
                return Task.FromResult(result);
            }

            result.IdentityToken = response.IdentityToken;
            result.Code = response.Code;
            result.IsError = false;

            return Task.FromResult(result);
        }
    }
}