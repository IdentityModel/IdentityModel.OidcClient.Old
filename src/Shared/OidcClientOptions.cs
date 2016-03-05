// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityModel.OidcClient.WebView;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace IdentityModel.OidcClient
{
    public class OidcClientOptions
    {
        private readonly Lazy<Task<ProviderInformation>> _providerInfo;

        public string ClientId { get; }
        public string ClientSecret { get; }
        public string Scope { get; }
        public string RedirectUri { get; }
        public IWebView WebView { get; }
        public IIdentityTokenValidator IdentityTokenValidator { get; }

        public Flow Flow { get; set; } = Flow.Hybrid;
        public bool UseFormPost { get; set; } = false;
        public bool LoadProfile { get; set; } = true;
        public bool FilterClaims { get; set; } = true;
        public bool UseProofKeys { get; set; } = true;

        public IList<string> FilteredClaims { get; set; } = new List<string>
        {
            JwtClaimTypes.Issuer,
            JwtClaimTypes.Expiration,
            JwtClaimTypes.NotBefore,
            JwtClaimTypes.Audience,
            JwtClaimTypes.Nonce,
            JwtClaimTypes.IssuedAt,
            JwtClaimTypes.AuthenticationTime,
            JwtClaimTypes.AuthorizationCodeHash,
            JwtClaimTypes.AccessTokenHash
        };

        private OidcClientOptions(string clientId, string clientSecret, string scope, string redirectUri, IIdentityTokenValidator validator, IWebView webView = null)
        {
            if (string.IsNullOrWhiteSpace(clientId)) throw new ArgumentNullException(nameof(clientId));
            if (string.IsNullOrWhiteSpace(clientSecret)) throw new ArgumentNullException(nameof(clientSecret));
            if (string.IsNullOrWhiteSpace(scope)) throw new ArgumentNullException(nameof(scope));
            if (string.IsNullOrWhiteSpace(redirectUri)) throw new ArgumentNullException(nameof(redirectUri));
            if (validator == null) throw new ArgumentNullException(nameof(validator));

            ClientId = clientId;
            ClientSecret = clientSecret;
            Scope = scope;
            RedirectUri = redirectUri;
            WebView = webView;
            IdentityTokenValidator = validator;
        }

        public OidcClientOptions(ProviderInformation info, string clientId, string clientSecret, string scope, string redirectUri, IIdentityTokenValidator validator, IWebView webView = null)
            : this(clientId, clientSecret, scope, redirectUri, validator, webView)
        {
            if (info == null) throw new ArgumentNullException(nameof(info));
            info.Validate();

            _providerInfo = new Lazy<Task<ProviderInformation>>(() => Task.FromResult(info));
        }

        public OidcClientOptions(string authority, string clientId, string clientSecret, string scope, string redirectUri, IIdentityTokenValidator validator, IWebView webView = null)
            : this(clientId, clientSecret, scope, redirectUri, validator, webView)
        {
            if (string.IsNullOrWhiteSpace(authority)) throw new ArgumentNullException(nameof(authority));

            _providerInfo = new Lazy<Task<ProviderInformation>>(async () => await ProviderInformation.LoadFromMetadataAsync(authority));
        }

        public async Task<ProviderInformation> GetProviderInformationAsync()
        {
            return await _providerInfo.Value;
        }
    }
}