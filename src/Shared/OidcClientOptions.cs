﻿// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityModel.OidcClient.IdentityTokenValidation;
using IdentityModel.OidcClient.WebView;
using System;
using System.Collections.Generic;
using System.Net.Http;
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

        public bool UseFormPost { get; set; } = false;
        public bool LoadProfile { get; set; } = true;
        public bool FilterClaims { get; set; } = true;
        public AuthenticationStyle Style = AuthenticationStyle.Hybrid;
        
        public TimeSpan WebViewTimeout { get; set; } = TimeSpan.FromSeconds(10);
        public TimeSpan BackchannelTimeout { get; set; } = TimeSpan.FromSeconds(30);
        public HttpMessageHandler BackchannelHandler { get; set; }

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

        public enum AuthenticationStyle
        {
            AuthorizationCode,
            Hybrid
        }

        private OidcClientOptions(string clientId, string clientSecret, string scope, string redirectUri, IWebView webView = null, IIdentityTokenValidator validator = null)
        {
            if (string.IsNullOrWhiteSpace(clientId)) throw new ArgumentNullException(nameof(clientId));
            if (string.IsNullOrWhiteSpace(clientSecret)) throw new ArgumentNullException(nameof(clientSecret));
            if (string.IsNullOrWhiteSpace(scope)) throw new ArgumentNullException(nameof(scope));
            if (string.IsNullOrWhiteSpace(redirectUri)) throw new ArgumentNullException(nameof(redirectUri));
            
            ClientId = clientId;
            ClientSecret = clientSecret;
            Scope = scope;
            RedirectUri = redirectUri;
            IdentityTokenValidator = validator ?? new DefaultIdentityTokenValidator();
            WebView = webView;
        }

        public OidcClientOptions(ProviderInformation info, string clientId, string clientSecret, string scope, string redirectUri, IWebView webView = null, IIdentityTokenValidator validator = null)
            : this(clientId, clientSecret, scope, redirectUri, webView, validator)
        {
            if (info == null) throw new ArgumentNullException(nameof(info));
            info.Validate();

            _providerInfo = new Lazy<Task<ProviderInformation>>(() => Task.FromResult(info));
        }

        public OidcClientOptions(string authority, string clientId, string clientSecret, string scope, string redirectUri, IWebView webView = null, IIdentityTokenValidator validator = null)
            : this(clientId, clientSecret, scope, redirectUri, webView, validator)
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