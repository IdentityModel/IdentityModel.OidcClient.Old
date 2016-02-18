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
        private readonly Lazy<Task<Endpoints>> _endpoints;

        public string ClientId { get; }
        public string ClientSecret { get; }
        public string Scope { get; }
        public string RedirectUri { get; }
        public IWebView WebView { get; }
        public Flow Flow { get; set; } = Flow.Hybrid;
        public bool UseFormPost { get; set; } = true;
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

        private OidcClientOptions(string clientId, string clientSecret, string scope, string redirectUri, IWebView webView)
        {
            if (string.IsNullOrWhiteSpace(clientId)) throw new ArgumentNullException(nameof(clientId));
            if (string.IsNullOrWhiteSpace(clientSecret)) throw new ArgumentNullException(nameof(clientSecret));
            if (string.IsNullOrWhiteSpace(scope)) throw new ArgumentNullException(nameof(scope));
            if (string.IsNullOrWhiteSpace(redirectUri)) throw new ArgumentNullException(nameof(redirectUri));
            if (webView == null) throw new ArgumentNullException(nameof(webView));

            ClientId = clientId;
            ClientSecret = clientSecret;
            Scope = scope;
            RedirectUri = redirectUri;
            WebView = webView;
        }
        public OidcClientOptions(Endpoints endpoints, string clientId, string clientSecret, string scope, string redirectUri, IWebView webView)
            : this(clientId, clientSecret, scope, redirectUri, webView)
        {
            if (endpoints == null) throw new ArgumentNullException(nameof(endpoints));
            endpoints.Validate();

            _endpoints = new Lazy<Task<Endpoints>>(() => Task.FromResult(endpoints));
        }

        public OidcClientOptions(string authority, string clientId, string clientSecret, string scope, string redirectUri, IWebView webView)
            : this(clientId, clientSecret, scope, redirectUri, webView)
        {
            if (string.IsNullOrWhiteSpace(authority)) throw new ArgumentNullException(nameof(authority));

            _endpoints = new Lazy<Task<Endpoints>>(async () => await Endpoints.LoadFromMetadataAsync(authority));
        }

        public async Task<Endpoints> GetEndpointsAsync()
        {
            return await _endpoints.Value;
        }
    }
}
