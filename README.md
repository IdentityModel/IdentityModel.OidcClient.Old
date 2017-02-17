**important** This repo is not maintained anymore. This version of OidcClient is based on the PCL (portable class library) technology, which is not encouraged to use anymore. [OidcClient2](https://github.com/IdentityModel/IdentityModel.OidcClient2) is the recommended successor, and is based on netstandard.


# OpenID Connect Client Library for native Applications

OidcClient is a portable library (Desktop .NET, UWP, Xamarin iOS & Android) that provides a couple of helpers typically needed by native applications
to implement user authentication and access token requests using OpenID Connect and OAuth 2.0:

* Creating authorization requests
* Parsing authorization responses
* WebView/Browser interaction
* Validating identity tokens
* Requesting access and refresh tokens
* Refresh token management

We follow the recommendations from [OAuth 2.0 for Native Apps](https://tools.ietf.org/html/draft-ietf-oauth-native-apps-01)
and implement OpenID Connect [Hybrid Flow](https://openid.net/specs/openid-connect-core-1_0.html#HybridFlowAuth) and [PKCE](https://tools.ietf.org/html/rfc7636) for maximum security.

## Setup

The `OidcClientOptions` class lets you set up the parameters for communicating
with the OpenID Connect provider. Here you specify the base address of the 
provider, client ID, client secret, scopes and redirect URI.

```csharp
var authority = "https://demo.identityserver.io";

var options = new OidcClientOptions (
    authority: authority,
    clientId: "native",
    clientSecret: "secret",
    scope: "openid profile api offline_access",
    redirectUri: "com.mycompany.myapp://callback");
```

Optionally you can also pass in an implementation of a web view. The [samples](https://github.com/IdentityModel/IdentityModel.OidcClient.Samples)
repository has sample web views for WinForms (.NET Desktop) and the Universal Windows Platform.
Feel free to contribute to add more platforms.

## Requesting tokens

The `OidcClient` class supports two modes to interact with the token provider

* generation of requests and parsing of response message. Interaction with the web view is done manually
* the web view interaction is encapsulated

### Manual

To generate the authorize start URL and the necessary artifacts like nonce, code verifier and challenge,
call `PrepareLoginAsync`. This will return a state object that will be used later to validate the response.

```csharp
var client = new OidcClient(options);
var state = await _client.PrepareLoginAsync();
```

You can now launch your favourite browser using the `StartUrl` property returned from the state object.

```csharp
var safari = new SafariServices.SFSafariViewController (new NSUrl (_state.StartUrl));
```

In this mode, it is also your responsibility to capture the full return URL after the authentication is done.
You can pass the URL back to `OidcClient` to do the parsing and validation.
If successful, the `LoginResult` result returned will contain the claims of the user, access token and refresh token:

```csharp
var result = await client.ValidateResponseAsync (url, state);

var sb = new StringBuilder (128);
foreach (var claim in result.Claims) 
{
    sb.AppendFormat ("{0}: {1}\n", claim.Type, claim.Value);
}

sb.AppendFormat ("\n{0}: {1}\n", "refresh token", result.RefreshToken);
sb.AppendFormat ("\n{0}: {1}\n", "access token", result.AccessToken);

TokenTextView.Text = sb.ToString ();
```

### Encapsulated Web View

You can also wrap the web view interaction in an `IWebView`. If such an implementation exists,
you can simply call `LoginAsync` and get back the `LoginResult` directly:

```csharp
var result = await oidcClient.LoginAsync();
```

## Calling APIs

You now have everything you need to call APIs. You can use the access token to
authenticate against the API, and the refresh token (if requested) to refresh an expired access token.

If you want to automate token handling, you can also use our `RefreshTokenHandler` which will take
care of setting tokens on outgoing requests as well as refreshing tokens if the API returns a 401.

The handler is available as a standalone class, as well a directly from the `LoginResult`:

```csharp
var apiClient = new HttpClient(result.Handler);
apiClient.BaseAddress = new Uri("https://demo.identityserver.io/api/");

var result = await apiClient.GetAsync("resource");
```

# OSS FTW!

`OidcClient` is based on the following OSS projects:

* [IdentityModel](https://github.com/IdentityModel/IdentityModel)
* [PCLCrypto](https://github.com/AArnott/PCLCrypto)
* [Jose-Pcl](https://github.com/dvsekhvalnov/jose-pcl)
* [Json.Net](https://github.com/JamesNK/Newtonsoft.Json)
