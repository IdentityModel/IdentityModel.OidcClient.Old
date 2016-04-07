using System;
using System.Threading.Tasks;
using System.Linq;
using JosePCL.Keys.Rsa;
using Newtonsoft.Json.Linq;

namespace IdentityModel.OidcClient.IdentityTokenValidation
{
    public class LocalIdentityTokenValidator : IIdentityTokenValidator
    {
        public TimeSpan ClockSkew { get; set; } = TimeSpan.FromMinutes(5);

        public Task<IdentityTokenValidationResult> ValidateAsync(string identityToken, string clientId, ProviderInformation providerInformation)
        {
            var fail = new IdentityTokenValidationResult
            {
                Success = false
            };

            var e = Base64Url.Decode(providerInformation.KeySet.Keys.First().E);
            var n = Base64Url.Decode(providerInformation.KeySet.Keys.First().N);
            var pubKey = PublicKey.New(e, n);

            var json = JosePCL.Jwt.Decode(identityToken, pubKey);
            var payload = JObject.Parse(json);

            var issuer = payload["iss"].ToString();
            var audience = payload["aud"].ToString();

            if (issuer != providerInformation.IssuerName)
            {
                fail.Error = "Invalid issuer name";
                return Task.FromResult(fail);
            }

            if (audience != clientId)
            {
                fail.Error = "Invalid audience";
                return Task.FromResult(fail);
            }

            // todo: exp/nbf check

            //var exp = payload["exp"].ToString();
            //var nbf = payload["nbf"].ToString();

            //DateTime utcNow = DateTime.UtcNow;
            //if (notBefore.HasValue && (notBefore.Value > DateTimeUtil.Add(utcNow, validationParameters.ClockSkew)))
            //    throw LogHelper.LogException<SecurityTokenNotYetValidException>(LogMessages.IDX10222, notBefore.Value, utcNow);

            //if (expires.HasValue && (expires.Value < DateTimeUtil.Add(utcNow, validationParameters.ClockSkew.Negate())))
            //    throw LogHelper.LogException<SecurityTokenExpiredException>(LogMessages.IDX10223, expires.Value, utcNow);

            return Task.FromResult(new IdentityTokenValidationResult
            {
                Success = true,
                Claims = payload.ToClaims(),
                SignatureAlgorithm = "RS256"
            });

        }
    }
}